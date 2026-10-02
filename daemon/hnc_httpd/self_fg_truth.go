// self_fg_truth.go — v5.24 T2 本机前台真值采集。
//
// 干什么: 本机开着「本机流量归因」时, 每 10 秒读一次当前前台 App 的包名,
// 只在前台变化时往 run/self_fg.YYYYMMDD.jsonl 追加一行「这个时刻, 前台是某个包」。
// 这是 v5.25 前台评估(HMM 那套)要用的真值 —— v5.24 只采集, 不拿它评估。
//
// 边界(工作文档 §2):
//   - 只采本机自己, 不碰热点客户端设备。
//   - 只存 时间 + 包名 + 取数方式; 不存窗口标题、界面内容、截图。
//   - 只写本机 run/ 下, 7 天过期, 不上传。
//   - 不改变任何识别 / 限速 / 封锁行为; 本文件是纯采集旁路。
//
// 资源(§2.3 + §7):
//   - 仅当 run/activity.json 的 screen_known && screen_on 时才探测(熄屏不跑),
//     且仅当 run/self_capture.enabled 存在时才跑(和本机抓包同一个开关)。
//   - dumpsys 很慢且可能卡死: 每个命令 2 秒超时 + hardenCmd(防僵尸)。
//   - ColorOS / Android 16 的 dumpsys 输出格式和原生不同: 解析宽松, 失败记
//     source:"none" 并降级, 绝不 panic。
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	// selfFGInterval 探测间隔: 10 秒。
	selfFGInterval = 10 * time.Second
	// selfFGCmdTimeout 单条 dumpsys 命令的超时(§7.2: dumpsys 可能卡住)。
	selfFGCmdTimeout = 2 * time.Second
	// selfFGRetainDays 前台真值保留天数, 与样本一致(§2.2)。
	selfFGRetainDays = 7
	// selfFGFileMode run/ 下私有, 不放全局可读。
	selfFGFileMode = os.FileMode(0o640)
)

// selfFGRecord 是落到 jsonl 的一行(字段名固定, 见工作文档 T2)。
type selfFGRecord struct {
	Ts     int64  `json:"ts"`
	Pkg    string `json:"pkg"`
	Source string `json:"source"` // activities | window | none
}

// fgPkgRe 从 dumpsys 行里取包名: 形如 "com.ss.android.ugc.aweme/..."。
// 要求至少一个 "." 分隔的多段标识符后紧跟 "/"(组件分隔符), 避免误抓到别的词。
var fgPkgRe = regexp.MustCompile(`([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+)/`)

// fgTruthLoop 后台循环, 由 main.go 启动一次。
// 与 self_capture.enabled 同开合同关; 熄屏不探测。
func (s *server) fgTruthLoop(stop <-chan struct{}) {
	var lastPkg string
	tk := time.NewTicker(selfFGInterval)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-tk.C:
			// 两道门: 本机抓包开关 + 明确亮屏。任一不满足就跳过这一轮。
			if !selfFGEnabled(s.hncDir) || !screenOnNow() {
				continue
			}
			pkg, src := readForegroundPkg(runDumpsysCmd)
			if pkg == "" {
				// 没取到前台包(ColorOS / Android 16 格式不认): 记 none, 不写行,
				// 让评估页能报告「这台手机取不到前台应用」(§T2)。
				continue
			}
			if pkg == lastPkg {
				continue // 只在前台包名变化时写
			}
			lastPkg = pkg
			rec := selfFGRecord{Ts: now.Unix(), Pkg: pkg, Source: src}
			if err := appendSelfFG(s.hncDir, now, rec); err != nil {
				continue
			}
			// 每天首次写入(跨天)顺带做过期清理, 避免每轮都扫盘。
			sweepSelfFG(s.hncDir, now)
		}
	}
}

// selfFGEnabled 本机抓包开关是否打开(和 dpid self_capture 同一个标志文件)。
func selfFGEnabled(hncDir string) bool {
	_, err := os.Stat(filepath.Join(hncDir, "run", "self_capture.enabled"))
	return err == nil
}

// screenOnNow 从 run/activity.json 读亮屏状态。
// 仅当 screen_known && screen_on 才返回 true —— 状态未知按「不确定」处理, 不探测。
func screenOnNow() bool {
	a := activityNow()
	return a.ScreenKnown && a.ScreenOn
}

// dumpsysRunner 是取 dumpsys 输出的可注入函数(单测替换)。
type dumpsysRunner func(args ...string) (string, bool)

// runDumpsysCmd 用 hardenCmd + 2s 超时执行 dumpsys, 返回 stdout 与是否成功。
func runDumpsysCmd(args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), selfFGCmdTimeout)
	defer cancel()
	// #nosec G204 — args 来自本文件内固定字面量("activity activities"/"window"),
	// 不含用户输入; dumpsys 是系统命令。
	cmd := hardenCmd(exec.CommandContext(ctx, "dumpsys", args...))
	out, err := cmd.Output()
	if err != nil || ctx.Err() != nil {
		return "", false
	}
	return string(out), true
}

// readForegroundPkg 依次尝试两种取数方式, 第一个成功即用(§T2)。
// 全程解析宽松, 任何异常都返回 ("", "none"), 不 panic。
func readForegroundPkg(run dumpsysRunner) (pkg, source string) {
	if out, ok := run("activity", "activities"); ok {
		if p := parseFGActivities(out); p != "" {
			return p, "activities"
		}
	}
	if out, ok := run("window"); ok {
		if p := parseFGWindow(out); p != "" {
			return p, "window"
		}
	}
	return "", "none"
}

// parseFGActivities 从 `dumpsys activity activities` 取前台包名:
// 找含 topResumedActivity 或 mResumedActivity 的第一行, 再用 fgPkgRe 抓包名。
func parseFGActivities(out string) string {
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // dumpsys 单行可能很长
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "topResumedActivity") || strings.Contains(line, "mResumedActivity") {
			if p := firstPkg(line); p != "" {
				return p
			}
		}
	}
	return ""
}

// parseFGWindow 从 `dumpsys window` 取前台包名:
// 找含 mCurrentFocus 或 mFocusedApp 的第一行, 再用 fgPkgRe 抓包名。
func parseFGWindow(out string) string {
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "mCurrentFocus") || strings.Contains(line, "mFocusedApp") {
			if p := firstPkg(line); p != "" {
				return p
			}
		}
	}
	return ""
}

// firstPkg 取一行里第一个形如 "com.x.y/" 的包名。没有则返回 ""。
func firstPkg(line string) string {
	m := fgPkgRe.FindStringSubmatch(line)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// selfFGPath 当天前台真值文件路径。
func selfFGPath(hncDir string, t time.Time) string {
	return filepath.Join(hncDir, "run", "self_fg."+t.Local().Format("20060102")+".jsonl")
}

// appendSelfFG 追加一行(文件不存在则创建)。失败只返回 err, 不影响循环。
func appendSelfFG(hncDir string, t time.Time, rec selfFGRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	path := selfFGPath(hncDir, t)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, selfFGFileMode)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(b)
	return err
}

// sweepSelfFG 删除 7 天前的 self_fg.*.jsonl。只删自己前缀 + 标准日期名的文件,
// 绝不碰别人的东西。读目录失败 / 删除失败都静默(采集不能因此中断)。
func sweepSelfFG(hncDir string, now time.Time) {
	dir := filepath.Join(hncDir, "run")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := now.AddDate(0, 0, -selfFGRetainDays).Format("20060102")
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "self_fg.") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		day := strings.TrimSuffix(strings.TrimPrefix(name, "self_fg."), ".jsonl")
		if len(day) != 8 || day >= cutoff {
			continue
		}
		_ = os.Remove(filepath.Join(dir, name))
	}
}

// selfFGSummary 给评估接口(T4)用: 24 小时内前台切换次数 + 最近一次。
// 读不到文件返回空摘要, 不报错。
type selfFGSummary struct {
	Switches24h int    `json:"switches_24h"`
	LastPkg     string `json:"last_pkg"`
	LastTs      int64  `json:"last_ts"`
	Source      string `json:"source"`
}

func summarizeSelfFG(hncDir string, now time.Time) selfFGSummary {
	var sum selfFGSummary
	sum.Source = "none"
	cutoff := now.Add(-24 * time.Hour).Unix()
	// 扫最近两天的文件(跨零点时 24 小时窗口会横跨两个日期文件)。
	for _, day := range []string{now.Local().Format("20060102"), now.AddDate(0, 0, -1).Local().Format("20060102")} {
		path := filepath.Join(hncDir, "run", "self_fg."+day+".jsonl")
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 8*1024), 64*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var rec selfFGRecord
			if json.Unmarshal([]byte(line), &rec) != nil {
				continue
			}
			if rec.Ts < cutoff {
				continue
			}
			sum.Switches24h++
			if rec.Ts >= sum.LastTs {
				sum.LastTs, sum.LastPkg, sum.Source = rec.Ts, rec.Pkg, rec.Source
			}
		}
		f.Close()
	}
	return sum
}
