// Package procfind —— HNC 进程检测的唯一权威实现(v5.26 T3)。
//
// 此前有四份各自为政的写法(httpd selfcheck 的 pidof 兜底、power_stats 的
// procTable+findPID、action_v511 runStatusScript 里的 shell pidof、
// bin/rc17_process_health.sh 的 ps -ef 扫描), 数值口径互相不一致, Android
// toybox 的 pidof/ps 还各有坑(带完整路径调用的进程会丢)。本包统一:
//   - 一次 /proc 扫描(Table), 拿到每个进程的 ppid / CPU ticks / starttime / cmdline
//   - 统一的查找语义(FindPID): Self → pidfile(存活+cmdline 校验) → cmdline 扫描
//
// FS 与 httpd 现有测试桩同构(ReadFile/ReadDir 函数字段), 测试可注入假 /proc。
package procfind

import (
	"os"
	"sort"
	"strconv"
	"strings"
)

// FS 读 /proc 的入口(测试注入)。
type FS struct {
	ReadFile func(string) ([]byte, error)
	ReadDir  func(string) ([]string, error)
	SelfPID  int
}

// New 返回真实 /proc 的 FS。
func New() FS {
	return FS{
		ReadFile: os.ReadFile,
		ReadDir: func(p string) ([]string, error) {
			ents, err := os.ReadDir(p)
			if err != nil {
				return nil, err
			}
			out := make([]string, 0, len(ents))
			for _, e := range ents {
				out = append(out, e.Name())
			}
			return out, nil
		},
		SelfPID: os.Getpid(),
	}
}

// Row 一次扫描得到的单个进程行。
type Row struct {
	PID, PPID int
	Own       uint64 // utime+stime (ticks)
	Child     uint64 // cutime+cstime (ticks)
	Start     uint64 // starttime (ticks)
	Cmdline   string // argv 以空格连接(NUL→空格)
}

// StatFields /proc/<pid>/stat → ppid, utime+stime, cutime+cstime, starttime。
// comm 可含空格/括号, 从最后一个 ')' 后切。
func StatFields(s string) (ppid int, own, child, start uint64, ok bool) {
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return
	}
	f := strings.Fields(s[i+1:])
	// f[0]=state(3) f[1]=ppid(4) f[11]=utime(14) f[12]=stime(15) f[13]=cutime(16) f[14]=cstime(17) f[19]=starttime(22)
	if len(f) < 20 {
		return
	}
	p, e0 := strconv.Atoi(f[1])
	u, e1 := strconv.ParseUint(f[11], 10, 64)
	st, e2 := strconv.ParseUint(f[12], 10, 64)
	cu, e3 := strconv.ParseInt(f[13], 10, 64) // cutime/cstime 是 long
	cs, e4 := strconv.ParseInt(f[14], 10, 64)
	sv, e5 := strconv.ParseUint(f[19], 10, 64)
	if e0 != nil || e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
		return
	}
	if cu < 0 {
		cu = 0
	}
	if cs < 0 {
		cs = 0
	}
	return p, u + st, uint64(cu) + uint64(cs), sv, true
}

// Cmdline 读单个进程的 cmdline(NUL→空格, 首尾去空白), 失败返回空串。
func (fs FS) Cmdline(pid int) string {
	b, err := fs.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
}

// Table 一次扫描 /proc: pid → Row(不含 cmdline, 需要时用 Cmdline 单读)。
func (fs FS) Table() map[int]Row {
	out := map[int]Row{}
	if fs.ReadDir == nil {
		return out
	}
	names, err := fs.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, n := range names {
		pid, err := strconv.Atoi(n)
		if err != nil || pid <= 0 {
			continue
		}
		b, err := fs.ReadFile("/proc/" + n + "/stat")
		if err != nil {
			continue
		}
		if pp, own, ch, st, ok := StatFields(string(b)); ok {
			out[pid] = Row{PID: pid, PPID: pp, Own: own, Child: ch, Start: st}
		}
	}
	return out
}

// Def 「找一个 HNC 进程」的定义。
type Def struct {
	Self     bool     // 是自己(httpd) → 直接返回 SelfPID
	PIDFiles []string // 相对 <hncDir>/run/ 的 pid 文件, 按序尝试
	Key      string   // pidfile 校验: cmdline 必含(空 cmdline 放行)
	ScanKey  string   // pidfile 全失效时扫 /proc: cmdline 必含(空则不扫)
}

// FindPID 统一查找: Self → pidfile(tab 中存活 + cmdline 含 Key 或为空)
// → ScanKey 扫描(升序, cmdline 含 ScanKey, 跳过自己)。找不到返回 0。
func (fs FS) FindPID(d Def, hncDir string, tab map[int]Row) int {
	if d.Self && fs.SelfPID > 0 {
		return fs.SelfPID
	}
	for _, f := range d.PIDFiles {
		b, err := fs.ReadFile(hncDir + "/run/" + f)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || pid <= 0 {
			continue
		}
		if _, ok := tab[pid]; !ok {
			continue
		}
		if cl := fs.Cmdline(pid); cl == "" || strings.Contains(cl, d.Key) {
			return pid
		}
	}
	if d.ScanKey == "" {
		return 0
	}
	pids := make([]int, 0, len(tab))
	for pid := range tab {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	for _, pid := range pids {
		if pid == fs.SelfPID {
			continue
		}
		if strings.Contains(fs.Cmdline(pid), d.ScanKey) {
			return pid
		}
	}
	return 0
}
