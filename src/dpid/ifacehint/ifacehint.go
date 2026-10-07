// Package ifacehint —— 热点网卡名的唯一权威出口(v5.26 T5)。
//
// bin/hnc_iface.sh 自 v5.20 起是唯一权威探测器, 结果原子写
// run/iface_detect.json({"schema":1,"ts":..,"iface":"wlan2"|"",..})。
// dpid 侧此前有三份各自判断(capture.readHNCHint 只读 hotspot_iface、
// dpid_supervisor.getIface 照抄 guard.sh 的写死候选表、guard.sh 的
// get_iface), 升级 ROM 后各自猜出不同网卡名。本包统一: 优先
// iface_detect.json(10 分钟内新鲜), 回退 hotspot_iface(格式校验同
// readHNCHint), 都没有 ok=false —— 调用方各自保留自己的扫描兜底。
package ifacehint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FreshWindow iface_detect.json 的可信窗口: hnc_iface.sh 由
// iface 事件与看门狗驱动, 正常情况下分钟级刷新; 超过 10 分钟视为
// 陈旧(服务挂了/探测失败), 不再盲信, 交给调用方扫描兜底。
const FreshWindow = 10 * time.Minute

type detectJSON struct {
	Schema int    `json:"schema"`
	Ts     int64  `json:"ts"`
	Iface  string `json:"iface"`
}

// Read 返回当前权威热点网卡名。
//   - iface_detect.json 存在且 iface 非空、ts 距 now 在 10 分钟内 → 用它
//   - 否则回退 runDir/hotspot_iface(单行, 字符白名单 [-_a-zA-Z0-9], 长度 1..32)
//   - 都没有 → ("", false)
func Read(runDir string, now time.Time) (string, bool) {
	if b, err := os.ReadFile(filepath.Join(runDir, "iface_detect.json")); err == nil {
		var d detectJSON
		if json.Unmarshal(b, &d) == nil {
			ts := time.Unix(d.Ts, 0)
			if d.Iface != "" && validIface(d.Iface) &&
				!now.Add(-FreshWindow).After(ts) && !ts.After(now.Add(FreshWindow)) {
				return d.Iface, true
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(runDir, "hotspot_iface")); err == nil {
		s := strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
		if validIface(s) {
			return s, true
		}
	}
	return "", false
}

// ReadDetect 只读 iface_detect.json(不回退 hotspot_iface), 且要求 ts 在
// now 前后 window 以内、iface 非空。v5.29 看门狗原生 probe 用: 回退的
// hotspot_iface 没有时间戳, 拿它当结论会让「探测器很久没跑」无从察觉。
func ReadDetect(runDir string, now time.Time, window time.Duration) (string, bool) {
	b, err := os.ReadFile(filepath.Join(runDir, "iface_detect.json"))
	if err != nil {
		return "", false
	}
	var d detectJSON
	if json.Unmarshal(b, &d) != nil || d.Iface == "" || !validIface(d.Iface) {
		return "", false
	}
	ts := time.Unix(d.Ts, 0)
	if now.Add(-window).After(ts) || ts.After(now.Add(window)) {
		return "", false
	}
	return d.Iface, true
}

// validIface 与 v5.26 前 capture.readHNCHint 的校验一致。
func validIface(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for _, r := range s {
		if !(r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}
