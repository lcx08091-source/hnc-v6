// api_sla.go — v5.7.0-rc42 · 只读 SLA / 运行健康聚合端点。
//
// 把散落在 run/ 下的真实计数器 + 标记聚合成一个 /api/sla,供设置页"运行健康"
// 面板展示,从"修 bug 驱动"转向"数据驱动维护"。
//
// 诚实原则(同 /api/metrics 的 instrumented:false 思路):没有埋点的信号一律返回
// null / 省略,绝不编造数字。计数器来源:
//   dpid.start_count            (dpid main 启动 +1, 持久, lifetime 重启数)
//   watchdog_full_restore.count (watchdog full_restore +1, 持久)
//   dpid.crashflag              (崩溃环启动时间戳, 健康跑 5min 后清; 行数=近期崩溃启动)
//   dpid_guard.heartbeat        (supervisor 2s 一次; now-ts = 心跳年龄)
//   tc_repair_fail_count        (watchdog tc 修复连续失败数, 熔断器)
//   uplink_fail_count           (上行 IFB/police 失败累计)
//   json_legacy_fallback.count  (JSON 写退回 legacy awk 累计)
//   tc_qos_fallback / uplink_unsupported (能力降级标记, 存在=降级中)

package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func (s *server) apiSLA(w http.ResponseWriter, r *http.Request) {
	run := filepath.Join(s.hncDir, "run")

	readInt := func(name string) interface{} {
		b, err := os.ReadFile(filepath.Join(run, name))
		if err != nil {
			return nil
		}
		n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		if err != nil {
			return nil
		}
		return n
	}
	countLines := func(name string) interface{} {
		b, err := os.ReadFile(filepath.Join(run, name))
		if err != nil {
			return nil
		}
		var c int64
		for _, ln := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(ln) != "" {
				c++
			}
		}
		return c
	}
	heartbeatAge := func() interface{} {
		b, err := os.ReadFile(filepath.Join(run, "dpid_guard.heartbeat"))
		if err != nil {
			return nil
		}
		ts, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		if err != nil {
			return nil
		}
		return time.Now().Unix() - ts
	}
	marker := func(name string) bool {
		_, err := os.Stat(filepath.Join(run, name))
		return err == nil
	}

	resp := map[string]interface{}{
		"generated_at": time.Now().Unix(),
		// 重启 / 崩溃
		"dpid_restart_count":          readInt("dpid.start_count"),
		"dpid_crash_recent":           countLines("dpid.crashflag"),
		"dpid_guard_heartbeat_age_s":  heartbeatAge(),
		"watchdog_full_restore_count": readInt("watchdog_full_restore.count"),
		// tc / 上行健康
		"tc_repair_fail_count": readInt("tc_repair_fail_count"),
		"uplink_fail_count":    readInt("uplink_fail_count"),
		// JSON 写健康
		"json_legacy_fallback_count": readInt("json_legacy_fallback.count"),
		// 能力降级标记(存在=正处于降级)
		"qos_fallback_active":  marker("tc_qos_fallback"),
		"uplink_unsupported":   marker("uplink_unsupported"),
	}
	setNoStore(w)
	writeJSON(w, http.StatusOK, resp)
}
