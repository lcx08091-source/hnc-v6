// capture_record.go — v5.29 T4: 流量录制的 httpd 侧(写开关文件 + 状态转出)。
//
// dpid 的录制循环(capture/recorder.go)只认文件:
//
//	run/capture_record.request  内容 = 分钟数(1~30)→ 开始录
//	run/capture_record.stop     存在 → 停止并搬运到 exports/
//	run/capture_rec/status.json 录制中状态(前端显示「录制中/剩余/大小」)
//
// action:
//
//	capture_record {minutes}  → 写 request(参数校验), 返回状态
//	capture_record_stop       → 写 stop, 返回状态
//
// /api/health 的 capture_rec 段 = status.json 转出(录制结束自动消失)。
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

// scCaptureRecordItem 状态文件的内存形态(缺字段 = 没在录)。
func captureRecordStatus(hncDir string) map[string]interface{} {
	b, err := os.ReadFile(filepath.Join(hncDir, "run", "capture_rec", "status.json"))
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

// actionCaptureRecord POST /api/action capture_record {minutes}。
func actionCaptureRecord(s *server, p map[string]string) actionResp {
	minutes := 10
	if v, ok := p["minutes"]; ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 30 {
			return actionResp{OK: false, Error: "bad params", Detail: "minutes 需为 1~30"}
		}
		minutes = n
	}
	req := filepath.Join(s.hncDir, "run", "capture_record.request")
	if err := os.WriteFile(req, []byte(fmt.Sprintf("%d\n", minutes)), 0o644); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	st := captureRecordStatus(s.hncDir)
	if st == nil {
		st = map[string]interface{}{"requested": true, "minutes": minutes}
	}
	st["requested"] = true
	st["minutes"] = minutes
	st["privacy"] = "录制内容包含连接设备访问的域名, 只存本机、请勿随意分享"
	b, _ := json.Marshal(st)
	return actionResp{OK: true, Detail: string(b)}
}

// actionCaptureRecordStop POST /api/action capture_record_stop。
func actionCaptureRecordStop(s *server) actionResp {
	// 请求还没被 dpid 取走 → 直接撤回请求; 否则写 stop(dpid 空闲时会清掉
	// 没人认领的 stop, 免得它把下一次录制直接取消)
	req := filepath.Join(s.hncDir, "run", "capture_record.request")
	if err := os.Remove(req); err == nil {
		b, _ := json.Marshal(map[string]interface{}{"recording": false, "cancelled": true})
		return actionResp{OK: true, Detail: string(b)}
	}
	stop := filepath.Join(s.hncDir, "run", "capture_record.stop")
	if err := os.WriteFile(stop, []byte("1\n"), 0o644); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	st := captureRecordStatus(s.hncDir)
	if st == nil {
		st = map[string]interface{}{}
	}
	st["stopping"] = true
	b, _ := json.Marshal(st)
	return actionResp{OK: true, Detail: string(b)}
}

// actionCaptureRecordDispatch 两个录制 action 的分发(dispatchSelfcheckAction 调)。
func actionCaptureRecordDispatch(s *server, action string, p map[string]string) (actionResp, bool) {
	switch action {
	case "capture_record":
		return actionCaptureRecord(s, p), true
	case "capture_record_stop":
		return actionCaptureRecordStop(s), true
	}
	return actionResp{}, false
}

// isCaptureRecPcap v5.29 T4: 录制文件名(rec-YYYYMMDD-HHMMSS.pcap)。
func isCaptureRecPcap(n string) bool {
	ok, _ := regexp.MatchString(`^rec-\d{8}-\d{6}\.pcap$`, n)
	return ok
}
