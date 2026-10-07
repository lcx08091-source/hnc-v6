// action_app_qos_v530_test.go — v5.30 T4: 「按应用分优先级」开关。
//
// 走真实 runBin(假脚本放在临时 hncDir/bin, 逐个参数记一行 —— 参数必须分开传,
// v5.29 有过把 "脚本 参数" 拼成一个参数的事故)。
// 「改动前会失败」: v5.29 没有 app_qos_set 动作(dispatch 返回 unknown action)。
package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// aqFake 临时 hncDir + 假 json_set.sh / apply_device_rule.sh(参数逐行记到 run/calls.log)。
func aqFake(t *testing.T, rules string) string {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"bin", "run", "data"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	rec := `echo "== $(basename "$0")" >> "$HNC_DIR/run/calls.log"; for a in "$@"; do echo "$a" >> "$HNC_DIR/run/calls.log"; done
`
	writeFileT(t, filepath.Join(dir, "bin", "json_set.sh"), "#!/bin/sh\n"+rec+
		`[ "$1" = device_get ] && [ -f "$HNC_DIR/run/mid" ] && cat "$HNC_DIR/run/mid"
exit 0
`)
	writeFileT(t, filepath.Join(dir, "bin", "apply_device_rule.sh"), "#!/bin/sh\n"+rec+"echo 7\n")
	writeFileT(t, filepath.Join(dir, "data", "rules.json"), rules)
	return dir
}

func aqCalls(t *testing.T, dir string) string {
	b, _ := os.ReadFile(filepath.Join(dir, "run", "calls.log"))
	return string(b)
}

func TestAppQosSetEnableAllocatesMid(t *testing.T) {
	dir := aqFake(t, `{"devices":{}}`)
	r := dispatchAction(newServer(dir), "app_qos_set", map[string]string{"mac": "AA:BB:CC:00:00:05", "enabled": "true"}, false)
	if !r.OK {
		t.Fatalf("%+v", r)
	}
	want := "== json_set.sh\ndevice_get\naa:bb:cc:00:00:05\nmark_id\n" +
		"== apply_device_rule.sh\nalloc_mid\naa:bb:cc:00:00:05\n" +
		"== json_set.sh\ndevice\naa:bb:cc:00:00:05\napp_qos\ntrue\n"
	if got := aqCalls(t, dir); got != want {
		t.Fatalf("calls =\n%s\nwant\n%s", got, want)
	}
	if _, err := os.Stat(filepath.Join(dir, "run", "app_limit.dirty")); err != nil {
		t.Fatal("应写 dirty 标记让看门狗立即下发")
	}
}

func TestAppQosSetExistingMidAndDisable(t *testing.T) {
	dir := aqFake(t, `{"devices":{}}`)
	writeFileT(t, filepath.Join(dir, "run", "mid"), "5\n")
	s := newServer(dir)
	if r := dispatchAction(s, "app_qos_set", map[string]string{"mac": "aa:bb:cc:00:00:05", "enabled": "on"}, false); !r.OK {
		t.Fatalf("%+v", r)
	}
	if strings.Contains(aqCalls(t, dir), "alloc_mid") {
		t.Fatal("已有 mark_id 不应再分配")
	}
	_ = os.Remove(filepath.Join(dir, "run", "calls.log"))
	if r := dispatchAction(s, "app_qos_set", map[string]string{"mac": "aa:bb:cc:00:00:05", "enabled": "false"}, false); !r.OK {
		t.Fatalf("%+v", r)
	}
	if got := aqCalls(t, dir); got != "== json_set.sh\ndevice\naa:bb:cc:00:00:05\napp_qos\nfalse\n" {
		t.Fatalf("关闭只写 flag: %q", got)
	}
}

func TestAppQosSetBadParamsAndDelayConflict(t *testing.T) {
	dir := aqFake(t, `{"devices":{"aa:bb:cc:00:00:05":{"mark_id":5,"delay_ms":50}}}`)
	s := newServer(dir)
	for _, p := range []map[string]string{
		{"mac": "nope", "enabled": "true"},
		{"mac": "aa:bb:cc:00:00:05", "enabled": "maybe"},
	} {
		if r := dispatchAction(s, "app_qos_set", p, false); r.OK || r.Error != "bad params" {
			t.Errorf("%v → %+v", p, r)
		}
	}
	r := dispatchAction(s, "app_qos_set", map[string]string{"mac": "aa:bb:cc:00:00:05", "enabled": "true"}, false)
	if r.OK || r.Error != "conflict" || aqCalls(t, dir) != "" {
		t.Fatalf("开着延迟时应拒绝且不写任何东西: %+v calls=%q", r, aqCalls(t, dir))
	}
}

// 反方向: 开着按应用分优先级时设延迟被拒(在探测网卡之前, 不起任何脚本)。
func TestDelaySetRefusedWhenAppQosOn(t *testing.T) {
	dir := aqFake(t, `{"devices":{"aa:bb:cc:00:00:05":{"mark_id":5,"app_qos":true}}}`)
	r := dispatchAction(newServer(dir), "delay_set", map[string]string{"mac": "aa:bb:cc:00:00:05", "delay_ms": "50", "jitter_ms": "0", "loss_pct": "0"}, false)
	if r.OK || r.Error != "conflict" || aqCalls(t, dir) != "" {
		t.Fatalf("%+v calls=%q", r, aqCalls(t, dir))
	}
}

// /api/devices 带出 app_qos(前端开关回读)。
func TestAPIDevicesHasAppQos(t *testing.T) {
	dir := t.TempDir()
	writeFileT(t, filepath.Join(dir, "data", "devices.json"), `{"aa:bb:cc:00:00:05":{"ip":"192.168.43.5","last_seen":1790000000}}`)
	writeFileT(t, filepath.Join(dir, "data", "rules.json"), `{"devices":{"aa:bb:cc:00:00:05":{"mark_id":5,"app_qos":true},"aa:bb:cc:00:00:06":{"mark_id":6,"app_qos":true}}}`)
	rec := httptest.NewRecorder()
	newServer(dir).apiDevices(rec, httptest.NewRequest("GET", "/api/devices", nil))
	var r struct {
		Devices []map[string]interface{} `json:"devices"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	n := 0
	for _, d := range r.Devices {
		if d["app_qos"] == true {
			n++
		}
	}
	if n != 2 { // 在线的 + 只在 rules.json 里的离线虚行
		t.Fatalf("app_qos 回读 %d 台, want 2: %s", n, rec.Body.String())
	}
}
