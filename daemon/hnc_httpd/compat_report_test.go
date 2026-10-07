// compat_report_test.go — v5.29 T5: 兼容性报告的脱敏断言与字段收集。
package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newCompatFixture 造一个带敏感内容的假世界:
// run 文件里故意塞 MAC / IP / SSID / 密码 / 设备名 / token / IMEI,
// 断言最终报告里一个都搜不到。
func newCompatFixture(t *testing.T) (*fakeSys, string) {
	t.Helper()
	hnc := t.TempDir()
	f := newFakeSys(hnc)
	run := f.h("run")
	os.MkdirAll(run, 0o755)
	os.MkdirAll(f.h("exports"), 0o755)

	// module.prop(带版本)
	os.WriteFile(filepath.Join(hnc, "module.prop"),
		[]byte("id=hnc\nversion=v5.29.0-rc1\nversionCode=5290001\n"), 0o644)
	// capabilities.json: 合法布尔 + 一个伪装成键的敏感项(纵深防御测试)
	os.WriteFile(filepath.Join(run, "capabilities.json"),
		[]byte(`{"tc_htb":true,"uplink_supported":false,"device_mac":"AA:BB:CC:DD:EE:FF","ssid_token":"home-wifi-secret"}`), 0o644)
	os.WriteFile(filepath.Join(run, "qdisc_caps.json"),
		[]byte(`{"mq":true,"clsact":true}`), 0o644)
	// offload_guard.json: 只该取 mode/state/fallback(detail 里的 iface 不取)
	os.WriteFile(filepath.Join(run, "offload_guard.json"),
		[]byte(`{"mode":"auto","state":"IDLE","fallback":0,"detail":"热点未开启","ifc":"wlan2"}`), 0o644)
	os.WriteFile(filepath.Join(run, "dpid_launcher.choice"), []byte("launcher\n"), 0o644)
	// 自检缓存(run/selfcheck.json): value 里带 SSID / IP —— 报告只取 ID+status
	os.WriteFile(filepath.Join(run, "selfcheck.json"),
		[]byte(`{"schema":1,"generated_at":1791200000,"version":"v5.29.0-rc1","sections":[{"id":"net","title":"网络","items":[{"id":"wifi","label":"Wi-Fi","status":"ok","value":"SSID=HomeNet ip=192.168.43.1"}]}],"summary":{"ok":1,"warn":1,"fail":0,"info":0}}`), 0o644)
	// 看门狗记账: 正常键 + 一个动作名带敏感字的(不该进摘要)
	os.WriteFile(filepath.Join(run, "watchdog_actions.json"),
		[]byte(`{"schema":1,"actions":{"check_health":{"calls_1h":60,"fails_1h":0,"last_rc":0},"probe aa:bb:cc:dd:ee:ff":{"calls_1h":9}}}`), 0o644)
	return f, hnc
}

func TestCompatReportRedaction(t *testing.T) {
	f, hnc := newCompatFixture(t)
	// getprop 桩: 通用机型名
	f.cmds["getprop"] = "[ro.build.version.release]: [16]\n[ro.product.brand]: [OPPO]\n[ro.product.model]: [RMX5010]\n"
	// selfcheck 缓存要被读到: 注入内存(或让它读 run/selfcheck.json —— selfcheckCached 首读文件)
	selfcheckState.mu.Lock()
	selfcheckState.last = nil
	selfcheckState.loaded = false
	selfcheckState.mu.Unlock()
	t.Cleanup(func() {
		selfcheckState.mu.Lock()
		selfcheckState.last = nil
		selfcheckState.loaded = false
		selfcheckState.mu.Unlock()
	})

	c := &scCtx{env: f.scEnv(), ctx: context.Background()}
	rep := buildCompatReport(hnc, c)

	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)

	// 脱敏硬断言: 报告全文搜不到任何敏感内容(夹具里故意全塞了)
	for _, bad := range []string{
		"AA:BB:CC", "aa:bb:cc", "192.168.43.1", "HomeNet", "wlan-secret",
		"EE:FF", "imei", "IMEI", "token", "SSID", "serial",
	} {
		if strings.Contains(out, bad) {
			t.Errorf("报告泄漏敏感内容 %q", bad)
		}
	}

	// 应该有的白名单内容
	if rep.Module.Version != "v5.29.0-rc1" || rep.Module.VersionCode != "5290001" {
		t.Errorf("module = %+v", rep.Module)
	}
	if rep.Android.Brand != "OPPO" || rep.Android.Model != "RMX5010" || rep.Android.Version != "16" {
		t.Errorf("android = %+v", rep.Android)
	}
	if rep.Android.Kernel == "" && kernelReadable() {
		t.Errorf("内核版本为空(/proc/version 可读时)")
	}
	if rep.Offload["state"] != "IDLE" || rep.Offload["mode"] != "auto" {
		t.Errorf("offload = %v", rep.Offload)
	}
	if rep.DpidChoice != "launcher" {
		t.Errorf("dpid choice = %q", rep.DpidChoice)
	}
	// 自检: 段 ID + 状态在, value(SSID)不在
	if len(rep.Selfcheck.Sections) != 1 || rep.Selfcheck.Sections[0].ID != "net" {
		t.Fatalf("selfcheck sections = %+v", rep.Selfcheck.Sections)
	}
	if len(rep.Selfcheck.Sections[0].Items) != 1 || rep.Selfcheck.Sections[0].Items[0].Status != "ok" {
		t.Errorf("selfcheck items = %+v", rep.Selfcheck.Sections[0].Items)
	}
	// capabilities: 布尔键转出, 敏感键被 scrub
	if !strings.Contains(out, `"tc_htb":true`) {
		t.Error("capabilities 的 tc_htb 应保留")
	}
	// 看门狗摘要: 正常动作在, 带敏感名的动作不在
	if wa, ok := rep.WatchdogActions["check_health"]; !ok || wa.(map[string]interface{})["calls_1h"] != float64(60) {
		t.Errorf("watchdog actions = %v", rep.WatchdogActions)
	}
	if _, ok := rep.WatchdogActions["probe aa:bb:cc:dd:ee:ff"]; ok {
		t.Error("带敏感名的动作不该进摘要")
	}
}

func kernelReadable() bool {
	_, err := os.Stat("/proc/version")
	return err == nil
}

func TestIsCompatExport(t *testing.T) {
	for _, c := range []struct {
		n  string
		ok bool
	}{
		{"hnc-compat-20261005.json", true},
		{"hnc-compat-2026100.json", false}, // 日期位数不对
		{"hnc-compat-20261005.txt", false}, // 只认 .json
		{"../etc/passwd", false},
		{"hnc-compat-20261005.json.sh", false},
	} {
		if got := isCompatExport(c.n); got != c.ok {
			t.Errorf("isCompatExport(%q) = %v, want %v", c.n, got, c.ok)
		}
	}
}

func TestActionCompatReportWritesFile(t *testing.T) {
	f, hnc := newCompatFixture(t)
	oldFac := selfcheckEnvFactory
	selfcheckEnvFactory = func(string) *scEnv { return f.scEnv() }
	t.Cleanup(func() { selfcheckEnvFactory = oldFac })
	s := &server{hncDir: hnc}
	resp := actionCompatReport(s)
	if !resp.OK {
		t.Fatalf("action 失败: %+v", resp)
	}
	var d struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}
	if json.Unmarshal([]byte(resp.Detail), &d) != nil {
		t.Fatalf("detail 解析失败: %v", resp.Detail)
	}
	if !isCompatExport(d.Name) {
		t.Errorf("name = %q", d.Name)
	}
	b, err := os.ReadFile(d.Path)
	if err != nil {
		t.Fatalf("文件没写: %v", err)
	}
	var rep compatReport
	if json.Unmarshal(b, &rep) != nil {
		t.Fatalf("报告不是合法 JSON")
	}
}

// TestCompatReportUsesBuildVersion 真机运行目录里没有 module.prop: 版本取
// 编译期注入值(rc1 只读 <hnc>/module.prop, 报告里版本恒为空)。
func TestCompatReportUsesBuildVersion(t *testing.T) {
	oldV, oldVC := version, versionCode
	version, versionCode = "v5.29.0-rc1", "5290001"
	t.Cleanup(func() { version, versionCode = oldV, oldVC })
	f := newFakeSys(t.TempDir())
	c := &scCtx{env: f.scEnv(), ctx: context.Background()}
	rep := buildCompatReport(t.TempDir(), c) // 空目录, 没有 module.prop
	if rep.Module.Version != "v5.29.0-rc1" || rep.Module.VersionCode != "5290001" {
		t.Fatalf("module = %+v", rep.Module)
	}
}
