package tzlocal

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"time"
)

// buildTzdata 按 Android ZoneInfoDB 格式打包一个只含一个时区的 tzdata。
func buildTzdata(name string, tzif []byte) []byte {
	const hdr, entry = 24, 52
	b := make([]byte, hdr+entry)
	copy(b, "tzdata2024a\x00")
	binary.BigEndian.PutUint32(b[12:16], hdr)
	binary.BigEndian.PutUint32(b[16:20], hdr+entry)
	binary.BigEndian.PutUint32(b[20:24], uint32(hdr+entry+len(tzif)))
	copy(b[hdr:hdr+40], name)
	binary.BigEndian.PutUint32(b[hdr+40:hdr+44], 0)
	binary.BigEndian.PutUint32(b[hdr+44:hdr+48], uint32(len(tzif)))
	return append(b, tzif...)
}

func noFile(string) ([]byte, error) { return nil, errors.New("no") }

func TestResolve_NonAndroidUsesTimeLocal(t *testing.T) {
	l := resolve("linux", func(string) string { return "Asia/Shanghai" }, noFile,
		func() (int, bool) { return 0, false })
	if l != time.Local {
		t.Fatalf("非 android 应直接用 time.Local, got %v", l)
	}
}

// 核心回归: android 上即便标准库加载不到, 也要从 APEX tzdata 解析出正确偏移。
func TestResolve_AndroidFromApexTzdata(t *testing.T) {
	tzif, err := os.ReadFile("/usr/share/zoneinfo/Asia/Shanghai")
	if err != nil {
		t.Skip("宿主机无 zoneinfo, 跳过")
	}
	// 用标准库不可能认识的名字, 逼 resolve 走自解析 tzdata 分支。
	const name = "Hnc/Test_Shanghai"
	pkg := buildTzdata(name, tzif)
	l := resolve("android", func(string) string { return name + "\n" },
		func(p string) ([]byte, error) {
			if p == tzdataPaths[0] {
				return pkg, nil
			}
			return nil, errors.New("no")
		},
		func() (int, bool) { return 0, false })
	_, off := time.Unix(1700000000, 0).In(l).Zone()
	if off != 8*3600 {
		t.Fatalf("偏移应为 +8h, got %d (loc=%v)", off, l)
	}
}

func TestResolve_AndroidDateFallback(t *testing.T) {
	l := resolve("android", func(string) string { return "" }, noFile,
		func() (int, bool) { return 8 * 3600, true })
	if _, off := time.Unix(0, 0).In(l).Zone(); off != 8*3600 {
		t.Fatalf("date 兜底偏移错误: %d", off)
	}
	// 全部失败 → 不能返回 nil
	if resolve("android", func(string) string { return "" }, noFile,
		func() (int, bool) { return 0, false }) == nil {
		t.Fatal("不得返回 nil")
	}
}

func TestParseOffset(t *testing.T) {
	cases := map[string]int{"+0800": 28800, "-0530": -19800, "+0000": 0}
	for s, want := range cases {
		got, ok := parseOffset(s)
		if !ok || got != want {
			t.Errorf("parseOffset(%q)=%d,%v want %d", s, got, ok, want)
		}
	}
	for _, s := range []string{"", "0800", "+08", "+08:00", "+2500"} {
		if _, ok := parseOffset(s); ok {
			t.Errorf("parseOffset(%q) 应失败", s)
		}
	}
}

func TestExtractTZif_Malformed(t *testing.T) {
	if _, err := extractTZif([]byte("tzdata"), "x"); err == nil {
		t.Error("短头应报错")
	}
	bad := buildTzdata("A/B", []byte("TZif"))
	binary.BigEndian.PutUint32(bad[16:20], 1<<30) // data_offset 越界
	if _, err := extractTZif(bad, "A/B"); err == nil {
		t.Error("越界偏移应报错")
	}
}

func encodeProtoRecord(key, val string) []byte {
	var rec []byte
	rec = append(rec, 0x0a, byte(len(key)))
	rec = append(rec, key...)
	rec = append(rec, 0x12, byte(len(val)))
	rec = append(rec, val...)
	var out []byte
	out = append(out, 0x0a, byte(len(rec)))
	out = append(out, rec...)
	return out
}

func TestResolve_PersistentPropertiesAndBuildPropNoFork(t *testing.T) {
	var protoBlob []byte
	protoBlob = append(protoBlob, encodeProtoRecord("persist.sys.locale", "zh-CN")...)
	protoBlob = append(protoBlob, encodeProtoRecord("persist.sys.timezone", "America/Los_Angeles")...)
	protoBlob = append(protoBlob, encodeProtoRecord("persist.sys.timezone", "Asia/Shanghai")...)

	propCalled := false
	l := resolve("android",
		func(string) string {
			propCalled = true
			return "UTC"
		},
		func(p string) ([]byte, error) {
			if p == persistentPropsPath {
				return protoBlob, nil
			}
			return nil, errors.New("missing")
		},
		func() (int, bool) { return 0, false },
	)
	if propCalled {
		t.Fatal("persistent_properties 命中时不应再调用 getprop")
	}
	if _, off := time.Unix(1700000000, 0).In(l).Zone(); off != 8*3600 {
		t.Fatalf("persistent_properties 解析偏移错误: got %d, want 28800", off)
	}

	// build.prop 兜底且同样不调用 getprop
	propCalled = false
	buildProp := []byte("# comment\nro.product.brand=Android\npersist.sys.timezone=Asia/Tokyo\n")
	l2 := resolve("android",
		func(string) string {
			propCalled = true
			return "UTC"
		},
		func(p string) ([]byte, error) {
			if p == systemBuildPropPath {
				return buildProp, nil
			}
			return nil, errors.New("missing")
		},
		func() (int, bool) { return 0, false },
	)
	if propCalled {
		t.Fatal("build.prop 命中时不应再调用 getprop")
	}
	if _, off := time.Unix(1700000000, 0).In(l2).Zone(); off != 9*3600 {
		t.Fatalf("build.prop 解析偏移错误: got %d, want 32400", off)
	}

	// 原始二进制块 ASCII 扫描兜底 + 拒绝路径穿越等非法值
	rawASCII := []byte("\x00\xffpersist.sys.timezone\x00\x0dEurope/Berlin\x00garbage")
	if got := extractPersistentPropTimezone(rawASCII); got != "Europe/Berlin" {
		t.Fatalf("ASCII 扫描预期 Europe/Berlin, got %q", got)
	}
	badTraversal := encodeProtoRecord("persist.sys.timezone", "../../etc/passwd")
	if got := extractPersistentPropTimezone(badTraversal); got != "" {
		t.Fatalf("非法时区串应被拒绝, got %q", got)
	}
}

func TestRunSubproc_TimeoutKillsProcessGroup(t *testing.T) {
	start := time.Now()
	// 派生后台孙进程持 stdout 不放, 验证 Setpgid + -pgid SIGKILL + WaitDelay 在超时后迅速返回。
	_, err := runSubproc(250*time.Millisecond, "sh", "-c", "(sleep 30) & sleep 30")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("超时子进程应返回错误")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("runSubproc 超时未及时杀掉进程组: 耗时 %v", elapsed)
	}
}

