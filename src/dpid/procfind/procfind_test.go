package procfind

import (
	"fmt"
	"strings"
	"testing"
)

// fakeProc 内存 /proc 桩: 任意路径 → 内容(files), /proc 目录列表由 /proc/<pid>/stat 键推导。
type fakeProc struct {
	files map[string]string
}

func statLine(pid, ppid int, comm string, utime, stime, cutime, cstime, start uint64) string {
	return fmt.Sprintf("%d (%s) S %d 1 1 0 -1 4194624 0 0 0 0 %d %d %d %d 0 0 1 0 %d 0 0 0 0 0 0 0 0 0 0",
		pid, comm, ppid, utime, stime, cutime, cstime, start)
}

func (f fakeProc) fs(self int) FS {
	return FS{
		ReadFile: func(p string) ([]byte, error) {
			if s, ok := f.files[p]; ok {
				return []byte(s), nil
			}
			return nil, fmt.Errorf("no such file: %s", p)
		},
		ReadDir: func(p string) ([]string, error) {
			if p != "/proc" {
				return nil, fmt.Errorf("unexpected dir: %s", p)
			}
			seen := map[string]bool{}
			for k := range f.files {
				if strings.HasPrefix(k, "/proc/") && strings.HasSuffix(k, "/stat") {
					seen[strings.TrimSuffix(strings.TrimPrefix(k, "/proc/"), "/stat")] = true
				}
			}
			names := make([]string, 0, len(seen))
			for n := range seen {
				names = append(names, n)
			}
			return names, nil
		},
		SelfPID: self,
	}
}

// cmdline 值以空格连接, fs 会写回 NUL 分隔。
func (f *fakeProc) setCmdline(pid int, cl string) {
	f.files[fmt.Sprintf("/proc/%d/cmdline", pid)] = strings.ReplaceAll(cl, " ", "\x00")
}

func newFake() *fakeProc {
	return &fakeProc{files: map[string]string{}}
}

func TestStatFields(t *testing.T) {
	// comm 带空格与括号: 从最后一个 ')' 后切
	pp, own, child, start, ok := StatFields(statLine(10, 1, "sh (x) y", 300, 200, 50, 25, 9999))
	if !ok || pp != 1 || own != 500 || child != 75 || start != 9999 {
		t.Fatalf("got ppid=%d own=%d child=%d start=%d ok=%v", pp, own, child, start, ok)
	}
	if _, _, _, _, ok := StatFields("garbage"); ok {
		t.Fatal("garbage should not parse")
	}
	if _, _, _, _, ok := StatFields("1 (a) S 2 1 1 0 -1 0 0 0 1 1 1 1 0 0 1 0"); ok {
		t.Fatal("short stat should not parse")
	}
}

func TestTable(t *testing.T) {
	f := newFake()
	f.files["/proc/10/stat"] = statLine(10, 1, "a", 1, 2, 3, 4, 100)
	f.files["/proc/20/stat"] = statLine(20, 10, "b", 5, 6, 7, 8, 200)
	f.setCmdline(10, "/data/local/hnc/bin/hnc_dpid -config x")
	tab := f.fs(99).Table()
	if len(tab) != 2 {
		t.Fatalf("table size = %d, want 2", len(tab))
	}
	if tab[10].PPID != 1 || tab[10].Own != 3 || tab[10].Child != 7 || tab[10].Start != 100 {
		t.Fatalf("row 10 = %+v", tab[10])
	}
	if f.fs(99).Cmdline(10) != "/data/local/hnc/bin/hnc_dpid -config x" {
		t.Fatalf("cmdline = %q", f.fs(99).Cmdline(10))
	}
}

func TestFindPIDSelf(t *testing.T) {
	f := newFake()
	f.files["/proc/7/stat"] = statLine(7, 1, "httpd", 1, 1, 0, 0, 1)
	fs := f.fs(7)
	if pid := fs.FindPID(Def{Self: true}, "/hnc", fs.Table()); pid != 7 {
		t.Fatalf("self pid = %d, want 7", pid)
	}
}

func TestFindPIDPidfile(t *testing.T) {
	f := newFake()
	f.files["/proc/30/stat"] = statLine(30, 1, "hotspotd", 1, 1, 0, 0, 1)
	f.setCmdline(30, "/data/local/hnc/bin/hotspotd")
	f.files["/hnc/run/hotspotd.pid"] = "30\n"
	fs := f.fs(99)
	tab := fs.Table()
	if pid := fs.FindPID(Def{PIDFiles: []string{"hotspotd.pid"}, Key: "hotspotd"}, "/hnc", tab); pid != 30 {
		t.Fatalf("pidfile pid = %d, want 30", pid)
	}
	// cmdline 不含 Key(PID 复用) → 不认
	f.setCmdline(30, "/system/bin/something_else")
	fs = f.fs(99)
	if pid := fs.FindPID(Def{PIDFiles: []string{"hotspotd.pid"}, Key: "hotspotd"}, "/hnc", fs.Table()); pid != 0 {
		t.Fatalf("reused pid accepted: %d", pid)
	}
	// 空 cmdline(内核线程) → 只查存活
	f.setCmdline(30, "")
	f.files["/hnc/run/hotspotd.pid"] = "30\n"
	fs = f.fs(99)
	if pid := fs.FindPID(Def{PIDFiles: []string{"hotspotd.pid"}, Key: "hotspotd"}, "/hnc", fs.Table()); pid != 30 {
		t.Fatalf("empty cmdline should pass: %d", pid)
	}
}

func TestFindPIDScanFallback(t *testing.T) {
	f := newFake()
	f.files["/proc/11/stat"] = statLine(11, 1, "sh", 1, 1, 0, 0, 1)
	f.setCmdline(11, "sh /data/local/hnc/bin/hnc_dpid_guard.sh")
	f.files["/proc/22/stat"] = statLine(22, 1, "sh", 1, 1, 0, 0, 2)
	f.setCmdline(22, "sh /data/local/hnc/bin/hnc_offload_guard.sh daemon")
	f.files["/hnc/run/dpid_guard.pid"] = "999\n" // 指向不存在的进程
	fs := f.fs(99)
	if pid := fs.FindPID(Def{PIDFiles: []string{"dpid_guard.pid"}, Key: "hnc_dpid_guard", ScanKey: "hnc_dpid_guard.sh"}, "/hnc", fs.Table()); pid != 11 {
		t.Fatalf("scan pid = %d, want 11", pid)
	}
	// 无 ScanKey → 不扫
	if pid := fs.FindPID(Def{PIDFiles: []string{"dpid_guard.pid"}, Key: "hnc_dpid_guard"}, "/hnc", fs.Table()); pid != 0 {
		t.Fatalf("no scankey should not scan: %d", pid)
	}
	// 扫描跳过自己
	f.setCmdline(99, "sh /data/local/hnc/bin/hnc_dpid_guard.sh")
	f.files["/proc/99/stat"] = statLine(99, 1, "sh", 1, 1, 0, 0, 3)
	fs = f.fs(99)
	if pid := fs.FindPID(Def{ScanKey: "hnc_dpid_guard.sh"}, "/hnc", fs.Table()); pid != 11 {
		t.Fatalf("scan should skip self: %d", pid)
	}
}

func TestFindPIDPidfileOrder(t *testing.T) {
	// 多个 pidfile 依序尝试: 第一个不可用则用第二个(dpid.child.pid → dpid.pid)
	f := newFake()
	f.files["/proc/40/stat"] = statLine(40, 1, "hnc_dpid", 1, 1, 0, 0, 1)
	f.setCmdline(40, "/data/local/hnc/bin/hnc_dpid -config c")
	f.files["/hnc/run/dpid.pid"] = "40\n"
	fs := f.fs(99)
	if pid := fs.FindPID(Def{PIDFiles: []string{"dpid.child.pid", "dpid.pid"}, Key: "dpid"}, "/hnc", fs.Table()); pid != 40 {
		t.Fatalf("second pidfile should be used: %d", pid)
	}
}

// v5.26 审查: dpid 已死、只剩 shell guard / Go supervisor 时, 扫描不能把它们认成 dpid。
func TestSpecDpidScanIgnoresGuards(t *testing.T) {
	f := newFake()
	f.files["/proc/200/stat"] = statLine(200, 1, "sh", 1, 1, 0, 0, 10)
	f.setCmdline(200, "sh /data/local/hnc/bin/hnc_dpid_guard.sh")
	f.files["/proc/201/stat"] = statLine(201, 1, "hnc_dpid_superv", 1, 1, 0, 0, 10)
	f.setCmdline(201, "/data/local/hnc/bin/hnc_dpid_supervisor")
	fs := f.fs(1)
	if pid := fs.FindPID(Spec("hnc_dpid"), "/data/local/hnc", fs.Table()); pid != 0 {
		t.Fatalf("guard/supervisor mistaken for dpid: pid=%d", pid)
	}
	f.files["/proc/300/stat"] = statLine(300, 200, "hnc_dpid", 1, 1, 0, 0, 10)
	f.setCmdline(300, "/data/local/hnc/bin/hnc_dpid -config /data/local/hnc/data/dpid.json")
	fs = f.fs(1)
	if pid := fs.FindPID(Spec("hnc_dpid"), "/data/local/hnc", fs.Table()); pid != 300 {
		t.Fatalf("real dpid not found: pid=%d", pid)
	}
}

func TestSpecTable(t *testing.T) {
	for _, n := range SpecNames() {
		d := Spec(n)
		if !d.Self && (len(d.PIDFiles) == 0 || d.Key == "" || d.ScanKey == "") {
			t.Errorf("%s: incomplete spec %+v", n, d)
		}
	}
	d := Spec("hnc_dpid")
	d.PIDFiles[0] = "mutated"
	if Spec("hnc_dpid").PIDFiles[0] != "dpid.child.pid" {
		t.Error("Spec must return a copy")
	}
	if Spec("nope").ScanKey != "" {
		t.Error("unknown spec should be zero")
	}
}
