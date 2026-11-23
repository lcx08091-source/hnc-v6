package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDataplaneRC2IptablesThreeStageWaitAndPathFallback(t *testing.T) {
	// 1. subprocEnvWithFallbackPath 必须包含 /system/bin 与 /usr/sbin:/sbin 兜底
	envSlice := subprocEnvWithFallbackPath("HNC_EXTRA=1")
	joinedEnv := strings.Join(envSlice, "\n")
	for _, wantDir := range []string{"/system/bin", "/vendor/bin", "/usr/sbin", "/sbin"} {
		if !strings.Contains(joinedEnv, wantDir) {
			t.Fatalf("subprocEnvWithFallbackPath missing %q in %v", wantDir, envSlice)
		}
	}

	// 2. xtables 1.4.20/1.4.21: `-w 2` 报 "Bad argument '2'", 裸 `-w` 成功 -> 停在第 2 级并校验 ensureFirewallBaseHooksLinked
	origIptRunner := nativeIptCmdRunner
	origPipeExec := nativePipeRestoreExecFn
	origScalpelResolve := scalpelResolveBinFn
	origScalpelExec := scalpelIptExecFn
	t.Cleanup(func() {
		nativeIptCmdRunner = origIptRunner
		nativePipeRestoreExecFn = origPipeExec
		scalpelResolveBinFn = origScalpelResolve
		scalpelIptExecFn = origScalpelExec
	})

	var calls1420 []string
	nativeIptCmdRunner = func(_ string, args ...string) (string, error) {
		cmdStr := strings.Join(args, " ")
		calls1420 = append(calls1420, cmdStr)
		if len(args) >= 2 && args[0] == "-w" && args[1] == "2" {
			return "iptables v1.4.20: Bad argument `2'\nTry `iptables -h' for more information.", errors.New("exit status 2")
		}
		if len(args) >= 1 && args[0] == "-w" {
			if strings.Contains(cmdStr, "-t mangle -S") {
				return "-P FORWARD ACCEPT\n-N HNC_MARK\n-A FORWARD -j HNC_MARK\n", nil
			}
			if strings.Contains(cmdStr, "-t filter -S") {
				return "-P FORWARD ACCEPT\n-N HNC_CTRL\n-A FORWARD -j HNC_CTRL\n", nil
			}
			return "ok", nil
		}
		t.Fatalf("unexpected fallthrough to no-wait when bare -w succeeded: %v", args)
		return "", nil
	}
	if !ensureFirewallBaseHooksLinked() && resolveIptablesRestoreBin("iptables") != "" {
		t.Fatalf("expected ensureFirewallBaseHooksLinked=true via bare -w fallback, calls=%v", calls1420)
	}
	out, err := runIptWithWaitFallback("/system/bin/iptables", "-t", "mangle", "-S")
	if err != nil || !strings.Contains(out, "-N HNC_MARK") {
		t.Fatalf("runIptWithWaitFallback 2nd-stage bare -w failed: err=%v out=%q", err, out)
	}

	// 3. 极老 xtables (<1.4.20): `-w 2` 与 `-w` 均失败 -> 自动落入第 3 级无 `-w`
	var callsLegacy []string
	nativeIptCmdRunner = func(_ string, args ...string) (string, error) {
		cmdStr := strings.Join(args, " ")
		callsLegacy = append(callsLegacy, cmdStr)
		if len(args) >= 1 && args[0] == "-w" {
			return "iptables v1.4.14: unknown option \"-w\"", errors.New("exit status 2")
		}
		return "legacy-ok", nil
	}
	outLeg, errLeg := runIptWithWaitFallback("/system/bin/iptables", "-t", "filter", "-S")
	if errLeg != nil || outLeg != "legacy-ok" || len(callsLegacy) != 3 {
		t.Fatalf("expected 3-stage fallback (-w 2 -> -w -> bare), got len=%d calls=%v err=%v", len(callsLegacy), callsLegacy, errLeg)
	}

	// 4. pipeIptablesRestore + FlowScalpel ensureForwardJump/defaultPipeRestore 三级回退
	var restoreStages []string
	nativePipeRestoreExecFn = func(_ string, args []string, _ []byte, _ time.Duration) error {
		s := strings.Join(args, " ")
		restoreStages = append(restoreStages, s)
		if s == "-w 2 --noflush" {
			return errors.New("iptables-restore v1.4.21: Bad argument '2'")
		}
		if s == "-w --noflush" {
			return nil
		}
		return errors.New("unexpected args " + s)
	}
	if err := pipeIptablesRestore("/system/bin/iptables-restore", []byte("*mangle\nCOMMIT\n")); err != nil {
		t.Fatalf("pipeIptablesRestore bare -w fallback failed: %v", err)
	}
	if strings.Join(restoreStages, " | ") != "-w 2 --noflush | -w --noflush" {
		t.Fatalf("unexpected restore stages: %v", restoreStages)
	}

	dir := setupNativeTierTestEnv(t, "wlan2")
	srv := &server{hncDir: dir}
	eng := newFlowScalpelEngine(srv)
	scalpelResolveBinFn = func(name string) string { return "/system/bin/" + name }
	var scalpelCmds []string
	scalpelIptExecFn = func(_ string, args ...string) (string, error) {
		s := strings.Join(args, " ")
		scalpelCmds = append(scalpelCmds, s)
		if len(args) >= 2 && args[0] == "-w" && args[1] == "2" {
			return "Bad argument '2'", errors.New("exit 2")
		}
		if len(args) >= 1 && args[0] == "-w" && strings.Contains(s, "-C FORWARD") {
			return "No chain/target/match", errors.New("exit 1")
		}
		return "", nil
	}
	eng.ensureForwardJump(false)
	if !eng.hookEnsuredV4 || !strings.Contains(strings.Join(scalpelCmds, "\n"), "-w -t filter -I FORWARD 1 -j HNC_SCALPEL") {
		t.Fatalf("scalpel ensureForwardJump failed bare -w fallback: %v", scalpelCmds)
	}

	// 5. dataplane_verify dpRunIptablesQuick 三级回退
	var dpIptCalls []string
	dpEnv := &dpVerifyEnv{
		RunCmd: func(_ context.Context, name string, args ...string) (string, error) {
			s := name + " " + strings.Join(args, " ")
			dpIptCalls = append(dpIptCalls, s)
			if len(args) >= 2 && args[0] == "-w" && args[1] == "2" {
				return "iptables: Bad argument '2'", errors.New("exit 2")
			}
			if len(args) >= 1 && args[0] == "-w" {
				return "iptables: unrecognized option '-w'", errors.New("exit 2")
			}
			return "-A HNC_MARK -j ACCEPT\n", nil
		},
	}
	gotVerifyIpt := dpRunIptablesQuick(dpEnv, "iptables", "-t", "mangle", "-S")
	if !strings.Contains(gotVerifyIpt, "HNC_MARK") || len(dpIptCalls) != 3 {
		t.Fatalf("dpRunIptablesQuick expected 3 stages, got %d (%v) out=%q", len(dpIptCalls), dpIptCalls, gotVerifyIpt)
	}
}

func TestDataplaneRC2RejectToDropFallbackAndTableIsolation(t *testing.T) {
	// 1. 铁律校验: buildScalpelRestorePayload 默认必须保留 -j REJECT --reject-with ...
	rules := []ScalpelActiveRule{
		{
			ID:         "r1",
			IsIPv6:     false,
			MatchSport: true,
			Tuple:      ScalpelTuple{Proto: "tcp", SrcIP: "192.168.43.88", Sport: 54321, DstIP: "104.16.132.229", Dport: 443},
		},
		{
			ID:         "r2",
			IsIPv6:     false,
			MatchSport: false,
			Tuple:      ScalpelTuple{Proto: "udp", SrcIP: "192.168.43.88", Sport: 55000, DstIP: "198.51.100.77", Dport: 3478},
		},
	}
	rawScalpel := buildScalpelRestorePayload(false, rules)
	if !strings.Contains(rawScalpel, "-j REJECT --reject-with tcp-reset") ||
		!strings.Contains(rawScalpel, "-j REJECT --reject-with icmp-port-unreachable") {
		t.Fatalf("default scalpel payload MUST preserve REJECT, got:\n%s", rawScalpel)
	}

	// 2. 运行期缺 ipt_REJECT 时 defaultPipeRestore 自动通过 replaceRejectWithDropInRestorePayload 降级为 -j DROP
	origPipeExec := nativePipeRestoreExecFn
	origScalpelResolve := scalpelResolveBinFn
	t.Cleanup(func() {
		nativePipeRestoreExecFn = origPipeExec
		scalpelResolveBinFn = origScalpelResolve
	})

	var submittedPayloads []string
	nativePipeRestoreExecFn = func(_ string, _ []string, data []byte, _ time.Duration) error {
		s := string(data)
		submittedPayloads = append(submittedPayloads, s)
		if strings.Contains(s, "REJECT") {
			return errors.New("iptables-restore: line 3 failed (Couldn't load target `REJECT':No such file or directory)")
		}
		return nil
	}
	scalpelResolveBinFn = func(name string) string { return "/system/bin/" + name }

	dir := setupNativeTierTestEnv(t, "wlan2")
	eng := newFlowScalpelEngine(&server{hncDir: dir})
	if err := eng.defaultPipeRestore(scalpelAfInet, rawScalpel); err != nil {
		t.Fatalf("defaultPipeRestore should succeed via DROP fallback, got: %v", err)
	}
	if len(submittedPayloads) != 2 {
		t.Fatalf("expected 2 attempts (REJECT then DROP), got %d", len(submittedPayloads))
	}
	if strings.Contains(submittedPayloads[1], "REJECT") || strings.Contains(submittedPayloads[1], "--reject-with") ||
		!strings.Contains(submittedPayloads[1], "-j DROP") {
		t.Fatalf("malformed DROP fallback payload:\n%s", submittedPayloads[1])
	}

	// 3. 应用限速防火墙载荷: *mangle 与 *filter 分步隔离容错, 即使 *filter 完全不可用也绝不连坐回滚 *mangle!
	asgs := []V6AppLimitSlotAssignment{
		{
			Slot:        1,
			MAC:         "aa:bb:cc:dd:ee:05",
			Mid:         5,
			AppID:       "bilibili",
			RateBps:     1_250_000,
			CeilBps:     1_250_000,
			IPv4Targets: []string{"203.0.113.88"},
			IPv6Targets: []string{"2001:db8::88"},
		},
	}
	v4App, _ := BuildAppLimitFirewallPayloads(asgs, map[string]string{"aa:bb:cc:dd:ee:05": "192.168.43.55"}, nil)
	if !strings.Contains(string(v4App), "-j REJECT --reject-with icmp-port-unreachable") {
		t.Fatalf("default BuildAppLimitFirewallPayloads must keep REJECT:\n%s", string(v4App))
	}

	var committedMangle string
	nativePipeRestoreExecFn = func(_ string, _ []string, data []byte, _ time.Duration) error {
		s := string(data)
		if strings.Contains(s, "*filter") {
			return errors.New("kernel filter table extension disabled")
		}
		if strings.Contains(s, "*mangle") {
			committedMangle = s
			return nil
		}
		return errors.New("unexpected payload")
	}
	mangleOK, filterOK, anyOK, _ := pipeRestoreTablesIsolated("/system/bin/iptables-restore", v4App)
	if !mangleOK || filterOK || !anyOK || !strings.Contains(committedMangle, "HNC_APP_LIMIT_UP") || !strings.Contains(committedMangle, "CONNMARK --save-mark") {
		t.Fatalf("expected isolated *mangle commit to succeed despite *filter failure: mangleOK=%v filterOK=%v committed=%q",
			mangleOK, filterOK, committedMangle)
	}
}

func TestNativeRC2NoIFBFullRestoreAndColorOSIngressBypass(t *testing.T) {
	dir := setupNativeTierTestEnv(t, "wlan2")
	if err := os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{
		"version": 1,
		"devices": {
			"aa:bb:cc:dd:ee:11": {
				"mark_id": 2,
				"ip": "192.168.43.21",
				"limit_enabled": true,
				"down_mbps": "20",
				"up_mbps": "8"
			}
		}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

	origResolve := nativeResolveSystemBinFn
	origTCExec := nativeTCExecFn
	origTCShow := nativeTCQdiscShowFn
	origCollectV6 := nativeCollectDevIPv6Fn
	origLiveIfs := v6LiveInterfacesFn
	origDefRoutes := v6DumpDefaultRouteIfindexesFn
	t.Cleanup(func() {
		nativeResolveSystemBinFn = origResolve
		nativeTCExecFn = origTCExec
		nativeTCQdiscShowFn = origTCShow
		nativeCollectDevIPv6Fn = origCollectV6
		v6LiveInterfacesFn = origLiveIfs
		v6DumpDefaultRouteIfindexesFn = origDefRoutes
	})

	// 1. ColorOS /system/bin/tc 对裸 `ingress` 报错时自动回退 `parent ffff:fff2`
	nativeResolveSystemBinFn = func(_ string) string { return "/system/bin/tc" }
	nativeTCQdiscShowFn = func(_, _ string) string { return "qdisc clsact ffff: parent ffff:fff1" }
	nativeCollectDevIPv6Fn = func(_, _, _ string) []string { return nil }

	var tcExecuted []string
	nativeTCExecFn = func(_ string, args ...string) error {
		cmd := strings.Join(args, " ")
		tcExecuted = append(tcExecuted, cmd)
		for _, tok := range args {
			if tok == "ingress" {
				return errors.New("ColorOS tc: unknown token ingress")
			}
		}
		return nil
	}
	if err := applyNativeIngressPolice(dir, "wlan2", 2, "aa:bb:cc:dd:ee:11", "192.168.43.21", 1_000_000, 0x00820000, 0x00ff0000); err != nil {
		t.Fatalf("ColorOS ingress fallback failed: %v", err)
	}
	joinedTC := strings.Join(tcExecuted, "\n")
	if !strings.Contains(joinedTC, "filter add dev wlan2 parent ffff:fff2 protocol ip prio 302") {
		t.Fatalf("expected fallback to `parent ffff:fff2` in:\n%s", joinedTC)
	}

	// 1b. NativeFullRestoreV6 在无 ifb0 (GKI 6.1/6.6/6.12 无 CONFIG_IFB) 场景下自动补齐上行 ingress police
	origCollectProbe := v6CollectProbeInputsFn
	origResolveIdx := v6ResolveIfaceIndexFn
	t.Cleanup(func() {
		v6CollectProbeInputsFn = origCollectProbe
		v6ResolveIfaceIndexFn = origResolveIdx
	})
	v6ResolveIfaceIndexFn = func(_ string) (int, error) { return 0, errors.New("no ifb0 on GKI") }
	v6CollectProbeInputsFn = func(_ string) []V6IfaceProbeInput {
		return []V6IfaceProbeInput{
			{Name: "ap0", Ifindex: 99, OperUp: true, IPv4CIDRs: []string{"192.168.43.1/24"}},
		}
	}
	tcExecuted = nil
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("ACTIVE:ap0\n"), 0o644)
	srvRestore := &server{hncDir: dir}
	repRestore, rErr := srvRestore.NativeFullRestoreV6()
	if rErr != nil {
		t.Fatalf("NativeFullRestoreV6 without ifb0 failed: %v", rErr)
	}
	if repRestore.DevicesRestored != 1 || !strings.Contains(strings.Join(tcExecuted, "\n"), "src 192.168.43.21/32 police rate 8000kbit") {
		t.Fatalf("expected NativeFullRestoreV6 without ifb0 to install 8000kbit ingress police on ap0, rep=%+v cmds=%v", repRestore, tcExecuted)
	}

	// 2. dataplane_verify dpCollectIngressFilters: `ingress` 返回空串时自动回退 `parent ffff:` 及 RTNetlink
	env := &dpVerifyEnv{
		Ifindex: func(_ string) int { return 11 },
		RunCmd: func(_ context.Context, name string, args ...string) (string, error) {
			s := name + " " + strings.Join(args, " ")
			if strings.HasSuffix(s, "dev wlan2 ingress") {
				return "", nil // ColorOS 空返回缺陷
			}
			if strings.HasSuffix(s, "dev wlan2 parent ffff:") {
				return "filter parent ffff: protocol ip pref 302 u32 police rate 8000Kbit burst 125Kb drop\n", nil
			}
			return "", nil
		},
	}
	gotIng := dpCollectIngressFilters(env, "wlan2")
	if !strings.Contains(gotIng, "police") {
		t.Fatalf("expected dpCollectIngressFilters to recover via `parent ffff:`, got %q", gotIng)
	}

	envNL := &dpVerifyEnv{
		Ifindex: func(_ string) int { return 11 },
		DumpIngressNetlink: func(idx int) string {
			if idx == 11 {
				return "filter parent ffff: protocol all pref 1 bpf handle 0x1 hnc_clsact direct-action police"
			}
			return ""
		},
	}
	if gotNL := dpCollectIngressFilters(envNL, "wlan2"); !strings.Contains(gotNL, "hnc_clsact") || !strings.Contains(gotNL, "police") {
		t.Fatalf("expected RTNetlink ingress filter dump priority, got %q", gotNL)
	}
}

func TestTier3RC2BatchPreDelToleranceAndDynamicQdiscCaps(t *testing.T) {
	dir := setupNativeTierTestEnv(t, "wlan2")

	// 1. qdisc_caps.json 仅支持 sfq/pfifo 时动态生成 sfq / 缩放 pfifo, 绝不硬写死 fq_codel
	if err := os.WriteFile(filepath.Join(dir, "run", "qdisc_caps.json"),
		[]byte(`{"schema":1,"available":["sfq","pfifo"],"chosen":"sfq"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	expLines := buildTier3VectorExpressBatchLinesWithCaps(dir, "wlan2", false, true, true, false, 0x01000000, 0x03000000, 50000, 100000, 0)
	joinedExp := strings.Join(expLines, "\n")
	if strings.Contains(joinedExp, "fq_codel") || !strings.Contains(joinedExp, "handle 8010: sfq perturb 10") {
		t.Fatalf("expected sfq leaf from qdisc_caps.json, got:\n%s", joinedExp)
	}

	if err := os.WriteFile(filepath.Join(dir, "run", "qdisc_caps.json"),
		[]byte(`{"schema":1,"available":["pfifo"],"chosen":"pfifo"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	leashLines := buildTier3UpdateLeashBatchLines("wlan2", false, true, 0x03000000, 0x03000000, 1500, dir)
	joinedLeash := strings.Join(leashLines, "\n")
	if strings.Contains(joinedLeash, "fq_codel") || !strings.Contains(joinedLeash, "handle 9990: pfifo limit 16") {
		t.Fatalf("expected scaled pfifo limit 16 for 1500kbps UpdateLeash, got:\n%s", joinedLeash)
	}

	// 2. execTier3AtomicBatch: 预清理 `del` 因节点不存在导致第一次 `tc -force -batch` 返回 exit 2 时, 自动剥离 `del` 重放主变更 `replace` 成功!
	var batchPayloads []string
	var v4ArgsLog []string
	h := defaultDPTierHooks()
	h.resolveBin = func(name string) string { return "/system/bin/" + name }
	h.runTier3Cmd = func(bin string, args []string, stdin []byte) error {
		s := string(stdin)
		if strings.HasSuffix(bin, "/tc") {
			batchPayloads = append(batchPayloads, s)
			if strings.Contains(s, "filter del ") {
				return errors.New("tc [-force -batch -]: exit status 2 (RTNETLINK answers: No such file or directory)")
			}
			return nil
		}
		if strings.HasSuffix(bin, "iptables-restore") {
			aStr := strings.Join(args, " ")
			v4ArgsLog = append(v4ArgsLog, aStr)
			if aStr == "-w 2 --noflush" {
				return errors.New("iptables-restore: Bad argument '2'")
			}
			if strings.Contains(s, "REJECT") {
				return errors.New("No chain/target/match by that name (REJECT)")
			}
			return nil
		}
		return nil
	}

	v4WithReject := []byte("*filter\n:HNC_CTRL - [0:0]\n-A HNC_CTRL -p tcp -j REJECT --reject-with tcp-reset\nCOMMIT\n")
	if err := execTier3AtomicBatch(h, expLines, v4WithReject, nil); err != nil {
		t.Fatalf("execTier3AtomicBatch should recover from pre-del ENOENT, -w 2 bad arg, and missing REJECT: %v", err)
	}
	if len(batchPayloads) != 2 || strings.Contains(batchPayloads[1], "filter del ") || !strings.Contains(batchPayloads[1], "class replace ") {
		t.Fatalf("expected 2nd tc replay with only replace lines, got %v", batchPayloads)
	}
	if len(v4ArgsLog) < 2 || v4ArgsLog[1] != "-w --noflush" {
		t.Fatalf("expected tier3 restore -w fallback, got %v", v4ArgsLog)
	}

	// 纯卸载 `del` 批次遇不存在错误同样幂等成功
	delOnly := buildTier3UpdateLeashBatchLines("wlan2", false, false, 0x03000000, 0x03000000, 0, dir)
	if err := execTier3AtomicBatch(h, delOnly, nil, nil); err != nil {
		t.Fatalf("expected pure-del tier3 batch to tolerate ENOENT, got: %v", err)
	}
}

func TestDataplaneRC2LegacyKernelEthPAllDualStackAndLeafFallback(t *testing.T) {
	origSend := nlBatchSendAckFn
	origDumpQ := nlBatchDumpQdiscsFn
	origDumpC := nlBatchDumpClassesFn
	origEnsure := nlBatchEnsureHTBRootFn
	t.Cleanup(func() {
		nlBatchSendAckFn = origSend
		nlBatchDumpQdiscsFn = origDumpQ
		nlBatchDumpClassesFn = origDumpC
		nlBatchEnsureHTBRootFn = origEnsure
	})

	nlBatchDumpQdiscsFn = func(_ int, ifidx int) ([]rtnlQdiscBrief, error) {
		return []rtnlQdiscBrief{{ifIndex: ifidx, handle: rtnlHtbRootMaj, kind: "htb"}}, nil
	}
	nlBatchDumpClassesFn = func(_ int, _ int) (map[string]HTBClassStat, error) {
		return map[string]HTBClassStat{"1:1": {ClassID: "1:1"}}, nil
	}
	nlBatchEnsureHTBRootFn = func(_ int, _ int, _ uint16, _ uint64) error { return nil }

	var seenFilterProtos []string
	var seenQdiscKinds []string

	// 模拟 4.14/4.19 裁剪内核: 拒绝 ETH_P_ALL 过滤器, 且拒绝 fq_codel 和 fq, 仅支持 sfq/pfifo
	nlBatchSendAckFn = func(_ int, msg []byte, _ uint32) error {
		msgType := binary.LittleEndian.Uint16(msg[4:6])
		if msgType == rtnlNewTFilter {
			info := binary.LittleEndian.Uint32(msg[32:36])
			protoNet := uint16(info & 0xffff)
			prio := uint16(info >> 16)
			if protoNet == rtnlHtons(rtnlEthPAll) {
				return syscall.EINVAL
			}
			switch protoNet {
			case rtnlHtons(rtnlEthPIP):
				seenFilterProtos = append(seenFilterProtos, fmt.Sprintf("ip@prio%d", prio))
			case rtnlHtons(rtnlEthPIPv6):
				seenFilterProtos = append(seenFilterProtos, fmt.Sprintf("ipv6@prio%d", prio))
			}
			return nil
		}
		if msgType == rtnlNewQdisc {
			attrs := msg[rtnlMsgHdrLen+rtnlTcMsgLen:]
			kind := ""
			if len(attrs) >= 8 {
				alen := int(binary.LittleEndian.Uint16(attrs[0:2]))
				if alen >= 5 && alen <= len(attrs) {
					kind = strings.TrimRight(string(attrs[4:alen]), "\x00")
				}
			}
			seenQdiscKinds = append(seenQdiscKinds, kind)
			if kind == "fq_codel" || kind == "fq" {
				return syscall.ENOENT
			}
			return nil
		}
		return nil
	}

	// 1) 验证 nlApplyBatchWithFWFallbackOnSocket (UpdateLeash 批次)
	leashMsgs := buildUpdateLeashUpsertBatch(9, false, 250_000, 0x03000000, 0x03000000, pschedDefaultTickUsec)
	if _, err := nlApplyBatchWithFWFallbackOnSocket(77, leashMsgs); err != nil {
		t.Fatalf("nlApplyBatchWithFWFallbackOnSocket failed on legacy kernel: %v", err)
	}
	joinedProtos1 := strings.Join(seenFilterProtos, ",")
	if !strings.Contains(joinedProtos1, "ip@prio6") || !strings.Contains(joinedProtos1, "ipv6@prio7") {
		t.Fatalf("expected ETH_P_ALL split into ip@prio6 + ipv6@prio7, got %s", joinedProtos1)
	}
	if !strings.Contains(strings.Join(seenQdiscKinds, "->"), "fq_codel->fq_codel->fq->sfq") {
		t.Fatalf("expected adaptive leaf fallback chain to sfq, got %v", seenQdiscKinds)
	}

	// 2) 验证 v6_native_subtrees sendNetlinkBatchBestEffort (AppQoS 子树) + pfifo 最终兜底
	seenFilterProtos = nil
	seenQdiscKinds = nil
	nlBatchSendAckFn = func(_ int, msg []byte, _ uint32) error {
		msgType := binary.LittleEndian.Uint16(msg[4:6])
		if msgType == rtnlNewTFilter {
			info := binary.LittleEndian.Uint32(msg[32:36])
			protoNet := uint16(info & 0xffff)
			prio := uint16(info >> 16)
			parent := binary.LittleEndian.Uint32(msg[28:32])
			if protoNet == rtnlHtons(rtnlEthPAll) {
				return syscall.EINVAL
			}
			tag := "ip"
			if protoNet == rtnlHtons(rtnlEthPIPv6) {
				tag = "ipv6"
			}
			seenFilterProtos = append(seenFilterProtos, fmt.Sprintf("%s@%s/p%d", formatTCHandle(parent), tag, prio))
			return nil
		}
		if msgType == rtnlNewQdisc {
			attrs := msg[rtnlMsgHdrLen+rtnlTcMsgLen:]
			alen := int(binary.LittleEndian.Uint16(attrs[0:2]))
			kind := strings.TrimRight(string(attrs[4:alen]), "\x00")
			seenQdiscKinds = append(seenQdiscKinds, kind)
			if kind != "pfifo" {
				return syscall.ENOENT
			}
			return nil
		}
		return nil
	}

	qosBatch, err := BuildAppQoSSubtreeNetlinkBatch(9, 5, 2_500_000, 2_500_000, 0x00850000, 0x00ff0000, ComputeDynamicQoSRatios(0, 0), pschedDefaultTickUsec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sendNetlinkBatchBestEffort(77, qosBatch); err != nil {
		t.Fatalf("sendNetlinkBatchBestEffort failed: %v", err)
	}
	joinedSub := strings.Join(seenFilterProtos, ",")
	for _, want := range []string{"1:@ip/p1", "1:@ipv6/p3", "1:5@ip/p2", "1:5@ipv6/p4", "1:5@ip/p9", "1:5@ipv6/p10"} {
		if !strings.Contains(joinedSub, want) {
			t.Fatalf("missing dual-stack subtree filter %q in %s", want, joinedSub)
		}
	}
	if !strings.Contains(strings.Join(seenQdiscKinds, ","), "pfifo") {
		t.Fatalf("expected fallback to scaled pfifo on ultra-trimmed kernel, got %v", seenQdiscKinds)
	}

	// 3) 验证 v6_multi_iface applyLANFastlaneBatchOnSocket (1:fffe 2.5Gbps 直通类)
	seenFilterProtos = nil
	seenQdiscKinds = nil
	fastMsgs, err := BuildLANFastlaneNetlinkBatch(9, []string{"192.168.43.1/24"}, pschedDefaultTickUsec)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyLANFastlaneBatchOnSocket(77, 9, fastMsgs); err != nil {
		t.Fatalf("applyLANFastlaneBatchOnSocket failed: %v", err)
	}
	joinedFast := strings.Join(seenFilterProtos, ",")
	if !strings.Contains(joinedFast, "1:@ip/p1") || !strings.Contains(joinedFast, "1:@ipv6/p3") {
		t.Fatalf("expected LAN fastlane ETH_P_ALL fw split to 1:@ip/p1 + 1:@ipv6/p3, got %s", joinedFast)
	}
	if !strings.Contains(strings.Join(seenQdiscKinds, ","), "pfifo") {
		t.Fatalf("expected LAN fastlane leaf adaptive fallback to pfifo, got %v", seenQdiscKinds)
	}
}

func encodeTestRouteMsg(family, dstLen, rtmType uint8, rtmFlags uint32, oif int) []byte {
	var attrs []byte
	if oif > 0 {
		attrs = rtnlPutAttrU32(attrs, rtnlRtaOif, uint32(oif))
	}
	total := rtnlMsgHdrLen + rtnlRtMsgLen + len(attrs)
	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(total))
	binary.LittleEndian.PutUint16(buf[4:6], rtnlNewRoute)
	binary.LittleEndian.PutUint16(buf[6:8], rtnlFMulti)
	buf[16] = family
	buf[17] = dstLen
	buf[23] = rtmType
	binary.LittleEndian.PutUint32(buf[24:28], rtmFlags)
	copy(buf[28:], attrs)
	return buf
}

func TestMultiIfaceRC2DualStaRouteGuardAndAutorateWifiIsolation(t *testing.T) {
	// 1. 验证纯 Go Netlink RTM_GETROUTE 响应解析: 仅提取 rtm_dst_len == 0 && RTN_UNICAST 且非 CLONED 的默认路由口
	var rtStream []byte
	// wlan0 (ifindex=3, table 1021): 默认路由 dst_len=0, RTN_UNICAST -> 命中!
	rtStream = append(rtStream, encodeTestRouteMsg(2, 0, rtnlRtnUnicast, 0, 3)...)
	// wlan1 副 STA (ifindex=11, table 1022): 默认路由 dst_len=0, RTN_UNICAST -> 命中!
	rtStream = append(rtStream, encodeTestRouteMsg(10, 0, rtnlRtnUnicast, 0, 11)...)
	// wlan2 热点下游子网路由 (ifindex=12, 192.168.43.0/24 -> dst_len=24): 绝不能误标为默认路由!
	rtStream = append(rtStream, encodeTestRouteMsg(2, 24, rtnlRtnUnicast, 0, 12)...)
	// netd unreachable 兜底路由 (rtm_type = 7 RTN_UNREACHABLE): 忽略!
	rtStream = append(rtStream, encodeTestRouteMsg(2, 0, 7, 0, 15)...)
	rtStream = append(rtStream, testRTNLEncodeDone(1)...)

	defIfs, done, err := parseDefaultRouteIfindexesMsgs(rtStream)
	if err != nil || !done || !defIfs[3] || !defIfs[11] || defIfs[12] || defIfs[15] {
		t.Fatalf("parseDefaultRouteIfindexesMsgs mismatch: done=%v err=%v map=%+v", done, err, defIfs)
	}

	// 2. 验证 iface_detect.json 新增 default_route_ifaces + CollectLiveIfaceProbeInputs + AnalyzeMultiInterfaces
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "run", "iface_detect.json"), []byte(`{
		"iface": "wlan2",
		"authoritative": true,
		"upstream": "wlan0",
		"default_route_ifaces": ["wlan0", "wlan1", "tun0"]
	}`), 0o644)

	detWANs, authIfc := v6ReadIfaceDetectDefaultWANs(dir)
	if authIfc != "wlan2" || !detWANs["wlan0"] || !detWANs["wlan1"] || detWANs["tun0"] || detWANs["wlan2"] {
		t.Fatalf("v6ReadIfaceDetectDefaultWANs unexpected: auth=%q map=%+v", authIfc, detWANs)
	}

	origLiveIfs := v6LiveInterfacesFn
	origDefDump := v6DumpDefaultRouteIfindexesFn
	t.Cleanup(func() {
		v6LiveInterfacesFn = origLiveIfs
		v6DumpDefaultRouteIfindexesFn = origDefDump
	})
	v6LiveInterfacesFn = func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 3, MTU: 1500, Name: "wlan0", Flags: net.FlagUp},
			{Index: 11, MTU: 1500, Name: "wlan1", Flags: net.FlagUp},
			{Index: 12, MTU: 1500, Name: "wlan2", Flags: net.FlagUp},
		}, nil
	}
	v6DumpDefaultRouteIfindexesFn = func() (map[int]bool, error) {
		return map[int]bool{3: true, 11: true}, nil
	}
	liveInputs := CollectLiveIfaceProbeInputs(dir)
	byName := map[string]V6IfaceProbeInput{}
	for _, in := range liveInputs {
		byName[in.Name] = in
	}
	if !byName["wlan0"].IsDefaultWAN || !byName["wlan1"].IsDefaultWAN || byName["wlan2"].IsDefaultWAN {
		t.Fatalf("expected wlan0 & secondary STA wlan1 marked IsDefaultWAN=true, got %+v", byName)
	}

	// 即便副 STA wlan1 拥有 192.168.100.25/24 私网 IP, AnalyzeMultiInterfaces 也必须将其归入 PhysicalUpstreams, 绝不误判为热点下游口!
	dualStaInputs := []V6IfaceProbeInput{
		{Name: "wlan0", Ifindex: 3, OperUp: true, IPv4CIDRs: []string{"192.168.1.10/24"}, IsDefaultWAN: true},
		{Name: "wlan1", Ifindex: 11, OperUp: true, IPv4CIDRs: []string{"192.168.100.25/24"}, IsDefaultWAN: true},
		{Name: "wlan2", Ifindex: 12, OperUp: true, IPv4CIDRs: []string{"192.168.43.1/24"}, IsDefaultWAN: false},
	}
	miSnap := AnalyzeMultiInterfaces(dualStaInputs, "wlan2", nil)
	if strings.Join(miSnap.ShapeTargets, ",") != "wlan2" || miSnap.DualBandOrMLO {
		t.Fatalf("Dual-STA wlan1 was misclassified as hotspot AP! ShapeTargets=%v DualBandOrMLO=%v", miSnap.ShapeTargets, miSnap.DualBandOrMLO)
	}
	if strings.Join(miSnap.Tun0Guard.PhysicalUpstreams, ",") != "wlan0,wlan1" {
		t.Fatalf("expected both wlan0 and wlan1 in PhysicalUpstreams, got %v", miSnap.Tun0Guard.PhysicalUpstreams)
	}
}

func TestAutorateRC2WifiRelayIgnoresWeakCellularCeiling(t *testing.T) {
	withAutorateTestHooks(t)

	dir := t.TempDir()
	for _, sub := range []string{"bin", "run", "data"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("ACTIVE:wlan2\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "bin", "tc_manager.sh"), []byte("#!/system/bin/sh\nexit 0\n"), 0o755)

	activeUpstream := "wlan0"
	autorateInspectIfaceFn = func(name string) autorateIfaceState {
		if name == activeUpstream {
			return autorateIfaceState{Exists: true, FlagUp: true, HasIPv4: true}
		}
		return autorateIfaceState{Exists: true, FlagUp: false}
	}

	// 模拟室内弱蜂窝信号 (RFCeilingFactor=0.35), 但热点正在通过千兆 Wi-Fi STA (wlan0) 中继
	sigMon := &signalMonitor{
		last: hostSignalStatus{
			Available:       true,
			Mode:            "cellular", // 哪怕异步信号缓存尚未切到 wifi_sta, 只要物理上游非蜂窝口也不得乱砍!
			RAT:             "4G LTE",
			RFCeilingFactor: 0.35,
		},
		lastAt: time.Now(),
	}

	ctl := newAutorateCtl(dir)
	cfg := defaultAutorateConfig()
	cfg.Enabled = true
	cfg.DownMinMbps = 20
	cfg.DownMaxMbps = 500
	cfg.UpMinMbps = 10
	cfg.UpMaxMbps = 200
	cfg.RTTDeltaMs = 25
	ctl.mu.Lock()
	ctl.cfg = cfg
	ctl.syncStatusConfigLocked(cfg)
	ctl.st.CurDownMbps = 480
	ctl.st.CurUpMbps = 180
	ctl.appliedIface = "wlan2"
	ctl.appliedDown = 480
	ctl.appliedUp = 180
	ctl.mu.Unlock()

	srv := &server{
		hncDir:    dir,
		autorate:  ctl,
		signalCtl: sigMon,
	}

	curT := time.Unix(1770010000, 0)
	var hsTx uint64
	autorateNowFn = func() time.Time { return curT }
	autorateReadNetDevFn = func() ([]byte, error) {
		_ = os.WriteFile(filepath.Join(dir, "run", "iface_detect.json"),
			[]byte(fmt.Sprintf(`{"iface":"wlan2","tether_upstream":%q,"upstream":%q}`, activeUpstream, activeUpstream)), 0o644)
		return formatSyntheticProcNetDev("wlan2", 1000, hsTx, activeUpstream, 50000, 50000), nil
	}
	autorateProbeRTTFn = func(_ string, _ []string, _ *int) (float64, bool) {
		return 8.0, true
	}

	srv.autorateStep(cfg) // 建立采样基线
	curT = curT.Add(2 * time.Second)
	hsTx += uint64((450.0 * 1e6 * 2.0) / 8.0) // 450 Mbps 满载下载
	srv.autorateStep(cfg)

	snapWifi := ctl.Snapshot()
	// 若误乘 0.35, DownMaxMbps=500 会被砍到 175Mbps; 隔离修复后必须扩速突破至 500Mbps!
	if snapWifi.CurDownMbps <= 480 || snapWifi.CurDownMbps != 500 {
		t.Fatalf("Wi-Fi STA relay was throttled by weak cellular RFCeilingFactor! CurDownMbps=%v want 500", snapWifi.CurDownMbps)
	}

	// 切换回真实蜂窝口 rmnet_data0 且 Mode="cellular" 时, RFCeilingFactor=0.35 正常生效压顶至 175Mbps
	activeUpstream = "rmnet_data0"
	curT = curT.Add(2 * time.Second)
	hsTx += uint64((450.0 * 1e6 * 2.0) / 8.0)
	srv.autorateStep(cfg)
	snapCell := ctl.Snapshot()
	if snapCell.CurDownMbps != 175 {
		t.Fatalf("expected cellular upstream to enforce RFCeilingFactor=0.35 (500*0.35=175), got %v", snapCell.CurDownMbps)
	}
}

func encodeTestNeighIPv6Msg(ifidx int, state uint16, ipStr, macStr string, confirmedAge uint32) []byte {
	ip := net.ParseIP(ipStr).To16()
	hw, _ := net.ParseMAC(macStr)
	var ci [16]byte
	binary.LittleEndian.PutUint32(ci[0:4], confirmedAge)
	binary.LittleEndian.PutUint32(ci[8:12], confirmedAge)

	var attrs []byte
	attrs = rtnlPutAttr(attrs, ndaDst, ip)
	attrs = rtnlPutAttr(attrs, ndaLLAddr, hw)
	attrs = rtnlPutAttr(attrs, ndaCacheInfo, ci[:])

	total := rtnlMsgHdrLen + 12 + len(attrs)
	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(total))
	binary.LittleEndian.PutUint16(buf[4:6], rtnlNewNeigh)
	binary.LittleEndian.PutUint16(buf[6:8], rtnlFMulti)
	buf[16] = rtnlAfInet6
	binary.LittleEndian.PutUint32(buf[20:24], uint32(ifidx))
	binary.LittleEndian.PutUint16(buf[24:26], state)
	copy(buf[28:], attrs)
	return buf
}

func TestNativeRC2IPv6NeighborRankingCap16AndMtkActionState(t *testing.T) {
	// 1. 单设备 >16 个 IPv6 隐私地址优胜劣汰:
	// 先塞入 16 条陈旧 STALE 地址 (confirmedAge=5000..5015), 再追加 4 条高优地址 (REACHABLE/DELAY/PROBE/PERMANENT)!
	const mac = "aa:bb:cc:dd:ee:77"
	var stream []byte
	for i := 1; i <= 16; i++ {
		stream = append(stream, encodeTestNeighIPv6Msg(9, nudStale, fmt.Sprintf("2409:8900:aa00::%x", i), mac, uint32(5000+i))...)
	}
	// 后追加的高优活跃地址绝不能被前 16 条 STALE 挤掉!
	stream = append(stream, encodeTestNeighIPv6Msg(9, nudDelay, "2409:8900:bb00::d1", mac, 200)...)
	stream = append(stream, encodeTestNeighIPv6Msg(9, nudProbe, "2409:8900:bb00::b2", mac, 100)...)
	stream = append(stream, encodeTestNeighIPv6Msg(9, nudPermanent, "2409:8900:bb00::c3", mac, 150)...)
	stream = append(stream, encodeTestNeighIPv6Msg(9, nudReachable, "2409:8900:bb00::a2", mac, 80)...)
	stream = append(stream, encodeTestNeighIPv6Msg(9, nudReachable, "2409:8900:bb00::a1", mac, 10)...) // 最新确认 REACHABLE, 必须排第 0 位!
	stream = append(stream, testRTNLEncodeDone(1)...)

	gotMap, done, err := parseIPv6NeighDumpMsgs(stream, map[int]bool{9: true})
	if err != nil || !done {
		t.Fatalf("parseIPv6NeighDumpMsgs failed: done=%v err=%v", done, err)
	}
	ips := gotMap[mac]
	if len(ips) != v6IPv6MaxAddrs {
		t.Fatalf("expected capped %d addresses, got %d", v6IPv6MaxAddrs, len(ips))
	}
	wantTop5 := []string{
		"2409:8900:bb00::a1", // REACHABLE, confirmedAge=10
		"2409:8900:bb00::a2", // REACHABLE, confirmedAge=80
		"2409:8900:bb00::b2", // PROBE, confirmedAge=100
		"2409:8900:bb00::c3", // PERMANENT, confirmedAge=150
		"2409:8900:bb00::d1", // DELAY, confirmedAge=200
	}
	for i, w := range wantTop5 {
		if ips[i].String() != w {
			t.Fatalf("rank[%d] = %q, want %q (full=%v)", i, ips[i].String(), w, ips)
		}
	}
	// 最老的 STALE (confirmedAge=5016 -> ::10) 必须被淘汰
	for _, ip := range ips {
		if ip.String() == "2409:8900:aa00::10" {
			t.Fatalf("oldest STALE address 2409:8900:aa00::10 should have been evicted: %v", ips)
		}
	}

	// 1b. 验证 collectDeviceIPv6Addrs 结合实时活跃邻居 + run/v6/<mac> 时间戳降序补齐并封顶 16 条
	origDumpV6 := nativeDumpIPv6NeighFn
	t.Cleanup(func() { nativeDumpIPv6NeighFn = origDumpV6 })
	nativeDumpIPv6NeighFn = func(_ map[int]bool) (map[string][]net.IP, error) {
		return map[string][]net.IP{mac: {net.ParseIP("2409:8900:dd00::1")}}, nil
	}
	snapDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(snapDir, "run", "v6"), 0o755)
	var snapBuf strings.Builder
	snapBuf.WriteString("#hnc_v6 iface=wlan2\n")
	for i := 1; i <= 20; i++ {
		fmt.Fprintf(&snapBuf, "2409:8900:cc00::%x %d\n", i, 1000+i)
	}
	_ = os.WriteFile(filepath.Join(snapDir, "run", "v6", mac), []byte(snapBuf.String()), 0o644)
	collected := collectDeviceIPv6Addrs(snapDir, "", mac)
	if len(collected) != v6IPv6MaxAddrs || collected[0] != "2409:8900:dd00::1" || collected[1] != "2409:8900:cc00::14" {
		t.Fatalf("collectDeviceIPv6Addrs ranking/cap mismatch: len=%d got=%v", len(collected), collected)
	}

	// 2. run/v6_sync.lock 跨进程死锁回收与加解锁契约
	dir := t.TempDir()
	staleLock := filepath.Join(dir, "run", "v6_sync.lock")
	_ = os.MkdirAll(staleLock, 0o755)
	// 写入不存在的死进程 PID 99999999 -> 必须被自动回收
	_ = os.WriteFile(filepath.Join(staleLock, "pid"), []byte("99999999\n"), 0o644)
	oldTime := time.Now().Add(-10 * time.Second)
	_ = os.Chtimes(staleLock, oldTime, oldTime)

	unlock, lErr := acquireV6SyncLock(dir)
	if lErr != nil {
		t.Fatalf("acquireV6SyncLock failed to reclaim dead-PID lock: %v", lErr)
	}
	if _, sErr := os.Stat(filepath.Join(staleLock, "pid")); sErr != nil {
		t.Fatalf("expected active v6_sync.lock/pid while locked: %v", sErr)
	}
	unlock()
	if _, sErr := os.Stat(staleLock); !os.IsNotExist(sErr) {
		t.Fatalf("expected v6_sync.lock removed on unlock")
	}

	// 3. dpInspectOffloadGuard 优先读取 mtk["action"] 再回退 mtk["state"]
	env := &dpVerifyEnv{
		HNCDir:   dir,
		ReadFile: os.ReadFile,
	}
	_ = os.WriteFile(filepath.Join(dir, "run", "mtk_hwnat.json"), []byte(`{"action":"disabled_by_guard","state":"legacy_state"}`), 0o644)
	og1, _ := dpInspectOffloadGuard(env)
	if og1.HWNAT != "disabled_by_guard" {
		t.Fatalf("expected mtk[\"action\"] prioritized, got %q", og1.HWNAT)
	}
	_ = os.WriteFile(filepath.Join(dir, "run", "mtk_hwnat.json"), []byte(`{"state":"legacy_state"}`), 0o644)
	og2, _ := dpInspectOffloadGuard(env)
	if og2.HWNAT != "legacy_state" {
		t.Fatalf("expected fallback to mtk[\"state\"], got %q", og2.HWNAT)
	}

	// 4. 32 位 ARM 64 位原子字段首部 8 字节对齐复核 (纯 reflect 检查, 零 unsafe 导入)
	fieldChecks := []struct {
		typ   reflect.Type
		field string
	}{
		{reflect.TypeOf(dataplaneCounters{}), "nlEnsureCalls"},
		{reflect.TypeOf(dataplaneCounters{}), "seqGen"},
		{reflect.TypeOf(DataplaneActor{}), "savedForks"},
		{reflect.TypeOf(DataplaneActor{}), "closedFlag"},
		{reflect.TypeOf(v6SubtreeController{}), "appLimitApplies"},
		{reflect.TypeOf(v6SubtreeController{}), "v6NeighSyncs"},
		{reflect.TypeOf(v6MultiIfaceEngine{}), "probeRuns"},
		{reflect.TypeOf(v6MultiIfaceEngine{}), "tun0GuardChecks"},
		{reflect.TypeOf(flowScalpelEngine{}), "seqGen"},
		{reflect.TypeOf(flowScalpelEngine{}), "cutTotal"},
		{reflect.TypeOf(dpVerifySnapshotStore{}), "runsCount"},
	}
	for _, it := range fieldChecks {
		sf, ok := it.typ.FieldByName(it.field)
		if !ok {
			t.Fatalf("missing atomic field %s.%s", it.typ.Name(), it.field)
		}
		if sf.Offset%8 != 0 {
			t.Fatalf("64-bit atomic field %s.%s offset=%d violates 8-byte alignment for 32-bit ARM", it.typ.Name(), it.field, sf.Offset)
		}
	}
}
