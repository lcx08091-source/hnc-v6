package io.hnc.probe.core;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * 纯 Java 小测试(不依赖 JUnit): java io.hnc.probe.core.CoreTest &lt;act_probe 目录&gt;
 * 覆盖: JSON、剧本解析、规则匹配 / 标注、HNC /api/devices 解析、混淆计数、root dumpsys 解析、会话存取。
 */
public final class CoreTest {
    private static int pass = 0, fail = 0;
    private static String base;

    public static void main(String[] args) throws Exception {
        base = args.length > 0 ? args[0] : ".";
        run("json", CoreTest::testJson);
        run("script_default", CoreTest::testScriptDefault);
        run("script_invalid", CoreTest::testScriptInvalid);
        run("rules_default", CoreTest::testRulesDefault);
        run("rules_custom", CoreTest::testRulesCustom);
        run("rules_invalid", CoreTest::testRulesInvalid);
        run("labeler", CoreTest::testLabeler);
        run("hnc_parse", CoreTest::testHncParse);
        run("hnc_auth", CoreTest::testHncAuth);
        run("attach_truth", CoreTest::testAttachTruth);
        run("summary_confusion", CoreTest::testSummary);
        run("root_parsers", CoreTest::testRootParsers);
        run("session_roundtrip", CoreTest::testSession);
        run("recent_activities", CoreTest::testRecent);
        System.out.println();
        System.out.println("通过 " + pass + " 项, 失败 " + fail + " 项");
        if (fail > 0) System.exit(1);
    }

    interface T { void run() throws Exception; }

    private static void run(String name, T t) {
        int before = fail;
        try {
            t.run();
        } catch (Throwable e) {
            fail++;
            System.out.println("  [异常] " + name + ": " + e);
            e.printStackTrace(System.out);
        }
        System.out.println((fail == before ? "ok   " : "FAIL ") + name);
    }

    private static void check(boolean cond, String what) {
        if (cond) pass++;
        else { fail++; System.out.println("  [失败] " + what); }
    }

    private static void eq(Object want, Object got, String what) {
        boolean ok = want == null ? got == null : want.equals(got);
        check(ok, what + ": 期望 " + want + ", 实际 " + got);
    }

    private static void throwsIAE(String what, String mustContain, T t) {
        try {
            t.run();
            check(false, what + ": 应该抛异常");
        } catch (IllegalArgumentException e) {
            check(e.getMessage() != null && e.getMessage().contains(mustContain),
                    what + ": 异常信息应含「" + mustContain + "」, 实际: " + e.getMessage());
        } catch (Exception e) {
            check(false, what + ": 异常类型不对 " + e);
        }
    }

    private static String read(String rel) throws IOException {
        return Session.readText(new File(base, rel));
    }

    // ─── JSON ────────────────────────────────────────────────────────────

    private static void testJson() {
        Map<String, Object> m = Json.parseObject("﻿{\"a\":1,\"b\":-2.5,\"c\":\"x\\\"y\\u4e2d\\n\",\"d\":[true,false,null],\"e\":{}}");
        eq(1L, m.get("a"), "整数解析为 Long");
        eq(-2.5, m.get("b"), "小数解析为 Double");
        eq("x\"y中\n", m.get("c"), "字符串转义");
        eq(Arrays.asList(true, false, null), m.get("d"), "数组");
        String s = Json.stringify(m);
        eq(m, Json.parseObject(s), "序列化后再解析一致");
        eq("{\"k\":1.0E-4,\"n\":3,\"z\":null}", Json.stringify(map("k", 0.0001, "n", 3.0, "z", Double.NaN)), "数字格式");
        check(Json.pretty(m).contains("\n  \"a\": 1"), "pretty 缩进");
        throwsIAE("缺逗号", "缺少", () -> Json.parse("{\"a\":1 \"b\":2}"));
        throwsIAE("末尾多余", "多余", () -> Json.parse("{} x"));
        throwsIAE("根不是对象", "根必须是对象", () -> Json.parseObject("[1]"));
        throwsIAE("未结束字符串", "没有结束", () -> Json.parse("\"abc"));
    }

    // ─── 剧本 ────────────────────────────────────────────────────────────

    private static void testScriptDefault() throws IOException {
        Script s = Script.parse(read("assets/default_script.json"));
        eq(18, s.steps.size(), "默认剧本 18 步(16 个活动 + 2 个对照)");
        eq(20, s.warmupSec, "warmup_sec");
        eq("voice_call", s.steps.get(0).expect, "第 1 步 expect");
        eq("com.tencent.mm", s.steps.get(0).app, "第 1 步 app");
        eq(120000L, s.steps.get(0).durationMs(), "2 分钟 = 120000 ms");
        Step idle = s.steps.get(16);
        eq("idle", idle.expect, "熄屏对照步 expect=idle");
        check(idle.anyApp(), "熄屏对照步不限应用");
        check(s.steps.get(17).anyApp() && "download".equals(s.steps.get(17).expect), "后台下载对照步");
        List<String> want = Arrays.asList("voice_call", "video_call", "browsing", "video_stream", "upload",
                "gaming", "voice_call", "download", "voice_call", "video_call",
                "video_stream", "live_stream", "upload", "video_stream", "live_stream", "upload", "idle", "download");
        List<String> got = new ArrayList<>();
        for (Step st : s.steps) got.add(st.expect);
        eq(want, got, "各步 expect");
        check(s.totalMinutes() > 30 && s.totalMinutes() < 60, "总时长合理: " + s.totalMinutes());
        // toMap → 再解析一致
        Script s2 = Script.parse(Json.stringify(s.toMap()));
        eq(s.steps.size(), s2.steps.size(), "toMap 往返");
    }

    private static void testScriptInvalid() {
        throwsIAE("空 steps", "非空数组", () -> Script.parse("{\"steps\":[]}"));
        throwsIAE("未知 expect", "不是已知活动 id", () -> Script.parse(
                "{\"steps\":[{\"app\":\"com.a.b\",\"expect\":\"dancing\",\"label\":\"x\",\"minutes\":1}]}"));
        throwsIAE("缺 label", "缺少 label", () -> Script.parse(
                "{\"steps\":[{\"app\":\"com.a.b\",\"expect\":\"gaming\",\"minutes\":1}]}"));
        throwsIAE("minutes=0", "minutes", () -> Script.parse(
                "{\"steps\":[{\"app\":\"com.a.b\",\"expect\":\"gaming\",\"label\":\"x\",\"minutes\":0}]}"));
        throwsIAE("app 不像包名", "不像包名", () -> Script.parse(
                "{\"steps\":[{\"app\":\"抖音\",\"expect\":\"gaming\",\"label\":\"x\",\"minutes\":1}]}"));
        throwsIAE("schema 错", "schema", () -> Script.parse(
                "{\"schema\":\"other/1\",\"steps\":[{\"expect\":\"idle\",\"label\":\"x\",\"minutes\":1}]}"));
        throwsIAE("多处错误一起报", "第 2 步", () -> Script.parse(
                "{\"steps\":[{\"expect\":\"idle\",\"label\":\"x\",\"minutes\":1},{\"expect\":\"nope\",\"label\":\"y\",\"minutes\":1}]}"));
        Script ok = Script.parse("{\"steps\":[{\"expect\":\"idle\",\"label\":\"熄屏\",\"minutes\":0.5}]}");
        eq(30000L, ok.steps.get(0).durationMs(), "0.5 分钟");
        eq("未命名剧本", ok.name, "缺 name 时的默认名");
    }

    // ─── 规则 ────────────────────────────────────────────────────────────

    private static Signals sig(String pkg, String cls, Boolean inCall, Boolean cam, Boolean mic, Boolean screen) {
        Signals s = new Signals();
        s.t = 1000;
        s.pkg = pkg;
        s.cls = cls;
        s.inCall = inCall;
        s.camera = cam;
        s.mic = mic;
        s.screenOn = screen;
        return s;
    }

    private static Step step(String app, String expect) {
        return new Step(0, app, null, expect, "测试步", 1, "", null);
    }

    private static void testRulesDefault() throws IOException {
        Rules r = Rules.parse(read("assets/default_rules.json"));
        eq(5, r.packages.size(), "默认规则 5 个包");
        eq("douyin", r.hncAppFor("com.ss.android.ugc.aweme"), "抖音 → HNC app_id");
        eq("tencent_wzry_exclusive", r.hncAppFor("com.tencent.tmgp.sgame"), "王者 → HNC app_id");
        check(!r.packages.get("com.tencent.wemeet.app").verified, "腾讯会议包名标为待核实");
        eq(3, r.activeCount(), "生效规则 3 条(其余是待核实占位)");
        int ph = 0;
        for (Rules.Rule x : r.rules) if (x.placeholder) ph++;
        eq(7, ph, "待核实占位 7 条");

        Step wx = step("com.tencent.mm", "voice_call");
        eq("video_call_by_camera", id(r.firstMatch(sig("com.tencent.mm", null, true, true, true, true), wx)), "通话+相机 → 视频通话");
        eq("voice_call_no_camera", id(r.firstMatch(sig("com.tencent.mm", null, true, false, true, true), wx)), "通话+无相机 → 语音通话");
        eq(null, id(r.firstMatch(sig("com.tencent.tmgp.sgame", null, true, false, true, true), wx)), "游戏里通话不套语音规则");
        eq("video_call_by_camera", id(r.firstMatch(sig("com.tencent.tmgp.sgame", null, true, true, true, true), wx)), "游戏里通话+相机仍是视频通话");
        eq("screen_off_idle", id(r.firstMatch(sig("com.tencent.mm", null, false, false, false, false), wx)), "熄屏不通话 → idle");
        eq("voice_call_no_camera", id(r.firstMatch(sig("com.tencent.mm", null, true, false, true, false), wx)), "熄屏贴耳通话仍是语音通话");
        eq(null, id(r.firstMatch(sig("com.tencent.mm", null, null, null, null, true), wx)), "信号拿不到 = 不命中");
        eq(null, id(r.firstMatch(sig("com.ss.android.ugc.aweme", "com.ss.android.ugc.aweme.live.LivePlayActivity", false, false, false, true),
                step("com.ss.android.ugc.aweme", "live_stream"))), "待核实占位规则不生效");
    }

    private static String id(Rules.Rule r) { return r == null ? null : r.id; }

    private static void testRulesCustom() {
        String js = "{\"schema\":\"hnc-probe-rules/1\",\"rules\":["
                + "{\"id\":\"live\",\"when\":{\"pkg\":[\"com.a.app\",\"com.b.app\"],\"activity\":\"\\\\.Live(Room)?Activity$\"},\"then\":\"live_stream\"},"
                + "{\"id\":\"up_only_when_expected\",\"when\":{\"pkg\":\"com.a.app\",\"mic\":false,\"expect\":[\"upload\"]},\"then\":\"upload\"},"
                + "{\"id\":\"off\",\"enabled\":false,\"when\":{\"pkg\":\"com.a.app\"},\"then\":\"browsing\"}]}";
        Rules r = Rules.parse(js);
        Step s = step("com.a.app", "video_stream");
        eq("live", id(r.firstMatch(sig("com.b.app", "com.b.app.ui.LiveRoomActivity", false, false, false, true), s)), "pkg 数组 + 类名正则");
        eq(null, id(r.firstMatch(sig("com.b.app", "com.b.app.ui.LiveRoomActivityX", false, false, false, true), s)), "正则 $ 锚定");
        eq(null, id(r.firstMatch(sig("com.a.app", null, false, false, false, true), s)), "类名拿不到时 activity 条件不命中");
        eq(null, id(r.firstMatch(sig("com.a.app", "x.Main", false, false, false, true), s)), "expect 条件不满足");
        eq("up_only_when_expected", id(r.firstMatch(sig("com.a.app", "x.Main", false, false, false, true), step("com.a.app", "upload"))), "expect 条件满足");
        check(!r.rules.get(2).active(), "enabled=false 不生效");
    }

    private static void testRulesInvalid() {
        throwsIAE("then 非法", "不是已知活动 id", () -> Rules.parse("{\"rules\":[{\"id\":\"a\",\"when\":{\"pkg\":\"x.y\"},\"then\":\"zzz\"}]}"));
        throwsIAE("未知条件", "不认识的条件", () -> Rules.parse("{\"rules\":[{\"id\":\"a\",\"when\":{\"package\":\"x.y\"},\"then\":\"idle\"}]}"));
        throwsIAE("坏正则", "正则写错了", () -> Rules.parse("{\"rules\":[{\"id\":\"a\",\"when\":{\"activity\":\"(\"},\"then\":\"idle\"}]}"));
        throwsIAE("id 重复", "id 重复", () -> Rules.parse("{\"rules\":[{\"id\":\"a\",\"when\":{\"camera\":true},\"then\":\"idle\"},{\"id\":\"a\",\"when\":{\"camera\":true},\"then\":\"idle\"}]}"));
        throwsIAE("布尔条件写成字符串", "true / false", () -> Rules.parse("{\"rules\":[{\"id\":\"a\",\"when\":{\"in_call\":\"yes\"},\"then\":\"idle\"}]}"));
        throwsIAE("缺 when", "when", () -> Rules.parse("{\"rules\":[{\"id\":\"a\",\"then\":\"idle\"}]}"));
    }

    // ─── 标注 ────────────────────────────────────────────────────────────

    private static void testLabeler() throws IOException {
        Rules r = Rules.parse(read("assets/default_rules.json"));
        String self = "io.hnc.probe";
        // 规则命中且一致
        Labeler.Result a = Labeler.label(sig("com.tencent.mm", null, true, true, true, true), step("com.tencent.mm", "video_call"), r, self);
        eq("video_call", a.truth, "规则命中 → 规则真值");
        eq("rule", a.src, "来源 rule");
        check(a.flags.isEmpty(), "一致时没有 flag: " + a.flags);
        // 剧本说视频通话, 实际没开相机 → 规则判语音, 标不一致 + 相机缺失
        Labeler.Result b = Labeler.label(sig("com.tencent.mm", null, true, false, true, true), step("com.tencent.mm", "video_call"), r, self);
        eq("voice_call", b.truth, "规则改写真值");
        check(b.flags.contains(Labeler.F_RULE_DISAGREE), "rule_disagree");
        check(b.flags.contains(Labeler.F_CAMERA_MISSING), "camera_missing");
        // 规则不命中 → 剧本
        Labeler.Result c = Labeler.label(sig("com.ss.android.ugc.aweme", null, false, false, false, true), step("com.ss.android.ugc.aweme", "live_stream"), r, self);
        eq("live_stream", c.truth, "规则不命中 → expect");
        eq("script", c.src, "来源 script");
        check(c.flags.isEmpty(), "正常时无 flag");
        // 前台不是指定应用 / 是采集 App
        check(Labeler.label(sig("com.tencent.mm", null, false, false, false, true), step("tv.danmaku.bili", "video_stream"), r, self)
                .flags.contains(Labeler.F_PKG_MISMATCH), "pkg_mismatch");
        check(Labeler.label(sig(self, null, false, false, false, true), step("tv.danmaku.bili", "video_stream"), r, self)
                .flags.contains(Labeler.F_PROBE_FG), "probe_in_fg");
        // 剧本说通话, 没通话也没录音
        check(Labeler.label(sig("com.tencent.mm", null, false, false, false, true), step("com.tencent.mm", "voice_call"), r, self)
                .flags.contains(Labeler.F_CALL_MISSING), "call_missing");
        // 熄屏
        Labeler.Result e = Labeler.label(sig("tv.danmaku.bili", null, false, false, false, false), step("tv.danmaku.bili", "video_stream"), r, self);
        eq("idle", e.truth, "熄屏规则 → idle");
        check(e.flags.contains(Labeler.F_SCREEN_OFF) && e.flags.contains(Labeler.F_RULE_DISAGREE), "screen_off + rule_disagree");
        // idle 步亮屏
        Labeler.Result f = Labeler.label(sig("com.android.launcher", null, false, false, false, true), step("", "idle"), r, self);
        eq("idle", f.truth, "idle 步不命中规则 → idle");
        check(f.flags.contains(Labeler.F_SCREEN_ON_IDLE), "screen_on_in_idle");
        // idle 步熄屏: 规则 idle 与 expect 一致
        check(Labeler.label(sig(null, null, false, false, false, false), step("", "idle"), r, self).flags.isEmpty(), "idle 步熄屏无 flag");
    }

    // ─── HNC 解析 ────────────────────────────────────────────────────────

    private static void testHncParse() throws IOException {
        String body = read("test/fixtures/devices.json");
        HncObs o = HncParser.parse(body, "192.168.43.7", null);
        check(o.ok, "按 IP 找到本机: " + o.err);
        eq("aa:bb:cc:00:00:02", o.mac, "同 IP 多条时取 online 的");
        eq("douyin", o.fgApp, "fg.app_id");
        eq("抖音", o.fgName, "fg.name");
        eq(82.0, o.fgConf, "fg.confidence");
        eq("active", o.fgState, "fg.state");
        eq(1760000200L, o.fgUpdated, "fg.updated");
        eq("live_stream", o.actId, "fg.activity.id");
        eq("看直播", o.actLabel, "fg.activity.label");
        eq(0.72, o.actConf, "fg.activity.conf");
        eq("domain", o.actSrc, "fg.activity.src");
        eq("live_stream", o.ttType, "traffic_type.type");
        eq(0.81, o.ttConf, "traffic_type.confidence");

        HncObs w = HncParser.parse(body, "192.168.43.9", null);
        check(w.ok && w.actId == null, "没有 activity 字段");
        eq("none", w.actKey(), "没输出 → none 列");
        eq("wechat", w.fgApp, "微信设备 app_id");

        HncObs miss = HncParser.parse(body, "192.168.43.200", null);
        check(!miss.ok && miss.err.contains("没找到本机"), "列表里没有本机: " + miss.err);
        HncObs byMac = HncParser.parse(body, "10.0.0.1", "AA:BB:CC:00:00:03");
        check(byMac.ok && "wechat".equals(byMac.fgApp), "IP 不匹配时按 MAC(忽略大小写)兜底");
        check(!HncParser.parse("<html>401</html>", "1.2.3.4", null).ok, "非 JSON");
        check(HncParser.parse("{\"error\":\"auth required\"}", "1.2.3.4", null).err.contains("devices"), "没有 devices 数组");
        HncObs stale = HncParser.parse("{\"devices\":[{\"ip\":\"1.1.1.1\",\"fg\":{\"app_id\":\"\",\"state\":\"stale\"}}]}", "1.1.1.1", null);
        check(stale.ok && stale.fgApp == null, "空 app_id 视为没有");
    }

    private static void testHncAuth() {
        HncAuth.Addr a = HncAuth.parseAddr(" https://192.168.43.1:8443/ ");
        eq("192.168.43.1", a.host, "去掉 https:// 和尾部 /");
        eq(8443, a.port, "端口");
        eq(8443, HncAuth.parseAddr("10.41.82.1").port, "默认端口 8443");
        eq(9443, HncAuth.parseAddr("172.20.10.1:9443").port, "自定义端口");
        throwsIAE("http 拒绝", "HTTPS", () -> HncAuth.parseAddr("http://192.168.43.1:8080"));
        throwsIAE("公网拒绝", "私网", () -> HncAuth.parseAddr("8.8.8.8"));
        throwsIAE("172.32 不是私网", "私网", () -> HncAuth.parseAddr("172.32.0.1"));
        throwsIAE("域名拒绝", "私网", () -> HncAuth.parseAddr("hnc.example.com"));
        throwsIAE("带路径拒绝", "路径", () -> HncAuth.parseAddr("192.168.43.1:8443/api/devices"));
        throwsIAE("坏端口", "端口", () -> HncAuth.parseAddr("192.168.43.1:99999"));
        throwsIAE("空地址", "请填", () -> HncAuth.parseAddr("  "));

        String tok = "AbCdEfGhIjK.0123456789abcdefghijABCDEFGHIJ_-";
        check(HncAuth.validToken(tok), "合法令牌");
        check(!HncAuth.validToken("abc"), "太短");
        check(!HncAuth.validToken("AbCdEfGhIjK.012345;rm"), "含非法字符");
        eq(tok, HncAuth.tokenFromSetCookie(Arrays.asList(
                "other=1; Path=/",
                "hnc_token=" + tok + "; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Strict")), "从 Set-Cookie 取令牌");
        eq(null, HncAuth.tokenFromSetCookie(Arrays.asList("hnc_token=; Path=/; Max-Age=0")), "清除 cookie 的空值忽略");
        eq(null, HncAuth.tokenFromSetCookie(null), "没有 Set-Cookie");
        check(HncAuth.validPin("012345") && !HncAuth.validPin("12345") && !HncAuth.validPin("12345a"), "配对码 6 位数字");

        check(HncAuth.describe(401, "{\"error\":\"auth required\"}").contains("重新配对"), "401 说明");
        check(HncAuth.describe(403, null).contains("白名单"), "403 说明");
        String wrong = HncAuth.describe(400, "{\"error\":\"wrong pin\",\"attempts_remaining\":3}");
        check(wrong.contains("wrong pin") && wrong.contains("还能试 3 次"), "错码剩余次数: " + wrong);
        check(HncAuth.describe(429, "{\"error\":\"too many pin attempts\",\"locked_for_sec\":600}").contains("锁定 600 秒"), "锁定秒数");
        eq("0A:FF", HncAuth.fingerprintHex(new byte[]{0x0a, (byte) 0xff}), "指纹格式");
    }

    private static void testAttachTruth() {
        Step st = step("com.a.b", "video_stream");
        Sample s = new Sample();
        s.t = 10_000; s.step = 3; s.phase = Sample.RUN; s.truth = "idle"; s.truthSrc = "rule";
        HncObs o = new HncObs();
        o.t = 13_000; o.step = 3; o.phase = Sample.RUN;
        o.attachTruth(s, st, 5000);
        eq("idle", o.truth, "取最近样本的真值");
        HncObs o2 = new HncObs();
        o2.t = 30_000; o2.step = 3; o2.phase = Sample.RUN;
        o2.attachTruth(s, st, 5000);
        eq("video_stream", o2.truth, "样本太旧 → 剧本 expect");
        eq("script", o2.truthSrc, "来源 script");
        HncObs o3 = new HncObs();
        o3.t = 11_000; o3.step = 3; o3.phase = Sample.GAP;
        o3.attachTruth(s, st, 5000);
        eq(null, o3.truth, "步间不配真值");
    }

    // ─── 汇总 / 混淆 ────────────────────────────────────────────────────

    private static HncObs obs(int step, String phase, boolean ok, String truth, String act, String app) {
        HncObs o = new HncObs();
        o.step = step; o.phase = phase; o.ok = ok; o.truth = truth; o.actId = act; o.fgApp = app;
        if (!ok) o.err = "连不上";
        return o;
    }

    private static Sample smp(int step, String phase, String truth, String pkg, String... flags) {
        Sample s = new Sample();
        s.step = step; s.phase = phase; s.truth = truth; s.sig.pkg = pkg;
        s.flags.addAll(Arrays.asList(flags));
        return s;
    }

    @SuppressWarnings("unchecked")
    private static void testSummary() throws IOException {
        Script sc = Script.parse("{\"steps\":["
                + "{\"app\":\"com.tencent.mm\",\"expect\":\"voice_call\",\"label\":\"微信语音\",\"minutes\":1},"
                + "{\"app\":\"\",\"expect\":\"idle\",\"label\":\"熄屏\",\"minutes\":1}]}");
        Rules ru = Rules.parse(read("assets/default_rules.json"));
        List<Sample> ss = new ArrayList<>();
        ss.add(smp(0, Sample.WARMUP, "voice_call", "com.tencent.mm"));
        ss.add(smp(0, Sample.RUN, "voice_call", "com.tencent.mm"));
        ss.add(smp(0, Sample.RUN, "voice_call", "com.tencent.mm"));
        ss.add(smp(0, Sample.RUN, "video_call", "com.tencent.mm", Labeler.F_RULE_DISAGREE));
        ss.add(smp(0, Sample.GAP, null, "io.hnc.probe"));
        ss.add(smp(1, Sample.RUN, "idle", null));
        List<HncObs> os = new ArrayList<>();
        os.add(obs(0, Sample.WARMUP, true, "voice_call", null, "wechat"));      // 预热, 不计
        os.add(obs(0, Sample.RUN, true, "voice_call", "voice_call", "wechat"));
        os.add(obs(0, Sample.RUN, true, "voice_call", "voice_call", "wechat"));
        os.add(obs(0, Sample.RUN, true, "voice_call", "browsing", "wechat"));
        os.add(obs(0, Sample.RUN, true, "video_call", "voice_call", "wechat"));
        os.add(obs(0, Sample.RUN, false, "voice_call", null, null));             // 失败, 不计
        os.add(obs(1, Sample.RUN, true, "idle", null, null));
        os.add(obs(1, Sample.RUN, true, "idle", "background", null));
        os.add(obs(1, Sample.RUN, true, "idle", "video_stream", "douyin"));
        os.add(obs(1, Sample.GAP, true, null, "video_stream", "douyin"));        // 步间, 不计

        Map<String, Object> sum = Summary.compute(sc, ss, os, ru);
        List<Object> steps = Json.asArr(sum.get("steps"));
        Map<String, Object> s0 = Json.asObj(steps.get(0));
        eq(4L, s0.get("samples"), "第 1 步样本(不含 gap)");
        eq(3L, s0.get("samples_counted"), "第 1 步计入样本(不含预热)");
        eq("voice_call", s0.get("truth_top"), "第 1 步主要真值");
        eq(1L, s0.get("flagged_samples"), "第 1 步被标记样本");
        eq(5L, s0.get("hnc_obs"), "第 1 步 HNC 观测(run)");
        eq(4L, s0.get("hnc_ok"), "第 1 步 HNC 成功观测");
        eq(2L, s0.get("hit"), "第 1 步命中");
        eq(0.5, s0.get("hit_ratio"), "第 1 步命中率");
        eq("voice_call", s0.get("hnc_activity_top"), "第 1 步 HNC 主要输出");
        eq("wechat", s0.get("want_hnc_app"), "第 1 步期望 HNC 应用");
        eq(1.0, s0.get("app_hit_ratio"), "第 1 步应用命中率");
        Map<String, Object> s1 = Json.asObj(steps.get(1));
        eq(2L, s1.get("hit"), "idle 步: 没输出 / background 都算命中");
        eq(0.667, s1.get("hit_ratio"), "idle 步命中率");

        Map<String, Object> cm = Json.asObj(sum.get("confusion"));
        eq(Arrays.asList("voice_call", "video_call", "idle"), cm.get("rows"), "混淆行(按词表顺序)");
        eq(Arrays.asList("video_stream", "voice_call", "browsing", "background", "none"), cm.get("cols"), "混淆列(含 none)");
        Map<String, Object> counts = Json.asObj(cm.get("counts"));
        eq(2L, Json.asObj(counts.get("voice_call")).get("voice_call"), "voice_call→voice_call");
        eq(1L, Json.asObj(counts.get("voice_call")).get("browsing"), "voice_call→browsing");
        eq(0L, Json.asObj(counts.get("voice_call")).get("none"), "voice_call→none");
        eq(1L, Json.asObj(counts.get("video_call")).get("voice_call"), "video_call→voice_call");
        eq(1L, Json.asObj(counts.get("idle")).get("none"), "idle→none");
        eq(1L, Json.asObj(counts.get("idle")).get("video_stream"), "idle→video_stream");
        Map<String, Object> ov = Json.asObj(sum.get("overall"));
        eq(7L, ov.get("hnc_ok"), "总成功观测");
        eq(4L, ov.get("hit"), "总命中");
        eq(1L, ov.get("hnc_errors"), "总失败观测");
        String txt = Summary.confusionText(sum);
        check(txt.startsWith("truth\\hnc") && txt.contains("voice_call") && txt.contains("none"), "等宽文本矩阵:\n" + txt);
        // 序列化后再算文本一致(界面读 summary.json 用)
        eq(txt, Summary.confusionText(Json.parseObject(Json.stringify(sum))), "summary JSON 往返后矩阵文本一致");
        // 没有观测
        Map<String, Object> empty = Summary.compute(sc, ss, new ArrayList<HncObs>(), ru);
        check(Summary.confusionText(empty).contains("没有可统计"), "无观测时的提示");
        eq(null, Json.asObj(Json.asArr(empty.get("steps")).get(0)).get("hit_ratio"), "无观测时命中率为 null");
    }

    // ─── root dumpsys 解析 ──────────────────────────────────────────────

    private static void testRootParsers() {
        String act = "    mResumedActivity: ActivityRecord{8f1e2d u0 com.tencent.mm/.ui.LauncherUI t812}\n"
                + "  topResumedActivity=ActivityRecord{1a2b3c4 u0 com.tencent.mm/com.tencent.mm.plugin.voip.ui.VideoActivity t812}\n";
        String[] r = RootParsers.resumedActivity(act);
        eq("com.tencent.mm", r[0], "前台包名");
        eq("com.tencent.mm.plugin.voip.ui.VideoActivity", r[1], "以 topResumedActivity 为准");
        String[] r2 = RootParsers.resumedActivity("  ResumedActivity: ActivityRecord{abc u0 tv.danmaku.bili/.MainActivityV2 t5}\n");
        eq("tv.danmaku.bili.MainActivityV2", r2[1], "短类名展开");
        eq(null, RootParsers.resumedActivity("nothing here"), "解析不出 → null");

        eq(null, RootParsers.camera("Number of camera devices: 2\n"), "没有段 → null");
        RootParsers.Cam c0 = RootParsers.camera("Active Camera Clients:\n[]\n");
        check(c0 != null && !c0.inUse, "相机空闲");
        RootParsers.Cam c1 = RootParsers.camera("Active Camera Clients:\n[\n(Camera ID: 1, Cost: 100, PID: 9871, Score: 0, State: 0User Id: 0, Client Package Name: com.tencent.wemeet.app, Conflicting Client Devices: {})\n]\n");
        check(c1 != null && c1.inUse, "相机占用");
        eq("com.tencent.wemeet.app", c1.pkg, "占用相机的包");

        eq("MODE_IN_COMMUNICATION", RootParsers.audioMode("Audio mode: \n- Requested mode = MODE_NORMAL\n- Actual mode = MODE_IN_COMMUNICATION\n"), "Actual mode 优先");
        eq("MODE_NORMAL", RootParsers.audioMode("  mMode=MODE_NORMAL\n"), "mMode 兜底");
        eq(null, RootParsers.audioMode("ringer mode RINGER_MODE_NORMAL\n"), "RINGER_MODE_ 不误判");

        String aud = "RecordActivityMonitor dump time: 10:00:00\n"
                + "  riid 15; active true\n"
                + "  session:89 -- source client=VOICE_COMMUNICATION -- uid:10234 -- patch:31 -- pack:com.tencent.mm -- format client=x -- silenced:false\n"
                + "  riid 16; active false\n"
                + "  session:90 -- source client=MIC -- uid:10111 -- patch:0 -- pack:com.other.app -- silenced:false\n"
                + "  riid 17; active true\n"
                + "  session:91 -- source client=MIC -- uid:10112 -- patch:0 -- pack:com.silent.app -- silenced:true\n";
        eq(Arrays.asList("com.tencent.mm"), RootParsers.recordingPackages(aud), "只算 active 且没被静音的录音");
        eq(null, RootParsers.recordingPackages("no monitor\n"), "没有段 → null");
        check(RootParsers.recordingPackages("RecordActivityMonitor dump time: x\n").isEmpty(), "段在但没人录音");

        Map<String, String> sp = RootParsers.split("##ACT\nline a\n##CAM\nActive Camera Clients:\n[]\n##AUD\n- Actual mode = MODE_NORMAL\n");
        eq(3, sp.size(), "分段数");
        check(sp.get("ACT").contains("line a") && sp.get("CAM").contains("[]") && sp.get("AUD").contains("MODE_NORMAL"), "分段内容");
        check(!RootParsers.SAMPLE_CMD.matches(".*\\b(rm|mv|setprop|settings put|am |pm |chmod|echo [^']*>).*"), "root 命令只读(不含写操作)");
        eq("pkg.ui.Foo", RootParsers.fullClass("pkg", ".ui.Foo"), "fullClass");
    }

    // ─── 会话存取 ────────────────────────────────────────────────────────

    private static void testSession() throws IOException {
        File root = new File(System.getProperty("java.io.tmpdir"), "hnc-probe-test-" + System.nanoTime());
        String scriptJson = read("assets/default_script.json");
        String rulesJson = read("assets/default_rules.json");
        Map<String, Object> settings = map("interval_sec", 3, "root", false, "hnc_enabled", true);
        Session s = Session.create(root, "20261019-120000", scriptJson, rulesJson, settings,
                map("package", "io.hnc.probe", "version_name", "0.1.0"), map("sdk_int", 34), 1000L);
        Sample a = smp(0, Sample.RUN, "voice_call", "com.tencent.mm");
        a.t = 2000;
        a.sig.inCall = true;
        s.add(a);
        s.add(smp(0, Sample.RUN, "video_call", "com.tencent.mm", Labeler.F_RULE_DISAGREE));
        HncObs o = obs(0, Sample.RUN, true, "voice_call", "voice_call", "wechat");
        o.t = 2500;
        s.add(o);
        eq("running", s.endState(), "没结束 = running");
        // 模拟进程被杀时写了半行
        try (FileOutputStream f = new FileOutputStream(new File(s.dir, "samples.jsonl"), true)) {
            f.write("{\"t\":99,\"st".getBytes(StandardCharsets.UTF_8));
        }
        Session l1 = Session.load(s.dir);
        eq(2, l1.samples.size(), "半行被跳过");
        eq(1, l1.obs.size(), "观测条数");
        eq(Boolean.TRUE, l1.samples.get(0).sig.inCall, "样本字段往返");
        eq(1L, Json.asObj(Json.asObj(l1.summary()).get("overall")).get("hit"), "未结束会话现算汇总");

        s.finish("aborted", 5000L);
        Session l2 = Session.load(s.dir);
        eq("aborted", l2.endState(), "结束状态");
        Map<String, Object> doc = l2.exportDoc(6000L);
        eq(Session.EXPORT_SCHEMA, doc.get("schema"), "导出 schema");
        for (String k : new String[]{"app", "system", "session", "script", "rules", "samples", "hnc", "summary", "notes"}) {
            check(doc.containsKey(k), "导出含 " + k);
        }
        eq(2, Json.asArr(doc.get("samples")).size(), "导出样本数");
        String flat = Json.stringify(doc);
        check(!flat.contains("hnc_token") && !flat.contains("\"token\""), "导出不含访问令牌");
        check(Json.str(Json.asObj(doc.get("script")), "_doc") != null, "导出保留剧本原文(含 _doc)");
        Script back = Script.parse(Json.stringify(doc.get("script")));
        eq(18, back.steps.size(), "导出的剧本可再导入");
        // 清理
        for (File f : s.dir.listFiles()) f.delete();
        s.dir.delete();
        root.delete();
    }

    private static void testRecent() {
        RecentActivities r = new RecentActivities();
        r.note("com.a", "com.a.Main", "usage", 100);
        r.note("com.a", "com.a.Main", "root", 300);
        r.note("com.b", "com.b.Live$Inner", "usage", 200);
        List<RecentActivities.Entry> l = r.list(null);
        eq(2, l.size(), "去重");
        eq("com.a.Main", l.get(0).cls, "按最后出现排序");
        eq(2L, l.get(0).count, "计数");
        eq("usage+root", l.get(0).src, "来源合并");
        eq(1, r.list(Arrays.asList("com.b")).size(), "按包过滤");
        RecentActivities r2 = RecentActivities.fromJson(r.toJson());
        eq(2, r2.size(), "JSON 往返");
        check(RecentActivities.fromJson("not json").size() == 0, "坏文件当空");
        Map<String, Object> d = RecentActivities.ruleDraft("com.b", "com.b.Live$Inner");
        String re = Json.str(Json.asObj(d.get("when")), "activity");
        check(Pattern.compile(re).matcher("com.b.Live$Inner").find(), "草稿正则匹配原类名: " + re);
        check(!Pattern.compile(re).matcher("com.bxLive$Inner").find(), "草稿正则转义了点号");
        throwsIAE("草稿不改 then 不能直接导入", "不是已知活动 id", () -> {
            Map<String, Object> rules = new LinkedHashMap<>();
            List<Object> lst = new ArrayList<>();
            lst.add(d);
            rules.put("rules", lst);
            Rules.parse(Json.stringify(rules));
        });
    }

    private static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }
}
