package io.hnc.probe.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 标注规则(JSON): 把真值信号映射成活动 id。
 * <pre>
 * {"schema":"hnc-probe-rules/1", "name":"...",
 *  "packages":{"com.tencent.mm":{"app":"wechat","name":"微信","verified":true}},
 *  "rules":[{"id":"video_call_by_camera","when":{"in_call":true,"camera":true},"then":"video_call"},
 *           {"id":"douyin_live","enabled":false,
 *            "when":{"pkg":"com.ss.android.ugc.aweme","activity":"待核实"},"then":"live_stream"}]}
 * </pre>
 * when 支持(全部满足才算命中, 信号拿不到 = 不命中):
 *   pkg(字符串或数组)、pkg_not(数组)、activity(正则, find 匹配完整类名)、
 *   in_call / camera / mic / screen_on(布尔)、expect(字符串或数组: 当前剧本步的 expect)。
 * 按顺序匹配, 第一条命中的生效。enabled=false 或任何条件写着「待核实」的规则跳过。
 */
public final class Rules {
    public static final String SCHEMA = "hnc-probe-rules/1";
    public static final String PLACEHOLDER = "待核实";
    private static final Set<String> WHEN_KEYS = new HashSet<>(Arrays.asList(
            "pkg", "pkg_not", "activity", "in_call", "camera", "mic", "screen_on", "expect"));

    public static final class PkgInfo {
        public final String pkg, app, name, note;
        public final boolean verified;

        PkgInfo(String pkg, String app, String name, boolean verified, String note) {
            this.pkg = pkg; this.app = app; this.name = name; this.verified = verified; this.note = note;
        }
    }

    public static final class Rule {
        public final String id, then, note;
        public final boolean enabled;
        /** 有「待核实」占位, 永不生效 */
        public final boolean placeholder;
        final List<String> pkg, pkgNot, expect;
        final Pattern activity;
        final Boolean inCall, camera, mic, screenOn;

        Rule(String id, String then, String note, boolean enabled, boolean placeholder,
             List<String> pkg, List<String> pkgNot, List<String> expect, Pattern activity,
             Boolean inCall, Boolean camera, Boolean mic, Boolean screenOn) {
            this.id = id; this.then = then; this.note = note; this.enabled = enabled;
            this.placeholder = placeholder; this.pkg = pkg; this.pkgNot = pkgNot; this.expect = expect;
            this.activity = activity; this.inCall = inCall; this.camera = camera; this.mic = mic;
            this.screenOn = screenOn;
        }

        public boolean active() { return enabled && !placeholder; }

        public boolean matches(Signals s, Step step) {
            if (!active() || s == null) return false;
            if (pkg != null && (s.pkg == null || !pkg.contains(s.pkg))) return false;
            if (pkgNot != null && s.pkg != null && pkgNot.contains(s.pkg)) return false;
            if (activity != null && (s.cls == null || !activity.matcher(s.cls).find())) return false;
            if (!boolOk(inCall, s.inCall)) return false;
            if (!boolOk(camera, s.camera)) return false;
            if (!boolOk(mic, s.mic)) return false;
            if (!boolOk(screenOn, s.screenOn)) return false;
            if (expect != null && (step == null || !expect.contains(step.expect))) return false;
            return true;
        }

        private static boolean boolOk(Boolean want, Boolean have) {
            if (want == null) return true;
            return have != null && want.equals(have);
        }
    }

    public final String name;
    public final Map<String, PkgInfo> packages;
    public final List<Rule> rules;

    private Rules(String name, Map<String, PkgInfo> packages, List<Rule> rules) {
        this.name = name;
        this.packages = Collections.unmodifiableMap(packages);
        this.rules = Collections.unmodifiableList(rules);
    }

    public Rule firstMatch(Signals s, Step step) {
        for (Rule r : rules) if (r.matches(s, step)) return r;
        return null;
    }

    /** 包名 → HNC 的 app_id(规则文件 packages 里配的), 没配返回 null。 */
    public String hncAppFor(String pkg) {
        PkgInfo p = pkg == null ? null : packages.get(pkg);
        return p == null ? null : p.app;
    }

    public String nameFor(String pkg) {
        PkgInfo p = pkg == null ? null : packages.get(pkg);
        return p == null ? null : p.name;
    }

    public int activeCount() {
        int n = 0;
        for (Rule r : rules) if (r.active()) n++;
        return n;
    }

    public static Rules parse(String json) {
        Map<String, Object> root = Json.parseObject(json);
        List<String> errs = new ArrayList<>();
        String schema = Json.str(root, "schema");
        if (schema != null && !schema.startsWith("hnc-probe-rules/")) {
            errs.add("schema 应为 " + SCHEMA + "(当前 " + schema + ")");
        }
        String name = Json.strNE(root, "name");
        if (name == null) name = "未命名规则";

        Map<String, PkgInfo> pk = new LinkedHashMap<>();
        Object pkV = root.get("packages");
        if (pkV != null) {
            Map<String, Object> pm = Json.asObj(pkV);
            if (pm == null) {
                errs.add("packages 应为对象 {包名: {...}}");
            } else {
                for (Map.Entry<String, Object> e : pm.entrySet()) {
                    Map<String, Object> v = Json.asObj(e.getValue());
                    if (v == null) { errs.add("packages." + e.getKey() + " 应为对象"); continue; }
                    Boolean ver = Json.bool(v, "verified");
                    pk.put(e.getKey(), new PkgInfo(e.getKey(), Json.strNE(v, "app"), Json.strNE(v, "name"),
                            ver != null && ver, Json.str(v, "note")));
                }
            }
        }

        List<Rule> rules = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        List<Object> arr = Json.asArr(root.get("rules"));
        if (root.containsKey("rules") && arr == null) errs.add("rules 应为数组");
        if (arr != null) {
            for (int i = 0; i < arr.size(); i++) {
                Map<String, Object> r = Json.asObj(arr.get(i));
                String where = "规则 #" + (i + 1);
                if (r == null) { errs.add(where + " 不是对象"); continue; }
                String id = Json.strNE(r, "id");
                if (id == null) { errs.add(where + ": 缺少 id"); id = "#" + (i + 1); }
                else where = "规则 " + id;
                if (!ids.add(id)) errs.add(where + ": id 重复");
                String then = Json.str(r, "then");
                if (!Activities.isTruthId(then)) {
                    errs.add(where + ": then \"" + then + "\" 不是已知活动 id(可用: "
                            + String.join(" ", Activities.TRUTH_IDS) + ")");
                }
                Boolean en = Json.bool(r, "enabled");
                Map<String, Object> w = Json.asObj(r.get("when"));
                if (w == null || w.isEmpty()) { errs.add(where + ": 缺少 when 条件对象"); continue; }
                for (String k : w.keySet()) {
                    if (!WHEN_KEYS.contains(k)) errs.add(where + ": 不认识的条件 \"" + k + "\"(可用: " + WHEN_KEYS + ")");
                }
                boolean ph = false;
                List<String> pkg = strList(w.get("pkg"), where + ".pkg", errs);
                List<String> pkgNot = strList(w.get("pkg_not"), where + ".pkg_not", errs);
                List<String> exp = strList(w.get("expect"), where + ".expect", errs);
                if (pkg != null && pkg.contains(PLACEHOLDER)) ph = true;
                if (exp != null) {
                    for (String e : exp) {
                        if (!Activities.isTruthId(e)) errs.add(where + ".expect: \"" + e + "\" 不是已知活动 id");
                    }
                }
                Pattern act = null;
                Object av = w.get("activity");
                if (av != null) {
                    if (!(av instanceof String) || ((String) av).isEmpty()) {
                        errs.add(where + ".activity 应为非空正则字符串");
                    } else if (((String) av).contains(PLACEHOLDER)) {
                        ph = true;
                    } else {
                        try {
                            act = Pattern.compile((String) av);
                        } catch (PatternSyntaxException ex) {
                            errs.add(where + ".activity 正则写错了: " + ex.getDescription());
                        }
                    }
                }
                Boolean inCall = boolCond(w, "in_call", where, errs);
                Boolean cam = boolCond(w, "camera", where, errs);
                Boolean mic = boolCond(w, "mic", where, errs);
                Boolean scr = boolCond(w, "screen_on", where, errs);
                rules.add(new Rule(id, then, Json.str(r, "note"), en == null || en, ph,
                        pkg, pkgNot, exp, act, inCall, cam, mic, scr));
            }
        }
        if (!errs.isEmpty()) throw new IllegalArgumentException("规则有问题:\n- " + String.join("\n- ", errs));
        return new Rules(name, pk, rules);
    }

    private static Boolean boolCond(Map<String, Object> w, String k, String where, List<String> errs) {
        if (!w.containsKey(k)) return null;
        Object v = w.get(k);
        if (!(v instanceof Boolean)) { errs.add(where + "." + k + " 应为 true / false"); return null; }
        return (Boolean) v;
    }

    private static List<String> strList(Object v, String where, List<String> errs) {
        if (v == null) return null;
        List<String> out = new ArrayList<>();
        if (v instanceof String) {
            out.add((String) v);
            return out;
        }
        List<Object> a = Json.asArr(v);
        if (a == null || a.isEmpty()) { errs.add(where + " 应为字符串或非空字符串数组"); return null; }
        for (Object o : a) {
            if (!(o instanceof String)) { errs.add(where + " 里有非字符串"); return null; }
            out.add((String) o);
        }
        return out;
    }
}
