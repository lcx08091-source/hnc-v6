package io.hnc.probe.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 剧本(JSON):
 * <pre>
 * {"schema":"hnc-probe-script/1", "name":"...", "warmup_sec":20,
 *  "steps":[{"app":"com.tencent.mm","app_name":"微信","expect":"voice_call",
 *            "label":"微信语音通话","minutes":2,"instruction":"..."}]}
 * </pre>
 * warmup_sec: 每步开头这么多秒不计入命中率 / 混淆(HNC 的活动判定有 ~30 s 衰减和换标签防抖)。
 */
public final class Script {
    public static final String SCHEMA = "hnc-probe-script/1";
    public static final int MAX_STEPS = 200;

    public final String name;
    public final int warmupSec;
    public final List<Step> steps;

    public Script(String name, int warmupSec, List<Step> steps) {
        this.name = name;
        this.warmupSec = warmupSec;
        this.steps = Collections.unmodifiableList(new ArrayList<>(steps));
    }

    public double totalMinutes() {
        double t = 0;
        for (Step s : steps) t += s.minutes;
        return t;
    }

    public Step step(int i) { return i >= 0 && i < steps.size() ? steps.get(i) : null; }

    /** 解析 + 校验; 出错抛 IllegalArgumentException(中文, 列出所有问题)。 */
    public static Script parse(String json) {
        Map<String, Object> root = Json.parseObject(json);
        List<String> errs = new ArrayList<>();
        String schema = Json.str(root, "schema");
        if (schema != null && !schema.startsWith("hnc-probe-script/")) {
            errs.add("schema 应为 " + SCHEMA + "(当前 " + schema + ")");
        }
        String name = Json.strNE(root, "name");
        if (name == null) name = "未命名剧本";
        int warm = 20;
        if (root.containsKey("warmup_sec")) {
            Double w = Json.num(root, "warmup_sec");
            if (w == null || w < 0 || w > 300) errs.add("warmup_sec 应为 0–300 的数字");
            else warm = (int) Math.round(w);
        }
        List<Object> arr = Json.asArr(root.get("steps"));
        List<Step> steps = new ArrayList<>();
        if (arr == null || arr.isEmpty()) {
            errs.add("steps 必须是非空数组");
        } else if (arr.size() > MAX_STEPS) {
            errs.add("steps 最多 " + MAX_STEPS + " 步");
        } else {
            for (int i = 0; i < arr.size(); i++) {
                String where = "第 " + (i + 1) + " 步";
                Map<String, Object> s = Json.asObj(arr.get(i));
                if (s == null) { errs.add(where + " 不是对象"); continue; }
                String expect = Json.str(s, "expect");
                if (!Activities.isTruthId(expect)) {
                    errs.add(where + ": expect \"" + expect + "\" 不是已知活动 id(可用: "
                            + String.join(" ", Activities.TRUTH_IDS) + ")");
                }
                String label = Json.strNE(s, "label");
                if (label == null) errs.add(where + ": 缺少 label");
                Double min = Json.num(s, "minutes");
                if (min == null || !(min > 0) || min > 120) errs.add(where + ": minutes 应为 0–120 之间的正数");
                Object appV = s.get("app");
                if (appV != null && !(appV instanceof String)) errs.add(where + ": app 应为包名字符串(不限应用写 \"*\")");
                String app = Json.str(s, "app");
                if (app != null && !app.isEmpty() && !"*".equals(app) && !app.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+")) {
                    errs.add(where + ": app \"" + app + "\" 不像包名");
                }
                if (errs.isEmpty()) {
                    steps.add(new Step(i, app, Json.strNE(s, "app_name"), expect, label,
                            min, Json.str(s, "instruction"), Json.strNE(s, "hnc_app")));
                }
            }
        }
        if (!errs.isEmpty()) throw new IllegalArgumentException("剧本有问题:\n- " + String.join("\n- ", errs));
        return new Script(name, warm, steps);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("schema", SCHEMA);
        m.put("name", name);
        m.put("warmup_sec", warmupSec);
        List<Object> l = new ArrayList<>();
        for (Step s : steps) l.add(s.toMap());
        m.put("steps", l);
        return m;
    }
}
