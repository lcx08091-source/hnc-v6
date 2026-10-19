package io.hnc.probe.core;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 一次剧本运行的数据(全部在 App 私有目录 files/sessions/&lt;id&gt;/):
 *   meta.json      剧本 / 规则原文、设置、App 与系统版本、开始结束时间
 *   samples.jsonl  真值样本(一行一个)
 *   hnc.jsonl      HNC 对照观测(一行一个)
 *   summary.json   跑完(或中止)时的汇总
 * 只用 java.io, 不依赖 Android, test.sh 直接测。
 */
public final class Session {
    public static final String EXPORT_SCHEMA = "hnc-probe-export/1";

    public final File dir;
    public final String id;
    private final Map<String, Object> meta;
    public final List<Sample> samples = new ArrayList<>();
    public final List<HncObs> obs = new ArrayList<>();
    private final Script script;
    private final Rules rules;
    private Map<String, Object> summary;

    private Session(File dir, Map<String, Object> meta, Script script, Rules rules) {
        this.dir = dir;
        this.id = dir.getName();
        this.meta = meta;
        this.script = script;
        this.rules = rules;
    }

    public Script script() { return script; }

    public Rules rules() { return rules; }

    public synchronized Map<String, Object> meta() { return meta; }

    public static Session create(File root, String id, String scriptJson, String rulesJson,
                                 Map<String, Object> settings, Map<String, Object> app,
                                 Map<String, Object> system, long started) throws IOException {
        Script sc = Script.parse(scriptJson);
        Rules ru = Rules.parse(rulesJson);
        File dir = new File(root, id);
        if (!dir.mkdirs() && !dir.isDirectory()) throw new IOException("建不了目录 " + dir);
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("id", id);
        meta.put("started", started);
        meta.put("ended", null);
        meta.put("end_state", null);
        meta.put("settings", settings);
        meta.put("app", app);
        meta.put("system", system);
        meta.put("script", Json.parse(scriptJson));
        meta.put("rules", Json.parse(rulesJson));
        Session s = new Session(dir, meta, sc, ru);
        s.writeMeta();
        return s;
    }

    public static Session load(File dir) throws IOException {
        Map<String, Object> meta = Json.parseObject(readText(new File(dir, "meta.json")));
        Script sc = Script.parse(Json.stringify(meta.get("script")));
        Rules ru = Rules.parse(Json.stringify(meta.get("rules")));
        Session s = new Session(dir, meta, sc, ru);
        for (Map<String, Object> m : readLines(new File(dir, "samples.jsonl"))) s.samples.add(Sample.fromMap(m));
        for (Map<String, Object> m : readLines(new File(dir, "hnc.jsonl"))) s.obs.add(HncObs.fromMap(m));
        File sf = new File(dir, "summary.json");
        if (sf.isFile()) {
            try {
                s.summary = Json.parseObject(readText(sf));
            } catch (IllegalArgumentException ignored) {
                s.summary = null;
            }
        }
        return s;
    }

    public synchronized void add(Sample x) throws IOException {
        samples.add(x);
        appendLine(new File(dir, "samples.jsonl"), Json.stringify(x.toMap()));
    }

    public synchronized void add(HncObs o) throws IOException {
        obs.add(o);
        appendLine(new File(dir, "hnc.jsonl"), Json.stringify(o.toMap()));
    }

    /** 结束: done | aborted。写 summary.json 和 meta 的结束时间。 */
    public synchronized Map<String, Object> finish(String endState, long ended) throws IOException {
        meta.put("ended", ended);
        meta.put("end_state", endState);
        writeMeta();
        summary = Summary.compute(script, samples, obs, rules);
        writeAtomic(new File(dir, "summary.json"), Json.pretty(summary));
        return summary;
    }

    /** 已结束的会话用 summary.json; 没结束(运行中 / 进程被杀)就现算。 */
    public synchronized Map<String, Object> summary() {
        if (summary != null && meta.get("ended") != null) return summary;
        return Summary.compute(script, samples, obs, rules);
    }

    /** done | aborted | running(没有结束标记: 正在跑, 或进程被杀 → 界面显示「未正常结束」) */
    public synchronized String endState() {
        String s = Json.str(meta, "end_state");
        return s == null ? "running" : s;
    }

    public synchronized Map<String, Object> exportDoc(long now) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("schema", EXPORT_SCHEMA);
        d.put("exported_at", now);
        d.put("app", meta.get("app"));
        d.put("system", meta.get("system"));
        Map<String, Object> se = new LinkedHashMap<>();
        se.put("id", id);
        se.put("started", meta.get("started"));
        se.put("ended", meta.get("ended"));
        se.put("end_state", endState());
        se.put("settings", meta.get("settings"));
        d.put("session", se);
        d.put("script", meta.get("script"));
        d.put("rules", meta.get("rules"));
        List<Object> sl = new ArrayList<>();
        for (Sample x : samples) sl.add(x.toMap());
        d.put("samples", sl);
        List<Object> ol = new ArrayList<>();
        for (HncObs o : obs) ol.add(o.toMap());
        d.put("hnc", ol);
        d.put("summary", summary());
        Map<String, Object> notes = new LinkedHashMap<>();
        notes.put("truth", "真值 = 规则命中时取规则结果(truth_src=rule), 否则取剧本步 expect(truth_src=script); flags 标出剧本与实际信号不符的样本");
        notes.put("stats", "summary 只统计 phase=run(不含每步开头 warmup_sec 预热期与步间 gap); HNC 只统计 ok=true 的观测");
        notes.put("privacy", "数据只在本机生成; 不含 HNC 访问令牌; 除用户填写的 HNC 地址外本 App 不联网");
        d.put("notes", notes);
        return d;
    }

    private void writeMeta() throws IOException {
        writeAtomic(new File(dir, "meta.json"), Json.pretty(meta));
    }

    // ─── 文件小工具 ──────────────────────────────────────────────────────

    public static String readText(File f) throws IOException {
        StringBuilder b = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
            char[] buf = new char[8192];
            int n;
            while ((n = r.read(buf)) > 0) b.append(buf, 0, n);
        }
        return b.toString();
    }

    public static void writeAtomic(File f, String text) throws IOException {
        File tmp = new File(f.getPath() + ".tmp");
        try (OutputStream o = new FileOutputStream(tmp)) {
            o.write(text.getBytes(StandardCharsets.UTF_8));
            o.flush();
        }
        if (!tmp.renameTo(f)) {
            //noinspection ResultOfMethodCallIgnored
            f.delete();
            if (!tmp.renameTo(f)) throw new IOException("写不进 " + f);
        }
    }

    private static void appendLine(File f, String line) throws IOException {
        try (OutputStream o = new FileOutputStream(f, true)) {
            o.write((line + "\n").getBytes(StandardCharsets.UTF_8));
        }
    }

    /** 逐行读 jsonl; 坏行(进程被杀时写了半行)跳过。 */
    private static List<Map<String, Object>> readLines(File f) throws IOException {
        List<Map<String, Object>> out = new ArrayList<>();
        if (!f.isFile()) return out;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.trim().isEmpty()) continue;
                try {
                    Map<String, Object> m = Json.parseObject(line);
                    out.add(m);
                } catch (IllegalArgumentException ignored) {
                    // 半行, 跳过
                }
            }
        }
        return out;
    }
}
