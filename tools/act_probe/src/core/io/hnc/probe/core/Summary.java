package io.hnc.probe.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 汇总: 按步统计 + 总混淆计数(真值 × HNC 输出, 含「没输出」一列)。
 * 只统计 phase=run 的样本 / 观测(预热期与步间不算); HNC 观测只统计 ok 的。
 * 命中: Activities.hit(真值, HNC fg.activity.id) —— idle 真值时 HNC 没输出 / background 都算命中。
 */
public final class Summary {
    private Summary() {}

    public static Map<String, Object> compute(Script script, List<Sample> samples, List<HncObs> obs, Rules rules) {
        int n = script.steps.size();
        List<Object> steps = new ArrayList<>();
        Map<String, Map<String, Long>> conf = new LinkedHashMap<>();
        long totOk = 0, totHit = 0, totSamples = 0, totFlagged = 0, totObs = 0, totErr = 0;

        for (int i = 0; i < n; i++) {
            Step st = script.steps.get(i);
            Map<String, Long> truthDist = new LinkedHashMap<>();
            Map<String, Long> flagDist = new LinkedHashMap<>();
            Map<String, Long> pkgDist = new LinkedHashMap<>();
            long sAll = 0, sRun = 0, sFlag = 0;
            for (Sample s : samples) {
                if (s.step != i) continue;
                if (Sample.GAP.equals(s.phase)) continue;
                sAll++;
                if (!Sample.RUN.equals(s.phase)) continue;
                sRun++;
                inc(truthDist, s.truth == null ? "-" : s.truth);
                inc(pkgDist, s.sig.pkg == null ? "-" : s.sig.pkg);
                if (!s.flags.isEmpty()) sFlag++;
                for (String f : s.flags) inc(flagDist, f);
            }
            Map<String, Long> actDist = new LinkedHashMap<>();
            Map<String, Long> appDist = new LinkedHashMap<>();
            Map<String, Long> ttDist = new LinkedHashMap<>();
            Map<String, Long> errDist = new LinkedHashMap<>();
            long oAll = 0, oOk = 0, oHit = 0, oAppHit = 0;
            String wantApp = st.hncApp != null ? st.hncApp : (rules == null ? null : rules.hncAppFor(st.app));
            for (HncObs o : obs) {
                if (o.step != i || !Sample.RUN.equals(o.phase)) continue;
                oAll++;
                if (!o.ok) {
                    inc(errDist, o.err == null ? "?" : shorten(o.err));
                    continue;
                }
                oOk++;
                inc(actDist, o.actKey());
                inc(appDist, o.fgApp == null ? Activities.NONE : o.fgApp);
                inc(ttDist, o.ttType == null ? Activities.NONE : o.ttType);
                if (Activities.hit(o.truth, o.actId)) oHit++;
                if (wantApp != null && wantApp.equals(o.fgApp)) oAppHit++;
                if (o.truth != null) {
                    Map<String, Long> row = conf.get(o.truth);
                    if (row == null) { row = new LinkedHashMap<>(); conf.put(o.truth, row); }
                    inc(row, o.actKey());
                }
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("index", i);
            m.put("label", st.label);
            m.put("app", st.app);
            m.put("expect", st.expect);
            m.put("minutes", st.minutes);
            m.put("samples", sAll);
            m.put("samples_counted", sRun);
            m.put("truth_top", top(truthDist));
            m.put("truth_dist", truthDist);
            m.put("fg_pkg_top", top(pkgDist));
            m.put("flagged_samples", sFlag);
            m.put("flagged_ratio", ratio(sFlag, sRun));
            m.put("flags", flagDist);
            m.put("hnc_obs", oAll);
            m.put("hnc_ok", oOk);
            m.put("hnc_errors", errDist);
            m.put("hnc_activity_top", top(actDist));
            m.put("hnc_activity_dist", actDist);
            m.put("hnc_app_top", top(appDist));
            m.put("hnc_app_dist", appDist);
            m.put("hnc_traffic_dist", ttDist);
            m.put("hit", oHit);
            m.put("hit_ratio", ratio(oHit, oOk));
            m.put("want_hnc_app", wantApp);
            m.put("app_hit_ratio", wantApp == null ? null : ratio(oAppHit, oOk));
            steps.add(m);
            totOk += oOk;
            totHit += oHit;
            totSamples += sRun;
            totFlagged += sFlag;
            totObs += oAll;
            totErr += oAll - oOk;
        }

        // 混淆: 行 = 真值(按词表顺序), 列 = HNC 活动(按词表顺序)+ none
        List<String> rows = new ArrayList<>();
        for (String id : Activities.TRUTH_IDS) if (conf.containsKey(id)) rows.add(id);
        for (String id : conf.keySet()) if (!rows.contains(id)) rows.add(id);
        List<String> cols = new ArrayList<>();
        for (String id : Activities.HNC_IDS) {
            for (Map<String, Long> r : conf.values()) if (r.containsKey(id)) { cols.add(id); break; }
        }
        for (Map<String, Long> r : conf.values()) {
            for (String c : r.keySet()) if (!cols.contains(c) && !Activities.NONE.equals(c)) cols.add(c);
        }
        cols.add(Activities.NONE);
        Map<String, Object> counts = new LinkedHashMap<>();
        for (String r : rows) {
            Map<String, Object> rowOut = new LinkedHashMap<>();
            Map<String, Long> row = conf.get(r);
            for (String c : cols) rowOut.put(c, row.containsKey(c) ? row.get(c) : 0L);
            counts.put(r, rowOut);
        }
        Map<String, Object> cm = new LinkedHashMap<>();
        cm.put("rows", rows);
        cm.put("cols", cols);
        cm.put("counts", counts);

        Map<String, Object> overall = new LinkedHashMap<>();
        overall.put("samples_counted", totSamples);
        overall.put("flagged_samples", totFlagged);
        overall.put("hnc_obs", totObs);
        overall.put("hnc_ok", totOk);
        overall.put("hnc_errors", totErr);
        overall.put("hit", totHit);
        overall.put("hit_ratio", ratio(totHit, totOk));

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("steps", steps);
        out.put("confusion", cm);
        out.put("overall", overall);
        return out;
    }

    /** 混淆矩阵的等宽文本(给界面显示; 只用 id, 避免中文宽度不齐)。 */
    @SuppressWarnings("unchecked")
    public static String confusionText(Map<String, Object> summary) {
        Map<String, Object> cm = Json.asObj(summary.get("confusion"));
        if (cm == null) return "";
        List<Object> rows = Json.asArr(cm.get("rows"));
        List<Object> cols = Json.asArr(cm.get("cols"));
        Map<String, Object> counts = Json.asObj(cm.get("counts"));
        if (rows == null || cols == null || counts == null || rows.isEmpty()) return "(没有可统计的 HNC 观测)";
        int w0 = "truth\\hnc".length();
        for (Object r : rows) w0 = Math.max(w0, String.valueOf(r).length());
        int[] w = new int[cols.size()];
        for (int k = 0; k < cols.size(); k++) w[k] = Math.max(4, abbr(String.valueOf(cols.get(k))).length());
        StringBuilder b = new StringBuilder();
        b.append(pad("truth\\hnc", w0));
        for (int k = 0; k < cols.size(); k++) b.append(' ').append(padL(abbr(String.valueOf(cols.get(k))), w[k]));
        b.append('\n');
        for (Object r : rows) {
            Map<String, Object> row = Json.asObj(counts.get(String.valueOf(r)));
            b.append(pad(String.valueOf(r), w0));
            for (int k = 0; k < cols.size(); k++) {
                Object v = row == null ? null : row.get(String.valueOf(cols.get(k)));
                b.append(' ').append(padL(v == null ? "0" : String.valueOf(v), w[k]));
            }
            b.append('\n');
        }
        return b.toString();
    }

    /** 列名缩写(手机屏幕窄)。 */
    public static String abbr(String id) {
        switch (id) {
            case Activities.VIDEO: return "video";
            case Activities.LIVE: return "live";
            case Activities.VOICE: return "voice";
            case Activities.VIDEO_CALL: return "vcall";
            case Activities.GAMING: return "game";
            case Activities.DOWNLOAD: return "down";
            case Activities.UPLOAD: return "up";
            case Activities.BROWSING: return "browse";
            case Activities.BACKGROUND: return "bg";
            case Activities.NONE: return "none";
            default: return id;
        }
    }

    private static String pad(String s, int w) {
        StringBuilder b = new StringBuilder(s);
        while (b.length() < w) b.append(' ');
        return b.toString();
    }

    private static String padL(String s, int w) {
        StringBuilder b = new StringBuilder();
        while (b.length() + s.length() < w) b.append(' ');
        return b.append(s).toString();
    }

    private static void inc(Map<String, Long> m, String k) {
        Long v = m.get(k);
        m.put(k, v == null ? 1L : v + 1);
    }

    static String top(Map<String, Long> m) {
        String best = null;
        long bv = -1;
        for (Map.Entry<String, Long> e : m.entrySet()) {
            if (e.getValue() > bv) { bv = e.getValue(); best = e.getKey(); }
        }
        return best;
    }

    private static Double ratio(long a, long b) {
        if (b <= 0) return null;
        return Math.round(a * 1000.0 / b) / 1000.0;
    }

    private static String shorten(String s) {
        return s.length() > 60 ? s.substring(0, 60) + "…" : s;
    }
}
