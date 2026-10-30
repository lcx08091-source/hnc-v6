package io.hnc.probe.core;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 一次 HNC 对照观测(每 10 秒 GET /api/devices, 按本机 Wi-Fi IP 找到自己)。
 * ok=false 时 err 说明原因(连不上 / 401 / 列表里没有本机……), 不计入混淆。
 */
public final class HncObs {
    public long t;
    public int step = -1;
    public String phase = Sample.GAP;
    public boolean ok;
    public String err;
    public int http;
    public long latencyMs;
    public String ip, mac;
    public Boolean online;
    public String fgState, fgApp, fgName;
    public Double fgConf;
    public Long fgUpdated;
    public String actId, actLabel, actSrc;
    public Double actConf;
    public String ttType, ttLabel;
    public Double ttConf;
    /** 观测时刻的真值(取最近一个同步真值样本; 没有则用剧本 expect) */
    public String truth, truthSrc;

    public static HncObs error(String err, int http) {
        HncObs o = new HncObs();
        o.ok = false;
        o.err = err;
        o.http = http;
        return o;
    }

    /**
     * 给观测配上当时的真值: 最近一个同一步、相隔不超过 maxAgeMs 的真值样本; 没有就用剧本 expect。
     * gap(两步之间)不配真值。
     */
    public void attachTruth(Sample last, Step stepObj, long maxAgeMs) {
        if (!Sample.RUN.equals(phase) && !Sample.WARMUP.equals(phase)) return;
        if (last != null && last.step == step && last.truth != null && Math.abs(t - last.t) <= maxAgeMs) {
            truth = last.truth;
            truthSrc = last.truthSrc;
        } else if (stepObj != null) {
            truth = stepObj.expect;
            truthSrc = "script";
        }
    }

    /** 混淆矩阵里 HNC 一侧的列: 活动 id, 没给活动 = none。 */
    public String actKey() { return actId == null ? Activities.NONE : actId; }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("t", t);
        m.put("step", step);
        m.put("phase", phase);
        m.put("ok", ok);
        m.put("err", err);
        m.put("http", http);
        m.put("latency_ms", latencyMs);
        m.put("ip", ip);
        m.put("mac", mac);
        m.put("online", online);
        m.put("fg_state", fgState);
        m.put("fg_app", fgApp);
        m.put("fg_name", fgName);
        m.put("fg_conf", fgConf);
        m.put("fg_updated", fgUpdated);
        m.put("act_id", actId);
        m.put("act_label", actLabel);
        m.put("act_conf", actConf);
        m.put("act_src", actSrc);
        m.put("tt_type", ttType);
        m.put("tt_label", ttLabel);
        m.put("tt_conf", ttConf);
        m.put("truth", truth);
        m.put("truth_src", truthSrc);
        return m;
    }

    public static HncObs fromMap(Map<String, Object> m) {
        HncObs o = new HncObs();
        Long t = Json.lng(m, "t");
        o.t = t == null ? 0 : t;
        Long st = Json.lng(m, "step");
        o.step = st == null ? -1 : st.intValue();
        String ph = Json.str(m, "phase");
        o.phase = ph == null ? Sample.GAP : ph;
        o.ok = Boolean.TRUE.equals(Json.bool(m, "ok"));
        o.err = Json.str(m, "err");
        Long h = Json.lng(m, "http");
        o.http = h == null ? 0 : h.intValue();
        Long lat = Json.lng(m, "latency_ms");
        o.latencyMs = lat == null ? 0 : lat;
        o.ip = Json.str(m, "ip");
        o.mac = Json.str(m, "mac");
        o.online = Json.bool(m, "online");
        o.fgState = Json.str(m, "fg_state");
        o.fgApp = Json.str(m, "fg_app");
        o.fgName = Json.str(m, "fg_name");
        o.fgConf = Json.num(m, "fg_conf");
        o.fgUpdated = Json.lng(m, "fg_updated");
        o.actId = Json.str(m, "act_id");
        o.actLabel = Json.str(m, "act_label");
        o.actConf = Json.num(m, "act_conf");
        o.actSrc = Json.str(m, "act_src");
        o.ttType = Json.str(m, "tt_type");
        o.ttLabel = Json.str(m, "tt_label");
        o.ttConf = Json.num(m, "tt_conf");
        o.truth = Json.str(m, "truth");
        o.truthSrc = Json.str(m, "truth_src");
        return o;
    }
}
