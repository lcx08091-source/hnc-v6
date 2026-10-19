package io.hnc.probe.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 一个真值样本(每 2–5 秒一个)。导出 JSON 里是扁平对象(见 README「导出字段」)。
 * phase: run = 计入统计; warmup = 每步开头的预热期; gap = 两步之间等用户点「下一步」。
 */
public final class Sample {
    public static final String RUN = "run", WARMUP = "warmup", GAP = "gap";

    public long t;
    public int step = -1;
    public String phase = GAP;
    public Signals sig = new Signals();
    public String truth, truthSrc, ruleId;
    public List<String> flags = new ArrayList<>();

    public static Sample of(Signals s, int step, String phase, Labeler.Result r) {
        Sample x = new Sample();
        x.t = s.t;
        x.sig = s;
        x.step = step;
        x.phase = phase;
        if (r != null) {
            x.truth = r.truth;
            x.truthSrc = r.src;
            x.ruleId = r.ruleId;
            x.flags = new ArrayList<>(r.flags);
        }
        return x;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("t", t);
        m.put("step", step);
        m.put("phase", phase);
        m.put("pkg", sig.pkg);
        m.put("cls", sig.cls);
        m.put("cls_src", sig.clsSrc);
        m.put("in_call", sig.inCall);
        m.put("audio_mode", sig.audioMode);
        m.put("camera", sig.camera);
        m.put("camera_pkg", sig.cameraPkg);
        m.put("mic", sig.mic);
        m.put("mic_pkg", sig.micPkg);
        m.put("screen_on", sig.screenOn);
        m.put("root", sig.root);
        m.put("truth", truth);
        m.put("truth_src", truthSrc);
        m.put("rule", ruleId);
        m.put("flags", new ArrayList<Object>(flags));
        return m;
    }

    public static Sample fromMap(Map<String, Object> m) {
        Sample x = new Sample();
        Long t = Json.lng(m, "t");
        x.t = t == null ? 0 : t;
        Long st = Json.lng(m, "step");
        x.step = st == null ? -1 : st.intValue();
        String ph = Json.str(m, "phase");
        x.phase = ph == null ? GAP : ph;
        Signals s = new Signals();
        s.t = x.t;
        s.pkg = Json.str(m, "pkg");
        s.cls = Json.str(m, "cls");
        s.clsSrc = Json.str(m, "cls_src");
        s.inCall = Json.bool(m, "in_call");
        s.audioMode = Json.str(m, "audio_mode");
        s.camera = Json.bool(m, "camera");
        s.cameraPkg = Json.str(m, "camera_pkg");
        s.mic = Json.bool(m, "mic");
        s.micPkg = Json.str(m, "mic_pkg");
        s.screenOn = Json.bool(m, "screen_on");
        s.root = Boolean.TRUE.equals(Json.bool(m, "root"));
        x.sig = s;
        x.truth = Json.str(m, "truth");
        x.truthSrc = Json.str(m, "truth_src");
        x.ruleId = Json.str(m, "rule");
        List<Object> f = Json.asArr(m.get("flags"));
        if (f != null) for (Object o : f) if (o instanceof String) x.flags.add((String) o);
        return x;
    }
}
