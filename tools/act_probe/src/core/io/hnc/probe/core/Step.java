package io.hnc.probe.core;

import java.util.LinkedHashMap;
import java.util.Map;

/** 剧本的一步: {app, expect, label, minutes, instruction}(app_name / hnc_app 可选)。 */
public final class Step {
    public final int index;
    /** 包名; "" 或 "*" = 不限应用(对照步)。 */
    public final String app;
    public final String appName;
    /** 这一步的真值活动 id(Activities.TRUTH_IDS 之一)。 */
    public final String expect;
    public final String label;
    public final double minutes;
    public final String instruction;
    /** 可选: 期望 HNC 给出的 fg.app_id; 不填则按规则文件 packages 映射。 */
    public final String hncApp;

    public Step(int index, String app, String appName, String expect, String label,
                double minutes, String instruction, String hncApp) {
        this.index = index;
        this.app = app == null ? "" : app;
        this.appName = appName;
        this.expect = expect;
        this.label = label;
        this.minutes = minutes;
        this.instruction = instruction == null ? "" : instruction;
        this.hncApp = hncApp;
    }

    public boolean anyApp() { return app.isEmpty() || "*".equals(app); }

    public long durationMs() { return Math.round(minutes * 60000.0); }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("app", app);
        if (appName != null) m.put("app_name", appName);
        m.put("expect", expect);
        m.put("label", label);
        m.put("minutes", minutes);
        m.put("instruction", instruction);
        if (hncApp != null) m.put("hnc_app", hncApp);
        return m;
    }
}
