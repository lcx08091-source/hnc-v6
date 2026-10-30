package io.hnc.probe.core;

import java.util.ArrayList;
import java.util.List;

/**
 * 真值标注: 规则命中 → 规则给的活动; 没命中 → 剧本步的 expect(剧本是主真值)。
 * 另外按信号做几条「剧本与实际不符」的检查, 打成 flags(只标记, 不改真值):
 *   rule_disagree       规则判出的活动与剧本 expect 不一致
 *   pkg_mismatch        这一步指定了应用, 但前台是别的应用(亮屏时)
 *   probe_in_fg         前台是本采集 App 自己(看倒计时 / 设置时)
 *   call_missing        剧本说在通话, 但没检测到通话模式也没有录音
 *   camera_missing      剧本说视频通话, 但相机没被占用
 *   screen_off          剧本不是 idle 也不在通话, 却熄屏了
 *   screen_on_in_idle   剧本 idle, 却亮着屏
 */
public final class Labeler {
    private Labeler() {}

    public static final String F_RULE_DISAGREE = "rule_disagree";
    public static final String F_PKG_MISMATCH = "pkg_mismatch";
    public static final String F_PROBE_FG = "probe_in_fg";
    public static final String F_CALL_MISSING = "call_missing";
    public static final String F_CAMERA_MISSING = "camera_missing";
    public static final String F_SCREEN_OFF = "screen_off";
    public static final String F_SCREEN_ON_IDLE = "screen_on_in_idle";

    public static final class Result {
        public String truth;
        /** script | rule */
        public String src;
        public String ruleId;
        public final List<String> flags = new ArrayList<>();
    }

    public static String flagLabel(String f) {
        switch (f) {
            case F_RULE_DISAGREE: return "规则判断与剧本不一致";
            case F_PKG_MISMATCH: return "前台不是剧本指定的应用";
            case F_PROBE_FG: return "前台是采集 App 自己";
            case F_CALL_MISSING: return "剧本说通话, 但没检测到通话/录音";
            case F_CAMERA_MISSING: return "剧本说视频通话, 但相机没在用";
            case F_SCREEN_OFF: return "剧本没让熄屏, 但屏幕是灭的";
            case F_SCREEN_ON_IDLE: return "剧本要熄屏, 但屏幕亮着";
            default: return f;
        }
    }

    public static Result label(Signals s, Step step, Rules rules, String selfPkg) {
        Result r = new Result();
        Rules.Rule hit = rules == null ? null : rules.firstMatch(s, step);
        if (hit != null) {
            r.truth = hit.then;
            r.src = "rule";
            r.ruleId = hit.id;
        } else {
            r.truth = step == null ? null : step.expect;
            r.src = "script";
        }
        if (step == null || s == null) return r;

        String exp = step.expect;
        if (hit != null && !Activities.agrees(hit.then, exp)) r.flags.add(F_RULE_DISAGREE);

        boolean screenOn = !Boolean.FALSE.equals(s.screenOn);
        if (!step.anyApp() && screenOn && s.pkg != null && !s.pkg.equals(step.app)) {
            r.flags.add(selfPkg != null && selfPkg.equals(s.pkg) ? F_PROBE_FG : F_PKG_MISMATCH);
        } else if (step.anyApp() && screenOn && selfPkg != null && selfPkg.equals(s.pkg)
                && !Activities.IDLE.equals(exp)) {
            r.flags.add(F_PROBE_FG);
        }

        boolean expCall = Activities.VOICE.equals(exp) || Activities.VIDEO_CALL.equals(exp);
        if (expCall && Boolean.FALSE.equals(s.inCall) && !Boolean.TRUE.equals(s.mic)) r.flags.add(F_CALL_MISSING);
        if (Activities.VIDEO_CALL.equals(exp) && Boolean.FALSE.equals(s.camera)) r.flags.add(F_CAMERA_MISSING);

        if (Activities.IDLE.equals(exp)) {
            if (Boolean.TRUE.equals(s.screenOn)) r.flags.add(F_SCREEN_ON_IDLE);
        } else if (Boolean.FALSE.equals(s.screenOn) && !Boolean.TRUE.equals(s.inCall)) {
            r.flags.add(F_SCREEN_OFF);
        }
        return r;
    }
}
