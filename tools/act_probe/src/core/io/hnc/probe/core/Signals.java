package io.hnc.probe.core;

/**
 * 一次真值采样拿到的原始信号。Boolean 为 null 表示「这次拿不到」(不是 false)。
 * 免 root: UsageStatsManager / AudioManager / CameraManager 回调 / PowerManager;
 * root 模式: dumpsys 只读结果覆盖或补充(clsSrc / cameraPkg / micPkg 标出来源)。
 */
public final class Signals {
    public long t;
    /** 前台包名 */
    public String pkg;
    /** 前台 Activity 完整类名(com.x.y.FooActivity), 拿不到为 null */
    public String cls;
    /** pkg/cls 的来源: usage | root */
    public String clsSrc;
    /** 在通话: AudioManager 模式为 MODE_IN_COMMUNICATION / MODE_IN_CALL */
    public Boolean inCall;
    /** 音频模式名, 如 MODE_NORMAL / MODE_IN_COMMUNICATION */
    public String audioMode;
    public Boolean camera;
    /** root 模式下解析到的占用相机的包(可能为 null) */
    public String cameraPkg;
    public Boolean mic;
    public String micPkg;
    public Boolean screenOn;
    /** 本次是否用到了 root 结果 */
    public boolean root;

    public static Boolean inCallFromMode(String mode) {
        if (mode == null) return null;
        return "MODE_IN_COMMUNICATION".equals(mode) || "MODE_IN_CALL".equals(mode)
                || "MODE_CALL_SCREENING".equals(mode) || "MODE_COMMUNICATION_REDIRECT".equals(mode)
                || "MODE_CALL_REDIRECT".equals(mode);
    }

    /** AudioManager.getMode() 的整数 → 名字(与 android.media.AudioManager 常量一致)。 */
    public static String audioModeName(int mode) {
        switch (mode) {
            case 0: return "MODE_NORMAL";
            case 1: return "MODE_RINGTONE";
            case 2: return "MODE_IN_CALL";
            case 3: return "MODE_IN_COMMUNICATION";
            case 4: return "MODE_CALL_SCREENING";
            case 5: return "MODE_CALL_REDIRECT";
            case 6: return "MODE_COMMUNICATION_REDIRECT";
            default: return "MODE_" + mode;
        }
    }
}
