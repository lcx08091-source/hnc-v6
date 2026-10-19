package io.hnc.probe.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * 活动 id 词表, 与 HNC daemon/hnc_httpd/app_activity.go(appActValidTag)保持一致:
 * video_stream live_stream voice_call video_call gaming download upload browsing background。
 * 额外两个本工具自用的键:
 *   idle —— 只作真值: 熄屏 / 什么都不做(期望 HNC 不给活动或给 background);
 *   none —— 只作 HNC 一侧: 找到了本机但 fg.activity 没给(「没输出」)。
 */
public final class Activities {
    private Activities() {}

    public static final String VIDEO = "video_stream";
    public static final String LIVE = "live_stream";
    public static final String VOICE = "voice_call";
    public static final String VIDEO_CALL = "video_call";
    public static final String GAMING = "gaming";
    public static final String DOWNLOAD = "download";
    public static final String UPLOAD = "upload";
    public static final String BROWSING = "browsing";
    public static final String BACKGROUND = "background";
    public static final String IDLE = "idle";
    public static final String NONE = "none";

    public static final List<String> HNC_IDS = Collections.unmodifiableList(Arrays.asList(
            VIDEO, LIVE, VOICE, VIDEO_CALL, GAMING, DOWNLOAD, UPLOAD, BROWSING, BACKGROUND));

    public static final List<String> TRUTH_IDS;
    static {
        List<String> t = new ArrayList<>(HNC_IDS);
        t.add(IDLE);
        TRUTH_IDS = Collections.unmodifiableList(t);
    }

    public static boolean isHncId(String id) { return id != null && HNC_IDS.contains(id); }

    public static boolean isTruthId(String id) { return id != null && TRUTH_IDS.contains(id); }

    public static String label(String id) {
        if (id == null) return "-";
        switch (id) {
            case VIDEO: return "看视频(点播/短视频)";
            case LIVE: return "看直播";
            case VOICE: return "语音通话";
            case VIDEO_CALL: return "视频通话";
            case GAMING: return "游戏对局";
            case DOWNLOAD: return "下载";
            case UPLOAD: return "上传";
            case BROWSING: return "浏览";
            case BACKGROUND: return "后台";
            case IDLE: return "空闲/熄屏";
            case NONE: return "(无输出)";
            default: return id;
        }
    }

    /** HNC 的输出(actId, null = 没输出)算不算命中真值。 */
    public static boolean hit(String truth, String hncAct) {
        if (truth == null) return false;
        if (IDLE.equals(truth)) return hncAct == null || NONE.equals(hncAct) || BACKGROUND.equals(hncAct);
        return truth.equals(hncAct);
    }

    /** 两个真值说法是否一致(idle 与 background 视为一致)。 */
    public static boolean agrees(String a, String b) {
        if (a == null || b == null) return a == null && b == null;
        if (a.equals(b)) return true;
        boolean ai = IDLE.equals(a) || BACKGROUND.equals(a);
        boolean bi = IDLE.equals(b) || BACKGROUND.equals(b);
        return ai && bi;
    }
}
