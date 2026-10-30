package io.hnc.probe.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * root 模式: 只读 dumpsys 输出的解析(纯文本处理, 便于单测)。
 *
 * 一次采样只跑 SAMPLE_CMD 这一条固定命令(没有任何外部输入拼进去), 输出按 ##ACT / ##CAM / ##AUD 分段。
 * dumpsys 的格式来自 AOSP, 各 ROM / 版本可能不同: 每个解析器解析不出来就返回 null,
 * 调用方回退到免 root 的信号 —— root 结果只是「更准的补充」, 不是唯一来源。
 */
public final class RootParsers {
    private RootParsers() {}

    /** 一次 root 采样执行的固定只读命令。 */
    public static final String SAMPLE_CMD =
            "echo '##ACT'; dumpsys activity activities 2>/dev/null | grep -i 'resumedactivity'; "
            + "echo '##CAM'; dumpsys media.camera 2>/dev/null | grep -i -A 8 'active camera clients'; "
            + "echo '##AUD'; dumpsys audio 2>/dev/null | grep -E 'MODE_|pack:|riid|RecordActivityMonitor'";

    /** 读本机 Wi-Fi MAC(热点侧按 MAC 找本机的兜底)。 */
    public static final String MAC_CMD = "cat /sys/class/net/wlan0/address";

    /** 把 SAMPLE_CMD 的输出切成 ACT / CAM / AUD 三段。 */
    public static Map<String, String> split(String out) {
        Map<String, String> m = new LinkedHashMap<>();
        if (out == null) return m;
        String cur = null;
        StringBuilder b = new StringBuilder();
        for (String line : out.split("\n", -1)) {
            String tl = line.trim();
            if (tl.startsWith("##") && tl.length() > 2 && tl.length() <= 6) {
                if (cur != null) m.put(cur, b.toString());
                cur = tl.substring(2);
                b.setLength(0);
            } else if (cur != null) {
                b.append(line).append('\n');
            }
        }
        if (cur != null) m.put(cur, b.toString());
        return m;
    }

    private static final Pattern AR = Pattern.compile(
            "ActivityRecord\\{[0-9a-fA-F]+ u\\d+ ([A-Za-z0-9_.]+)/([A-Za-z0-9_.$]+)");

    /** dumpsys activity activities 里的前台 Activity → {pkg, 完整类名}; 解析不出 null。 */
    public static String[] resumedActivity(String text) {
        if (text == null) return null;
        String[] best = null;
        for (String line : text.split("\n")) {
            if (!line.toLowerCase().contains("resumedactivity")) continue;
            Matcher m = AR.matcher(line);
            if (!m.find()) continue;
            String[] r = {m.group(1), fullClass(m.group(1), m.group(2))};
            if (line.contains("topResumedActivity")) return r; // 多窗口时以 top 为准
            if (best == null) best = r;
        }
        return best;
    }

    /** ".ui.Foo" → "pkg.ui.Foo"; 已是完整类名则原样返回。 */
    public static String fullClass(String pkg, String cls) {
        if (cls == null) return null;
        if (cls.startsWith(".")) return pkg + cls;
        if (!cls.contains(".")) return pkg + "." + cls;
        return cls;
    }

    /** 相机占用结果。 */
    public static final class Cam {
        public final boolean inUse;
        public final String pkg;

        Cam(boolean inUse, String pkg) { this.inUse = inUse; this.pkg = pkg; }
    }

    private static final Pattern CAM_PKG = Pattern.compile(
            "(?i)package(?:\\s*name)?\\s*[:=]\\s*([A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z0-9_]+)+)");

    /** dumpsys media.camera 的 Active Camera Clients 段; 段不存在返回 null。 */
    public static Cam camera(String text) {
        if (text == null) return null;
        int at = text.toLowerCase().indexOf("active camera clients");
        if (at < 0) return null;
        String rest = text.substring(at);
        int nl = rest.indexOf('\n');
        rest = nl < 0 ? "" : rest.substring(nl + 1);
        String first = "";
        for (String line : rest.split("\n")) {
            if (!line.trim().isEmpty()) { first = line.trim(); break; }
        }
        if (first.isEmpty() || first.startsWith("[]") || first.equalsIgnoreCase("none")) return new Cam(false, null);
        Matcher m = CAM_PKG.matcher(rest);
        if (m.find()) return new Cam(true, m.group(1));
        if (rest.contains("Camera ID") || rest.contains("PID")) return new Cam(true, null);
        return new Cam(false, null);
    }

    private static final Pattern MODE_ACTUAL = Pattern.compile("(?i)actual mode\\s*[=:]\\s*(MODE_[A-Z_]+)");
    private static final Pattern MODE_REQ = Pattern.compile("(?i)requested mode\\s*[=:]\\s*(MODE_[A-Z_]+)");
    private static final Pattern MODE_M = Pattern.compile("\\bmMode\\s*[=:]\\s*(MODE_[A-Z_]+)");

    /** dumpsys audio 里当前音频模式; 解析不出 null(调用方用 AudioManager.getMode())。 */
    public static String audioMode(String text) {
        if (text == null) return null;
        for (Pattern p : new Pattern[]{MODE_ACTUAL, MODE_REQ, MODE_M}) {
            Matcher m = p.matcher(text);
            if (m.find()) return m.group(1);
        }
        return null;
    }

    private static final Pattern RIID = Pattern.compile("(?i)riid\\s*:?\\s*\\d+\\s*;?\\s*active\\s*:?\\s*(true|false)");
    private static final Pattern PACK = Pattern.compile("--\\s*pack:\\s*([A-Za-z0-9_.]+)");

    /**
     * dumpsys audio 的 RecordActivityMonitor 段里正在录音的包(AudioRecordingConfiguration 的
     * "... -- pack:com.x -- ... -- silenced:false" 行); 段不存在返回 null。
     */
    public static List<String> recordingPackages(String text) {
        if (text == null) return null;
        int at = text.indexOf("RecordActivityMonitor");
        if (at < 0) return null;
        List<String> out = new ArrayList<>();
        Boolean active = null;
        for (String line : text.substring(at).split("\n")) {
            Matcher r = RIID.matcher(line);
            if (r.find()) {
                active = Boolean.valueOf(r.group(1).equalsIgnoreCase("true"));
                continue;
            }
            Matcher p = PACK.matcher(line);
            if (!p.find()) continue;
            if (Boolean.FALSE.equals(active)) continue;
            if (line.contains("silenced:true")) continue;
            if (!out.contains(p.group(1))) out.add(p.group(1));
        }
        return out;
    }
}
