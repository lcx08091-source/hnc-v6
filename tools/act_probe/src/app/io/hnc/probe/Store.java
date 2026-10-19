package io.hnc.probe;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import io.hnc.probe.core.RecentActivities;
import io.hnc.probe.core.Rules;
import io.hnc.probe.core.Script;
import io.hnc.probe.core.Session;

/** App 私有目录里的文件: 剧本 / 规则(导入的副本)、会话、最近 Activity。 */
final class Store {
    private Store() {}

    static final String SCRIPT_FILE = "script.json";
    static final String RULES_FILE = "rules.json";
    static final String RECENT_FILE = "recent_activities.json";

    static String readAsset(Context c, String name) throws IOException {
        try (InputStream in = c.getAssets().open(name)) {
            return readAll(in, 1 << 20);
        }
    }

    static String readUri(Context c, Uri u) throws IOException {
        try (InputStream in = c.getContentResolver().openInputStream(u)) {
            if (in == null) throw new IOException("打不开文件");
            return readAll(in, 1 << 20);
        }
    }

    private static String readAll(InputStream in, int max) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            bo.write(buf, 0, n);
            if (bo.size() > max) throw new IOException("文件太大(>1MB)");
        }
        return new String(bo.toByteArray(), StandardCharsets.UTF_8);
    }

    // ─── 剧本 / 规则 ─────────────────────────────────────────────────────

    static boolean customScript(Context c) { return new File(c.getFilesDir(), SCRIPT_FILE).isFile(); }

    static boolean customRules(Context c) { return new File(c.getFilesDir(), RULES_FILE).isFile(); }

    /** 当前剧本 JSON 原文: 导入过且能解析就用导入的, 否则内置默认。 */
    static String scriptJson(Context c) throws IOException {
        File f = new File(c.getFilesDir(), SCRIPT_FILE);
        if (f.isFile()) {
            String s = Session.readText(f);
            try {
                Script.parse(s);
                return s;
            } catch (IllegalArgumentException ignored) {
                // 坏了就退回默认
            }
        }
        return readAsset(c, "default_script.json");
    }

    static String rulesJson(Context c) throws IOException {
        File f = new File(c.getFilesDir(), RULES_FILE);
        if (f.isFile()) {
            String s = Session.readText(f);
            try {
                Rules.parse(s);
                return s;
            } catch (IllegalArgumentException ignored) {
                // 坏了就退回默认
            }
        }
        return readAsset(c, "default_rules.json");
    }

    /** 校验通过才保存; 不通过抛 IllegalArgumentException(中文原因)。 */
    static Script saveScript(Context c, String json) throws IOException {
        Script s = Script.parse(json);
        Session.writeAtomic(new File(c.getFilesDir(), SCRIPT_FILE), json);
        return s;
    }

    static Rules saveRules(Context c, String json) throws IOException {
        Rules r = Rules.parse(json);
        Session.writeAtomic(new File(c.getFilesDir(), RULES_FILE), json);
        return r;
    }

    static void resetScript(Context c) {
        //noinspection ResultOfMethodCallIgnored
        new File(c.getFilesDir(), SCRIPT_FILE).delete();
    }

    static void resetRules(Context c) {
        //noinspection ResultOfMethodCallIgnored
        new File(c.getFilesDir(), RULES_FILE).delete();
    }

    // ─── 会话 ────────────────────────────────────────────────────────────

    static File sessionsRoot(Context c) {
        File d = new File(c.getFilesDir(), "sessions");
        //noinspection ResultOfMethodCallIgnored
        d.mkdirs();
        return d;
    }

    /** 会话目录, 新的在前。 */
    static List<File> sessions(Context c) {
        File[] fs = sessionsRoot(c).listFiles(f -> f.isDirectory() && new File(f, "meta.json").isFile());
        List<File> l = new ArrayList<>(fs == null ? Collections.<File>emptyList() : Arrays.asList(fs));
        Collections.sort(l, (a, b) -> b.getName().compareTo(a.getName()));
        return l;
    }

    static void deleteSession(File dir) {
        File[] fs = dir.listFiles();
        if (fs != null) for (File f : fs) //noinspection ResultOfMethodCallIgnored
            f.delete();
        //noinspection ResultOfMethodCallIgnored
        dir.delete();
    }

    static String newSessionId() {
        return new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new Date());
    }

    // ─── 最近 Activity ──────────────────────────────────────────────────

    static RecentActivities loadRecent(Context c) {
        File f = new File(c.getFilesDir(), RECENT_FILE);
        try {
            return f.isFile() ? RecentActivities.fromJson(Session.readText(f)) : new RecentActivities();
        } catch (IOException e) {
            return new RecentActivities();
        }
    }

    static void saveRecent(Context c, RecentActivities r) {
        try {
            Session.writeAtomic(new File(c.getFilesDir(), RECENT_FILE), r.toJson());
        } catch (IOException ignored) {
            // 不影响主流程
        }
    }

    // ─── 版本信息(写进会话 / 导出) ──────────────────────────────────────

    @SuppressWarnings("deprecation")
    static Map<String, Object> appInfo(Context c) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("package", c.getPackageName());
        try {
            PackageInfo pi = c.getPackageManager().getPackageInfo(c.getPackageName(), 0);
            m.put("version_name", pi.versionName);
            m.put("version_code", Build.VERSION.SDK_INT >= 28 ? pi.getLongVersionCode() : pi.versionCode);
        } catch (PackageManager.NameNotFoundException e) {
            m.put("version_name", null);
        }
        return m;
    }

    static String versionName(Context c) {
        Object v = appInfo(c).get("version_name");
        return v == null ? "?" : v.toString();
    }

    static Map<String, Object> systemInfo() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("manufacturer", Build.MANUFACTURER);
        m.put("brand", Build.BRAND);
        m.put("model", Build.MODEL);
        m.put("device", Build.DEVICE);
        m.put("android_release", Build.VERSION.RELEASE);
        m.put("sdk_int", Build.VERSION.SDK_INT);
        m.put("security_patch", Build.VERSION.SECURITY_PATCH);
        m.put("build_display", Build.DISPLAY);
        m.put("build_incremental", Build.VERSION.INCREMENTAL);
        return m;
    }
}
