package io.hnc.probe;

import android.content.Context;
import android.content.SharedPreferences;

/** 设置(App 私有 SharedPreferences; allowBackup=false, 不进云备份)。 */
final class Prefs {
    private Prefs() {}

    private static SharedPreferences sp(Context c) {
        return c.getSharedPreferences("probe", Context.MODE_PRIVATE);
    }

    static boolean root(Context c) { return sp(c).getBoolean("root", false); }

    static void setRoot(Context c, boolean v) { sp(c).edit().putBoolean("root", v).apply(); }

    /** 采样间隔 2–5 秒, 默认 3。 */
    static int interval(Context c) {
        int v = sp(c).getInt("interval", 3);
        return Math.max(2, Math.min(5, v));
    }

    static void setInterval(Context c, int v) { sp(c).edit().putInt("interval", Math.max(2, Math.min(5, v))).apply(); }

    static boolean hncEnabled(Context c) { return sp(c).getBoolean("hnc_on", false); }

    static void setHncEnabled(Context c, boolean v) { sp(c).edit().putBoolean("hnc_on", v).apply(); }

    /** "host:port"(已校验过的私网地址), 没填为 null。 */
    static String hncAddr(Context c) { return sp(c).getString("hnc_addr", null); }

    /** 换地址 = 换了一台机器: 清掉证书指纹和令牌。 */
    static void setHncAddr(Context c, String v) {
        String old = hncAddr(c);
        SharedPreferences.Editor e = sp(c).edit().putString("hnc_addr", v);
        if (old == null || !old.equals(v)) e.remove("hnc_pin").remove("hnc_token");
        e.apply();
    }

    /** HNC 访问令牌(TokenID.Secret)。只存在这里, 不进导出文件。 */
    static String hncToken(Context c) { return sp(c).getString("hnc_token", null); }

    static void setHncToken(Context c, String v) {
        if (v == null) sp(c).edit().remove("hnc_token").apply();
        else sp(c).edit().putString("hnc_token", v).apply();
    }

    /** 用户确认信任的 HNC 自签证书 SHA-256 指纹。 */
    static String hncPin(Context c) { return sp(c).getString("hnc_pin", null); }

    static void setHncPin(Context c, String v) {
        if (v == null) sp(c).edit().remove("hnc_pin").apply();
        else sp(c).edit().putString("hnc_pin", v).apply();
    }
}
