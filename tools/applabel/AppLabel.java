package io.hnc.applabel;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Looper;

import java.io.PrintStream;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Locale;

/**
 * Tiny app_process helper for HNC dpid: prints one tab-separated line
 * "uid\tpkg\tlabel" for every installed application, using the real
 * PackageManager so labels are the localized launcher/settings names
 * (e.g. "查找手机", "通话") rather than a guessed package segment.
 *
 * Invocation (as root, from dpid):
 *   CLASSPATH=/.../bin/hnc_applabel.dex app_process / io.hnc.applabel.AppLabel
 *
 * The system-context bootstrap (ActivityThread.systemMain /
 * getSystemContext) uses @hide APIs, so we reach them via reflection and
 * compile only against the public android.jar. Everything else
 * (getInstalledApplications / getApplicationLabel) is public API.
 *
 * Failure model: any error prints to stderr and exits non-zero; dpid
 * then keeps its previous label cache and falls back to the curated map.
 */
public final class AppLabel {

    public static void main(String[] args) {
        try {
            Locale.setDefault(Locale.SIMPLIFIED_CHINESE);

            // Some ROMs require a main looper before ActivityThread bootstrap.
            // systemMain() may prepare it itself on certain versions, so a
            // double-prepare can throw — swallow that specific case.
            try {
                Looper.prepareMainLooper();
            } catch (Throwable ignore) {
                // already prepared (or not needed) — fine
            }

            Context ctx = systemContext();
            if (ctx == null) {
                System.err.println("hnc_applabel: could not obtain system context");
                System.exit(2);
                return;
            }

            Context zhCtx = ctx;
            try {
                Resources sysRes = ctx.getResources();
                if (sysRes != null) {
                    Configuration cfg = new Configuration(sysRes.getConfiguration());
                    cfg.setLocale(Locale.SIMPLIFIED_CHINESE);
                    Context created = ctx.createConfigurationContext(cfg);
                    if (created != null) {
                        zhCtx = created;
                    }
                }
            } catch (Throwable ignore) {
            }

            PackageManager pm = zhCtx.getPackageManager();
            if (pm == null) {
                pm = ctx.getPackageManager();
            }
            if (pm == null) {
                System.err.println("hnc_applabel: null PackageManager");
                System.exit(2);
                return;
            }

            List<ApplicationInfo> apps = pm.getInstalledApplications(0);
            PrintStream out = new PrintStream(System.out, true, "UTF-8");
            StringBuilder sb = new StringBuilder(256);
            int emitted = 0;

            for (ApplicationInfo ai : apps) {
                if (ai == null || ai.packageName == null) {
                    continue;
                }
                String label = resolveSimplifiedChineseLabel(pm, ai);
                label = sanitize(label);
                if (label.isEmpty() || label.equalsIgnoreCase(ai.packageName)) {
                    // Empty or raw package-name fallback; let dpid fall back to curated/pretty.
                    continue;
                }
                sb.setLength(0);
                sb.append(ai.uid).append('\t')
                  .append(ai.packageName).append('\t')
                  .append(label);
                out.println(sb.toString());
                emitted++;
            }
            out.flush();

            if (emitted == 0) {
                System.err.println("hnc_applabel: no labels resolved");
                System.exit(3);
                return;
            }
        } catch (Throwable t) {
            System.err.println("hnc_applabel: " + t);
            System.exit(1);
            return;
        }
        System.exit(0);
    }

    @SuppressWarnings("deprecation")
    private static String resolveSimplifiedChineseLabel(PackageManager pm, ApplicationInfo ai) {
        if (ai.nonLocalizedLabel != null) {
            String nl = ai.nonLocalizedLabel.toString();
            if (nl != null && !nl.trim().isEmpty() && !nl.trim().equalsIgnoreCase(ai.packageName)) {
                return nl;
            }
        }
        if (ai.labelRes != 0) {
            try {
                Resources appRes = pm.getResourcesForApplication(ai);
                if (appRes != null) {
                    Configuration cfg = new Configuration(appRes.getConfiguration());
                    cfg.setLocale(Locale.SIMPLIFIED_CHINESE);
                    appRes.updateConfiguration(cfg, appRes.getDisplayMetrics());
                    CharSequence cs = appRes.getText(ai.labelRes);
                    if (cs != null) {
                        String s = cs.toString();
                        if (!s.trim().isEmpty() && !s.trim().equalsIgnoreCase(ai.packageName)) {
                            return s;
                        }
                    }
                }
            } catch (Throwable ignore) {
            }
        }
        try {
            CharSequence cs = pm.getApplicationLabel(ai);
            return (cs == null) ? "" : cs.toString();
        } catch (Throwable t) {
            return "";
        }
    }

    /** Obtain a system Context via reflection (hidden ActivityThread APIs). */
    private static Context systemContext() {
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Method systemMain = at.getMethod("systemMain");
            Object thread = systemMain.invoke(null);
            Method getSystemContext = at.getMethod("getSystemContext");
            Object ctx = getSystemContext.invoke(thread);
            return (Context) ctx;
        } catch (Throwable t) {
            System.err.println("hnc_applabel: systemContext failed: " + t);
            return null;
        }
    }

    /** Replace our delimiters (tab/newline) with spaces and trim. */
    private static String sanitize(String s) {
        int n = s.length();
        StringBuilder b = new StringBuilder(n);
        for (int i = 0; i < n; i++) {
            char c = s.charAt(i);
            if (c == '\t' || c == '\n' || c == '\r') {
                c = ' ';
            }
            b.append(c);
        }
        return b.toString().trim();
    }

    private AppLabel() {
    }
}
