package io.hnc.applabel;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Looper;

import java.io.PrintStream;
import java.lang.reflect.Method;
import java.util.List;

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

            PackageManager pm = ctx.getPackageManager();
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
                String label;
                try {
                    CharSequence cs = pm.getApplicationLabel(ai);
                    label = (cs == null) ? "" : cs.toString();
                } catch (Throwable t) {
                    label = "";
                }
                label = sanitize(label);
                if (label.isEmpty()) {
                    // Nothing useful; let dpid fall back to curated/pretty for this pkg.
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
