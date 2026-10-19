package io.hnc.probe;

import android.app.AppOpsManager;
import android.app.usage.UsageEvents;
import android.app.usage.UsageStatsManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.camera2.CameraManager;
import android.media.AudioManager;
import android.media.AudioRecordingConfiguration;
import android.os.Build;
import android.os.Handler;
import android.os.PowerManager;
import android.os.Process;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.hnc.probe.core.RecentActivities;
import io.hnc.probe.core.RootParsers;
import io.hnc.probe.core.Signals;

/**
 * 真值采样(只在剧本运行时被调用)。
 * 免 root:
 *   前台包名 / Activity 类名  UsageStatsManager.queryEvents 的 ACTIVITY_RESUMED 事件(需「使用情况访问」)
 *   在通话                    AudioManager.getMode() == MODE_IN_COMMUNICATION / MODE_IN_CALL
 *   相机占用                  CameraManager.AvailabilityCallback(有相机不可用 = 有应用在用)
 *   录音占用                  AudioManager.getActiveRecordingConfigurations() 非空(去掉被静音的)
 *   亮屏                      PowerManager.isInteractive()
 * root 模式: 再跑一条只读 dumpsys(RootParsers.SAMPLE_CMD), 解析得出的值覆盖上面的(解析不出就保留免 root 值)。
 */
final class TruthSampler {
    private final UsageStatsManager usm;
    private final AudioManager am;
    private final PowerManager pm;
    private final CameraManager cm;
    private final RecentActivities recent;
    private final Set<String> camBusy = Collections.synchronizedSet(new HashSet<String>());
    private CameraManager.AvailabilityCallback camCb;
    private boolean camOk;
    private String fgPkg, fgCls;
    private long lastQueryEnd;

    TruthSampler(Context c, Handler h, RecentActivities recent) {
        this.recent = recent;
        usm = (UsageStatsManager) c.getSystemService(Context.USAGE_STATS_SERVICE);
        am = (AudioManager) c.getSystemService(Context.AUDIO_SERVICE);
        pm = (PowerManager) c.getSystemService(Context.POWER_SERVICE);
        cm = (CameraManager) c.getSystemService(Context.CAMERA_SERVICE);
        if (cm != null) {
            camCb = new CamCb(camBusy);
            try {
                cm.registerAvailabilityCallback(camCb, h);
                camOk = true;
            } catch (RuntimeException e) {
                camOk = false;
            }
        }
    }

    /**
     * 相机可用性回调。写成静态嵌套类而不是匿名类: JDK 21 javac 会给匿名 / 非静态内部类的构造器写
     * MethodParameters(隐式外部参数名为空), build-tools 34 的 d8 8.2 处理不了会崩。
     */
    private static final class CamCb extends CameraManager.AvailabilityCallback {
        private final Set<String> busy;

        CamCb(Set<String> busy) { this.busy = busy; }

        @Override
        public void onCameraAvailable(String id) { busy.remove(id); }

        @Override
        public void onCameraUnavailable(String id) { busy.add(id); }
    }

    void close() {
        if (cm != null && camCb != null) {
            try {
                cm.unregisterAvailabilityCallback(camCb);
            } catch (RuntimeException ignored) {
                // 忽略
            }
        }
    }

    Signals sample(RootShell root) {
        Signals s = new Signals();
        s.t = System.currentTimeMillis();
        updateUsage(s.t);
        s.pkg = fgPkg;
        s.cls = fgCls;
        s.clsSrc = fgPkg != null ? "usage" : null;
        if (am != null) {
            try {
                s.audioMode = Signals.audioModeName(am.getMode());
                s.inCall = Signals.inCallFromMode(s.audioMode);
            } catch (RuntimeException ignored) {
                // 拿不到就留 null
            }
            try {
                List<AudioRecordingConfiguration> rc = am.getActiveRecordingConfigurations();
                int n = 0;
                if (rc != null) {
                    for (AudioRecordingConfiguration cfg : rc) {
                        if (Build.VERSION.SDK_INT >= 29 && cfg.isClientSilenced()) continue;
                        n++;
                    }
                }
                s.mic = n > 0;
            } catch (RuntimeException ignored) {
                // 留 null
            }
        }
        s.camera = camOk ? Boolean.valueOf(!camBusy.isEmpty()) : null;
        if (pm != null) s.screenOn = pm.isInteractive();
        if (root != null && root.isOpen()) applyRoot(s, root);
        return s;
    }

    private void applyRoot(Signals s, RootShell root) {
        String out = root.run(RootParsers.SAMPLE_CMD, 3000);
        if (out == null) return;
        Map<String, String> sec = RootParsers.split(out);
        String[] act = RootParsers.resumedActivity(sec.get("ACT"));
        if (act != null) {
            s.pkg = act[0];
            s.cls = act[1];
            s.clsSrc = "root";
            s.root = true;
            if (recent != null) recent.note(act[0], act[1], "root", s.t);
        }
        RootParsers.Cam cam = RootParsers.camera(sec.get("CAM"));
        if (cam != null) {
            s.camera = cam.inUse;
            s.cameraPkg = cam.pkg;
            s.root = true;
        }
        String mode = RootParsers.audioMode(sec.get("AUD"));
        if (mode != null) {
            s.audioMode = mode;
            s.inCall = Signals.inCallFromMode(mode);
            s.root = true;
        }
        List<String> rec = RootParsers.recordingPackages(sec.get("AUD"));
        if (rec != null) {
            s.mic = !rec.isEmpty();
            s.micPkg = rec.isEmpty() ? null : String.join(",", rec);
            s.root = true;
        }
    }

    /** 增量读使用情况事件, 记下最后一个 ACTIVITY_RESUMED 的包名 / 类名。 */
    @SuppressWarnings("deprecation")
    private void updateUsage(long now) {
        if (usm == null) return;
        long from = lastQueryEnd == 0 ? now - 6 * 3600_000L : lastQueryEnd;
        UsageEvents ev;
        try {
            ev = usm.queryEvents(from, now);
        } catch (RuntimeException e) {
            return;
        }
        lastQueryEnd = now;
        if (ev == null) return;
        UsageEvents.Event e = new UsageEvents.Event();
        while (ev.hasNextEvent()) {
            if (!ev.getNextEvent(e)) break;
            if (e.getEventType() != UsageEvents.Event.MOVE_TO_FOREGROUND) continue; // == ACTIVITY_RESUMED(1)
            fgPkg = e.getPackageName();
            String cls = e.getClassName();
            fgCls = cls == null ? null : RootParsers.fullClass(fgPkg, cls);
            if (recent != null && fgCls != null) recent.note(fgPkg, fgCls, "usage", e.getTimeStamp());
        }
    }

    /** 「Activity」页: 扫最近 sinceMs 的使用情况事件, 把见过的 Activity 记进 recent。返回事件数。 */
    @SuppressWarnings("deprecation")
    static int scanRecent(Context c, RecentActivities recent, long sinceMs) {
        UsageStatsManager u = (UsageStatsManager) c.getSystemService(Context.USAGE_STATS_SERVICE);
        if (u == null) return -1;
        long now = System.currentTimeMillis();
        UsageEvents ev;
        try {
            ev = u.queryEvents(now - sinceMs, now);
        } catch (RuntimeException e) {
            return -1;
        }
        if (ev == null) return 0;
        int n = 0;
        UsageEvents.Event e = new UsageEvents.Event();
        while (ev.hasNextEvent()) {
            if (!ev.getNextEvent(e)) break;
            if (e.getEventType() != UsageEvents.Event.MOVE_TO_FOREGROUND || e.getClassName() == null) continue;
            recent.note(e.getPackageName(), RootParsers.fullClass(e.getPackageName(), e.getClassName()), "usage", e.getTimeStamp());
            n++;
        }
        return n;
    }

    @SuppressWarnings("deprecation")
    static boolean hasUsageAccess(Context c) {
        AppOpsManager ao = (AppOpsManager) c.getSystemService(Context.APP_OPS_SERVICE);
        if (ao == null) return false;
        int mode;
        if (Build.VERSION.SDK_INT >= 29) {
            mode = ao.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), c.getPackageName());
        } else {
            mode = ao.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), c.getPackageName());
        }
        if (mode == AppOpsManager.MODE_DEFAULT) {
            return c.checkCallingOrSelfPermission("android.permission.PACKAGE_USAGE_STATS") == PackageManager.PERMISSION_GRANTED;
        }
        return mode == AppOpsManager.MODE_ALLOWED;
    }
}
