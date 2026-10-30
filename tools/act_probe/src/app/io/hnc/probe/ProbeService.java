package io.hnc.probe;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.media.AudioAttributes;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Looper;
import android.os.PowerManager;
import android.os.VibrationEffect;
import android.os.Vibrator;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import io.hnc.probe.core.HncObs;
import io.hnc.probe.core.HncParser;
import io.hnc.probe.core.Labeler;
import io.hnc.probe.core.RecentActivities;
import io.hnc.probe.core.RootParsers;
import io.hnc.probe.core.Rules;
import io.hnc.probe.core.Sample;
import io.hnc.probe.core.Script;
import io.hnc.probe.core.Session;
import io.hnc.probe.core.Signals;
import io.hnc.probe.core.Step;

/**
 * 剧本运行(前台服务): 计时 / 每步结束震动 / 真值采样(每 2–5 秒)/ HNC 对照(每 10 秒)/ 落盘。
 * 状态机: 开始 → 第 1 步 RUNNING → 到时震动 → WAITING(等用户点「下一步」, 期间样本记为 gap 不计入统计)
 *        → 第 2 步 RUNNING … → 最后一步到时 → DONE。任何时候「中止」→ ABORTED(已跑的部分照样汇总)。
 * 通知栏常驻「下一步 / 中止」按钮: 不用切回本 App(切回来会被标成 probe_in_fg)。
 */
public final class ProbeService extends Service {
    static final String ACT_START = "io.hnc.probe.START";
    static final String ACT_NEXT = "io.hnc.probe.NEXT";
    static final String ACT_ABORT = "io.hnc.probe.ABORT";

    static final int ST_IDLE = 0, ST_RUNNING = 1, ST_WAITING = 2, ST_DONE = 3, ST_ABORTED = 4;

    private static final String CH_RUN = "run", CH_ALERT = "alert";
    private static final int NID_RUN = 1, NID_ALERT = 2;
    private static final long HNC_EVERY_MS = 10_000;

    /** 给界面读的快照。 */
    static final class Status {
        int state = ST_IDLE;
        int stepIdx = -1, steps;
        String scriptName, stepLabel, expect, instruction, nextLabel, sessionId, msg;
        long stepEnd, now;
        boolean hncOn, rootOn;
        Sample lastSample;
        HncObs lastObs;
    }

    private static volatile ProbeService inst;
    private static volatile Status finished;

    static Status status() {
        ProbeService s = inst;
        if (s != null && (s.state == ST_RUNNING || s.state == ST_WAITING)) return s.snapshot();
        Status f = finished;
        return f != null ? f : new Status();
    }

    static boolean running() {
        ProbeService s = inst;
        return s != null && (s.state == ST_RUNNING || s.state == ST_WAITING);
    }

    private final Handler main = new Handler(Looper.getMainLooper());
    private HandlerThread sampThread, hncThread;
    private Handler samp, hncH;

    private volatile int state = ST_IDLE;
    private volatile int stepIdx = -1;
    private volatile long stepStart, stepEnd;
    private volatile Sample lastSample;
    private volatile HncObs lastObs;
    private volatile String msg;

    private Script script;
    private Rules rules;
    private Session session;
    private TruthSampler sampler;
    private volatile RootShell root;
    private volatile boolean rootOn;
    private volatile String rootMac;
    private HncClient hnc;
    private boolean hncOn;
    private int hncFail;
    private int intervalSec;
    private RecentActivities recent;
    private PowerManager.WakeLock wl;
    private long lastNotif;

    @Override
    public void onCreate() {
        super.onCreate();
        inst = this;
        NotificationManager nm = getSystemService(NotificationManager.class);
        NotificationChannel run = new NotificationChannel(CH_RUN, "剧本运行中", NotificationManager.IMPORTANCE_LOW);
        run.setShowBadge(false);
        NotificationChannel alert = new NotificationChannel(CH_ALERT, "每步结束提醒", NotificationManager.IMPORTANCE_HIGH);
        alert.enableVibration(true);
        alert.setVibrationPattern(new long[]{0, 400, 200, 400});
        nm.createNotificationChannel(run);
        nm.createNotificationChannel(alert);
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }

    @Override
    public int onStartCommand(Intent it, int flags, int startId) {
        String a = it == null ? null : it.getAction();
        if (ACT_START.equals(a)) {
            startRun();
        } else if (ACT_NEXT.equals(a)) {
            next();
        } else if (ACT_ABORT.equals(a)) {
            finish("aborted");
        }
        // 没在跑(陈旧通知上的按钮 / 未知 action): 不留空壳服务
        if (!ACT_START.equals(a) && state != ST_RUNNING && state != ST_WAITING) stopSelf();
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        if (state == ST_RUNNING || state == ST_WAITING) finish("aborted");
        inst = null;
        super.onDestroy();
    }

    // ─── 运行控制 ────────────────────────────────────────────────────────

    private void startFg(Notification n) {
        if (Build.VERSION.SDK_INT >= 34) startForeground(NID_RUN, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        else startForeground(NID_RUN, n);
    }

    private void startRun() {
        // 每次 startForegroundService 之后 5 秒内都必须 startForeground(已在跑也一样)
        startFg(notif("准备中…", "", false));
        if (state == ST_RUNNING || state == ST_WAITING) {
            updateNotif(true);
            return;
        }

        String scriptJson, rulesJson;
        try {
            scriptJson = Store.scriptJson(this);
            rulesJson = Store.rulesJson(this);
            script = Script.parse(scriptJson);
            rules = Rules.parse(rulesJson);
        } catch (IOException | IllegalArgumentException e) {
            failStart("读剧本 / 规则失败: " + e.getMessage());
            return;
        }
        intervalSec = Prefs.interval(this);
        rootOn = Prefs.root(this);
        String addr = Prefs.hncAddr(this), token = Prefs.hncToken(this), pin = Prefs.hncPin(this);
        hncOn = Prefs.hncEnabled(this) && addr != null && token != null && pin != null;
        hnc = null;
        if (hncOn) {
            try {
                hnc = new HncClient(addr, pin, token, Store.versionName(this));
            } catch (IllegalArgumentException e) {
                hncOn = false;
            }
        }
        Map<String, Object> settings = new LinkedHashMap<>();
        settings.put("interval_sec", intervalSec);
        settings.put("root_mode", rootOn);
        settings.put("hnc_enabled", hncOn);
        settings.put("hnc_addr", hncOn ? addr : null);
        settings.put("usage_access", TruthSampler.hasUsageAccess(this));
        settings.put("custom_script", Store.customScript(this));
        settings.put("custom_rules", Store.customRules(this));
        try {
            session = Session.create(Store.sessionsRoot(this), Store.newSessionId(), scriptJson, rulesJson,
                    settings, Store.appInfo(this), Store.systemInfo(), System.currentTimeMillis());
        } catch (IOException | IllegalArgumentException e) {
            failStart("建会话目录失败: " + e.getMessage());
            return;
        }
        recent = Store.loadRecent(this);
        finished = null;
        msg = hncOn ? null : (Prefs.hncEnabled(this) ? "HNC 对照没配好(地址 / 证书 / 令牌), 本次只记真值" : null);

        sampThread = new HandlerThread("probe-sample");
        sampThread.start();
        samp = new Handler(sampThread.getLooper());
        hncThread = new HandlerThread("probe-hnc");
        hncThread.start();
        hncH = new Handler(hncThread.getLooper());
        sampler = new TruthSampler(this, samp, recent);

        PowerManager pm = getSystemService(PowerManager.class);
        wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "hncprobe:run");
        wl.acquire((long) (script.totalMinutes() * 60_000) + 90 * 60_000L);

        if (rootOn) {
            samp.post(() -> {
                root = new RootShell();
                if (!root.open(15_000)) {
                    root = null;
                    msg = "root 不可用(su 没授权?), 本次只用免 root 信号";
                } else {
                    String mac = root.run(RootParsers.MAC_CMD, 2000);
                    if (mac != null && mac.trim().matches("(?i)[0-9a-f]{2}(:[0-9a-f]{2}){5}")) rootMac = mac.trim().toLowerCase();
                }
            });
        }
        beginStep(0);
        samp.post(sampleTask);
        if (hncOn) hncH.postDelayed(hncTask, 2000);
        main.post(tick);
    }

    private void failStart(String why) {
        msg = why;
        Status s = new Status();
        s.state = ST_ABORTED;
        s.msg = why;
        finished = s;
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    private void beginStep(int i) {
        stepIdx = i;
        stepStart = System.currentTimeMillis();
        stepEnd = stepStart + script.steps.get(i).durationMs();
        state = ST_RUNNING;
        getSystemService(NotificationManager.class).cancel(NID_ALERT);
        updateNotif(true);
    }

    private void next() {
        if (state == ST_RUNNING) {
            endStep();
        } else if (state == ST_WAITING) {
            if (stepIdx + 1 < script.steps.size()) beginStep(stepIdx + 1);
            else finish("done");
        }
    }

    private void endStep() {
        vibrate(false);
        if (stepIdx + 1 >= script.steps.size()) {
            finish("done");
            return;
        }
        state = ST_WAITING;
        Step nx = script.steps.get(stepIdx + 1);
        updateNotif(true);
        Notification a = new Notification.Builder(this, CH_ALERT)
                .setSmallIcon(android.R.drawable.ic_lock_idle_alarm)
                .setContentTitle("第 " + (stepIdx + 1) + " 步结束")
                .setContentText("准备好后点『下一步』: " + nx.label)
                .setStyle(new Notification.BigTextStyle().bigText("准备好后点『下一步』开始第 " + (stepIdx + 2) + " 步: "
                        + nx.label + "\n" + nx.instruction))
                .setContentIntent(openApp())
                .addAction(new Notification.Action.Builder(null, "下一步", svc(ACT_NEXT, 11)).build())
                .setAutoCancel(true)
                .build();
        getSystemService(NotificationManager.class).notify(NID_ALERT, a);
    }

    private void finish(String endState) {
        if (state != ST_RUNNING && state != ST_WAITING) return;
        state = "done".equals(endState) ? ST_DONE : ST_ABORTED;
        main.removeCallbacks(tick);
        final Session sess = session;
        final HandlerThread st = sampThread, ht = hncThread;
        final TruthSampler sp = sampler;
        final RecentActivities rc = recent;
        final android.content.Context app = getApplicationContext();
        if (samp != null) samp.removeCallbacksAndMessages(null);
        if (hncH != null) hncH.removeCallbacksAndMessages(null);
        Status fin = snapshot();
        fin.state = state;
        fin.msg = "done".equals(endState) ? "剧本跑完了, 去『结果』页看汇总" : "已中止, 已跑的部分照样汇总(在『结果』页)";
        finished = fin;
        // 收尾放后台线程: 等采样 / HNC 线程把手上那次做完再写 summary
        new Thread(() -> {
            if (st != null) st.quitSafely();
            if (ht != null) ht.quitSafely();
            try {
                if (st != null) st.join(5000);
                if (ht != null) ht.join(10_000);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            if (sp != null) sp.close();
            RootShell r = root;
            if (r != null) r.close();
            try {
                if (sess != null) sess.finish(endState, System.currentTimeMillis());
            } catch (IOException e) {
                fin.msg = "写汇总失败: " + e.getMessage();
            }
            if (rc != null) Store.saveRecent(app, rc);
        }, "probe-finish").start();
        vibrate(true);
        if (wl != null && wl.isHeld()) wl.release();
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.cancel(NID_ALERT);
        stopForeground(STOP_FOREGROUND_REMOVE);
        nm.notify(NID_ALERT, new Notification.Builder(this, CH_ALERT)
                .setSmallIcon(android.R.drawable.ic_menu_agenda)
                .setContentTitle("done".equals(endState) ? "剧本跑完了" : "剧本已中止")
                .setContentText("打开 HNC 采集看结果 / 导出")
                .setContentIntent(openApp())
                .setAutoCancel(true)
                .build());
        stopSelf();
    }

    // ─── 定时任务 ────────────────────────────────────────────────────────

    // 三个定时任务用方法引用而不是匿名类(理由见 TruthSampler.CamCb)
    private final Runnable tick = this::onTick;
    private final Runnable sampleTask = this::onSample;
    private final Runnable hncTask = this::onHnc;

    private void onTick() {
        if (state == ST_RUNNING && System.currentTimeMillis() >= stepEnd) endStep();
        if (state != ST_RUNNING && state != ST_WAITING) return;
        updateNotif(false);
        main.postDelayed(tick, 1000);
    }

    private String phaseAt(long t) {
        if (state == ST_RUNNING) return t - stepStart < script.warmupSec * 1000L ? Sample.WARMUP : Sample.RUN;
        return Sample.GAP;
    }

    private void onSample() {
        if (state != ST_RUNNING && state != ST_WAITING) return;
        long t0 = System.currentTimeMillis();
        try {
            RootShell r = rootOn ? root : null;
            Signals s = sampler.sample(r);
            if (rootOn && r != null && !r.isOpen() && root != null) {
                // 会话断了(超时 / su 被杀), 下次重开
                if (!root.open(5000)) msg = "root 会话断了, 暂时只用免 root 信号";
            }
            int idx = stepIdx;
            String phase = phaseAt(s.t);
            Step st = Sample.GAP.equals(phase) ? null : script.step(idx);
            Labeler.Result lr = st == null ? null : Labeler.label(s, st, rules, getPackageName());
            Sample x = Sample.of(s, idx, phase, lr);
            session.add(x);
            lastSample = x;
        } catch (IOException e) {
            msg = "写样本失败: " + e.getMessage();
        } catch (RuntimeException e) {
            msg = "采样出错: " + e;
        }
        long wait = intervalSec * 1000L - (System.currentTimeMillis() - t0);
        samp.postDelayed(sampleTask, Math.max(500, wait));
    }

    private void onHnc() {
        if (state != ST_RUNNING && state != ST_WAITING) return;
        long t0 = System.currentTimeMillis();
        int idx = stepIdx;
        String phase = phaseAt(t0);
        NetUtil.Wifi w = NetUtil.wifi(ProbeService.this);
        HncObs o;
        HncClient.Result res = null;
        if (w == null || w.ip == null) {
            o = HncObs.error("没连 Wi-Fi(或拿不到本机 Wi-Fi IP)", 0);
        } else {
            res = hnc.devices(w.network);
            if (res.ok()) o = HncParser.parse(res.body, w.ip, rootMac);
            else o = HncObs.error(res.describe(), res.code);
            if (o.ip == null) o.ip = w.ip;
        }
        o.t = t0;
        o.latencyMs = System.currentTimeMillis() - t0;
        o.step = idx;
        o.phase = phase;
        o.attachTruth(lastSample, script.step(idx), intervalSec * 2000L + 1500);
        try {
            session.add(o);
        } catch (IOException e) {
            msg = "写 HNC 观测失败: " + e.getMessage();
        }
        lastObs = o;
        boolean fatal = res != null && (res.code == 401 || res.code == 403 || res.untrustedFp != null);
        hncFail = fatal ? hncFail + 1 : 0;
        if (hncFail >= 3) {
            msg = "HNC 对照连续失败, 已停止对照: " + o.err;
            return;
        }
        hncH.postDelayed(hncTask, HNC_EVERY_MS);
    }

    // ─── 通知 / 震动 ─────────────────────────────────────────────────────

    private Status snapshot() {
        Status s = new Status();
        s.state = state;
        s.stepIdx = stepIdx;
        s.now = System.currentTimeMillis();
        s.stepEnd = stepEnd;
        s.msg = msg;
        s.hncOn = hncOn;
        s.rootOn = rootOn;
        s.lastSample = lastSample;
        s.lastObs = lastObs;
        s.sessionId = session == null ? null : session.id;
        Script sc = script;
        if (sc != null) {
            s.steps = sc.steps.size();
            s.scriptName = sc.name;
            Step st = sc.step(stepIdx);
            if (st != null) {
                s.stepLabel = st.label;
                s.expect = st.expect;
                s.instruction = st.instruction;
            }
            Step nx = sc.step(stepIdx + 1);
            if (nx != null) s.nextLabel = nx.label;
        }
        return s;
    }

    static String mmss(long ms) {
        long sec = Math.max(0, (ms + 999) / 1000);
        return String.format(java.util.Locale.US, "%02d:%02d", sec / 60, sec % 60);
    }

    private void updateNotif(boolean force) {
        long now = System.currentTimeMillis();
        if (!force && now - lastNotif < 5000) return;
        lastNotif = now;
        Script sc = script;
        if (sc == null) return;
        Step st = sc.step(stepIdx);
        String title, text;
        if (state == ST_RUNNING && st != null) {
            title = "第 " + (stepIdx + 1) + "/" + sc.steps.size() + " 步 · " + st.label;
            text = "剩 " + mmss(stepEnd - now) + " · 真值 " + st.expect;
        } else if (state == ST_WAITING) {
            Step nx = sc.step(stepIdx + 1);
            title = "第 " + (stepIdx + 1) + " 步已结束";
            text = "准备好后点『下一步』: " + (nx == null ? "" : nx.label);
        } else {
            return;
        }
        getSystemService(NotificationManager.class).notify(NID_RUN, notif(title, text, true));
    }

    private Notification notif(String title, String text, boolean actions) {
        Notification.Builder b = new Notification.Builder(this, CH_RUN)
                .setSmallIcon(android.R.drawable.ic_media_play)
                .setContentTitle(title)
                .setContentText(text)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setContentIntent(openApp());
        if (actions) {
            b.addAction(new Notification.Action.Builder(null, "下一步", svc(ACT_NEXT, 1)).build());
            b.addAction(new Notification.Action.Builder(null, "中止", svc(ACT_ABORT, 2)).build());
        }
        return b.build();
    }

    private PendingIntent svc(String action, int req) {
        Intent i = new Intent(this, ProbeService.class).setAction(action);
        return PendingIntent.getService(this, req, i, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    private PendingIntent openApp() {
        Intent i = new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        return PendingIntent.getActivity(this, 0, i, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    @SuppressWarnings("deprecation")
    private void vibrate(boolean longOne) {
        try {
            Vibrator v = (Vibrator) getSystemService(VIBRATOR_SERVICE);
            if (v == null || !v.hasVibrator()) return;
            long[] pat = longOne ? new long[]{0, 800, 300, 800, 300, 800} : new long[]{0, 400, 200, 400, 200, 400};
            AudioAttributes aa = new AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_ALARM)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                    .build();
            v.vibrate(VibrationEffect.createWaveform(pat, -1), aa);
        } catch (RuntimeException ignored) {
            // 震不了就算了, 还有通知
        }
    }
}
