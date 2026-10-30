package io.hnc.probe;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.MediaStore;
import android.provider.Settings;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import io.hnc.probe.core.Activities;
import io.hnc.probe.core.HncAuth;
import io.hnc.probe.core.HncObs;
import io.hnc.probe.core.HncParser;
import io.hnc.probe.core.Json;
import io.hnc.probe.core.Labeler;
import io.hnc.probe.core.RecentActivities;
import io.hnc.probe.core.RootParsers;
import io.hnc.probe.core.Rules;
import io.hnc.probe.core.Sample;
import io.hnc.probe.core.Script;
import io.hnc.probe.core.Session;
import io.hnc.probe.core.Step;
import io.hnc.probe.core.Summary;

/** 界面全部用代码搭(不需要资源编译)。四个页: 剧本 / 结果 / Activity / 设置。 */
public final class MainActivity extends Activity {
    private static final int REQ_SCRIPT = 1, REQ_RULES = 2, REQ_SAVE_AS = 3;
    private static final String[] TABS = {"剧本", "结果", "Activity", "设置"};
    private static final int C_ACCENT = 0xFF1565C0, C_WARN = 0xFFB71C1C, C_DIM = 0xFF666666, C_HL = 0x221565C0;

    private final Handler h = new Handler(Looper.getMainLooper());
    private LinearLayout content;
    private final Button[] tabBtns = new Button[TABS.length];
    private int tab;

    // 剧本页的动态部分
    private TextView stTitle, stBody, stSample, stHnc, stMsg;
    private Button bStart, bNext, bAbort;
    private LinearLayout stepList;
    private int renderedStep = -2, renderedState = -1;

    // 结果页
    private String selectedSession;
    private String pendingExport, pendingExportName;

    // Activity 页
    private boolean onlyScriptPkgs = true;

    // 方法引用而不是匿名类(理由见 TruthSampler.CamCb)
    private final Runnable ticker = this::onTick;

    private void onTick() {
        if (tab == 0) refreshStatus();
        h.postDelayed(ticker, 1000);
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        for (int i = 0; i < TABS.length; i++) {
            final int k = i;
            Button t = new Button(this);
            t.setText(TABS[i]);
            t.setAllCaps(false);
            t.setOnClickListener(v -> showTab(k));
            tabBtns[i] = t;
            bar.addView(t, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        }
        root.addView(bar);
        ScrollView sv = new ScrollView(this);
        content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(14), dp(8), dp(14), dp(24));
        sv.addView(content);
        root.addView(sv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(root);
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != 0) {
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 9);
        }
        showTab(0);
    }

    @Override
    protected void onResume() {
        super.onResume();
        showTab(tab); // 权限可能刚改过
        h.post(ticker);
    }

    @Override
    protected void onPause() {
        super.onPause();
        h.removeCallbacks(ticker);
    }

    private void showTab(int k) {
        tab = k;
        for (int i = 0; i < tabBtns.length; i++) {
            tabBtns[i].setTextColor(i == k ? C_ACCENT : Color.BLACK);
            tabBtns[i].setTypeface(null, i == k ? Typeface.BOLD : Typeface.NORMAL);
        }
        content.removeAllViews();
        stTitle = null;
        renderedStep = -2;
        renderedState = -1;
        switch (k) {
            case 0: buildScriptTab(); break;
            case 1: buildResultTab(); break;
            case 2: buildActivityTab(); break;
            default: buildSettingsTab(); break;
        }
    }

    // ═══ 剧本页 ═══════════════════════════════════════════════════════════

    private void buildScriptTab() {
        if (!TruthSampler.hasUsageAccess(this)) {
            add(warn("没有「使用情况访问」权限: 拿不到前台应用, 真值只能靠剧本。"));
            add(button("去授权(在列表里找到 HNC 采集并打开)", v -> openUsageAccess()));
        }
        Script sc;
        try {
            sc = Script.parse(Store.scriptJson(this));
        } catch (IOException | IllegalArgumentException e) {
            add(warn("剧本读不出来: " + e.getMessage()));
            return;
        }
        add(title("剧本"));
        add(text(sc.name + "\n共 " + sc.steps.size() + " 步, 约 " + Math.round(sc.totalMinutes()) + " 分钟; 每步开头 "
                + sc.warmupSec + " 秒为预热(不计入统计)" + (Store.customScript(this) ? " · 已导入" : " · 内置默认")));
        add(row(button("导入剧本", v -> pickJson(REQ_SCRIPT)),
                button("恢复默认", v -> confirm("恢复内置默认剧本?", () -> { Store.resetScript(this); showTab(0); }))));

        add(title("运行"));
        stTitle = text("");
        stTitle.setTextSize(17);
        stTitle.setTypeface(null, Typeface.BOLD);
        add(stTitle);
        stBody = text("");
        add(stBody);
        stSample = text("");
        stSample.setTextSize(13);
        add(stSample);
        stHnc = text("");
        stHnc.setTextSize(13);
        add(stHnc);
        stMsg = text("");
        stMsg.setTextColor(C_WARN);
        add(stMsg);
        bStart = button("开始", v -> startRun());
        bNext = button("下一步", v -> sendSvc(ProbeService.ACT_NEXT));
        bAbort = button("中止", v -> confirm("中止本次剧本? 已跑的部分会保留并汇总。", () -> sendSvc(ProbeService.ACT_ABORT)));
        add(row(bStart, bNext, bAbort));
        add(note("运行中可以直接用通知栏的「下一步 / 中止」, 不必切回本 App(切回来时前台是本 App, 样本会被标成 probe_in_fg)。"));

        add(title("步骤"));
        stepList = new LinearLayout(this);
        stepList.setOrientation(LinearLayout.VERTICAL);
        add(stepList);
        refreshStatus();
    }

    private void renderSteps(Script sc, int cur, int state) {
        stepList.removeAllViews();
        for (Step st : sc.steps) {
            boolean isCur = st.index == cur && (state == ProbeService.ST_RUNNING || state == ProbeService.ST_WAITING);
            TextView t = text((st.index + 1) + ". " + st.label + "  [" + st.expect + "] · " + fmtMin(st.minutes)
                    + (st.anyApp() ? "" : "\n    " + st.app) + (isCur ? "\n    " + st.instruction : ""));
            t.setTextSize(13);
            if (isCur) {
                t.setBackgroundColor(C_HL);
                t.setTypeface(null, Typeface.BOLD);
            } else if (st.index < cur && state != ProbeService.ST_IDLE) {
                t.setTextColor(C_DIM);
            }
            stepList.addView(t);
        }
    }

    private void refreshStatus() {
        if (stTitle == null) return;
        ProbeService.Status s = ProbeService.status();
        boolean running = s.state == ProbeService.ST_RUNNING || s.state == ProbeService.ST_WAITING;
        switch (s.state) {
            case ProbeService.ST_RUNNING:
                stTitle.setText("第 " + (s.stepIdx + 1) + "/" + s.steps + " 步 · " + s.stepLabel + " · 剩 " + ProbeService.mmss(s.stepEnd - s.now));
                stBody.setText("真值(剧本): " + s.expect + " " + Activities.label(s.expect) + "\n" + s.instruction);
                break;
            case ProbeService.ST_WAITING:
                stTitle.setText("第 " + (s.stepIdx + 1) + " 步已结束 → 准备好后点「下一步」");
                stBody.setText("下一步: " + (s.nextLabel == null ? "(没有了)" : s.nextLabel));
                break;
            case ProbeService.ST_DONE:
                stTitle.setText("已完成");
                stBody.setText("去「结果」页看汇总 / 导出。");
                break;
            case ProbeService.ST_ABORTED:
                stTitle.setText("已中止");
                stBody.setText("已跑的部分在「结果」页。");
                break;
            default:
                stTitle.setText("未开始");
                stBody.setText("点「开始」从第 1 步开始计时。开始前先把要用的应用登录好、HNC 对照(可选)在设置页测通。");
        }
        stSample.setText(s.lastSample == null ? "" : sampleText(s.lastSample, s.now));
        if (running && !s.hncOn) stHnc.setText("HNC 对照: 未开启");
        else stHnc.setText(s.lastObs == null ? "" : obsText(s.lastObs, s.now));
        stMsg.setText(s.msg == null ? "" : s.msg);
        bStart.setEnabled(!running);
        bNext.setEnabled(running);
        bAbort.setEnabled(running);
        if (s.stepIdx != renderedStep || s.state != renderedState) {
            renderedStep = s.stepIdx;
            renderedState = s.state;
            try {
                renderSteps(Script.parse(Store.scriptJson(this)), s.stepIdx, s.state);
            } catch (IOException | IllegalArgumentException ignored) {
                // 上面已提示
            }
        }
    }

    private String sampleText(Sample x, long now) {
        StringBuilder b = new StringBuilder();
        b.append("真值样本(").append(Math.max(0, (now - x.t) / 1000)).append(" 秒前, ").append(x.phase).append("): ");
        if (x.truth != null) {
            b.append(x.truth).append(" ← ").append("rule".equals(x.truthSrc) ? "规则 " + x.ruleId : "剧本");
        } else {
            b.append("-(步间不标注)");
        }
        b.append("\n前台: ").append(x.sig.pkg == null ? "?(没授权使用情况访问?)" : x.sig.pkg);
        if (x.sig.cls != null) b.append("\n  ").append(x.sig.cls).append(" [").append(x.sig.clsSrc).append("]");
        b.append("\n通话 ").append(yn(x.sig.inCall));
        if (x.sig.audioMode != null) b.append("(").append(x.sig.audioMode.replace("MODE_", "")).append(")");
        b.append(" · 相机 ").append(yn(x.sig.camera)).append(x.sig.cameraPkg == null ? "" : "(" + x.sig.cameraPkg + ")");
        b.append(" · 麦克风 ").append(yn(x.sig.mic)).append(x.sig.micPkg == null ? "" : "(" + x.sig.micPkg + ")");
        b.append(" · 亮屏 ").append(yn(x.sig.screenOn)).append(x.sig.root ? " · root" : "");
        if (!x.flags.isEmpty()) {
            b.append("\n标记: ");
            for (int i = 0; i < x.flags.size(); i++) b.append(i > 0 ? "; " : "").append(Labeler.flagLabel(x.flags.get(i)));
        }
        return b.toString();
    }

    private String obsText(HncObs o, long now) {
        StringBuilder b = new StringBuilder("HNC(").append(Math.max(0, (now - o.t) / 1000)).append(" 秒前): ");
        if (!o.ok) return b.append(o.err).toString();
        b.append(o.fgName != null ? o.fgName : (o.fgApp != null ? o.fgApp : "无前台"));
        if (o.fgState != null) b.append("(").append(o.fgState).append(")");
        b.append(" · 活动 ");
        if (o.actId == null) b.append("(无输出)");
        else b.append(o.actLabel).append(" [").append(o.actId).append(" ").append(o.actConf).append(" ").append(o.actSrc).append("]");
        b.append(" · 流量 ").append(o.ttType == null ? "-" : o.ttType);
        if (o.truth != null) b.append(Activities.hit(o.truth, o.actId) ? " · 命中" : " · 未中(真值 " + o.truth + ")");
        return b.toString();
    }

    private void startRun() {
        if (!TruthSampler.hasUsageAccess(this)) {
            new AlertDialog.Builder(this).setTitle("没有使用情况访问权限")
                    .setMessage("拿不到前台应用, 规则和偏差检查基本失效, 真值只能用剧本。仍然开始?")
                    .setPositiveButton("仍然开始", (d, w) -> doStart())
                    .setNegativeButton("去授权", (d, w) -> openUsageAccess())
                    .show();
            return;
        }
        doStart();
    }

    private void doStart() {
        Intent i = new Intent(this, ProbeService.class).setAction(ProbeService.ACT_START);
        startForegroundService(i);
        h.postDelayed(this::refreshStatus, 600);
    }

    private void sendSvc(String action) {
        if (!ProbeService.running()) return;
        startService(new Intent(this, ProbeService.class).setAction(action));
        h.postDelayed(this::refreshStatus, 300);
    }

    // ═══ 结果页 ═══════════════════════════════════════════════════════════

    private void buildResultTab() {
        List<File> ss = Store.sessions(this);
        add(title("会话"));
        if (ss.isEmpty()) {
            add(text("还没有运行记录。"));
            return;
        }
        if (selectedSession == null || !new File(Store.sessionsRoot(this), selectedSession).isDirectory()) {
            selectedSession = ss.get(0).getName();
        }
        LinearLayout pick = new LinearLayout(this);
        pick.setOrientation(LinearLayout.VERTICAL);
        int shown = 0;
        for (File f : ss) {
            if (shown++ >= 12) break;
            final String id = f.getName();
            Button b = button((id.equals(selectedSession) ? "● " : "○ ") + fmtId(id), v -> { selectedSession = id; showTab(1); });
            b.setGravity(Gravity.START | Gravity.CENTER_VERTICAL);
            pick.addView(b);
        }
        add(pick);
        final TextView loading = text("读取中…");
        add(loading);
        final File dir = new File(Store.sessionsRoot(this), selectedSession);
        new Thread(() -> {
            Session s = null;
            String err = null;
            try {
                s = Session.load(dir);
            } catch (IOException | IllegalArgumentException e) {
                err = e.getMessage();
            }
            final Session fs = s;
            final String fe = err;
            runOnUiThread(() -> {
                if (tab != 1) return;
                content.removeView(loading);
                if (fs == null) add(warn("读不了这个会话: " + fe));
                else renderSession(fs);
            });
        }, "load-session").start();
    }

    private void renderSession(final Session s) {
        Map<String, Object> sum = s.summary();
        Map<String, Object> ov = Json.asObj(sum.get("overall"));
        String st = s.endState();
        ProbeService.Status ps = ProbeService.status();
        boolean mine = s.id.equals(ps.sessionId);
        String stText = "done".equals(st) ? "已完成" : "aborted".equals(st) ? "已中止"
                : mine && ProbeService.running() ? "运行中(数据截至现在)"
                : mine && (ps.state == ProbeService.ST_DONE || ps.state == ProbeService.ST_ABORTED) ? "收尾中(稍后刷新)"
                : "未正常结束(进程被杀?)";
        add(title(fmtId(s.id) + " · " + stText));
        add(text("剧本: " + s.script().name + "\n真值样本(计入) " + ov.get("samples_counted") + ", 其中被标记 " + ov.get("flagged_samples")
                + "\nHNC 观测 " + ov.get("hnc_obs") + "(成功 " + ov.get("hnc_ok") + ", 失败 " + ov.get("hnc_errors") + ")"
                + "\n总命中率: " + pct(ov.get("hit"), ov.get("hit_ratio"), ov.get("hnc_ok"))));

        add(title("按步"));
        List<Object> steps = Json.asArr(sum.get("steps"));
        if (steps != null) {
            for (Object o : steps) {
                Map<String, Object> m = Json.asObj(o);
                if (m == null) continue;
                StringBuilder b = new StringBuilder();
                int idx = ((Number) m.get("index")).intValue();
                b.append(idx + 1).append(". ").append(m.get("label")).append("  [剧本 ").append(m.get("expect")).append("]");
                Object cnt = m.get("samples_counted");
                if (cnt instanceof Number && ((Number) cnt).longValue() == 0) {
                    b.append("\n   (没跑 / 被跳过)");
                } else {
                    b.append("\n   真值: ").append(dist(Json.asObj(m.get("truth_dist"))));
                    b.append("\n   前台: ").append(m.get("fg_pkg_top"));
                    Object fr = m.get("flagged_ratio");
                    if (fr instanceof Number && ((Number) fr).doubleValue() > 0) {
                        b.append("\n   偏差标记: ").append(Math.round(((Number) fr).doubleValue() * 100)).append("% 样本 · ")
                                .append(flagDist(Json.asObj(m.get("flags"))));
                    }
                    Object ok = m.get("hnc_ok");
                    if (ok instanceof Number && ((Number) ok).longValue() > 0) {
                        b.append("\n   HNC 活动: ").append(dist(Json.asObj(m.get("hnc_activity_dist"))));
                        b.append("\n   HNC 应用: ").append(dist(Json.asObj(m.get("hnc_app_dist"))));
                        if (m.get("app_hit_ratio") != null) b.append("(期望 ").append(m.get("want_hnc_app")).append(")");
                        b.append("\n   HNC 流量形态: ").append(dist(Json.asObj(m.get("hnc_traffic_dist"))));
                        b.append("\n   命中: ").append(pct(m.get("hit"), m.get("hit_ratio"), ok));
                    } else if (((Number) m.get("hnc_obs")).longValue() > 0) {
                        b.append("\n   HNC 全部失败: ").append(dist(Json.asObj(m.get("hnc_errors"))));
                    } else {
                        b.append("\n   HNC: 没有对照数据");
                    }
                }
                TextView t = text(b.toString());
                t.setTextSize(13);
                add(t);
            }
        }

        add(title("混淆计数(行 = 真值, 列 = HNC fg.activity)"));
        TextView mx = text(Summary.confusionText(sum));
        mx.setTypeface(Typeface.MONOSPACE);
        mx.setTextSize(11);
        mx.setTextIsSelectable(true);
        HorizontalScrollView hs = new HorizontalScrollView(this);
        hs.addView(mx);
        add(hs);
        add(note("列缩写: video=video_stream live=live_stream voice=voice_call vcall=video_call game=gaming down=download "
                + "up=upload browse=browsing bg=background none=HNC 找到本机但没给活动。真值 idle 时 none / bg 算命中。"
                + "只统计每步预热期之后的数据。"));

        add(title("导出"));
        add(note("导出的 JSON 含: 样本、HNC 观测、汇总、剧本、规则、App / 系统版本。不含 HNC 访问令牌。"));
        add(row(button("导出到下载目录", v -> export(s, false)), button("另存为…", v -> export(s, true))));
        add(button("删除此会话", v -> confirm("删除会话 " + fmtId(s.id) + "? 不可恢复。", () -> {
            if (ProbeService.running() && s.id.equals(ProbeService.status().sessionId)) {
                toast("正在运行的会话不能删");
                return;
            }
            Store.deleteSession(s.dir);
            selectedSession = null;
            showTab(1);
        })));
    }

    private void export(Session s, boolean saveAs) {
        final String name = "hnc-probe-" + s.id + ".json";
        final String json = Json.pretty(s.exportDoc(System.currentTimeMillis()));
        if (saveAs || Build.VERSION.SDK_INT < 29) {
            pendingExport = json;
            pendingExportName = name;
            Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                    .setType("application/json").putExtra(Intent.EXTRA_TITLE, name);
            startActivityForResult(i, REQ_SAVE_AS);
            return;
        }
        try {
            ContentValues cv = new ContentValues();
            cv.put(MediaStore.MediaColumns.DISPLAY_NAME, name);
            cv.put(MediaStore.MediaColumns.MIME_TYPE, "application/json");
            cv.put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/HNC-Probe");
            Uri u = getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
            if (u == null) throw new IOException("系统没给写入位置");
            try (OutputStream o = getContentResolver().openOutputStream(u)) {
                if (o == null) throw new IOException("打不开输出");
                o.write(json.getBytes(StandardCharsets.UTF_8));
            }
            alert("已导出", "下载/HNC-Probe/" + name + "\n(" + (json.length() / 1024) + " KB)");
        } catch (IOException | RuntimeException e) {
            alert("导出失败", e.getMessage() + "\n可以试试「另存为…」");
        }
    }

    // ═══ Activity 页 ══════════════════════════════════════════════════════

    private void buildActivityTab() {
        add(title("最近见过的 Activity 类名"));
        add(note("用途: 看清目标应用真实的 Activity 类名(比如进了直播间时是哪个类), 再写进标注规则的 activity 正则。"
                + "来源 usage = 系统使用情况记录(免 root), root = dumpsys。点一行复制类名, 长按复制一条规则草稿(JSON)。"));
        add(row(button("从使用情况记录刷新(24 小时)", v -> {
            RecentActivities r = Store.loadRecent(this);
            int n = TruthSampler.scanRecent(this, r, 24 * 3600_000L);
            Store.saveRecent(this, r);
            toast(n < 0 ? "读不了使用情况记录(没授权?)" : "读到 " + n + " 个事件");
            showTab(2);
        }), button("读当前前台(root)", v -> rootPeek())));
        add(button(onlyScriptPkgs ? "当前: 只看剧本 / 规则涉及的包(点切换)" : "当前: 显示全部包(点切换)", v -> {
            onlyScriptPkgs = !onlyScriptPkgs;
            showTab(2);
        }));
        List<String> filter = null;
        if (onlyScriptPkgs) {
            filter = new ArrayList<>();
            try {
                for (Step st : Script.parse(Store.scriptJson(this)).steps) if (!st.anyApp()) filter.add(st.app);
                filter.addAll(Rules.parse(Store.rulesJson(this)).packages.keySet());
            } catch (IOException | IllegalArgumentException ignored) {
                filter = null;
            }
        }
        RecentActivities r = Store.loadRecent(this);
        List<RecentActivities.Entry> l = r.list(filter);
        if (l.isEmpty()) add(text("(空) 先点「刷新」, 或跑一遍剧本。"));
        SimpleDateFormat f = new SimpleDateFormat("MM-dd HH:mm:ss", Locale.US);
        for (final RecentActivities.Entry e : l) {
            TextView t = text(e.pkg + "\n  " + e.cls + "\n  " + e.src + " · " + e.count + " 次 · 最后 " + f.format(new Date(e.last)));
            t.setTextSize(12);
            t.setPadding(0, dp(6), 0, dp(6));
            t.setOnClickListener(v -> copy("Activity", e.cls));
            t.setOnLongClickListener(v -> {
                copy("规则草稿", Json.pretty(RecentActivities.ruleDraft(e.pkg, e.cls)));
                return true;
            });
            add(t);
        }
    }

    private void rootPeek() {
        if (!Prefs.root(this)) {
            toast("先在设置里打开 root 模式");
            return;
        }
        toast("读取中…");
        new Thread(() -> {
            RootShell rs = new RootShell();
            String msg;
            if (!rs.open(15_000)) {
                msg = "su 不可用或没授权";
            } else {
                String out = rs.run(RootParsers.SAMPLE_CMD, 4000);
                rs.close();
                if (out == null) {
                    msg = "dumpsys 超时";
                } else {
                    Map<String, String> sec = RootParsers.split(out);
                    String[] act = RootParsers.resumedActivity(sec.get("ACT"));
                    RootParsers.Cam cam = RootParsers.camera(sec.get("CAM"));
                    String mode = RootParsers.audioMode(sec.get("AUD"));
                    List<String> rec = RootParsers.recordingPackages(sec.get("AUD"));
                    if (act != null) {
                        RecentActivities r = Store.loadRecent(this);
                        r.note(act[0], act[1], "root", System.currentTimeMillis());
                        Store.saveRecent(this, r);
                    }
                    msg = "前台: " + (act == null ? "解析不出" : act[0] + "\n  " + act[1])
                            + "\n相机: " + (cam == null ? "解析不出" : (cam.inUse ? "占用 " + (cam.pkg == null ? "" : cam.pkg) : "空闲"))
                            + "\n音频模式: " + (mode == null ? "解析不出" : mode)
                            + "\n录音: " + (rec == null ? "解析不出" : (rec.isEmpty() ? "无" : String.join(",", rec)))
                            + "\n\n(本机此刻前台是本 App; 想看别的应用的类名: 跑剧本时 root 模式会自动记下, 或用「刷新」读使用情况记录。)";
                }
            }
            final String m = msg;
            runOnUiThread(() -> {
                alert("root 只读结果", m);
                if (tab == 2) showTab(2);
            });
        }, "root-peek").start();
    }

    // ═══ 设置页 ═══════════════════════════════════════════════════════════

    private void buildSettingsTab() {
        add(title("权限"));
        boolean ua = TruthSampler.hasUsageAccess(this);
        add(text("使用情况访问(前台应用 / Activity): " + (ua ? "已授权" : "未授权")));
        if (!ua) add(button("去授权", v -> openUsageAccess()));
        if (Build.VERSION.SDK_INT >= 33) {
            boolean np = checkSelfPermission("android.permission.POST_NOTIFICATIONS") == 0;
            add(text("通知(每步结束提醒 / 通知栏按钮): " + (np ? "已授权" : "未授权")));
            if (!np) add(button("请求通知权限", v -> requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 9)));
        }
        add(button("电池优化设置(ColorOS 建议允许本 App 后台运行)", v -> {
            try {
                startActivity(new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS));
            } catch (RuntimeException e) {
                toast("打不开: " + e.getMessage());
            }
        }));

        add(title("采样"));
        final EditText iv = edit(String.valueOf(Prefs.interval(this)), "2–5", InputType.TYPE_CLASS_NUMBER);
        add(row(label("采样间隔(秒)"), iv, button("保存", v -> {
            try {
                int n = Integer.parseInt(iv.getText().toString().trim());
                if (n < 2 || n > 5) throw new NumberFormatException();
                Prefs.setInterval(this, n);
                toast("已保存(下次运行生效)");
            } catch (NumberFormatException e) {
                toast("填 2–5 的整数");
            }
        })));
        boolean rootOn = Prefs.root(this);
        add(text("root 模式: " + (rootOn ? "已开启" : "未开启")));
        add(note("开启后每次采样额外执行一条固定的只读命令(dumpsys activity activities / media.camera / audio, 用 grep 过滤),"
                + "拿到 Activity 完整类名、占用相机 / 录音的包名、系统音频模式; 启动时读一次 /sys/class/net/wlan0/address 作为在 HNC 里找本机的兜底。"
                + "不执行任何写操作。su 不可用时自动退回免 root 信号。"));
        add(button(rootOn ? "关闭 root 模式" : "开启 root 模式(会检查 su)", v -> {
            if (Prefs.root(this)) {
                Prefs.setRoot(this, false);
                showTab(3);
                return;
            }
            toast("检查 su… 如果 root 管理器弹窗请允许");
            new Thread(() -> {
                RootShell rs = new RootShell();
                boolean ok = rs.open(30_000);
                rs.close();
                runOnUiThread(() -> {
                    if (ok) Prefs.setRoot(this, true);
                    alert("root 模式", ok ? "su 可用(uid=0), 已开启。" : "su 不可用或被拒绝, 保持关闭。");
                    if (tab == 3) showTab(3);
                });
            }, "su-check").start();
        }));

        add(title("标注规则"));
        try {
            Rules r = Rules.parse(Store.rulesJson(this));
            int ph = 0;
            for (Rules.Rule x : r.rules) if (x.placeholder) ph++;
            add(text(r.name + (Store.customRules(this) ? " · 已导入" : " · 内置默认") + "\n生效 " + r.activeCount() + " 条, 待核实占位 " + ph
                    + " 条, 包映射 " + r.packages.size() + " 个"));
        } catch (IOException | IllegalArgumentException e) {
            add(warn("规则读不出来: " + e.getMessage()));
        }
        add(row(button("导入规则", v -> pickJson(REQ_RULES)),
                button("恢复默认", v -> confirm("恢复内置默认规则?", () -> { Store.resetRules(this); showTab(3); })),
                button("查看", v -> {
                    try {
                        showText("当前规则", Json.pretty(Json.parse(Store.rulesJson(this))));
                    } catch (IOException | IllegalArgumentException e) {
                        toast(e.getMessage());
                    }
                })));
        add(button("复制当前剧本 JSON(改完再导入)", v -> {
            try {
                copy("剧本", Store.scriptJson(this));
            } catch (IOException e) {
                toast(e.getMessage());
            }
        }));

        buildHncSettings();

        add(title("隐私"));
        add(note("数据只存在本 App 私有目录(卸载即删), 导出才会写到下载目录。除了连你填的 HNC 地址, 本 App 不联网, 没有任何统计上报。"
                + "只用于维护者自己的测试设备: 不抓包、不做中间人、不解密、不用无障碍服务。"));
        add(note("版本 " + Store.versionName(this) + " · Android " + Build.VERSION.RELEASE + " (SDK " + Build.VERSION.SDK_INT + ")"));
    }

    private void buildHncSettings() {
        add(title("HNC 对照(可选)"));
        add(note("在热点手机的 HNC 设置里先开「远程访问服务」(:8443), 再「生成配对码」(6 位, 120 秒有效), 填到下面点配对。"
                + "本 App 只调 GET /api/devices(只读)。"));
        final boolean on = Prefs.hncEnabled(this);
        add(button(on ? "对照: 已开启(点关闭)" : "对照: 未开启(点开启)", v -> {
            Prefs.setHncEnabled(this, !on);
            showTab(3);
        }));
        NetUtil.Wifi w = NetUtil.wifi(this);
        String addr = Prefs.hncAddr(this);
        final EditText ae = edit(addr == null ? "" : addr, w != null && w.gateway != null ? w.gateway + ":8443" : "192.168.43.1:8443",
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        add(label("HNC 地址(热点网关 IP[:端口], 只走 HTTPS)"));
        add(ae);
        add(row(button("保存地址", v -> saveAddr(ae.getText().toString())),
                button("用网关地址", v -> {
                    NetUtil.Wifi ww = NetUtil.wifi(this);
                    if (ww == null || ww.gateway == null) toast("拿不到 Wi-Fi 网关");
                    else ae.setText(ww.gateway + ":8443");
                })));
        add(text("本机 Wi-Fi IP: " + (w == null || w.ip == null ? "(没连 Wi-Fi)" : w.ip) + (w != null && w.gateway != null ? " · 网关 " + w.gateway : "")));
        String pin = Prefs.hncPin(this);
        add(text("证书: " + (pin == null ? "未信任(第一次测试连接时确认)" : "已信任 SHA-256 " + pin.substring(0, Math.min(23, pin.length())) + "…")));
        if (pin != null) add(button("清除证书信任", v -> { Prefs.setHncPin(this, null); showTab(3); }));
        String tok = Prefs.hncToken(this);
        add(text("凭据: " + (tok == null ? "未配对" : "已配对(令牌 " + tok.substring(0, Math.min(6, tok.length())) + "…, 14 天不用会失效)")));
        final EditText pe = edit("", "6 位配对码", InputType.TYPE_CLASS_NUMBER);
        add(row(pe, button("配对", v -> pair(pe.getText().toString().trim()))));
        final EditText te = edit("", "或手动粘贴令牌 TokenID.Secret", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        add(row(te, button("保存令牌", v -> {
            String t = te.getText().toString().trim();
            if (!HncAuth.validToken(t)) {
                toast("格式不对(应为 TokenID.Secret)");
                return;
            }
            Prefs.setHncToken(this, t);
            showTab(3);
        })));
        add(row(button("测试连接", v -> testHnc()), button("清除凭据", v -> confirm("清除本机保存的 HNC 令牌?(热点手机上的授权记录要在 HNC 里撤销)", () -> {
            Prefs.setHncToken(this, null);
            showTab(3);
        }))));
    }

    private boolean saveAddr(String in) {
        try {
            HncAuth.Addr a = HncAuth.parseAddr(in);
            String old = Prefs.hncAddr(this);
            Prefs.setHncAddr(this, a.display());
            toast(old != null && !old.equals(a.display()) ? "已保存(换了地址, 证书与令牌已清除)" : "已保存");
            showTab(3);
            return true;
        } catch (IllegalArgumentException e) {
            alert("地址不对", e.getMessage());
            return false;
        }
    }

    private HncClient client() {
        String addr = Prefs.hncAddr(this);
        if (addr == null) {
            alert("还没填地址", "先填 HNC 地址并保存。");
            return null;
        }
        return new HncClient(addr, Prefs.hncPin(this), Prefs.hncToken(this), Store.versionName(this));
    }

    private void pair(final String pin) {
        if (!HncAuth.validPin(pin)) {
            toast("配对码是 6 位数字");
            return;
        }
        final HncClient c = client();
        if (c == null) return;
        toast("配对中…");
        new Thread(() -> {
            NetUtil.Wifi w = NetUtil.wifi(this);
            HncClient.Result r = c.pair(pin, w == null ? null : w.network);
            runOnUiThread(() -> {
                if (r.untrustedFp != null) {
                    trustDialog(r, () -> pair(pin));
                } else if (r.token != null) {
                    Prefs.setHncToken(this, r.token);
                    alert("配对成功", "已拿到访问令牌。热点手机 HNC 的「已授权设备」里会多一条记录, 不用时可在那里撤销。");
                    showTab(3);
                } else {
                    alert("配对失败", r.describe());
                }
            });
        }, "hnc-pair").start();
    }

    private void testHnc() {
        final HncClient c = client();
        if (c == null) return;
        toast("连接中…");
        new Thread(() -> {
            NetUtil.Wifi w = NetUtil.wifi(this);
            HncClient.Result r = c.devices(w == null ? null : w.network);
            runOnUiThread(() -> {
                if (r.untrustedFp != null) {
                    trustDialog(r, this::testHnc);
                } else if (r.ok()) {
                    HncObs o = HncParser.parse(r.body, w == null ? null : w.ip, null);
                    alert("连接正常", o.ok ? obsText(o, o.t) + "\n(本机 IP " + o.ip + " · MAC " + o.mac + ")" : o.err);
                } else if (r.code == 401 && Prefs.hncToken(this) == null) {
                    alert("证书 OK, 还没配对", "填配对码点「配对」。");
                } else {
                    alert("连接失败", r.describe());
                }
            });
        }, "hnc-test").start();
    }

    private void trustDialog(HncClient.Result r, Runnable retry) {
        new AlertDialog.Builder(this)
                .setTitle(r.certChanged ? "HNC 证书变了" : "确认 HNC 证书")
                .setMessage((r.certChanged ? r.err + "\n\n" : "")
                        + "HNC 用的是自签证书。只有确认这台就是你自己的 HNC 热点手机时才信任。\n\nSHA-256 指纹:\n" + r.untrustedFp
                        + "\n\n核对方法(热点手机 root shell, 结果是小写无冒号的同一串):\n"
                        + "grep -v CERTIFICATE /data/local/hnc/data/httpd_cert.pem | tr -d '\\n' | base64 -d | sha256sum"
                        + "\n\n信任后本 App 只接受这一个证书, 且只用于你填的这个地址。")
                .setPositiveButton("信任", (d, wh) -> {
                    Prefs.setHncPin(this, r.untrustedFp);
                    if (tab == 3) showTab(3);
                    retry.run();
                })
                .setNegativeButton("取消", null)
                .show();
    }

    // ═══ 文件导入 / 另存 ═════════════════════════════════════════════════

    private void pickJson(int req) {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")
                .putExtra(Intent.EXTRA_MIME_TYPES, new String[]{"application/json", "text/plain", "application/octet-stream"});
        try {
            startActivityForResult(i, req);
        } catch (RuntimeException e) {
            toast("没有可用的文件选择器");
        }
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (res != RESULT_OK || data == null || data.getData() == null) return;
        Uri u = data.getData();
        if (req == REQ_SAVE_AS) {
            if (pendingExport == null) return;
            try (OutputStream o = getContentResolver().openOutputStream(u)) {
                if (o == null) throw new IOException("打不开输出");
                o.write(pendingExport.getBytes(StandardCharsets.UTF_8));
                toast("已保存 " + pendingExportName);
            } catch (IOException | RuntimeException e) {
                alert("保存失败", e.getMessage());
            }
            pendingExport = null;
            return;
        }
        try {
            String text = Store.readUri(this, u);
            if (req == REQ_SCRIPT) {
                if (ProbeService.running()) {
                    alert("正在运行", "剧本运行中不能换剧本, 先中止。");
                    return;
                }
                Script s = Store.saveScript(this, text);
                alert("剧本已导入", s.name + "\n" + s.steps.size() + " 步, 约 " + Math.round(s.totalMinutes()) + " 分钟");
            } else if (req == REQ_RULES) {
                Rules r = Store.saveRules(this, text);
                alert("规则已导入", r.name + "\n生效 " + r.activeCount() + " 条 / 共 " + r.rules.size() + " 条"
                        + (ProbeService.running() ? "\n(本次运行仍用旧规则, 下次生效)" : ""));
            }
            showTab(tab);
        } catch (IllegalArgumentException e) {
            alert("导入失败(没有保存)", e.getMessage());
        } catch (IOException e) {
            alert("读文件失败", e.getMessage());
        }
    }

    // ═══ 小工具 ═══════════════════════════════════════════════════════════

    private void openUsageAccess() {
        try {
            Intent i = new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS);
            if (Build.VERSION.SDK_INT >= 29) i.setData(Uri.parse("package:" + getPackageName()));
            startActivity(i);
        } catch (RuntimeException e) {
            try {
                startActivity(new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS));
            } catch (RuntimeException e2) {
                toast("打不开设置页, 请手动到 设置 → 应用 → 特殊权限 → 使用情况访问");
            }
        }
    }

    private static String yn(Boolean b) { return b == null ? "?" : (b ? "是" : "否"); }

    private static String fmtMin(double m) {
        return m == Math.rint(m) ? ((long) m) + " 分钟" : String.format(Locale.US, "%.1f 分钟", m);
    }

    private static String fmtId(String id) {
        // yyyyMMdd-HHmmss → yyyy-MM-dd HH:mm:ss
        if (id.length() == 15 && id.charAt(8) == '-') {
            return id.substring(0, 4) + "-" + id.substring(4, 6) + "-" + id.substring(6, 8) + " "
                    + id.substring(9, 11) + ":" + id.substring(11, 13) + ":" + id.substring(13, 15);
        }
        return id;
    }

    private static String pct(Object hit, Object ratio, Object ok) {
        if (!(ratio instanceof Number)) return "-(没有成功的 HNC 观测)";
        return hit + "/" + ok + " = " + Math.round(((Number) ratio).doubleValue() * 100) + "%";
    }

    private static String dist(Map<String, Object> m) {
        if (m == null || m.isEmpty()) return "-";
        long tot = 0;
        for (Object v : m.values()) if (v instanceof Number) tot += ((Number) v).longValue();
        List<Map.Entry<String, Object>> es = new ArrayList<>(m.entrySet());
        es.sort((a, b) -> Long.compare(((Number) b.getValue()).longValue(), ((Number) a.getValue()).longValue()));
        StringBuilder b = new StringBuilder();
        int k = 0;
        for (Map.Entry<String, Object> e : es) {
            if (k++ >= 4) { b.append(" …"); break; }
            long v = ((Number) e.getValue()).longValue();
            if (b.length() > 0) b.append(", ");
            b.append(e.getKey()).append(" ").append(tot > 0 ? Math.round(v * 100.0 / tot) : 0).append("%");
        }
        return b.toString();
    }

    private static String flagDist(Map<String, Object> m) {
        if (m == null || m.isEmpty()) return "-";
        StringBuilder b = new StringBuilder();
        for (Map.Entry<String, Object> e : m.entrySet()) {
            if (b.length() > 0) b.append("; ");
            b.append(Labeler.flagLabel(e.getKey())).append(" ×").append(e.getValue());
        }
        return b.toString();
    }

    private int dp(int v) { return Math.round(v * getResources().getDisplayMetrics().density); }

    private void add(View v) { content.addView(v); }

    private TextView text(String s) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(14);
        t.setTextColor(Color.BLACK);
        t.setPadding(0, dp(3), 0, dp(3));
        return t;
    }

    private TextView title(String s) {
        TextView t = text(s);
        t.setTextSize(16);
        t.setTypeface(null, Typeface.BOLD);
        t.setTextColor(C_ACCENT);
        t.setPadding(0, dp(14), 0, dp(4));
        return t;
    }

    private TextView note(String s) {
        TextView t = text(s);
        t.setTextSize(12);
        t.setTextColor(C_DIM);
        return t;
    }

    private TextView warn(String s) {
        TextView t = text(s);
        t.setTextColor(C_WARN);
        return t;
    }

    private TextView label(String s) {
        TextView t = text(s);
        t.setGravity(Gravity.CENTER_VERTICAL);
        return t;
    }

    private Button button(String s, View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(s);
        b.setAllCaps(false);
        b.setOnClickListener(l);
        return b;
    }

    private EditText edit(String v, String hint, int type) {
        EditText e = new EditText(this);
        e.setText(v);
        e.setHint(hint);
        e.setSingleLine(true); // 先单行再设类型: 反过来 setSingleLine 会冲掉密码掩码
        e.setInputType(type);
        return e;
    }

    private LinearLayout row(View... vs) {
        LinearLayout r = new LinearLayout(this);
        r.setOrientation(LinearLayout.HORIZONTAL);
        for (View v : vs) r.addView(v, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        return r;
    }

    private void toast(String s) { Toast.makeText(this, s, Toast.LENGTH_SHORT).show(); }

    private void alert(String t, String m) {
        new AlertDialog.Builder(this).setTitle(t).setMessage(m).setPositiveButton("好", null).show();
    }

    private void confirm(String m, Runnable yes) {
        new AlertDialog.Builder(this).setMessage(m).setPositiveButton("确定", (d, w) -> yes.run())
                .setNegativeButton("取消", null).show();
    }

    private void showText(String t, String body) {
        TextView tv = text(body);
        tv.setTypeface(Typeface.MONOSPACE);
        tv.setTextSize(11);
        tv.setTextIsSelectable(true);
        tv.setPadding(dp(12), dp(8), dp(12), dp(8));
        ScrollView sv = new ScrollView(this);
        sv.addView(tv);
        new AlertDialog.Builder(this).setTitle(t).setView(sv)
                .setPositiveButton("复制", (d, w) -> copy(t, body)).setNegativeButton("关闭", null).show();
    }

    private void copy(String label, String s) {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) {
            cm.setPrimaryClip(ClipData.newPlainText(label, s));
            toast("已复制" + label);
        }
    }
}
