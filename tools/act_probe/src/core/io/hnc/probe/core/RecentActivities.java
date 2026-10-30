package io.hnc.probe.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 「最近见过的 Activity 类名」: 给维护者看真实类名、照着写规则用。
 * 来源: usage(使用情况记录里的 ACTIVITY_RESUMED 事件)/ root(dumpsys)。最多保留 MAX 条。
 */
public final class RecentActivities {
    public static final int MAX = 300;

    public static final class Entry {
        public String pkg, cls, src;
        public long first, last;
        public long count;
    }

    private final Map<String, Entry> map = new LinkedHashMap<>();

    public synchronized void note(String pkg, String cls, String src, long t) {
        if (pkg == null || cls == null) return;
        String k = pkg + "/" + cls;
        Entry e = map.get(k);
        if (e == null) {
            if (map.size() >= MAX) dropOldest();
            e = new Entry();
            e.pkg = pkg;
            e.cls = cls;
            e.first = t;
            map.put(k, e);
        }
        e.count++;
        if (t >= e.last) e.last = t;
        if (src != null && (e.src == null || !e.src.contains(src))) e.src = e.src == null ? src : e.src + "+" + src;
    }

    private void dropOldest() {
        String oldest = null;
        long ot = Long.MAX_VALUE;
        for (Map.Entry<String, Entry> e : map.entrySet()) {
            if (e.getValue().last < ot) { ot = e.getValue().last; oldest = e.getKey(); }
        }
        if (oldest != null) map.remove(oldest);
    }

    /** 按最后出现时间倒序; pkgFilter 非空时只留这些包。 */
    public synchronized List<Entry> list(List<String> pkgFilter) {
        List<Entry> l = new ArrayList<>();
        for (Entry e : map.values()) if (pkgFilter == null || pkgFilter.contains(e.pkg)) l.add(e);
        Collections.sort(l, (a, b) -> Long.compare(b.last, a.last));
        return l;
    }

    public synchronized int size() { return map.size(); }

    public synchronized String toJson() {
        List<Object> l = new ArrayList<>();
        for (Entry e : map.values()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("pkg", e.pkg);
            m.put("cls", e.cls);
            m.put("src", e.src);
            m.put("first", e.first);
            m.put("last", e.last);
            m.put("count", e.count);
            l.add(m);
        }
        return Json.stringify(l);
    }

    public static RecentActivities fromJson(String s) {
        RecentActivities r = new RecentActivities();
        if (s == null) return r;
        try {
            List<Object> l = Json.asArr(Json.parse(s));
            if (l == null) return r;
            for (Object o : l) {
                Map<String, Object> m = Json.asObj(o);
                if (m == null || Json.str(m, "pkg") == null || Json.str(m, "cls") == null) continue;
                Entry e = new Entry();
                e.pkg = Json.str(m, "pkg");
                e.cls = Json.str(m, "cls");
                e.src = Json.str(m, "src");
                Long f = Json.lng(m, "first"), la = Json.lng(m, "last"), c = Json.lng(m, "count");
                e.first = f == null ? 0 : f;
                e.last = la == null ? 0 : la;
                e.count = c == null ? 1 : c;
                r.map.put(e.pkg + "/" + e.cls, e);
            }
        } catch (IllegalArgumentException ignored) {
            // 文件坏了就当空的
        }
        return r;
    }

    /** 由一个类名生成一条规则草稿(enabled=false, then 待维护者填)。 */
    public static Map<String, Object> ruleDraft(String pkg, String cls) {
        Map<String, Object> when = new LinkedHashMap<>();
        when.put("pkg", pkg);
        // 类名只含 [A-Za-z0-9_.$], 转义 . 和 $ 即可
        when.put("activity", "^" + cls.replace(".", "\\.").replace("$", "\\$") + "$");
        Map<String, Object> r = new LinkedHashMap<>();
        String simple = cls.substring(cls.lastIndexOf('.') + 1);
        r.put("id", (pkg.substring(pkg.lastIndexOf('.') + 1) + "_" + simple).replaceAll("[^A-Za-z0-9_]", "_").toLowerCase());
        r.put("enabled", false);
        r.put("when", when);
        r.put("then", "填活动id");
        r.put("note", "由『最近 Activity』页生成; 把 then 改成活动 id、enabled 改 true 后导入");
        return r;
    }
}
