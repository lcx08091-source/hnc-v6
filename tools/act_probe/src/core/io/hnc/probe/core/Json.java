package io.hnc.probe.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 极简 JSON 解析 / 序列化(纯 Java, 不依赖 org.json —— 这样 test.sh 能在普通 JVM 上跑)。
 * 对象 → LinkedHashMap(保持键顺序), 数组 → ArrayList, 整数 → Long, 小数 → Double。
 */
public final class Json {
    private Json() {}

    public static Object parse(String s) {
        if (s == null) throw new IllegalArgumentException("JSON 为空");
        P p = new P(s);
        p.ws();
        Object v = p.value(0);
        p.ws();
        if (p.i != s.length()) throw p.err("末尾有多余内容");
        return v;
    }

    /** 解析并要求根是对象。 */
    public static Map<String, Object> parseObject(String s) {
        Map<String, Object> m = asObj(parse(s));
        if (m == null) throw new IllegalArgumentException("JSON 根必须是对象 {...}");
        return m;
    }

    private static final class P {
        final String s;
        int i;

        P(String s) {
            this.s = s;
            if (s.length() > 0 && s.charAt(0) == '﻿') i = 1; // UTF-8 BOM
        }

        IllegalArgumentException err(String m) {
            return new IllegalArgumentException("JSON 解析失败(第 " + (i + 1) + " 个字符): " + m);
        }

        void ws() {
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++;
                else break;
            }
        }

        char peek() {
            if (i >= s.length()) throw err("意外结束");
            return s.charAt(i);
        }

        Object value(int depth) {
            if (depth > 64) throw err("嵌套太深");
            char c = peek();
            switch (c) {
                case '{': return obj(depth);
                case '[': return arr(depth);
                case '"': return str();
                case 't': lit("true"); return Boolean.TRUE;
                case 'f': lit("false"); return Boolean.FALSE;
                case 'n': lit("null"); return null;
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) return num();
                    throw err("无法识别的字符 '" + c + "'");
            }
        }

        void lit(String w) {
            if (!s.startsWith(w, i)) throw err("应为 " + w);
            i += w.length();
        }

        Map<String, Object> obj(int d) {
            Map<String, Object> m = new LinkedHashMap<>();
            i++;
            ws();
            if (peek() == '}') { i++; return m; }
            while (true) {
                ws();
                if (peek() != '"') throw err("对象的键必须是带双引号的字符串");
                String k = str();
                ws();
                if (peek() != ':') throw err("键 \"" + k + "\" 后缺少 ':'");
                i++;
                ws();
                m.put(k, value(d + 1));
                ws();
                char c = peek();
                if (c == ',') { i++; continue; }
                if (c == '}') { i++; return m; }
                throw err("缺少 ',' 或 '}'");
            }
        }

        List<Object> arr(int d) {
            List<Object> a = new ArrayList<>();
            i++;
            ws();
            if (peek() == ']') { i++; return a; }
            while (true) {
                ws();
                a.add(value(d + 1));
                ws();
                char c = peek();
                if (c == ',') { i++; continue; }
                if (c == ']') { i++; return a; }
                throw err("缺少 ',' 或 ']'");
            }
        }

        String str() {
            i++; // 开头的 "
            StringBuilder b = new StringBuilder();
            while (true) {
                if (i >= s.length()) throw err("字符串没有结束");
                char c = s.charAt(i++);
                if (c == '"') return b.toString();
                if (c == '\\') {
                    if (i >= s.length()) throw err("转义不完整");
                    char e = s.charAt(i++);
                    switch (e) {
                        case '"': b.append('"'); break;
                        case '\\': b.append('\\'); break;
                        case '/': b.append('/'); break;
                        case 'b': b.append('\b'); break;
                        case 'f': b.append('\f'); break;
                        case 'n': b.append('\n'); break;
                        case 'r': b.append('\r'); break;
                        case 't': b.append('\t'); break;
                        case 'u':
                            if (i + 4 > s.length()) throw err("\\u 转义不完整");
                            try {
                                b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                            } catch (NumberFormatException ex) {
                                throw err("非法 \\u 转义");
                            }
                            i += 4;
                            break;
                        default:
                            throw err("非法转义 \\" + e);
                    }
                } else if (c < 0x20) {
                    throw err("字符串里有未转义的控制字符");
                } else {
                    b.append(c);
                }
            }
        }

        Object num() {
            int st = i;
            if (s.charAt(i) == '-') i++;
            while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
            boolean frac = false;
            if (i < s.length() && s.charAt(i) == '.') {
                frac = true;
                i++;
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
            }
            if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                frac = true;
                i++;
                if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
            }
            String t = s.substring(st, i);
            try {
                if (!frac && t.length() < 18) return Long.parseLong(t);
                return Double.parseDouble(t);
            } catch (NumberFormatException ex) {
                throw err("非法数字 " + t);
            }
        }
    }

    // ─── 序列化 ──────────────────────────────────────────────────────────

    public static String stringify(Object v) {
        StringBuilder b = new StringBuilder();
        write(b, v, -1, 0);
        return b.toString();
    }

    public static String pretty(Object v) {
        StringBuilder b = new StringBuilder();
        write(b, v, 2, 0);
        return b.toString();
    }

    private static void nl(StringBuilder b, int ind, int lvl) {
        if (ind < 0) return;
        b.append('\n');
        for (int k = 0; k < ind * lvl; k++) b.append(' ');
    }

    @SuppressWarnings("rawtypes")
    private static void write(StringBuilder b, Object v, int ind, int lvl) {
        if (v == null) {
            b.append("null");
        } else if (v instanceof String) {
            quote(b, (String) v);
        } else if (v instanceof Boolean) {
            b.append(v.toString());
        } else if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) b.append("null");
            else if (d == Math.rint(d) && Math.abs(d) < 1e15) b.append((long) d);
            else b.append(Double.toString(d));
        } else if (v instanceof Number) {
            b.append(v.toString());
        } else if (v instanceof Map) {
            Map m = (Map) v;
            if (m.isEmpty()) { b.append("{}"); return; }
            b.append('{');
            boolean first = true;
            for (Object o : m.entrySet()) {
                Map.Entry e = (Map.Entry) o;
                if (!first) b.append(',');
                first = false;
                nl(b, ind, lvl + 1);
                quote(b, String.valueOf(e.getKey()));
                b.append(ind < 0 ? ":" : ": ");
                write(b, e.getValue(), ind, lvl + 1);
            }
            nl(b, ind, lvl);
            b.append('}');
        } else if (v instanceof Collection) {
            Collection c = (Collection) v;
            if (c.isEmpty()) { b.append("[]"); return; }
            b.append('[');
            boolean first = true;
            for (Object o : c) {
                if (!first) b.append(',');
                first = false;
                nl(b, ind, lvl + 1);
                write(b, o, ind, lvl + 1);
            }
            nl(b, ind, lvl);
            b.append(']');
        } else if (v instanceof Object[]) {
            List<Object> l = new ArrayList<>();
            for (Object o : (Object[]) v) l.add(o);
            write(b, l, ind, lvl);
        } else {
            quote(b, v.toString());
        }
    }

    private static void quote(StringBuilder b, String s) {
        b.append('"');
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20 || c == ' ' || c == ' ') {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        b.append('"');
    }

    // ─── 取值小工具 ──────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asObj(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : null;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> asArr(Object o) {
        return o instanceof List ? (List<Object>) o : null;
    }

    public static String str(Map<String, Object> m, String k) {
        Object v = m == null ? null : m.get(k);
        return v instanceof String ? (String) v : null;
    }

    /** 字符串, 空串视为 null。 */
    public static String strNE(Map<String, Object> m, String k) {
        String s = str(m, k);
        return s == null || s.isEmpty() ? null : s;
    }

    public static Double num(Map<String, Object> m, String k) {
        Object v = m == null ? null : m.get(k);
        return v instanceof Number ? ((Number) v).doubleValue() : null;
    }

    public static Long lng(Map<String, Object> m, String k) {
        Object v = m == null ? null : m.get(k);
        return v instanceof Number ? ((Number) v).longValue() : null;
    }

    public static Boolean bool(Map<String, Object> m, String k) {
        Object v = m == null ? null : m.get(k);
        return v instanceof Boolean ? (Boolean) v : null;
    }
}
