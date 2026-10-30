package io.hnc.probe.core;

import java.util.List;
import java.util.Map;

/**
 * HNC 远程访问鉴权相关的纯逻辑(对应 daemon/hnc_httpd 的 middleware.go / pair.go / auth.go):
 *  - 远程端口 :8443 只走 HTTPS(自签证书, 见 tls.go); /api/devices 不在公开路径里, 必须带
 *    Cookie: hnc_token=&lt;TokenID&gt;.&lt;Secret&gt;(没有 Bearer / Authorization 头这条路);
 *  - 令牌只能靠配对拿: 热点手机 HNC 设置里「生成配对码」(6 位, 120 秒有效), 本 App
 *    POST /api/pair/verify (表单 pin=xxxxxx) → 302 + Set-Cookie: hnc_token=...;
 *  - 每 IP 10 分钟内错 5 次锁定(指数退避), 同一配对码错 10 次作废;
 *  - 令牌 14 天不用失效; 热点手机可在「已授权设备」里撤销。
 */
public final class HncAuth {
    private HncAuth() {}

    public static final int DEFAULT_PORT = 8443;
    public static final String COOKIE = "hnc_token";

    public static final class Addr {
        public final String host;
        public final int port;

        Addr(String host, int port) { this.host = host; this.port = port; }

        public String display() { return host + ":" + port; }
    }

    /**
     * 解析用户填的 HNC 地址: "192.168.43.1" / "192.168.43.1:8443" / "https://192.168.43.1:8443/"。
     * 只接受私网 IPv4(热点网关就在局域网里; 也避免误把数据发到公网)。
     */
    public static Addr parseAddr(String in) {
        if (in == null || in.trim().isEmpty()) throw new IllegalArgumentException("请填 HNC 地址(热点手机的网关 IP, 如 192.168.43.1)");
        String s = in.trim();
        String low = s.toLowerCase();
        if (low.startsWith("http://")) {
            throw new IllegalArgumentException("HNC 远程访问只走 HTTPS(端口 8443), 不要填 http://");
        }
        if (low.startsWith("https://")) s = s.substring(8);
        while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        if (s.contains("/") || s.contains("?") || s.contains("@")) throw new IllegalArgumentException("地址只填 IP[:端口], 不要带路径");
        String host = s;
        int port = DEFAULT_PORT;
        int c = s.lastIndexOf(':');
        if (c >= 0) {
            host = s.substring(0, c);
            try {
                port = Integer.parseInt(s.substring(c + 1));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("端口不是数字");
            }
            if (port < 1 || port > 65535) throw new IllegalArgumentException("端口超出范围");
        }
        if (!isPrivateIPv4(host)) {
            throw new IllegalArgumentException("只支持私网 IPv4 地址(10.x / 172.16–31.x / 192.168.x), 当前: " + host);
        }
        return new Addr(host, port);
    }

    public static boolean isPrivateIPv4(String h) {
        if (h == null) return false;
        String[] p = h.split("\\.", -1);
        if (p.length != 4) return false;
        int[] v = new int[4];
        for (int i = 0; i < 4; i++) {
            if (p[i].isEmpty() || p[i].length() > 3 || !p[i].matches("\\d+")) return false;
            v[i] = Integer.parseInt(p[i]);
            if (v[i] > 255) return false;
        }
        return v[0] == 10 || (v[0] == 172 && v[1] >= 16 && v[1] <= 31) || (v[0] == 192 && v[1] == 168);
    }

    /** 令牌格式: TokenID(8 字节 base64url ≈ 11 字符).Secret(24 字节 ≈ 32 字符)。 */
    public static boolean validToken(String t) {
        return t != null && t.matches("[A-Za-z0-9_-]{8,32}\\.[A-Za-z0-9_-]{16,64}");
    }

    public static boolean validPin(String p) {
        return p != null && p.matches("\\d{6}");
    }

    /** 从响应的 Set-Cookie 头里取 hnc_token 的值(清除 cookie 的空值忽略)。 */
    public static String tokenFromSetCookie(List<String> headers) {
        if (headers == null) return null;
        for (String h : headers) {
            if (h == null) continue;
            String t = h.trim();
            if (!t.startsWith(COOKIE + "=")) continue;
            int semi = t.indexOf(';');
            String v = t.substring(COOKIE.length() + 1, semi < 0 ? t.length() : semi).trim();
            if (validToken(v)) return v;
        }
        return null;
    }

    /** HTTP 失败的中文说明(body 是 HNC 返回的 JSON {"error":...} 时带上)。 */
    public static String describe(int code, String body) {
        String detail = null;
        if (body != null) {
            try {
                Map<String, Object> m = Json.parseObject(body);
                detail = Json.str(m, "error");
                Long rem = Json.lng(m, "attempts_remaining");
                Long lock = Json.lng(m, "locked_for_sec");
                if (rem != null) detail = (detail == null ? "" : detail) + ", 还能试 " + rem + " 次";
                if (lock != null) detail = (detail == null ? "" : detail) + ", 锁定 " + lock + " 秒";
            } catch (IllegalArgumentException ignored) {
                detail = null;
            }
        }
        String base;
        switch (code) {
            case 0: base = "连不上 HNC"; break;
            case 401: base = "凭据无效或已失效(令牌 14 天不用会过期, 也可能在热点手机上被撤销), 请重新配对"; break;
            case 403: base = "HNC 开了 WebUI 访问白名单, 本机不在名单里(热点手机 HNC 设置 → 远程访问里放行本机)"; break;
            case 404: base = "地址不对(这个端口上不是 HNC?)"; break;
            case 410: base = "配对码已过期或已作废, 在热点手机上重新生成"; break;
            case 429: base = "尝试太多被暂时锁定, 稍后再试"; break;
            case 400: base = "请求被拒绝"; break;
            default: base = "HTTP " + code;
        }
        return detail == null || detail.isEmpty() ? base : base + "(" + detail + ")";
    }

    /** SHA-256 摘要 → "AB:CD:..." */
    public static String fingerprintHex(byte[] digest) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < digest.length; i++) {
            if (i > 0) b.append(':');
            b.append(String.format("%02X", digest[i] & 0xff));
        }
        return b.toString();
    }
}
