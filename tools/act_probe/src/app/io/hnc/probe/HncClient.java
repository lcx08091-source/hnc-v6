package io.hnc.probe;

import android.net.Network;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import io.hnc.probe.core.HncAuth;

/**
 * 只连用户填的这一个 HNC 地址(https://&lt;私网IP&gt;:&lt;端口&gt;), 只调两个接口:
 *   POST /api/pair/verify   用配对码换令牌(302 + Set-Cookie: hnc_token=...)
 *   GET  /api/devices       只读设备列表
 * 证书: HNC 用自签证书, 且 -bind auto 时 SAN 里只有 127.0.0.1 / localhost(见 tls.go), 系统 CA 校验
 * 和主机名校验必然失败。这里改成「首次信任 + 指纹固定」: 第一次连接把证书 SHA-256 指纹给用户确认,
 * 之后只接受这一个指纹; 主机名只认用户填的 IP。这套信任只装在本类自己的连接上, 不改全局 TLS 设置。
 * 不跟随重定向(防止被带到别的地址)。
 */
final class HncClient {
    static final class Result {
        int code;
        String body;
        /** 网络 / TLS 层错误(code=0) */
        String err;
        /** 证书没被信任(首次连接或证书变了)时的实际指纹 */
        String untrustedFp;
        boolean certChanged;
        /** 配对成功拿到的令牌 */
        String token;

        boolean ok() { return code == 200 && body != null; }

        String describe() {
            if (err != null) return err;
            return HncAuth.describe(code, body);
        }
    }

    private static final int MAX_BODY = 4 << 20;

    private final String host;
    private final int port;
    private final String pinnedFp;
    private final String token;
    private final String ua;

    HncClient(String addr, String pinnedFp, String token, String versionName) {
        HncAuth.Addr a = HncAuth.parseAddr(addr);
        this.host = a.host;
        this.port = a.port;
        this.pinnedFp = pinnedFp;
        this.token = token;
        this.ua = "HNC-Probe/" + versionName + " (Android)";
    }

    Result devices(Network net) {
        return request("GET", "/api/devices", null, net, true);
    }

    Result pair(String pin, Network net) {
        if (!HncAuth.validPin(pin)) {
            Result r = new Result();
            r.err = "配对码应为 6 位数字";
            return r;
        }
        Result r = request("POST", "/api/pair/verify", "pin=" + pin, net, false);
        if (r.code == 302 && r.token == null && r.err == null) r.err = "HNC 回了跳转但没给令牌(版本不对?)";
        if (r.code != 302 && r.err == null) r.err = "配对失败: " + HncAuth.describe(r.code, r.body);
        return r;
    }

    /** 静态嵌套类(不用非静态内部类, 理由见 TruthSampler.CamCb)。 */
    private static final class PinTrust implements X509TrustManager {
        private final String pinnedFp;
        private final String[] seen;

        PinTrust(String pinnedFp, String[] seen) {
            this.pinnedFp = pinnedFp;
            this.seen = seen;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("不接受客户端证书");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            if (chain == null || chain.length == 0) throw new CertificateException("没有证书");
            String fp;
            try {
                fp = HncAuth.fingerprintHex(MessageDigest.getInstance("SHA-256").digest(chain[0].getEncoded()));
            } catch (GeneralSecurityException e) {
                throw new CertificateException(e);
            }
            seen[0] = fp;
            if (pinnedFp == null || !pinnedFp.equalsIgnoreCase(fp)) throw new CertificateException("证书未信任");
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    private Result request(String method, String path, String form, Network net, boolean withCookie) {
        Result r = new Result();
        final String[] seen = new String[1];
        HttpsURLConnection c = null;
        try {
            URL url = new URL("https", host, port, path);
            URLConnection uc = net != null ? net.openConnection(url) : url.openConnection();
            if (!(uc instanceof HttpsURLConnection)) throw new IOException("不是 HTTPS 连接");
            c = (HttpsURLConnection) uc;
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{new PinTrust(pinnedFp, seen)}, new SecureRandom());
            c.setSSLSocketFactory(ctx.getSocketFactory());
            c.setHostnameVerifier((h, s) -> host.equalsIgnoreCase(h));
            c.setInstanceFollowRedirects(false);
            c.setUseCaches(false);
            c.setConnectTimeout(4000);
            c.setReadTimeout(8000);
            c.setRequestMethod(method);
            c.setRequestProperty("User-Agent", ua);
            c.setRequestProperty("Accept", "application/json");
            if (withCookie && token != null) c.setRequestProperty("Cookie", HncAuth.COOKIE + "=" + token);
            if (form != null) {
                byte[] b = form.getBytes(StandardCharsets.UTF_8);
                c.setDoOutput(true);
                c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                c.setFixedLengthStreamingMode(b.length);
                try (OutputStream o = c.getOutputStream()) {
                    o.write(b);
                }
            }
            r.code = c.getResponseCode();
            List<String> cookies = new ArrayList<>();
            for (Map.Entry<String, List<String>> e : c.getHeaderFields().entrySet()) {
                if (e.getKey() != null && e.getKey().equalsIgnoreCase("Set-Cookie") && e.getValue() != null) cookies.addAll(e.getValue());
            }
            r.token = HncAuth.tokenFromSetCookie(cookies);
            InputStream in = r.code >= 400 ? c.getErrorStream() : c.getInputStream();
            if (in != null) {
                try (InputStream is = in) {
                    r.body = readCapped(is);
                }
            }
        } catch (SSLException e) {
            r.code = 0;
            if (seen[0] != null && (pinnedFp == null || !pinnedFp.equalsIgnoreCase(seen[0]))) {
                r.untrustedFp = seen[0];
                r.certChanged = pinnedFp != null;
                r.err = r.certChanged
                        ? "HNC 的证书变了(热点 IP 变了 HNC 会重新生成证书; 也可能连到了别的设备)。确认是自己的 HNC 后再信任新指纹"
                        : "HNC 证书还没被信任(自签证书), 需要先确认指纹";
            } else {
                r.err = "TLS 握手失败: " + e.getMessage();
            }
        } catch (SocketTimeoutException e) {
            r.code = 0;
            r.err = "连接超时(HNC 远程访问开了吗? 地址 / 端口对吗?)";
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            r.code = 0;
            r.err = "连不上 HNC: " + e.getClass().getSimpleName() + (e.getMessage() == null ? "" : " " + e.getMessage());
        } finally {
            if (c != null) c.disconnect();
        }
        return r;
    }

    private static String readCapped(InputStream in) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            bo.write(buf, 0, n);
            if (bo.size() > MAX_BODY) throw new IOException("HNC 返回太大(>4MB)");
        }
        return new String(bo.toByteArray(), StandardCharsets.UTF_8);
    }
}
