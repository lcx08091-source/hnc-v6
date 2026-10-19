package io.hnc.probe;

import io.hnc.probe.core.HncObs;
import io.hnc.probe.core.HncParser;

/**
 * 可选集成测试(it_hnc.sh 调用): 对一个真的 hnc_httpd 走一遍 App 用的鉴权流程 ——
 * 证书指纹固定 → 401 → 错误配对码 → 正确配对码拿令牌 → 配对码一次性 → 带令牌 GET /api/devices → 篡改令牌 401。
 * 用的是 App 里原样的 HncClient(android.net.Network 用桩代替)。
 */
public class ITMain {
    static int fail = 0;
    static void check(boolean c, String what) { System.out.println((c ? "ok   " : "FAIL ") + what); if (!c) fail++; }

    public static void main(String[] a) throws Exception {
        String addr = a[0], certFp = a[1], pin = a[2];
        // 1) 没信任证书 → 拿到指纹, 与证书文件一致
        HncClient.Result r1 = new HncClient(addr, null, null, "it").devices(null);
        System.out.println("   r1: code=" + r1.code + " err=" + r1.err + " fp=" + r1.untrustedFp);
        check(r1.untrustedFp != null && r1.untrustedFp.replace(":", "").equalsIgnoreCase(certFp), "首次连接返回证书指纹, 与 httpd_cert.pem 的 SHA-256 一致");
        check(!r1.certChanged, "首次不是『证书变了』");
        // 2) 指纹不对 → certChanged
        HncClient.Result r2 = new HncClient(addr, "00:11", null, "it").devices(null);
        check(r2.certChanged && r2.untrustedFp != null, "固定了别的指纹 → 拒绝并报『证书变了』");
        String fp = r1.untrustedFp;
        // 3) 信任后、没令牌 → 401
        HncClient.Result r3 = new HncClient(addr, fp, null, "it").devices(null);
        System.out.println("   r3: code=" + r3.code + " " + r3.describe());
        check(r3.code == 401, "信任证书但没令牌 → 401");
        // 4) 错误配对码
        HncClient.Result r4 = new HncClient(addr, fp, null, "it").pair("000000", null);
        System.out.println("   r4: code=" + r4.code + " " + r4.err);
        check(r4.code == 400 && r4.token == null && r4.err.contains("wrong pin") && r4.err.contains("还能试"), "错误配对码 → 400 wrong pin + 剩余次数");
        // 5) 正确配对码 → 302 + 令牌
        HncClient.Result r5 = new HncClient(addr, fp, null, "it").pair(pin, null);
        System.out.println("   r5: code=" + r5.code + " token=" + (r5.token == null ? null : r5.token.substring(0, 6) + "…") + " err=" + r5.err);
        check(r5.code == 302 && r5.token != null, "正确配对码 → 302 + Set-Cookie 令牌");
        // 6) 配对码一次性
        HncClient.Result r6 = new HncClient(addr, fp, null, "it").pair(pin, null);
        check(r6.token == null, "同一配对码不能再用: " + r6.err);
        // 7) 带令牌拉 /api/devices, 按 IP 找到本机
        HncClient.Result r7 = new HncClient(addr, fp, r5.token, "it").devices(null);
        System.out.println("   r7: code=" + r7.code + " body=" + (r7.body == null ? null : r7.body.substring(0, Math.min(160, r7.body.length()))) );
        check(r7.ok(), "带令牌 GET /api/devices → 200");
        HncObs o = HncParser.parse(r7.body, addr.substring(0, addr.indexOf(':')), null);
        check(o.ok && "aa:bb:cc:00:00:02".equals(o.mac), "按本机 IP 在真实返回里找到自己: " + (o.ok ? o.mac + " tt=" + o.ttType : o.err));
        // 8) 令牌被篡改 → 401
        HncClient.Result r8 = new HncClient(addr, fp, r5.token.substring(0, r5.token.length() - 2) + "AA", "it").devices(null);
        check(r8.code == 401, "篡改令牌 → 401: " + r8.describe());
        System.out.println(fail == 0 ? "集成测试全部通过" : ("失败 " + fail + " 项"));
        System.exit(fail == 0 ? 0 : 1);
    }
}
