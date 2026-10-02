#!/usr/bin/env python3
"""build_ip_owner.py — 生成 data/ip_owner.bin(离线 IP 归属库: 目的 IP → 组织/生态)

用途: hnc_httpd 在目的 IP 没有反查名、也没被规则/指纹/共现归到应用时, 查这张表
得到「这是谁家的 IP」(字节/腾讯/Apple/Cloudflare ...)。见 daemon/hnc_httpd/ip_owner.go。

数据源(公开): iptoasn.com 的 ip2asn-v4.tsv.gz / ip2asn-v6.tsv.gz
    (每行: range_start  range_end  AS_number  country_code  AS_description, 由 BGP 全表生成)
    https://iptoasn.com/data/ip2asn-v4.tsv.gz
    https://iptoasn.com/data/ip2asn-v6.tsv.gz
只挑下面 ORGS 表里列出的 ASN, 合并相邻同组织区间, 再叠加 CURATED 里的手工网段
(手工条目优先, 用于没有自有 ASN 或需要细化的网段)。

用法:
    python3 tools/build_ip_owner.py --download              # 联网下载到 /tmp 再生成
    python3 tools/build_ip_owner.py --v4 ip2asn-v4.tsv.gz --v6 ip2asn-v6.tsv.gz
    python3 tools/build_ip_owner.py --v4 ... --v6 ... --out data/ip_owner.bin --dump x.txt
无法联网时: 手动下载上面两个文件(或任何同格式的 TSV, 可不压缩)后用 --v4/--v6 指定。
两个都不给 → 只用 CURATED 生成(覆盖面很小, 仅供应急)。

二进制格式(小端, 全部定长, Go 侧 O(log n) 二分):
    magic   8B  "HNCIPOW1"
    u32     生成日期 YYYYMMDD(数据源日期, 无源时为 0)
    u16     组织数 N_org
    u32     v4 区间数 N4
    u32     v6 区间数 N6
    组织表  N_org × { u8 kind, u8 len, key(utf8), u8 len, name(utf8) }
            kind: 1=app(消费级应用运营方, 可归「XX系(未细分)」) 2=cloud 3=cdn 4=carrier
    v4 区间 N4 × { u32 start, u32 end, u16 org }       (按 start 升序, 互不重叠, 闭区间)
    v6 区间 N6 × { u64 start, u64 end, u16 org }       (地址高 64 位, 闭区间; 次 /64 的边界向下取整)
    u32     CRC32(IEEE) —— 覆盖前面全部字节
org 是组织表下标(0 起)。

ASN 选取原则(kind 的判定也在这里改):
    - app: 该 ASN 的流量绝大多数是运营方自家 App/服务(微信/抖音/B站 ...)。注意腾讯
      AS45090/AS132203 也承载部分腾讯云客户, 归为 app 是取舍(腾讯自家 App 大量用写死
      IP 的 HTTPDNS, 恰恰是「没名字」的那部分流量的主力); 阿里 AS37963 则以阿里云
      ECS 客户为主 → 记 cloud(阿里云), 只有淘宝 AS24429 记 app。
    - cloud/cdn/carrier: 只打标签(/api/dpi_unknown 显示「归属: 阿里云」等), 不归应用。
    - 美团 / 拼多多 / vivo / 小米大陆 等没有自有 ASN(托管在运营商 IDC 或公有云上),
      ASN 数据覆盖不到; 有可靠网段时加到 CURATED。
"""

import argparse
import gzip
import ipaddress
import os
import re
import struct
import sys
import urllib.request
import zlib

MAGIC = b"HNCIPOW1"
KIND = {"app": 1, "cloud": 2, "cdn": 3, "carrier": 4}

# key, 显示名, kind, ASN 列表(注释为 iptoasn 里的 AS 描述)
ORGS = [
    ("bytedance", "字节跳动", "app", [
        138699,  # TIKTOK-AS-AP TIKTOK PTE. LTD.
        396986,  # BYTEDANCE (US)
        137718,  # VOLCANO-ENGINE 北京火山引擎(抖音/今日头条 CDN 主力)
    ]),
    ("tencent", "腾讯", "app", [
        45090,   # TENCENT-NET-AP 深圳市腾讯计算机系统
        132203,  # TENCENT-NET-AP-CN Tencent Building
        137876,  # TENCENT-AS-AP Tencent Thailand
    ]),
    ("tencentcloud", "腾讯云", "cloud", [
        133478,  # TENCENT-AS-AP Tencent Cloud Computing Beijing
    ]),
    ("alibaba", "阿里巴巴", "app", [
        24429,   # TAOBAO 浙江淘宝网络
    ]),
    ("aliyun", "阿里云", "cloud", [
        37963,   # ALIBABA-CN-NET 杭州阿里巴巴广告(阿里云大陆, ECS 客户为主)
        45102,   # ALIBABA-CN-NET Alibaba US Technology
        134963,  # ASEPL-AS-AP Alibaba Cloud Singapore
        203513,  # ALIBABACLOUD
    ]),
    ("baidu", "百度", "app", [38365, 55967]),
    ("bilibili", "哔哩哔哩", "app", [140633]),
    ("kuaishou", "快手", "app", [
        139799,  # BDIITCL-AS-AP 北京达佳互联(快手运营主体)
    ]),
    ("netease", "网易", "app", [45062, 137263, 131659]),
    ("jd", "京东", "app", [131486, 137753, 137787]),
    ("iqiyi", "爱奇艺", "app", [133865]),
    ("didi", "滴滴", "app", [63646, 63648]),  # 北京小桔科技
    ("qihoo", "360", "app", [55992]),
    ("sina", "新浪/微博", "app", [37936]),
    ("xiaomi", "小米", "app", [63855, 63915]),
    ("huawei", "华为", "app", [
        131444, 141180, 151610,  # Huawei International / IT DC AP
        149640,  # HUAWEICDN
        206798,  # UK-HUAWEI
    ]),
    ("huaweicloud", "华为云", "cloud", [
        55990,   # HWCSNET 华为云服务数据中心
        136907,  # HWCLOUDS-AS-AP
    ]),
    ("oppo", "OPPO/一加/realme", "app", [
        63593,   # OPPO 广东欢太科技(HeyTap, OPPO/一加/realme 共用云服务)
    ]),
    ("apple", "Apple", "app", [714, 6185]),
    ("google", "Google", "app", [15169, 36040, 43515, 19527, 139070, 139190, 24424, 36492]),
    ("googlecloud", "Google Cloud", "cloud", [396982, 16550]),
    ("microsoft", "Microsoft", "app", [8075, 8068, 8069, 8070, 3598, 12076, 6584, 45139, 58862, 59067,
                                      13443, 14413]),  # 后两个 LinkedIn
    ("meta", "Meta", "app", [32934, 54115, 63293]),
    ("twitter", "X/Twitter", "app", [13414, 35995, 63179]),
    ("telegram", "Telegram", "app", [62041, 62014, 59930, 44907, 211157]),
    ("netflix", "Netflix", "app", [2906, 40027]),
    ("valve", "Steam", "app", [32590]),
    ("sony", "PlayStation", "app", [55901]),
    ("nintendo", "Nintendo", "app", [11278, 152877]),
    ("riot", "Riot Games", "app", [6507]),
    ("blizzard", "暴雪", "app", [57976]),
    ("hoyoverse", "米哈游", "app", [215543]),
    ("zoom", "Zoom", "app", [30103]),
    ("amazon", "Amazon/AWS", "cloud", [16509, 14618, 7224, 8987]),
    ("byteplus", "BytePlus", "cloud", [150436]),
    ("kingsoft", "金山云", "cloud", [59019, 137280]),
    ("ucloud", "UCloud", "cloud", [59077, 135377, 139327]),
    ("cloudflare", "Cloudflare", "cdn", [13335, 209242, 132892, 202623, 203898, 394536, 395747, 139242, 14789]),
    ("akamai", "Akamai", "cdn", [20940, 16625, 12222, 21342, 33905, 34164, 31108, 35994, 36183, 24319, 393560]),
    ("fastly", "Fastly", "cdn", [54113, 394192]),
    ("wangsu", "网宿", "cdn", [17442]),  # CHINANETCENTER(网宿科技)
    ("qiniu", "七牛云", "cdn", [152644]),
    ("chinatelecom", "中国电信", "carrier", [4134, 4809, 4812, 23724]),
    ("chinaunicom", "中国联通", "carrier", [4837, 9929, 4808, 17621, 17816]),
    ("chinamobile", "中国移动", "carrier", [9808, 56040, 56041, 56042, 56044, 56046, 56047, 56048, 58453, 9231]),
]

# 手工网段(优先于 ASN 数据)。只放有公开依据的条目。
CURATED = [
    ("183.232.84.0/24", "tencent"),  # 微信语音/视频通话中继(hnc_httpd api_conn.go wechatVoipNet 同源)
]


def open_any(path):
    with open(path, "rb") as f:
        head = f.read(2)
    if head == b"\x1f\x8b":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "rt", encoding="utf-8", errors="replace")


def parse_ip2asn(path, want, v6):
    """yield (start_int, end_int, org_index) for rows whose ASN is wanted."""
    out = []
    with open_any(path) as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) < 3:
                continue
            try:
                asn = int(p[2])
            except ValueError:
                continue
            org = want.get(asn)
            if org is None:
                continue
            try:
                a = ipaddress.ip_address(p[0])
                b = ipaddress.ip_address(p[1])
            except ValueError:
                continue
            if (a.version == 6) != v6 or (b.version == 6) != v6:
                continue
            s, e = int(a), int(b)
            if v6:
                s, e = s >> 64, e >> 64
            if e < s:
                continue
            out.append((s, e, org))
    return out


def paint(base, extra):
    """extra 区间覆盖 base(都是 (s, e, org)); 返回不重叠、按 start 排序的区间。"""
    if not extra:
        return base
    res = []
    extra = sorted(extra)
    for s, e, o in base:
        pieces = [(s, e)]
        for xs, xe, _ in extra:
            nxt = []
            for ps, pe in pieces:
                if xe < ps or xs > pe:
                    nxt.append((ps, pe))
                    continue
                if ps < xs:
                    nxt.append((ps, xs - 1))
                if pe > xe:
                    nxt.append((xe + 1, pe))
            pieces = nxt
        res.extend((ps, pe, o) for ps, pe in pieces)
    res.extend(extra)
    return res


def normalize(ranges):
    """排序、去重叠(先到先得: 起点更小者优先, 重叠部分裁掉)、合并相邻/重叠的同组织区间。"""
    ranges = sorted(ranges, key=lambda r: (r[0], r[1], r[2]))
    out = []
    for s, e, o in ranges:
        if out:
            ps, pe, po = out[-1]
            if s <= pe:  # 重叠
                if po == o:
                    if e > pe:
                        out[-1] = (ps, e, po)
                    continue
                if e <= pe:
                    continue  # 被前一个完全覆盖(不同组织): 丢弃, 保持确定性
                s = pe + 1
            if s == pe + 1 and po == o:
                out[-1] = (ps, e, po)
                continue
        out.append((s, e, o))
    return out


def curated_ranges(keys, v6):
    out = []
    for cidr, key in CURATED:
        net = ipaddress.ip_network(cidr, strict=False)
        if (net.version == 6) != v6:
            continue
        s, e = int(net.network_address), int(net.broadcast_address)
        if v6:
            s, e = s >> 64, e >> 64
        out.append((s, e, keys[key]))
    return out


def build(v4_path, v6_path, date):
    keys = {k: i for i, (k, _, _, _) in enumerate(ORGS)}
    want = {}
    for i, (k, _, _, asns) in enumerate(ORGS):
        for a in asns:
            if a in want:
                raise SystemExit("ASN %d listed twice (%s / %s)" % (a, ORGS[want[a]][0], k))
            want[a] = i
    v4 = parse_ip2asn(v4_path, want, False) if v4_path else []
    v6 = parse_ip2asn(v6_path, want, True) if v6_path else []
    v4 = normalize(paint(normalize(v4), curated_ranges(keys, False)))
    v6 = normalize(paint(normalize(v6), curated_ranges(keys, True)))
    return encode(v4, v6, date), v4, v6


def encode(v4, v6, date):
    b = bytearray(MAGIC)
    b += struct.pack("<IHII", date, len(ORGS), len(v4), len(v6))
    for k, name, kind, _ in ORGS:
        kb, nb = k.encode(), name.encode("utf-8")
        b += struct.pack("<BB", KIND[kind], len(kb)) + kb + struct.pack("<B", len(nb)) + nb
    for s, e, o in v4:
        b += struct.pack("<IIH", s, e, o)
    for s, e, o in v6:
        b += struct.pack("<QQH", s, e, o)
    b += struct.pack("<I", zlib.crc32(bytes(b)) & 0xFFFFFFFF)
    return bytes(b)


def download(dst):
    os.makedirs(dst, exist_ok=True)
    paths = []
    for n in ("ip2asn-v4.tsv.gz", "ip2asn-v6.tsv.gz"):
        p = os.path.join(dst, n)
        print("downloading", n, file=sys.stderr)
        urllib.request.urlretrieve("https://iptoasn.com/data/" + n, p)
        paths.append(p)
    return paths


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--v4", help="ip2asn-v4.tsv(.gz)")
    ap.add_argument("--v6", help="ip2asn-v6.tsv(.gz)")
    ap.add_argument("--download", action="store_true", help="从 iptoasn.com 下载到 --dl-dir")
    ap.add_argument("--dl-dir", default="/tmp/ip2asn")
    ap.add_argument("--date", type=int, default=0, help="数据日期 YYYYMMDD(默认取输入文件 mtime)")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "ip_owner.bin"))
    ap.add_argument("--dump", help="另写一份可读文本(调试/审查用)")
    a = ap.parse_args()
    if a.download:
        a.v4, a.v6 = download(a.dl_dir)
    date = a.date
    if not date and a.v4:
        import time
        date = int(time.strftime("%Y%m%d", time.gmtime(os.path.getmtime(a.v4))))
    if not re.fullmatch(r"\d{8}|0", str(date)):
        raise SystemExit("bad --date")
    blob, v4, v6 = build(a.v4, a.v6, date)
    with open(a.out, "wb") as f:
        f.write(blob)
    per = {}
    for _, _, o in v4 + v6:
        per[ORGS[o][0]] = per.get(ORGS[o][0], 0) + 1
    print("wrote %s: %d bytes, %d orgs, v4 %d ranges, v6 %d ranges" % (a.out, len(blob), len(ORGS), len(v4), len(v6)))
    print("ranges per org:", ", ".join("%s=%d" % (k, per.get(k, 0)) for k, _, _, _ in ORGS))
    if a.dump:
        with open(a.dump, "w", encoding="utf-8") as f:
            for s, e, o in v4:
                f.write("%s\t%s\t%s\n" % (ipaddress.IPv4Address(s), ipaddress.IPv4Address(e), ORGS[o][0]))
            for s, e, o in v6:
                f.write("%s\t%s\t%s\n" % (ipaddress.IPv6Address(s << 64), ipaddress.IPv6Address((e << 64) | (2**64 - 1)), ORGS[o][0]))


if __name__ == "__main__":
    main()
