#!/usr/bin/env python3
# rc30.12.30 (TASK-a) v2: dpi_rules.json -> dpi_rules.d/ 拆分迁移脚本.
#
# 用法 (在 hnc-v6 仓库根跑):
#   python3 tools/dpi_rules_split.py               # 实际写文件
#   python3 tools/dpi_rules_split.py --dry-run     # 只打印不写
#   python3 tools/dpi_rules_split.py --in <path> --out <dir>
#
# 红线 (跟 TASK-a 一致):
#   - 这个脚本是工具, 不要在 commit 提案时同时生成 dpi_rules.d/*.json 进 git.
#   - 实际拆分要等提案被 Ling 审过, 进入 Stage 3 时再跑.
#   - 跑出来的子文件可直接 git add. v2 锁定: dpi_rules.json 保留作为
#     dpi_rules.d/ 的派生产物 (双源, 由脚本同步生成, 不手编), 永不 git rm.
#
# 幂等性: 同输入 -> 同输出 (按 id 字典序 + bucket 编号顺序).
# 99-user-custom.json 不被脚本写, 留给用户本地抓包扩规则.

import argparse
import ipaddress
import json
import os
import sys
from collections import defaultdict


# ----- bucket 分桶逻辑 (跟提案 §1.5 表完全对齐) -----
# 改这里时也要更新 MIGRATION-PROPOSAL-dpi-rules-d.md §1.5.
def bucket_of(rule):
    rid = rule.get("id", "")
    cat = rule.get("category", "")
    # 元规则 (HNC 自检 / P2P 兜底)
    if cat == "meta-warning":
        return "00-core-meta"
    if rid == "p2p_unknown_attribution":
        return "00-core-meta"
    # 腾讯 IM
    if rid in ("wechat", "wechat_pcdn_heartbeat", "qq_im", "qq_extra", "qywechat"):
        return "10-tencent-im"
    # 腾讯游戏 (注意: tencent_game* + 几个具名独家游戏 + sdk-tencent-game category)
    if rid.startswith("tencent_game") or rid in (
        "tencent_wzry_exclusive",
        "tencent_pubgmhd_exclusive",
        "tencent_hyrz_naruto",
        "tencent_codev_valorant_mobile",
    ) or cat == "sdk-tencent-game":
        return "20-tencent-game"
    # 腾讯其他
    if rid.startswith("tencent_") or rid in ("gdt", "bugly"):
        return "21-tencent-other"
    # 字节系 + 快手 (合并)
    if rid.startswith("bytedance") or rid.startswith("douyin") or rid in (
        "toutiao", "xigua", "ixigua_disambiguation",
        "pangle", "volcengine", "tiktok", "doubao",
    ):
        return "30-bytedance-kuaishou"
    if rid.startswith("kuaishou"):
        return "30-bytedance-kuaishou"
    # 阿里
    if rid.startswith("alibaba") or rid.startswith("aliyun") or rid in (
        "amap", "taobao", "eleme", "tongyi", "umeng", "dingding",
    ):
        return "32-alibaba"
    # 百度
    if rid.startswith("baidu") or rid == "wenxin":
        return "33-baidu"
    # 米哈游
    if rid.startswith("mihoyo") or rid == "hoyoplay_launcher":
        return "34-mihoyo"
    # 网易
    if rid.startswith("netease") or rid == "lolm":
        return "35-netease"
    # 国内长视频/音乐
    if rid in ("bilibili", "iqiyi", "mango_tv", "youku",
               "qq_music", "kugou", "kuwo", "apple_music"):
        return "40-media-cn"
    # 国内社交/电商/出行 + 飞书
    if rid in ("weibo", "zhihu", "xiaohongshu", "douban",
               "jd", "pinduoduo", "meituan", "didi", "feishu"):
        return "41-social-shopping-cn"
    # 海外 AI
    if rid in ("anthropic", "openai", "openai_extra",
               "copilot", "gemini", "kimi"):
        return "43-ai"
    # ROM
    if rid.startswith("xiaomi"):
        return "50-rom-xiaomi"
    if rid.startswith("oppo") or "coloros" in rid or "realme" in rid or rid == "ms_telemetry_realme_baseline":
        return "51-rom-coloros"
    if rid.startswith("vivo"):
        return "52-rom-vivo"
    if rid.startswith("huawei"):
        return "53-rom-huawei"
    if rid.startswith("apple") or rid.startswith("microsoft") or rid == "samsung":
        return "54-rom-overseas"
    # 加速器 / 下载
    if "accelerator" in rid or rid == "xunlei":
        return "60-accelerator"
    # 海外游戏
    if rid in ("steam", "epic", "riot", "garena", "supercell", "battlenet",
               "playstation", "xbox", "minecraft", "roblox", "pubg_global"):
        return "61-game-overseas"
    # 海外社交/通讯/流媒体
    if rid in ("facebook", "instagram", "meta_group", "twitter", "twitch", "youtube",
               "discord", "telegram", "whatsapp", "line", "slack", "teams", "zoom",
               "netflix", "disneyplus", "spotify"):
        return "62-overseas-app"
    # 网络基础设施 (CDN + DoH 合并)
    if rid.endswith("_cdn") or "doh" in rid:
        return "70-network-infra"
    # 独立 SDK
    if rid in ("adjust", "appsflyer", "google_ads_firebase", "sensorsdata"):
        return "80-ads-sdk"
    # 海外其他基础
    if rid in ("google", "google_play", "github"):
        return "81-overseas-misc"
    # 兜底 (不应该被命中, 命中表示分桶逻辑漏了)
    return "99-misc"


# ----- CIDR overlap sanity check -----
def check_no_cidr_overlap(rules):
    """跑提案 §1.4 描述的两两 CIDR overlap 检测."""
    pool = []
    for r in rules:
        for m in (r.get("ip_matchers") or []):
            c = m.get("cidr")
            if c:
                try:
                    pool.append((r["id"], ipaddress.ip_network(c, strict=False), 4))
                except ValueError:
                    pass
        for m in (r.get("ipv6_matchers") or []):
            c = m.get("cidr")
            if c:
                try:
                    pool.append((r["id"], ipaddress.ip_network(c, strict=False), 6))
                except ValueError:
                    pass
    overlaps = []
    for i in range(len(pool)):
        for j in range(i + 1, len(pool)):
            id_a, n_a, v_a = pool[i]
            id_b, n_b, v_b = pool[j]
            if id_a == id_b or v_a != v_b:
                continue
            if n_a.overlaps(n_b):
                overlaps.append((id_a, str(n_a), id_b, str(n_b)))
    return pool, overlaps


# ----- main -----
def main():
    ap = argparse.ArgumentParser(description="Split data/dpi_rules.json -> data/dpi_rules.d/*.json")
    ap.add_argument("--in", dest="input_path", default="data/dpi_rules.json",
                    help="input rules file (default: data/dpi_rules.json)")
    ap.add_argument("--out", dest="output_dir", default="data/dpi_rules.d",
                    help="output directory (default: data/dpi_rules.d)")
    ap.add_argument("--dry-run", action="store_true",
                    help="don't write files, just print summary")
    args = ap.parse_args()

    if not os.path.isfile(args.input_path):
        print(f"[ERR] input not found: {args.input_path}", file=sys.stderr)
        return 1

    with open(args.input_path, "r", encoding="utf-8") as f:
        src = json.load(f)
    rules = src.get("rules") or []
    if not rules:
        print(f"[ERR] no 'rules' array in {args.input_path}", file=sys.stderr)
        return 1

    schema_version = src.get("schema_version")
    rules_version_base = src.get("rules_version", "unknown")

    # 分桶
    buckets = defaultdict(list)
    for r in rules:
        b = bucket_of(r)
        buckets[b].append(r)

    # 桶内按 id 字典序排序, 保证幂等
    for b in buckets:
        buckets[b].sort(key=lambda r: r.get("id", ""))

    # 检查 99-misc 是否为空 (理论上应为空, 兜底用)
    if "99-misc" in buckets and buckets["99-misc"]:
        print("[WARN] 99-misc bucket non-empty, 分桶逻辑有漏:")
        for r in buckets["99-misc"]:
            print(f"   - {r['id']} (category={r.get('category')})")
        print("   请更新 bucket_of() 把它归类掉, 不要让 99-misc 当垃圾桶")
        # 不退出, 仍然写出来, 让 Ling 看见

    # CIDR overlap sanity check
    cidr_pool, overlaps = check_no_cidr_overlap(rules)

    # 序列化每个 bucket
    file_specs = []
    for bname in sorted(buckets.keys()):
        sub = {
            "schema_version": schema_version,
            "subset": bname,
            "rules_version": f"{rules_version_base}#{bname}",
            "rules": buckets[bname],
        }
        serialized = json.dumps(sub, ensure_ascii=False, indent=2) + "\n"
        file_specs.append((bname, serialized))

    # 打印 summary
    total_count = sum(len(buckets[b]) for b in buckets)
    total_bytes = sum(len(s.encode("utf-8")) for _, s in file_specs)
    input_size = os.path.getsize(args.input_path)
    print("=== dpi_rules_split.py summary ===")
    print(f"input:  {args.input_path}  ({len(rules)} rules, {input_size} bytes)")
    print(f"output: {args.output_dir}/  ({len(file_specs)} files, {total_bytes} bytes)")
    print()
    print(f"{'bucket':<28} {'count':>5} {'bytes':>7}")
    print("-" * 50)
    for bname, serialized in file_specs:
        print(f"{bname:<28} {len(buckets[bname]):>5} {len(serialized.encode('utf-8')):>7}")
    print("-" * 50)
    print(f"{'TOTAL':<28} {total_count:>5} {total_bytes:>7}")
    print()

    # CIDR check report
    print(f"[CIDR] scanned {len(cidr_pool)} cidr entries from {len(rules)} rules")
    if overlaps:
        print(f"[WARN] {len(overlaps)} cross-rule CIDR overlap(s) detected:")
        for ida, na, idb, nb in overlaps:
            print(f"   {ida} {na}  <-->  {idb} {nb}")
        print("   (拆分后 merge 顺序会影响 match 优先级, 请人工 review)")
    else:
        print(f"[OK] no cross-rule CIDR overlap (拆分后 merge 顺序对 match 无影响)")
    print()

    # 校验所有规则都被分桶
    if total_count != len(rules):
        print(f"[ERR] bucket sum {total_count} != input rule count {len(rules)}", file=sys.stderr)
        return 1
    print(f"[OK] all {len(rules)} input rules assigned to exactly one bucket")
    print()

    if args.dry_run:
        print("[dry-run] no files written. rerun without --dry-run to apply.")
        return 0

    # 实际写盘. 先清理已有的 bucket 文件 (但保护 99-user-custom.json)
    os.makedirs(args.output_dir, exist_ok=True)
    cleared = []
    for fn in os.listdir(args.output_dir):
        if not fn.endswith(".json"):
            continue
        if fn == "99-user-custom.json":
            continue  # ★ 保护用户自定义文件
        path = os.path.join(args.output_dir, fn)
        os.remove(path)
        cleared.append(fn)
    if cleared:
        print(f"[clean] removed {len(cleared)} stale bucket files: {', '.join(cleared)}")

    # 写新文件
    for bname, serialized in file_specs:
        path = os.path.join(args.output_dir, bname + ".json")
        with open(path, "w", encoding="utf-8") as f:
            f.write(serialized)
        print(f"[write] {path}  ({len(serialized.encode('utf-8'))} bytes, {len(buckets[bname])} rules)")

    # 提示用户 99-user-custom.json
    user_custom = os.path.join(args.output_dir, "99-user-custom.json")
    if not os.path.exists(user_custom):
        print()
        print(f"[note] {user_custom} 不存在. 这是给用户本地抓包扩规则用的占位文件,")
        print(f"       脚本不主动生成. 用户需要时手动 touch + 写一个空 rules 数组.")
        print(f"       建议加进 .gitignore 让本地自定义不进 git.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
