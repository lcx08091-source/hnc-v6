#!/usr/bin/env python3
# rc30.12.30 (TASK-a) v3: dpi_rules 拆分 + 反向合并工具.
#
# 用法 (在 hnc-v6 仓库根跑):
#   python3 tools/dpi_rules_split.py                  # 默认 = split (拆 dpi_rules.json -> dpi_rules.d/)
#   python3 tools/dpi_rules_split.py split            # 同上, 显式
#   python3 tools/dpi_rules_split.py split --dry-run  # 只打印不写
#   python3 tools/dpi_rules_split.py sync-legacy      # 反向: dpi_rules.d/ -> dpi_rules.json (派生产物)
#   python3 tools/dpi_rules_split.py sync-legacy --dry-run
#
# 设计 (v2 锁定, Stage 3 实施):
#   Stage 3 起 dpi_rules.d/ 是规则的唯一权威源. dpi_rules.json 作为派生产物
#   永不手编, 由 sync-legacy 模式从 dpi_rules.d/ 反向合并生成, 跨升级保留
#   只是给加载器出预料外问题时的 70 KB 保险.
#
# Stage 3 工作流:
#   1. 编辑/新增规则 → 改 data/dpi_rules.d/<bucket>.json
#   2. 跑 `python3 tools/dpi_rules_split.py sync-legacy` 同步 dpi_rules.json
#   3. git add data/dpi_rules.d/ data/dpi_rules.json && git commit
#
# 幂等性: 同输入 -> 同输出 (按 id 字典序 + bucket 编号顺序).
# 99-user-custom.json 不被 split 写, 不被 sync-legacy 合并 (用户本地不进 git).

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


# ----- subcommand: split -----
def cmd_split(args):
    """dpi_rules.json -> dpi_rules.d/*.json (v2 主功能)"""
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
    print("=== dpi_rules_split.py: split summary ===")
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


# ----- subcommand: sync-legacy -----
def cmd_sync_legacy(args):
    """dpi_rules.d/*.json -> dpi_rules.json (Stage 3+, dpi_rules.json 派生产物模式)

    把 dpi_rules.d/ 里所有非 99-user-custom 的 bucket 文件 merge 成单个
    dpi_rules.json. 跟 dpid 加载器 loadL3RulesFromDir() 的 merge 顺序一致
    (filename ascending), 跟 compileExternalRules dedup 一致 (同 id 后入覆盖).
    """
    if not os.path.isdir(args.input_dir):
        print(f"[ERR] input dir not found: {args.input_dir}", file=sys.stderr)
        return 1

    # 收集子文件 (按文件名排序, 跟 dpid 加载器一致)
    sub_files = sorted([
        f for f in os.listdir(args.input_dir)
        if f.endswith(".json") and f != "99-user-custom.json"
    ])
    if not sub_files:
        print(f"[ERR] no bucket files in {args.input_dir} (excluding 99-user-custom.json)", file=sys.stderr)
        return 1

    schema_version = None
    rules_version_parts = []
    merged_rules = []
    seen_ids = {}  # id -> index in merged_rules, 用于 dedup
    per_file_counts = []

    for fn in sub_files:
        path = os.path.join(args.input_dir, fn)
        try:
            with open(path, "r", encoding="utf-8") as f:
                sub = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            print(f"[ERR] parse {path}: {e}", file=sys.stderr)
            return 1

        # 取第一个文件的 schema_version 作为合并产物的 schema_version
        if schema_version is None and "schema_version" in sub:
            schema_version = sub["schema_version"]

        rv = sub.get("rules_version", "")
        if rv:
            rules_version_parts.append(rv)

        rules = sub.get("rules") or []
        before = len(merged_rules)
        dups_in_file = 0
        for r in rules:
            rid = r.get("id", "")
            if not rid:
                continue
            if rid in seen_ids:
                # 跟 compileExternalRules 一致: 后入覆盖
                merged_rules[seen_ids[rid]] = r
                dups_in_file += 1
            else:
                seen_ids[rid] = len(merged_rules)
                merged_rules.append(r)
        per_file_counts.append((fn, len(rules), len(merged_rules) - before, dups_in_file))

    # 顶层 rules_version: 取最长公共前缀作为基础, 否则 fallback
    # 例 子文件版本: "hnc-curated-v3-rc30.12-...-v6-valorant-mobile#00-core-meta", "...#10-tencent-im"
    # 公共前缀: "hnc-curated-v3-rc30.12-...-v6-valorant-mobile"
    def common_prefix(strs):
        if not strs:
            return ""
        s1, s2 = min(strs), max(strs)
        i = 0
        while i < len(s1) and i < len(s2) and s1[i] == s2[i]:
            i += 1
        return s1[:i]

    base = common_prefix(rules_version_parts).rstrip("#")
    if not base:
        base = "merged-from-dpi_rules.d"
    merged_rules_version = f"{base}+derived-from-dpi_rules.d"

    # 序列化输出
    merged_doc = {
        "schema_version": schema_version,
        "rules_version": merged_rules_version,
        "_comment_top": (
            "★ This file is a DERIVED PRODUCT generated by "
            "`tools/dpi_rules_split.py sync-legacy` from data/dpi_rules.d/*.json. "
            "Do NOT edit by hand. Edit dpi_rules.d/<bucket>.json instead, then rerun sync-legacy. "
            "Kept around as a 70KB safety net in case the dpi_rules.d/ loader path "
            "hits an unforeseen issue and dpid needs to fall back."
        ),
        "rules": merged_rules,
    }
    serialized = json.dumps(merged_doc, ensure_ascii=False, indent=2) + "\n"
    serialized_bytes = serialized.encode("utf-8")

    print("=== dpi_rules_split.py: sync-legacy summary ===")
    print(f"input dir:  {args.input_dir}/  ({len(sub_files)} bucket files)")
    print(f"output:     {args.output_path}  ({len(merged_rules)} rules, {len(serialized_bytes)} bytes)")
    print()
    print(f"{'bucket file':<30} {'in':>5} {'+new':>5} {'dup':>5}")
    print("-" * 55)
    for fn, n, new, dup in per_file_counts:
        print(f"{fn:<30} {n:>5} {new:>5} {dup:>5}")
    print("-" * 55)
    print()
    print(f"merged rules_version: {merged_rules_version}")
    print()

    if args.dry_run:
        print("[dry-run] no file written. rerun without --dry-run to apply.")
        return 0

    # 实际写盘 (atomic via tmp + rename)
    tmp = args.output_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(serialized)
    os.replace(tmp, args.output_path)
    print(f"[write] {args.output_path}  ({len(serialized_bytes)} bytes)")
    print()
    print("[note] dpi_rules.json is now a DERIVED PRODUCT. Edit dpi_rules.d/<bucket>.json,")
    print("       then rerun `python3 tools/dpi_rules_split.py sync-legacy` to refresh it.")
    return 0


# ----- main dispatcher -----
def main():
    ap = argparse.ArgumentParser(
        description="dpi_rules.json <-> dpi_rules.d/*.json 转换工具",
    )
    sub = ap.add_subparsers(dest="command")

    # split (default if no subcommand given)
    sp_split = sub.add_parser("split",
        help="dpi_rules.json -> dpi_rules.d/*.json")
    sp_split.add_argument("--in", dest="input_path", default="data/dpi_rules.json",
        help="input rules file (default: data/dpi_rules.json)")
    sp_split.add_argument("--out", dest="output_dir", default="data/dpi_rules.d",
        help="output directory (default: data/dpi_rules.d)")
    sp_split.add_argument("--dry-run", action="store_true",
        help="don't write files, just print summary")

    # sync-legacy
    sp_sync = sub.add_parser("sync-legacy",
        help="dpi_rules.d/*.json -> dpi_rules.json (派生产物)")
    sp_sync.add_argument("--in", dest="input_dir", default="data/dpi_rules.d",
        help="input directory (default: data/dpi_rules.d)")
    sp_sync.add_argument("--out", dest="output_path", default="data/dpi_rules.json",
        help="output legacy file (default: data/dpi_rules.json)")
    sp_sync.add_argument("--dry-run", action="store_true",
        help="don't write file, just print summary")

    # 向后兼容: 如果没给子命令, 走 split (跟 v2 用法一致)
    # 同时仍支持 v2 风格 `python3 ... --in <path> --out <dir>` (无 subcommand)
    import sys as _sys
    argv = _sys.argv[1:]
    if not argv or (argv and not argv[0].startswith("-") and argv[0] not in ("split", "sync-legacy")):
        # 没参数 或 第一个 arg 既不是 flag 也不是 subcommand → 走 split 默认
        pass  # argparse 会按下面 hack 处理
    if argv and argv[0] not in ("split", "sync-legacy") and (argv[0].startswith("--") or not argv):
        # 例如 `python3 dpi_rules_split.py --dry-run`, 是 v2 风格调用
        argv = ["split"] + argv
    elif not argv:
        argv = ["split"]

    args = ap.parse_args(argv)
    if args.command == "split" or args.command is None:
        return cmd_split(args)
    elif args.command == "sync-legacy":
        return cmd_sync_legacy(args)
    else:
        ap.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
