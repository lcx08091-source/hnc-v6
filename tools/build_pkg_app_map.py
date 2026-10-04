#!/usr/bin/env python3
"""build_pkg_app_map.py — 生成 data/pkg_app_map.json(包名 → 规则库应用 id 对照表)

v5.24 T3。评估(识别自评)时, 每条本机带标签样本的「真值」= map[pkg];
包名不在表里则真值记为 "pkg:" + pkg(仍能统计「这个包从来没被认出来」)。
见 daemon/hnc_httpd/dpi_eval.go。

数据来源(都是仓库里现成的, 不联网):
  1. src/dpid/appmeta/labels.go 的 curatedLabels: 包名 → 中文显示名。
  2. data/dpi_rules.json + data/dpi_rules.d/*.json 每条规则的 (app 中文名 → id)。
按「中文名」把两者对起来: labels 的中文名 == 规则的 app 名 → 该包归到这个 id。

匹配分三级(从严到宽, 命中即停):
  a. 精确: labels 的中文名与某个规则的 app 名完全相同。
  b. 规范化: 去掉空格 / 全半角 / 常见后缀(极速版、国际版、Lite、B 服…)后再比。
     —— 让「抖音极速版」也能落到 douyin 这类同应用的不同版本。
  c. CURATED: 脚本里手工维护的「包名 → id」覆盖表, 处理名字对不上但确实同应用的
     情况(如 com.lemon.lv 剪映 → 规则库里没有「剪映」这条, 见下方说明)。

匹配不上的包名会打印出来(UNMATCHED), 由人工在 CURATED 里补, 不要瞎猜。

用法:
    python3 tools/build_pkg_app_map.py            # 生成 data/pkg_app_map.json
    python3 tools/build_pkg_app_map.py --check    # 只校验: 对照表与规则库/labels 一致
    python3 tools/build_pkg_app_map.py --out PATH # 指定输出
    python3 tools/build_pkg_app_map.py --verbose  # 打印每条匹配来源

--check 供 CI / 提交前自检: 重新生成并与现有文件比对, 不一致则非零退出。
纯标准库。
"""
import argparse
import glob
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LABELS_GO = os.path.join(REPO, "src", "dpid", "appmeta", "labels.go")
RULES_MAIN = os.path.join(REPO, "data", "dpi_rules.json")
RULES_DIR = os.path.join(REPO, "data", "dpi_rules.d")
DEFAULT_OUT = os.path.join(REPO, "data", "pkg_app_map.json")

# ─── 手工覆盖表(包名 → 规则库应用 id) ─────────────────────────────────
# 只放「名字对不上、但确属同一应用」且我有把握的条目。拿不准的一律不放,
# 让它进 UNMATCHED 由人工判断(工作文档 T3: 匹配不上的不要猜)。
# 值必须是规则库里真实存在的 id, 否则 --check 会失败。
CURATED = {
    # 极速版 / 精简版 → 与主版本同应用(同一套后端域名与指纹)。
    "com.ss.android.ugc.aweme.lite": "douyin",          # 抖音极速版
    "com.ss.android.article.lite": "toutiao",           # 今日头条极速版
    "com.kuaishou.nebula": "kuaishou",                  # 快手极速版
    "com.jingdong.lite": "jd",                          # 京东极速版
    "com.netease.cloudmusic.lite": "netease_music",     # 网易云音乐极速版
    "com.kugou.android.lite": "kugou",                  # 酷狗音乐极速版
    # 同一 App 的多个包名 / 马甲包(只放规则库里确有对应 id 且我有把握的;
    # 拿不准的宁可留 UNMATCHED —— 映射错会让评估把好识别判成错的)。
    "com.miHoYo.GenshinImpact": "mihoyo",               # 原神
    "com.miHoYo.GenshinImpact.bilibili": "mihoyo",      # 原神 B 服
    "com.miHoYo.bh3": "mihoyo",                         # 崩坏 3
    "com.miHoYo.bh3.bilibili": "mihoyo",                # 崩坏 3 B 服
    "com.miHoYo.hkrpg": "mihoyo",                       # 崩坏: 星穹铁道
    "com.miHoYo.hkrpg.bilibili": "mihoyo",              # 星穹铁道 B 服
    "com.tencent.tmgp.cf": "tencent_game_family",       # 穿越火线(腾讯手游通用)
    "com.tencent.tmgp.sgame": "tencent_wzry_exclusive", # 王者荣耀
    "com.tencent.tmgp.pubgmhd": "tencent_pubgmhd_exclusive",  # 和平精英
    "com.tencent.qqlite": "qq_im",                      # QQ 轻聊版
    # v5.27 T5: 规则库扩充后有了对应 id、但中文名对不上的官方 App(只放有把握的)。
    "com.anthropic.claude": "anthropic",                # Claude 官方 App
    "com.openai.chatgpt": "openai",                     # ChatGPT 官方 App
    "com.google.android.apps.bard": "gemini",           # Gemini(原 Bard)官方 App
    "com.twitter.android": "twitter",                   # X (Twitter) 官方 App
    "jp.pxv.android": "pixiv",                          # pixiv 官方 App
    "com.larksuite.suite": "feishu",                    # Lark = 飞书国际版
    "org.thunderdog.challegram": "telegram",            # Telegram X(Telegram 官方第二客户端)
    "com.sdu.didi.psnger": "didi",                      # 滴滴出行
    "com.didi.taxi": "didi",                            # 滴滴打车(滴滴出行旧包名)
    "com.bilibili.app.in": "bilibili",                  # 哔哩哔哩国际版
    "com.bilibili.app.blue": "bilibili",                # 哔哩哔哩概念版
    "com.miHoYo.cloudgames.genshin": "mihoyo",          # 云·原神
    "com.miHoYo.cloudgames.hkrpg": "mihoyo",            # 云·星穹铁道
}

# 规范化时要剥掉的版本 / 地区后缀(先长后短, 避免「极速版」被「速版」截断)。
_STRIP_SUFFIX = [
    "极速版", "精简版", "国际版", "海外版", "青少年版", "轻量版", "专业版",
    "B 服", "B服", " Lite", " lite", "Lite", "HD", "Pad",
]


def load_labels(path=LABELS_GO):
    """从 labels.go 抓 curatedLabels 的 "pkg": "中文名"。"""
    txt = open(path, encoding="utf-8").read()
    # 只取 map 字面量体, 避免抓到别处的字符串对。
    m = re.search(r"curatedLabels\s*=\s*map\[string\]string\{(.*?)\n\}", txt, re.S)
    body = m.group(1) if m else txt
    out = {}
    for pkg, cn in re.findall(r'"([A-Za-z0-9_.]+)"\s*:\s*"([^"]+)"', body):
        out[pkg] = cn
    return out


def load_rules():
    """返回 (app名 → [id...], 所有 id 集合)。dpi_rules.json 与 dpi_rules.d 合并。"""
    app_to_ids = {}
    all_ids = set()
    files = []
    if os.path.exists(RULES_MAIN):
        files.append(RULES_MAIN)
    files += sorted(glob.glob(os.path.join(RULES_DIR, "*.json")))
    for f in files:
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception as e:
            print("WARN: 规则文件解析失败 %s: %s" % (f, e), file=sys.stderr)
            continue
        for r in d.get("rules", []):
            rid, app = r.get("id", ""), r.get("app", "")
            if not rid:
                continue
            if r.get("_parent_rule_id"):
                # v5.27: 挂靠的子规则(<id>_v2fly / 自动扩展 / 导入)不是独立应用,
                # dpid 分类结果是父 id; 不能拿它当真值
                continue
            all_ids.add(rid)
            if app:
                app_to_ids.setdefault(app, [])
                if rid not in app_to_ids[app]:
                    app_to_ids[app].append(rid)
    return app_to_ids, all_ids


def norm_name(s):
    """规范化中文名: 去空格、统一冒号、剥版本后缀。用于宽松匹配。"""
    s = s.replace("：", ":").replace(" ", "").replace("\u3000", "")
    changed = True
    while changed:
        changed = False
        for suf in _STRIP_SUFFIX:
            suf = suf.replace(" ", "")
            if s.endswith(suf) and len(s) > len(suf):
                s = s[: -len(suf)]
                changed = True
    return s


def build_map(verbose=False):
    """返回 (map, unmatched[(pkg,cn)], stats)。"""
    labels = load_labels()
    app_to_ids, all_ids = load_rules()

    # 规范化名 → id(取该 app 名下的第一个 id; 规则库里同名一般只有一个 id)。
    norm_to_id = {}
    for app, ids in app_to_ids.items():
        norm_to_id.setdefault(norm_name(app), ids[0])
    exact_to_id = {app: ids[0] for app, ids in app_to_ids.items()}

    out = {}
    unmatched = []
    stats = {"exact": 0, "norm": 0, "curated": 0, "unmatched": 0}
    for pkg, cn in sorted(labels.items()):
        src, rid = None, None
        if pkg in CURATED:                       # c. 手工覆盖优先(处理名字对不上的)
            rid, src = CURATED[pkg], "curated"
        elif cn in exact_to_id:                  # a. 精确
            rid, src = exact_to_id[cn], "exact"
        elif norm_name(cn) in norm_to_id:        # b. 规范化
            rid, src = norm_to_id[norm_name(cn)], "norm"
        if rid and rid in all_ids:
            out[pkg] = rid
            stats[src] += 1
            if verbose:
                print("  %-42s %-16s -> %-24s [%s]" % (pkg, cn, rid, src))
        else:
            unmatched.append((pkg, cn))
            stats["unmatched"] += 1
            if verbose:
                print("  %-42s %-16s -> (未匹配)" % (pkg, cn))
    return out, unmatched, stats


def validate(out):
    """校验: 每个值都必须是规则库里真实存在的 id。返回错误列表。"""
    _, all_ids = load_rules()
    errs = []
    for pkg, rid in out.items():
        if rid not in all_ids:
            errs.append("包 %s 映射到不存在的规则 id %r" % (pkg, rid))
    # CURATED 里写了但没进 labels 的条目(可能是笔误 / labels 已删)。
    labels = load_labels()
    for pkg in CURATED:
        if pkg not in labels:
            errs.append("CURATED 里的包 %s 不在 labels.go 中(可能已改名/删除)" % pkg)
    return errs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--check", action="store_true", help="只校验一致性, 不写文件")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()

    out, unmatched, stats = build_map(verbose=a.verbose)
    errs = validate(out)

    payload = {"schema": 1, "map": {k: out[k] for k in sorted(out)}}
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False) + "\n"

    if errs:
        print("映射校验失败:", file=sys.stderr)
        for e in errs:
            print("  - " + e, file=sys.stderr)

    if a.check:
        if errs:
            return 2
        cur = ""
        if os.path.exists(a.out):
            cur = open(a.out, encoding="utf-8").read()
        if cur != text:
            print("--check 失败: %s 与由 labels.go + 规则库重新生成的结果不一致。" % a.out)
            print("请重新运行 `python3 tools/build_pkg_app_map.py` 并提交更新后的文件。")
            return 1
        print("--check 通过: 对照表与 labels.go / 规则库一致(%d 条)。" % len(out))
        return 0

    if errs:
        return 2
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    open(a.out, "w", encoding="utf-8").write(text)
    print("已写 %s: %d 个包名(精确 %d / 规范化 %d / 手工 %d)。"
          % (a.out, len(out), stats["exact"], stats["norm"], stats["curated"]))

    if unmatched:
        print("\nUNMATCHED(%d 个, 名字对不上规则库, 需人工在 CURATED 里补或确认无对应应用):"
              % len(unmatched))
        for pkg, cn in unmatched:
            print("  %-44s %s" % (pkg, cn))
    return 0


if __name__ == "__main__":
    sys.exit(main())
