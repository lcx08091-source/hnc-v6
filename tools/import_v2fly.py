#!/usr/bin/env python3
"""import_v2fly.py — v5.27 T5: 从 v2fly/domain-list-community 生成 DPI 规则 bucket

数据源: https://github.com/v2fly/domain-list-community (MIT) 的 data/ 目录, 一个清单一个文件。
行格式: `domain:x` 或裸 `x`(后缀匹配)、`full:x`(精确)、`keyword:` / `regexp:`(跳过)、
`include:<清单名> [@attr|@-attr]`(展开, 防循环)、行尾属性 `@ads`、`@cn`、`@!cn`…、`#` 注释。

映射表 tools/v2fly_map.json: {"<清单名>": {"id": "...", "app": "...", "category": "...",
"skip_include": ["<子清单>", ...], "exclude": ["<后缀>", ...]}}。只映射「一个清单 = 一个 App / 服务」的清单; 公司级大清单
(tencent / alibaba / bytedance / baidu / google / microsoft / apple / amazon …)不映射。

规则:
  - 映射到已有规则 id → 生成 `<id>_v2fly`, 带 "_parent_rule_id": "<id>"(dpid 的挂靠会把后缀
    并进父规则); 不存在 → 新的独立规则。多个清单映射到同一个 id 时合并成一条。
  - category 必须是现有规则里出现过的类别。
  - include 的子清单如果自己也被映射(或列在 skip_include 里), 不随父清单展开 ——
    例如 kuaishou 清单 include 了 acfun, AcFun 单独成一个应用, 不能被认成快手。
  - 带 @ads 的行跳过(除非映射的 category 本来就是广告类)。
  - full: 按后缀处理(规则库只有后缀匹配; 精确主机名当后缀只会多覆盖它自己的子域)。
  - 冲突检查: 后缀在现有规则里(按最长后缀匹配)已经归给别的应用 → 跳过并写进报告;
    已归给同一个应用 → 跳过(已覆盖); 是 auto_expand_blocklist.json 里的共享基础设施
    apex 本身、或只是一个公共后缀(com、com.cn、github.io 这类)→ 跳过。
  - 输出 46-v2fly-a.json、46-v2fly-b.json…(每个 ≤ 900 KB), 格式同现有 bucket,
    顶层加 "source": "v2fly/domain-list-community@<commit>"。重跑前先删旧的 46-v2fly-*.json,
    且计算冲突时不把它们算作「现有规则」(幂等)。

用法:
    python3 tools/import_v2fly.py --src <domain-list-community/data> \\
        --map tools/v2fly_map.json --out data/dpi_rules.d/ [--commit <sha>] [--dry-run]
    python3 tools/dpi_rules_split.py sync-legacy   # 之后同步派生的 dpi_rules.json

纯标准库。
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_RULES_DIR = os.path.join(REPO, "data", "dpi_rules.d")
DEFAULT_BLOCKLIST = os.path.join(REPO, "data", "auto_expand_blocklist.json")
OUT_PREFIX = "46-v2fly-"
MAX_BUCKET_BYTES = 900 * 1024
ADS_CATEGORIES = {"ads", "ad-sdk"}

# 两段式公共后缀(与 src/dpid/output/auto_expand.go compoundTLDs 一致)
COMPOUND_TLDS = {
    "co.uk", "co.nz", "co.za", "co.in", "co.id", "co.kr", "co.jp", "co.th", "co.il",
    "com.au", "com.cn", "com.hk", "com.tw", "com.sg", "com.br", "com.mx", "com.tr", "com.ar",
    "com.pe", "com.co", "com.ph", "com.my", "com.vn",
    "org.uk", "org.nz", "org.cn", "org.hk", "net.cn", "net.au", "net.nz", "net.tw",
    "gov.cn", "gov.uk", "gov.au", "edu.cn", "edu.au", "edu.hk",
    "ac.uk", "ac.jp", "ac.kr", "ac.cn", "ne.jp", "or.jp", "go.jp",
}
# 多租户托管后缀: 这些后缀下的子域属于各不相同的用户, 后缀本身不能归给任何一个应用
SHARED_HOSTING_SUFFIXES = {
    "github.io", "githubusercontent.com", "blogspot.com", "appspot.com", "herokuapp.com",
    "netlify.app", "vercel.app", "pages.dev", "workers.dev", "azurewebsites.net",
    "cloudfront.net", "amazonaws.com", "fastly.net", "akamaized.net", "akamaihd.net",
    "web.app", "firebaseapp.com",
}

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)+$")


class ListError(Exception):
    pass


def parse_line(raw):
    """一行 → (kind, value, attrs) 或 None。kind ∈ domain/full/keyword/regexp/include。"""
    line = raw.split("#", 1)[0].strip()
    if not line:
        return None
    parts = line.split()
    body, attrs = parts[0], [p for p in parts[1:] if p.startswith("@")]
    kind, value = "domain", body
    if ":" in body:
        k, v = body.split(":", 1)
        if k in ("domain", "full", "keyword", "regexp", "include"):
            kind, value = k, v
    return kind, value.strip(), [a[1:] for a in attrs]


def read_list(src, name, cache):
    if name in cache:
        return cache[name]
    path = os.path.join(src, name)
    if not os.path.isfile(path):
        raise ListError("list not found: " + name)
    entries = []
    with open(path, encoding="utf-8") as f:
        for raw in f:
            p = parse_line(raw)
            if p is not None:
                entries.append(p)
    cache[name] = entries
    return entries


def attr_filter_ok(attrs, filt):
    """include 行上的属性过滤: @x 只要带 x 的, @-x 不要带 x 的。"""
    for a in filt:
        if a.startswith("-"):
            if a[1:] in attrs:
                return False
        elif a not in attrs:
            return False
    return True


def expand(src, name, cache, skip, stats, stack=None, filt=None):
    """展开一个清单(含 include), 返回 [(kind, value, attrs, from_list)]。
    skip: 不随父清单展开的子清单名集合。防循环: 在当前展开栈上的清单再次出现时跳过。"""
    stack = stack or []
    if name in stack:
        stats["include_cycle"] = stats.get("include_cycle", 0) + 1
        return []
    out = []
    for kind, value, attrs in read_list(src, name, cache):
        if kind == "include":
            if value in skip:
                stats["include_skipped"] = stats.get("include_skipped", 0) + 1
                continue
            sub = expand(src, value, cache, skip, stats, stack + [name], attrs)
            out.extend(x for x in sub if attr_filter_ok(x[2], filt or []))
            continue
        if filt and not attr_filter_ok(attrs, filt):
            continue
        out.append((kind, value, attrs, name))
    return out


def norm_host(v):
    h = v.strip().lower().rstrip(".")
    if h.startswith("*."):
        h = h[2:]
    return h


def is_public_suffix(h):
    if "." not in h:
        return True
    if h in COMPOUND_TLDS or h in SHARED_HOSTING_SUFFIXES:
        return True
    return False


def load_existing(rules_dir):
    """现有规则(不含 46-v2fly-* 与 99-user-custom): 返回 (id→规则, 后缀→根应用 id, 类别集合)。"""
    by_id = {}
    files = sorted(glob.glob(os.path.join(rules_dir, "*.json")))
    for f in files:
        base = os.path.basename(f)
        if base.startswith(OUT_PREFIX) or base == "99-user-custom.json":
            continue
        with open(f, encoding="utf-8") as fh:
            doc = json.load(fh)
        for r in doc.get("rules") or []:
            rid = (r.get("id") or "").strip().lower()
            if rid:
                by_id[rid] = r  # 同 id 后写覆盖, 与加载器一致
    parent = {rid: (r.get("_parent_rule_id") or "").strip().lower() for rid, r in by_id.items()}

    def root(rid):
        seen = set()
        while parent.get(rid) and parent[rid] in by_id and rid not in seen:
            seen.add(rid)
            rid = parent[rid]
        return rid

    suffix_owner = {}
    cats = set()
    for rid, r in by_id.items():
        if r.get("category"):
            cats.add(r["category"].strip().lower())
        owner = root(rid)
        sufs = list(r.get("suffixes") or []) + list(r.get("domains") or [])
        for m in r.get("matchers") or []:
            if (m.get("type") or "").lower() in ("domain_suffix", "sni_suffix", "suffix", "domain", "exact_domain"):
                sufs.append(m.get("value") or "")
        for s in sufs:
            s = norm_host(s)
            if s and s not in suffix_owner:
                suffix_owner[s] = owner
    return by_id, suffix_owner, cats


def longest_owner(h, owners):
    """h 自身或其父域在 owners 里的最长匹配 → (后缀, 应用 id) 或 (None, None)。"""
    cur = h
    while True:
        if cur in owners:
            return cur, owners[cur]
        if "." not in cur:
            return None, None
        cur = cur.split(".", 1)[1]


def load_blocklist(path):
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (IOError, ValueError):
        return set()
    return {norm_host(x) for x in doc.get("blocked_apex") or [] if isinstance(x, str)}


def git_commit(src):
    try:
        out = subprocess.run(["git", "-C", src, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def build(src, mapping, rules_dir, blocklist_path, commit):
    """核心: 返回 (rules 列表, 报告 dict)。不写文件。"""
    by_id, owners, cats = load_existing(rules_dir)
    blocked = load_blocklist(blocklist_path)
    mapped = set(mapping)
    report = {
        "commit": commit, "lists_mapped": 0, "new_apps": 0, "merged_apps": 0,
        "new_suffixes": 0, "merged_suffixes": 0, "skipped": {}, "conflicts": [], "missing_lists": [],
        "empty_rules": [],
    }

    def skip(reason, n=1):
        report["skipped"][reason] = report["skipped"].get(reason, 0) + n

    # 按目标 id 分组(多个清单可以映射到同一个应用)
    groups = {}
    for lname in sorted(mapping):
        m = mapping[lname]
        tid = (m.get("id") or "").strip().lower()
        cat = (m.get("category") or "").strip().lower()
        if not re.match(r"^[a-z0-9_]{1,64}$", tid):
            raise ListError("bad id for list %s: %r" % (lname, tid))
        if cat not in cats:
            raise ListError("category %r (list %s) not used by any existing rule" % (cat, lname))
        g = groups.setdefault(tid, {"app": m.get("app") or tid, "category": cat, "lists": []})
        g["lists"].append(lname)

    cache = {}
    claimed = {}  # 后缀 → 本次已分给的目标 id(新清单之间的重复)
    out = []
    for tid in sorted(groups):
        g = groups[tid]
        sufs = set()
        used_lists = []
        for lname in g["lists"]:
            m = mapping[lname]
            # 自己以外被映射的清单 + skip_include 不随这个清单展开
            skipset = (mapped - {lname}) | set(m.get("skip_include") or [])
            excl = {norm_host(x) for x in m.get("exclude") or []}
            st = {}
            try:
                ents = expand(src, lname, cache, skipset, st)
            except ListError as e:
                report["missing_lists"].append(str(e))
                continue
            for k, v in st.items():
                skip(k, v)
            used_lists.append(lname)
            report["lists_mapped"] += 1
            for kind, value, attrs, _from in ents:
                if kind in ("keyword", "regexp"):
                    skip(kind)
                    continue
                if "ads" in attrs and g["category"] not in ADS_CATEGORIES:
                    skip("ads_attr")
                    continue
                h = norm_host(value)
                if not HOST_RE.match(h):
                    skip("invalid_host")
                    continue
                if is_public_suffix(h):
                    skip("public_suffix")
                    continue
                if longest_owner(h, {x: 1 for x in excl})[0] is not None:
                    skip("excluded")
                    continue
                if h in blocked:
                    skip("blocklist_apex")
                    continue
                s, owner = longest_owner(h, owners)
                if owner is not None:
                    if owner == tid:
                        skip("already_covered")
                    else:
                        skip("conflict_existing")
                        report["conflicts"].append({"suffix": h, "list": lname, "target": tid, "owner": owner, "matched": s})
                    continue
                if h in claimed and claimed[h] != tid:
                    skip("conflict_v2fly")
                    report["conflicts"].append({"suffix": h, "list": lname, "target": tid, "owner": claimed[h], "matched": h})
                    continue
                claimed[h] = tid
                sufs.add(h)
        if not sufs:
            report["empty_rules"].append(tid)
            continue
        src_tag = "v2fly:" + ",".join(used_lists)
        if tid in by_id:
            parent = by_id[tid]
            rule = {
                "id": tid + "_v2fly",
                "app": parent.get("app") or parent.get("name") or g["app"],
                "category": (parent.get("category") or g["category"]).strip().lower(),
                "suffixes": sorted(sufs),
                "_parent_rule_id": tid,
                "_source": src_tag,
            }
            report["merged_apps"] += 1
            report["merged_suffixes"] += len(sufs)
        else:
            rule = {
                "id": tid,
                "app": g["app"],
                "category": g["category"],
                "suffixes": sorted(sufs),
                "_source": src_tag,
            }
            report["new_apps"] += 1
            report["new_suffixes"] += len(sufs)
        out.append(rule)
    return out, report


def split_buckets(rules, commit, max_bytes=MAX_BUCKET_BYTES):
    """按大小拆成多个 bucket 文档: [(文件名, 文档)]。"""
    docs = []
    cur = []

    def mk(letter, rs):
        name = OUT_PREFIX + letter
        return name + ".json", {
            "schema_version": "2.0",
            "subset": name,
            "rules_version": "v2fly-%s#%s" % (commit[:12], name),
            "source": "v2fly/domain-list-community@%s" % commit,
            "_comment": "Generated by tools/import_v2fly.py from v2fly/domain-list-community (MIT, see THIRD_PARTY_NOTICES.md). Do not edit by hand; edit tools/v2fly_map.json and rerun.",
            "rules": rs,
        }

    def size_of(rs):
        return len(dump(mk("a", rs)[1]).encode("utf-8"))

    for r in rules:
        if cur and size_of(cur + [r]) > max_bytes:
            docs.append(cur)
            cur = []
        cur.append(r)
    if cur:
        docs.append(cur)
    out = []
    for i, rs in enumerate(docs):
        if i >= 26:
            raise ListError("too many buckets")
        out.append(mk(chr(ord("a") + i), rs))
    return out


def dump(doc):
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--src", required=True, help="domain-list-community 的 data/ 目录")
    ap.add_argument("--map", default=os.path.join(REPO, "tools", "v2fly_map.json"))
    ap.add_argument("--out", default=DEFAULT_RULES_DIR)
    ap.add_argument("--rules-dir", default=None, help="现有规则目录(默认 = --out)")
    ap.add_argument("--blocklist", default=DEFAULT_BLOCKLIST)
    ap.add_argument("--commit", default=None, help="数据源 commit(默认取 --src 所在 git 仓库的 HEAD)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--report-json", default=None, help="把报告另存为 JSON")
    a = ap.parse_args(argv)

    with open(a.map, encoding="utf-8") as f:
        mapping = {k: v for k, v in json.load(f).items() if not k.startswith("_")}
    commit = a.commit or git_commit(a.src)
    rules, report = build(a.src, mapping, a.rules_dir or a.out, a.blocklist, commit)
    buckets = split_buckets(rules, commit)

    print("=== import_v2fly: %s ===" % commit)
    print("映射清单: %d  新增应用: %d  并入已有应用: %d" % (report["lists_mapped"], report["new_apps"], report["merged_apps"]))
    print("新应用后缀: %d  并入已有应用的后缀: %d" % (report["new_suffixes"], report["merged_suffixes"]))
    print("跳过(按原因): " + ", ".join("%s=%d" % kv for kv in sorted(report["skipped"].items())))
    if report["missing_lists"]:
        print("缺失清单: " + "; ".join(report["missing_lists"]))
    if report["empty_rules"]:
        print("全部后缀被跳过、未生成规则: " + ", ".join(report["empty_rules"]))
    for c in report["conflicts"][:60]:
        print("  冲突: %-40s %s→%s 已归 %s(%s)" % (c["suffix"], c["list"], c["target"], c["owner"], c["matched"]))
    if len(report["conflicts"]) > 60:
        print("  …共 %d 条冲突" % len(report["conflicts"]))
    for name, doc in buckets:
        print("bucket %s: %d 条规则, %d 字节" % (name, len(doc["rules"]), len(dump(doc).encode("utf-8"))))
    if a.report_json:
        with open(a.report_json, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
    if a.dry_run:
        print("[dry-run] 未写文件")
        return 0
    for old in glob.glob(os.path.join(a.out, OUT_PREFIX + "*.json")):
        os.remove(old)
    for name, doc in buckets:
        path = os.path.join(a.out, name)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(dump(doc))
        os.replace(tmp, path)
        print("[write] " + path)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ListError as e:
        print("ERR: %s" % e, file=sys.stderr)
        sys.exit(1)
