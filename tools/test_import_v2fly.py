#!/usr/bin/env python3
"""tools/import_v2fly.py 单测(python3 -m unittest discover -s tools -p 'test_*.py')。

夹具在 tools/testdata/v2fly/: data/ 是迷你版 domain-list-community 清单,
rules/ 是「现有规则」, blocklist.json 是共享基础设施 apex。纯标准库。
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import import_v2fly as iv  # noqa: E402

FX = os.path.join(HERE, "testdata", "v2fly")
SRC = os.path.join(FX, "data")
RULES = os.path.join(FX, "rules")
BLOCK = os.path.join(FX, "blocklist.json")


def build(mapping):
    return iv.build(SRC, mapping, RULES, BLOCK, "0123456789abcdef0123")


def by_id(rules):
    return {r["id"]: r for r in rules}


class TestParse(unittest.TestCase):
    def test_parse_line(self):
        self.assertEqual(iv.parse_line("appa.com"), ("domain", "appa.com", []))
        self.assertEqual(iv.parse_line("full:api.appa.net @cn @ads  # c"), ("full", "api.appa.net", ["cn", "ads"]))
        self.assertEqual(iv.parse_line("include:x @-!cn"), ("include", "x", ["-!cn"]))
        self.assertIsNone(iv.parse_line("   # only comment"))
        self.assertIsNone(iv.parse_line(""))


class TestExpand(unittest.TestCase):
    def test_include_and_cycle(self):
        st = {}
        ents = iv.expand(SRC, "appa", {}, set(), st)
        vals = {e[1] for e in ents}
        # include 展开: appa-cdn、appb、loop1→loop2(→loop1 成环, 只展开一次)
        for v in ("appacdn.com", "cn.appacdn.com", "appb.com", "loop1.com", "loop2.com"):
            self.assertIn(v, vals)
        self.assertEqual(st.get("include_cycle"), 1)

    def test_include_attr_filter(self):
        c = {e[1] for e in iv.expand(SRC, "appc", {}, set(), {})}
        self.assertEqual(c, {"cn.appacdn.com", "appc.com"})
        d = {e[1] for e in iv.expand(SRC, "appd", {}, set(), {})}
        self.assertEqual(d, {"appacdn.com", "appd.com"})

    def test_skip_set(self):
        st = {}
        vals = {e[1] for e in iv.expand(SRC, "appa", {}, {"appb", "loop1"}, st)}
        self.assertNotIn("appb.com", vals)
        self.assertNotIn("loop1.com", vals)
        self.assertEqual(st.get("include_skipped"), 2)


class TestBuild(unittest.TestCase):
    def setUp(self):
        self.mapping = {
            "appa": {"id": "appa", "app": "应用A", "category": "video"},
            "appb": {"id": "appb", "app": "应用B", "category": "social"},
            "existing-more": {"id": "exist", "app": "已有应用", "category": "social"},
        }

    def test_new_app_and_filters(self):
        rules, rep = build(self.mapping)
        r = by_id(rules)["appa"]
        s = set(r["suffixes"])
        # 后缀匹配 + full 当后缀 + include 进来的
        for v in ("appa.com", "appa.org", "api.appa.net", "appacdn.com", "cn.appacdn.com", "loop1.com", "loop2.com", "x.cdnshared.com"):
            self.assertIn(v, s)
        # keyword / regexp 跳过; @ads 跳过
        self.assertGreaterEqual(rep["skipped"]["keyword"], 1)
        self.assertGreaterEqual(rep["skipped"]["regexp"], 1)
        self.assertEqual(rep["skipped"]["ads_attr"], 2)
        self.assertNotIn("ads.appa.com", s)
        # 被单独映射的 appb 不随 appa 展开, 归应用B
        self.assertNotIn("appb.com", s)
        self.assertEqual(by_id(rules)["appb"]["suffixes"], ["appb.com"])
        # 公共后缀 / 多租户托管后缀 / blocklist apex 本身 跳过
        for v in ("com.cn", "github.io", "cdnshared.com"):
            self.assertNotIn(v, s)
        self.assertEqual(rep["skipped"]["public_suffix"], 2)
        self.assertEqual(rep["skipped"]["blocklist_apex"], 1)
        self.assertEqual(rep["skipped"]["invalid_host"], 1)
        self.assertEqual(r["category"], "video")
        self.assertNotIn("_parent_rule_id", r)

    def test_conflict_skip(self):
        rules, rep = build(self.mapping)
        s = set(by_id(rules)["appa"]["suffixes"])
        # other.com 归别的应用; sub.other.com 最长后缀匹配也归它; childapp.example 是 other 的
        # 自动扩展子规则 → 按挂靠算作 other
        for v in ("other.com", "sub.other.com", "childapp.example", "exist.com"):
            self.assertNotIn(v, s)
        owners = {(c["suffix"], c["owner"]) for c in rep["conflicts"]}
        self.assertIn(("other.com", "other"), owners)
        self.assertIn(("sub.other.com", "other"), owners)
        self.assertIn(("childapp.example", "other"), owners)
        self.assertIn(("exist.com", "exist"), owners)

    def test_attach_to_existing(self):
        rules, rep = build(self.mapping)
        r = by_id(rules)["exist_v2fly"]
        self.assertEqual(r["_parent_rule_id"], "exist")
        self.assertEqual(r["app"], "已有应用")
        # exist.com 已覆盖(同一应用)→ 跳过; more.exist.com 也在 exist.com 之下 → 已覆盖
        self.assertEqual(r["suffixes"], ["exist-cdn.net"])
        self.assertEqual(rep["skipped"]["already_covered"], 2)
        self.assertEqual(rep["merged_apps"], 1)
        self.assertEqual(rep["new_apps"], 2)

    def test_ads_category_keeps_ads_lines(self):
        rules, _ = build({"adnet": {"id": "adnet", "app": "广告网络", "category": "ads"}})
        self.assertEqual(by_id(rules)["adnet"]["suffixes"], ["adnet.com", "pixel.adnet.com"])

    def test_bad_category_and_id(self):
        with self.assertRaises(iv.ListError):
            build({"appb": {"id": "appb", "app": "B", "category": "no-such-cat"}})
        with self.assertRaises(iv.ListError):
            build({"appb": {"id": "App-B", "app": "B", "category": "social"}})

    def test_skip_include_and_exclude(self):
        rules, _ = build({"withsub": {"id": "withsub", "app": "W", "category": "social", "skip_include": ["subapp"]}})
        self.assertEqual(by_id(rules)["withsub"]["suffixes"], ["withsub.com"])
        rules, rep = build({"appa": {"id": "appa", "app": "A", "category": "video", "exclude": ["appacdn.com"]}})
        s = set(by_id(rules)["appa"]["suffixes"])
        self.assertNotIn("appacdn.com", s)
        self.assertNotIn("cn.appacdn.com", s)
        self.assertEqual(rep["skipped"]["excluded"], 2)

    def test_v2fly_vs_v2fly_duplicate(self):
        # 两个清单映射到不同应用、给出同一个后缀: 先处理的(按 id 排序)拿到, 后者记冲突
        rules, rep = build({
            "appb": {"id": "zz_second", "app": "Z", "category": "social"},
            "subapp": {"id": "aa_first", "app": "A", "category": "social"},
            "withsub": {"id": "mm", "app": "M", "category": "social"},
        })
        r = by_id(rules)
        self.assertEqual(r["aa_first"]["suffixes"], ["subapp.com"])
        self.assertEqual(r["mm"]["suffixes"], ["withsub.com"])  # subapp 被映射, 不随 withsub 展开

    def test_ignores_previous_output(self):
        # rules/ 里旧的 46-v2fly-a.json 不算「现有规则」(重跑幂等): appa.com 不报冲突
        rules, rep = build(self.mapping)
        self.assertIn("appa.com", by_id(rules)["appa"]["suffixes"])
        self.assertFalse(any(c["suffix"] == "appa.com" for c in rep["conflicts"]))

    def test_multiple_lists_same_id_merge(self):
        rules, _ = build({
            "appb": {"id": "combo", "app": "C", "category": "social"},
            "subapp": {"id": "combo", "app": "C", "category": "social"},
        })
        r = by_id(rules)["combo"]
        self.assertEqual(r["suffixes"], ["appb.com", "subapp.com"])
        self.assertEqual(r["_source"], "v2fly:appb,subapp")


class TestBuckets(unittest.TestCase):
    def test_split_by_size(self):
        rules = [{"id": "r%03d" % i, "app": "x", "category": "video", "suffixes": ["host%03d-%s.example.com" % (i, "x" * 40)]} for i in range(60)]
        docs = iv.split_buckets(rules, "c0ffee" * 7, max_bytes=2500)
        self.assertGreater(len(docs), 2)
        names = [n for n, _ in docs]
        self.assertEqual(names[:3], ["46-v2fly-a.json", "46-v2fly-b.json", "46-v2fly-c.json"])
        total = 0
        for name, doc in docs:
            self.assertLessEqual(len(iv.dump(doc).encode("utf-8")), 2500)
            self.assertEqual(doc["subset"], name[:-5])
            self.assertTrue(doc["source"].startswith("v2fly/domain-list-community@c0ffee"))
            self.assertIn("schema_version", doc)
            self.assertIn("rules_version", doc)
            total += len(doc["rules"])
        self.assertEqual(total, 60)

    def test_main_writes_and_replaces(self):
        out = tempfile.mkdtemp()
        try:
            shutil.copy(os.path.join(RULES, "10-base.json"), out)
            with open(os.path.join(out, "46-v2fly-z.json"), "w") as f:
                f.write("{}")  # 旧的生成结果: 重跑时被删掉
            mp = os.path.join(out, "map.json")
            with open(mp, "w", encoding="utf-8") as f:
                json.dump({"_comment": "x", "appb": {"id": "appb", "app": "B", "category": "social"}}, f)
            rc = iv.main(["--src", SRC, "--map", mp, "--out", out, "--blocklist", BLOCK, "--commit", "abc"])
            self.assertEqual(rc, 0)
            files = sorted(os.listdir(out))
            self.assertNotIn("46-v2fly-z.json", files)
            with open(os.path.join(out, "46-v2fly-a.json"), encoding="utf-8") as f:
                doc = json.load(f)
            self.assertEqual(doc["source"], "v2fly/domain-list-community@abc")
            self.assertEqual(doc["rules"][0]["id"], "appb")
        finally:
            shutil.rmtree(out)


class TestRepoMap(unittest.TestCase):
    """仓库里的映射表本身: id 合法、类别是现有类别、不映射公司级大清单。"""

    def test_repo_map_sane(self):
        with open(os.path.join(HERE, "v2fly_map.json"), encoding="utf-8") as f:
            m = {k: v for k, v in json.load(f).items() if not k.startswith("_")}
        _, _, cats = iv.load_existing(iv.DEFAULT_RULES_DIR)
        for name, v in m.items():
            self.assertRegex(v["id"], r"^[a-z0-9_]{1,64}$", name)
            self.assertIn(v["category"], cats, name)
            self.assertTrue(v.get("app"), name)
        for company in ("tencent", "alibaba", "bytedance", "baidu", "google", "microsoft", "apple", "amazon",
                        "netease", "meta", "xiaomi", "huawei", "sina", "sohu", "bilibili2", "momo", "jd"):
            self.assertNotIn(company, m)


if __name__ == "__main__":
    unittest.main()
