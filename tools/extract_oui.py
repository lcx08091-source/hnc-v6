#!/usr/bin/env python3
"""extract_oui.py — 从 daemon/hotspotd/hnc_helpers.c 的 HNC_OUI_TABLE 抽出
数据文件 src/dpid/devname/oui_table.txt(厂商表唯一数据源, WORK-v5.31 §4 T2)。

C 侧本版不改(仍用编译进二进制的表), test/unit/test_v531_oui_table_sync.sh
核对两边一致 —— 以后改任一边不同步就失败。

格式: 每行 "<6 位大写 hex OUI>\\t<Vendor>", 按 OUI 升序(C 表本身有序)。

用法: python3 tools/extract_oui.py [--out 文件]   (默认覆盖仓库里的数据文件; 测试传
--out 写到临时文件再比对 —— v5.31 审查: 原来测试直接重写仓库文件, 不同步时把它「修好」了)。
路径按脚本所在仓库定位, 不依赖当前目录。
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "daemon/hotspotd/hnc_helpers.c")
OUT = os.path.join(ROOT, "src/dpid/devname/oui_table.txt")

# { 0x000048, "Epson" },  /  { 0x000048, "Epson" }
PAT = re.compile(r'\{\s*0x([0-9A-Fa-f]{6})\s*,\s*"([^"]+)"\s*\}')


def main() -> int:
    out = OUT
    if len(sys.argv) == 3 and sys.argv[1] == "--out":
        out = sys.argv[2]
    elif len(sys.argv) != 1:
        print("用法: extract_oui.py [--out 文件]", file=sys.stderr)
        return 2
    try:
        text = open(SRC, encoding="utf-8").read()
    except FileNotFoundError:
        print(f"找不到 {SRC}", file=sys.stderr)
        return 1
    m = re.search(r"HNC_OUI_TABLE\[\]\s*=\s*\{", text)
    if not m:
        print("找不到 HNC_OUI_TABLE 定义", file=sys.stderr)
        return 1
    body = text[m.end():]
    end = body.find("\n};")
    body = body[:end]

    entries = []
    for hit in PAT.finditer(body):
        prefix, vendor = hit.group(1).upper(), hit.group(2)
        entries.append((prefix, vendor))
    # 表必须升序 + 无重复(与 C 的 bsearch 前提一致)
    prefixes = [e[0] for e in entries]
    if prefixes != sorted(prefixes):
        print("C 表不是升序, 抽出前先修 C", file=sys.stderr)
        return 1
    if len(set(prefixes)) != len(prefixes):
        print("C 表有重复 OUI", file=sys.stderr)
        return 1

    with open(out, "w", encoding="utf-8") as f:
        for prefix, vendor in entries:
            f.write(f"{prefix}\t{vendor}\n")
    print(f"{out}: {len(entries)} 条")
    return 0


if __name__ == "__main__":
    sys.exit(main())
