#!/bin/sh
# rc30.12.33 (P0.1) — 一次性清理脚本: 删 src/hnc_httpd/ 死代码副本.
#
# 背景:
#   rc30.12.30 的 P2.11 修复 (hotfix*.go → api_live.go 等重命名) 只在
#   daemon/hnc_httpd/ 做了, 没改 src/hnc_httpd/, 两边内容分叉 120+ 行.
#   src/README.md 还在声称 "完全一致" — 等于源代码层面撒谎.
#   rc30.12.33 决定: daemon/hnc_httpd/ 是唯一权威源, 删 src/hnc_httpd/.
#
# 用法:
#   在 hnc-v6 仓库根跑:
#     sh tools/cleanup-src-hnc_httpd.sh           # 干跑, 只列要删的文件
#     sh tools/cleanup-src-hnc_httpd.sh --apply   # 真的 git rm
#
# 跑完后:
#   git add -A
#   git commit -m "rc30.12.33 P0.1: remove src/hnc_httpd/ duplicate (single source = daemon/hnc_httpd/)"

set -e

if [ ! -d "src/hnc_httpd" ]; then
    echo "[OK] src/hnc_httpd/ 已不存在, 无需清理"
    exit 0
fi

if [ ! -d "daemon/hnc_httpd" ]; then
    echo "[ERR] daemon/hnc_httpd/ 不存在 — 仓库布局异常, 不能继续 (否则会删光所有 httpd 源码)"
    exit 1
fi

DRY_RUN=1
if [ "$1" = "--apply" ]; then
    DRY_RUN=0
fi

echo "=== src/hnc_httpd/ 内容清单 ==="
find src/hnc_httpd -type f | sort

echo ""
echo "=== 这些文件将被 git rm ==="
if [ "$DRY_RUN" = "1" ]; then
    echo "(干跑模式, 加 --apply 才真删)"
    exit 0
fi

# 真删
git rm -rf src/hnc_httpd/
echo ""
echo "=== git status ==="
git status --short src/hnc_httpd 2>/dev/null
echo ""
echo "[OK] src/hnc_httpd/ 已 git rm. 下一步:"
echo "  git add -A"
echo "  git commit -m 'rc30.12.33 P0.1: remove src/hnc_httpd/ duplicate (single source = daemon/hnc_httpd/)'"
