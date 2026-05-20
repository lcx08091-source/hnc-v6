#!/bin/sh
# rc30.12.35: 撤回 rc34 B3 (inject_version_to_docs.sh)
#
# 背景:
#   rc34 B3 加了 bin/inject_version_to_docs.sh 想做"CI 自动注入文档版本号".
#   但 Ling 一人维护项目, 手改 2 个字段比维护一个脚本 + 改 CI yml 更省事.
#   过度工程, 撤回.
#
# 用法 (仓库根):
#   sh tools/cleanup-b3-revert.sh           # 干跑
#   sh tools/cleanup-b3-revert.sh --apply   # 真 git rm

set -e

TARGET="bin/inject_version_to_docs.sh"

if [ ! -f "$TARGET" ]; then
    echo "[OK] $TARGET 已不存在, 无需清理"
    exit 0
fi

if [ "$1" = "--apply" ]; then
    git rm "$TARGET"
    echo "[OK] $TARGET 已 git rm. 下一步:"
    echo "  git add -A"
    echo "  git commit -m 'rc30.12.35: revert B3 (inject_version_to_docs.sh) — 过度工程'"
else
    echo "[dry-run] 将删除: $TARGET"
    echo "加 --apply 真删"
fi
