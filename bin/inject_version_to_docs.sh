#!/system/bin/sh
# rc30.12.34 (TASK-B3): 文档版本号自动注入
# 把 README.md / ARCHITECTURE.md 等文件里的 {{VERSION}} / {{DATE}} 占位符
# 替换成 module.prop 里的真实版本号 + 当前日期.
#
# 用法:
#   sh bin/inject_version_to_docs.sh         # 实际写文件 (CI 用)
#   sh bin/inject_version_to_docs.sh --check # 只检查是否还有未注入的占位符 (单测用)
#
# 接入点 (Ling 决定):
#   方式 A: GitHub Actions yml 里在 zip 打包前加一步:
#     - run: sh bin/inject_version_to_docs.sh
#   方式 B: 顶层 build.sh (如果以后引入) 里调
#   方式 C: pre-commit hook 里调 (本地开发也能保持文档跟版本号同步)
#
# 之前历史:
#   rc30.12.30 P1.6 修了一半 — 把 README/ARCHITECTURE 头部版本号统一同步到
#   module.prop, 但仍是手动维护. rc30.12.34 收口剩下的一半: 占位符 + 注入.

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODULE_PROP="$REPO_ROOT/module.prop"

if [ ! -f "$MODULE_PROP" ]; then
    echo "[ERR] module.prop not found at $MODULE_PROP" >&2
    exit 1
fi

VERSION=$(grep '^version=' "$MODULE_PROP" | head -1 | sed 's/^version=//')
DATE=$(date +%Y-%m-%d 2>/dev/null || echo "unknown-date")

if [ -z "$VERSION" ]; then
    echo "[ERR] could not extract version from $MODULE_PROP" >&2
    exit 1
fi

CHECK_ONLY=0
if [ "$1" = "--check" ]; then
    CHECK_ONLY=1
fi

# 要处理的文件列表. 加新文件就在这里加一行.
DOC_FILES="
README.md
ARCHITECTURE.md
"

FAIL=0

for relpath in $DOC_FILES; do
    f="$REPO_ROOT/$relpath"
    if [ ! -f "$f" ]; then
        echo "[skip] $relpath not found"
        continue
    fi

    if [ "$CHECK_ONLY" = "1" ]; then
        # check 模式: 看占位符是否还在 (CI 中如果 inject 失败, --check 会报错)
        if grep -q "{{VERSION}}\|{{DATE}}" "$f"; then
            echo "[FAIL] $relpath still has unresolved placeholders ({{VERSION}} or {{DATE}})"
            FAIL=$((FAIL+1))
        else
            echo "[OK] $relpath has no unresolved placeholders"
        fi
        continue
    fi

    # inject 模式: 实际替换
    # 用 ~ 作为 sed 分隔符 (version 号里可能有 / 但不会有 ~)
    if grep -q "{{VERSION}}\|{{DATE}}" "$f"; then
        sed -i.bak \
            -e "s~{{VERSION}}~$VERSION~g" \
            -e "s~{{DATE}}~$DATE~g" \
            "$f"
        rm -f "$f.bak"
        echo "[inject] $relpath -> VERSION=$VERSION DATE=$DATE"
    else
        # 已经被注入过 (或者占位符从来没用). 不算错误, 但 warn 一下方便排查
        echo "[noop] $relpath has no placeholders (already injected or none defined)"
    fi
done

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
echo "[done] version=$VERSION date=$DATE"
exit 0
