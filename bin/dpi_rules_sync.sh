#!/system/bin/sh
# dpi_rules_sync.sh — HNC v5.27.0-rc1
# 开机把模块自带的 DPI 规则目录同步到运行目录, 同时保留「这台手机自己的」规则。
#
# 用法: dpi_rules_sync.sh <模块规则目录> <运行规则目录> <模块 module.prop 路径>
#   例: dpi_rules_sync.sh $MODDIR/data/dpi_rules.d $HNC_DIR/etc/dpi_rules.d $MODDIR/module.prop
#
# 同步规则(v5.27 T1, 修「重启把学到的规则删了」):
#   - 保留: 99-user-custom.json、所有 _*.json(_auto_expanded / _auto_promoted / _imported …)
#   - 97-online-update.json: 模块 versionCode 没变才保留; 变了(升级模块)→ 删 97
#     和 etc/dpi_rules_online.version(否则「检查更新」会说已是最新, 规则却没了)
#   - 其余: 以模块为准(模块删掉的旧 bucket 跟着消失)
#   - 模块目录不存在: 什么都不动
#
# 实现: 先把模块目录复制到运行目录旁边的暂存目录(同一文件系统), 再把要保留的
# 文件复制进暂存目录, 全部成功后才用两次 mv 换掉运行目录。任何一步失败都直接
# 放弃暂存目录 —— 运行目录(含用户规则)原封不动。上次被中断留下的半成品
# 在下次运行开头收拾。
#
# 退出码: 0 = 成功或无需同步; 1 = 失败(运行目录未改动)

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:/data/local/hnc/bin:$PATH

MOD="$1"
RT="$2"
PROP="$3"

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
LOG="${HNC_DPI_RULES_SYNC_LOG:-$HNC_DIR/logs/dpi_rules_sync.log}"
log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)] [RULES-SYNC] $*" >> "$LOG" 2>/dev/null || true; }

if [ -z "$MOD" ] || [ -z "$RT" ]; then
    echo "usage: $0 <module_rules_dir> <runtime_rules_dir> <module.prop>" >&2
    exit 1
fi
mkdir -p "$(dirname "$LOG")" 2>/dev/null

# 模块目录不存在 → 不动
if [ ! -d "$MOD" ]; then
    log "skip: module rules dir missing: $MOD"
    exit 0
fi

ETC=$(dirname "$RT")
VER_FILE="$ETC/.rules_sync_module_version"
ONLINE_VER="$ETC/dpi_rules_online.version"
STAGE="$ETC/.dpi_rules_sync.new.$$"
OLD="$ETC/.dpi_rules_sync.old.$$"

mkdir -p "$ETC" 2>/dev/null || { log "FAIL: mkdir $ETC"; exit 1; }

# ── 收拾上次中断留下的半成品 ─────────────────────────────────────────
# 换目录的两次 mv 之间被打断时, 运行目录可能不存在而旧目录在 .old.* 里 → 挪回去。
for d in "$ETC"/.dpi_rules_sync.old.*; do
    [ -d "$d" ] || continue
    if [ ! -d "$RT" ]; then
        mv "$d" "$RT" 2>/dev/null && log "recovered interrupted sync: $d -> $RT"
    else
        rm -rf "$d" 2>/dev/null
    fi
done
for d in "$ETC"/.dpi_rules_sync.new.*; do
    [ -d "$d" ] && rm -rf "$d" 2>/dev/null
done

# ── 模块版本: 决定 97 是否保留 ───────────────────────────────────────
MODVER=$(sed -n 's/^versionCode=\([0-9A-Za-z._-]*\).*/\1/p' "$PROP" 2>/dev/null | head -1)
OLDVER=$(head -1 "$VER_FILE" 2>/dev/null | tr -d ' \r\n')
KEEP97=0
if [ -n "$MODVER" ] && [ "$MODVER" = "$OLDVER" ]; then
    KEEP97=1
fi

fail(){
    rm -rf "$STAGE" 2>/dev/null
    log "FAIL: $* (runtime dir untouched)"
    exit 1
}

# ── 1) 模块目录 → 暂存目录 ──────────────────────────────────────────
rm -rf "$STAGE" 2>/dev/null
cp -r "$MOD" "$STAGE" 2>/dev/null || fail "cp $MOD -> $STAGE"
[ -d "$STAGE" ] || fail "stage dir missing after cp"

# ── 2) 要保留的文件 → 暂存目录(运行目录此时还没动) ───────────────────
KEPT=""
if [ -d "$RT" ]; then
    for f in "$RT"/99-user-custom.json "$RT"/_*.json "$RT"/97-online-update.json; do
        [ -f "$f" ] || continue
        b=$(basename "$f")
        if [ "$b" = "97-online-update.json" ] && [ "$KEEP97" != "1" ]; then
            continue
        fi
        cp -p "$f" "$STAGE/$b" 2>/dev/null || fail "preserve $b"
        KEPT="$KEPT $b"
    done
fi

# ── 3) 换目录 ───────────────────────────────────────────────────────
if [ -d "$RT" ]; then
    mv "$RT" "$OLD" 2>/dev/null || fail "mv $RT -> $OLD"
fi
if ! mv "$STAGE" "$RT" 2>/dev/null; then
    [ -d "$OLD" ] && mv "$OLD" "$RT" 2>/dev/null
    fail "mv $STAGE -> $RT"
fi
rm -rf "$OLD" 2>/dev/null

chmod 755 "$RT" 2>/dev/null
for f in "$RT"/*.json; do
    [ -f "$f" ] && chmod 644 "$f" 2>/dev/null
done

# ── 4) 升级了模块: 在线更新规则作废 ─────────────────────────────────
if [ "$KEEP97" != "1" ]; then
    if [ -f "$ONLINE_VER" ]; then
        rm -f "$ONLINE_VER" 2>/dev/null
        log "module version changed [$OLDVER] -> [$MODVER]: dropped 97-online-update.json + $(basename "$ONLINE_VER")"
    fi
fi
if [ -n "$MODVER" ]; then
    printf '%s\n' "$MODVER" > "$VER_FILE.tmp" 2>/dev/null && mv -f "$VER_FILE.tmp" "$VER_FILE" 2>/dev/null
fi

n=0
for f in "$RT"/*.json; do [ -f "$f" ] && n=$((n + 1)); done
log "synced $MOD -> $RT ($n files; kept:${KEPT:- none}; module_version=$MODVER)"
exit 0
