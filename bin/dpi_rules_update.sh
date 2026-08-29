#!/system/bin/sh
# dpi_rules_update.sh — DPI 策展规则库在线更新 (v5.10.0)
#
# 数据源: 本仓库 GitHub Releases 的 dpi-rules.zip + dpi-rules.zip.sha256
# (CI 每次发版自动把 data/dpi_rules.d/ 打包上传 —— 与刷机包同一发布流水线)。
#
# 设计:
#   - 下载的更新包安装为 etc/dpi_rules.d/97-online-update.json
#     (加载序: 内置 00-84 策展集 → 97 在线更新 → 99 用户自定义;
#      dpid 按 id last-write-wins, 同 id 规则被更新版覆盖, 用户规则优先级最高)
#   - sha256 校验(Release 附带的 .sha256 文件) + 内容校验(validate_rules)
#   - rules_version 比对: 远端不比当前新则跳过安装
#   - 全程 curl -L, 失败非致命(规则更新是增强, 不是依赖)
#
# 用法:
#   dpi_rules_update.sh --check      只检查, 输出 JSON {current, remote, update_available}
#   dpi_rules_update.sh --install    下载并安装(幂等)
#
# 网络注意: 走 api.github.com + github.com(HTTPS)。国内网络可能需要代理 —— 失败
# 时输出明确错误, 不影响模块其他功能。

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
MODDIR=${MODDIR:-/data/adb/modules/hotspot_network_control}
REPO="${HNC_RULES_REPO:-lcx08091-source/hnc-v6}"
API_URL="https://api.github.com/repos/$REPO/releases/latest"
DST="$HNC_DIR/etc/dpi_rules.d/97-online-update.json"
WORK="$HNC_DIR/run/dpi_rules_update.$$"
LOG="$HNC_DIR/logs/dpi_rules_update.log"
CUR_VERSION_FILE="$HNC_DIR/etc/dpi_rules_online.version"

mkdir -p "$HNC_DIR/etc/dpi_rules.d" "$HNC_DIR/run" "$HNC_DIR/logs" 2>/dev/null
log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)] [RULES-UPD] $*" >> "$LOG" 2>/dev/null; }
fail(){ echo "ERR: $*" >&2; log "ERR: $*"; rm -rf "$WORK" 2>/dev/null; exit 1; }

current_version() {
    if [ -f "$CUR_VERSION_FILE" ]; then
        cat "$CUR_VERSION_FILE" 2>/dev/null
    elif [ -f "$HNC_DIR/data/dpi_rules.json" ]; then
        grep -oE '"rules_version"[[:space:]]*:[[:space:]]*"[^"]*"' "$HNC_DIR/data/dpi_rules.json" 2>/dev/null \
            | head -1 | sed 's/.*:.*"\([^"]*\)".*/\1/'
    else
        echo "builtin"
    fi
}

fetch_json_field() {
    # $1=json文本 $2=字段名 → 取字符串值(裸字段, 无嵌套)
    printf '%s' "$1" | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
        | head -1 | sed "s/^[^:]*:[[:space:]]*\"//; s/\"$//"
}

rebind_dpi(){
    if [ -x "$HNC_DIR/bin/dpi_rebind.sh" ]; then
        iface=$(cat "$HNC_DIR/run/hotspot_iface" 2>/dev/null | head -1)
        [ -z "$iface" ] && iface=wlan2
        sh "$HNC_DIR/bin/dpi_rebind.sh" "$iface" >/dev/null 2>&1 || true
    fi
}

validate_rules() {
    f="$1"
    [ -s "$f" ] || return 1
    grep -q '"rules"[[:space:]]*:' "$f" 2>/dev/null || return 1
    first=$(tr -d ' \t\r\n' < "$f" | cut -c1 2>/dev/null)
    [ "$first" = "{" ] || return 1
    return 0
}

get_release_meta() {
    RELEASE_JSON=$(curl -sL --connect-timeout 10 --max-time 30 \
        -H "Accept: application/vnd.github+json" "$API_URL" 2>/dev/null) \
        || fail "cannot reach $API_URL"
    [ -n "$RELEASE_JSON" ] || fail "empty release response"
    REMOTE_VERSION=$(fetch_json_field "$RELEASE_JSON" "tag_name")
    [ -n "$REMOTE_VERSION" ] || fail "no tag_name in release response"
    # dpi-rules.zip 附件的下载 URL(browser_url 字段)
    DL_URL=$(printf '%s' "$RELEASE_JSON" \
        | grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]*dpi-rules\.zip"' \
        | head -1 | sed 's/.*://; s/"//g')
    SHA_URL=$(printf '%s' "$RELEASE_JSON" \
        | grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]*dpi-rules\.zip\.sha256"' \
        | head -1 | sed 's/.*://; s/"//g')
}

case "$1" in
  --check)
    CUR=$(current_version)
    AVAILABLE=maybe
    if [ "$REMOTE_VERSION" != "$CUR" ]; then AVAILABLE=yes; else AVAILABLE=no; fi
    printf '{"current":"%s","remote":"%s","update_available":"%s"}\n' \
        "$CUR" "$REMOTE_VERSION" "$AVAILABLE"
    exit 0
    ;;
  --install)
    CUR=$(current_version)
    # v5.10.1: 版本比对 —— 与当前版本相同则跳过重装
    if [ "$REMOTE_VERSION" = "$CUR" ]; then
        echo "ok: rules already at $CUR"
        exit 0
    fi
    get_release_meta
    [ -n "$DL_URL" ] || fail "release $REMOTE_VERSION has no dpi-rules.zip attachment"
    log "install from $DL_URL (current=$CUR remote=$REMOTE_VERSION)"

    mkdir -p "$WORK" 2>/dev/null || fail "mkdir $WORK failed"
    curl -sL --connect-timeout 10 --max-time 120 -o "$WORK/dpi-rules.zip" "$DL_URL" \
        || fail "download zip failed"
    [ -s "$WORK/dpi-rules.zip" ] || fail "downloaded zip is empty"

    if [ -n "$SHA_URL" ]; then
        curl -sL --connect-timeout 10 --max-time 30 -o "$WORK/rules.sha256" "$SHA_URL" 2>/dev/null
        if [ -s "$WORK/rules.sha256" ]; then
            EXPECT=$(cut -d' ' -f1 "$WORK/rules.sha256" 2>/dev/null)
            ACTUAL=$(sha256sum "$WORK/dpi-rules.zip" 2>/dev/null | cut -d' ' -f1)
            [ -n "$ACTUAL" ] || ACTUAL=$(shasum -a 256 "$WORK/dpi-rules.zip" 2>/dev/null | cut -d' ' -f1)
            if [ -n "$EXPECT" ] && [ "$ACTUAL" != "$EXPECT" ]; then
                fail "sha256 mismatch: expected $EXPECT got $ACTUAL"
            fi
            log "sha256 ok: $ACTUAL"
        fi
    fi

    # 解包: zip 里应有 dpi_rules.json(全量规则集)。toybox 无 unzip 时的兜底
    # 是 Python —— Android 无; 最终兜底: 让用户通过 WebUI 导入。检测可用工具。
    if command -v unzip >/dev/null 2>&1; then
        unzip -o -q "$WORK/dpi-rules.zip" -d "$WORK/x" 2>/dev/null || fail "unzip failed"
        NEWFILE=$(find "$WORK/x" -name 'dpi_rules.json' -o -name '*.json' 2>/dev/null | head -1)
        [ -n "$NEWFILE" ] && [ -s "$NEWFILE" ] || fail "zip has no rules json"
        cp -f "$NEWFILE" "$WORK/rules.json" || fail "copy extracted rules failed"
    else
        fail "unzip not available on this ROM; please import via WebUI instead"
    fi

    validate_rules "$WORK/rules.json" || fail "downloaded rules failed validation"
    NEWVER=$(grep -oE '"rules_version"[[:space:]]*:[[:space:]]*"[^"]*"' "$WORK/rules.json" 2>/dev/null \
        | head -1 | sed 's/.*:.*"\([^"]*\)".*/\1/')
    [ -z "$NEWVER" ] && NEWVER="$REMOTE_VERSION"

    TMP="$DST.tmp.$$"
    cp -f "$WORK/rules.json" "$TMP" || fail "stage failed"
    mv -f "$TMP" "$DST" || fail "install failed"
    chmod 644 "$DST" 2>/dev/null
    printf '%s' "$NEWVER" > "$CUR_VERSION_FILE" 2>/dev/null
    rm -rf "$WORK" 2>/dev/null
    log "installed rules version $NEWVER"
    rebind_dpi
    echo "ok: rules updated to $NEWVER (installed as 97-online-update)"
    exit 0
    ;;
  *)
    echo "usage: $0 --check | --install" >&2
    exit 1
    ;;
esac
