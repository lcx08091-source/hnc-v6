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

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH:/data/local/hnc/bin
HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
[ -f "$HNC_DIR/bin/hnc_env.sh" ] && . "$HNC_DIR/bin/hnc_env.sh"
if [ -z "$MODDIR" ]; then [ -d /data/adb/modules/hotspot_net_ctl ] && MODDIR=/data/adb/modules/hotspot_net_ctl || MODDIR=/data/adb/modules/hotspot_network_control; fi
REPO="${HNC_RULES_REPO:-lcx08091-source/hnc-v6}"
API_URL="https://api.github.com/repos/$REPO/releases/latest"
DST="$HNC_DIR/etc/dpi_rules.d/97-online-update.json"
WORK="$HNC_DIR/run/dpi_rules_update.$$"
LOG="$HNC_DIR/logs/dpi_rules_update.log"
CUR_VERSION_FILE="$HNC_DIR/etc/dpi_rules_online.version"

mkdir -p "$HNC_DIR/etc/dpi_rules.d" "$HNC_DIR/run" "$HNC_DIR/logs" 2>/dev/null
log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)] [RULES-UPD] $*" >> "$LOG" 2>/dev/null; }
fail(){ echo "ERR: $*" >&2; log "ERR: $*"; rm -rf "$WORK" 2>/dev/null; exit 1; }

find_busybox() {
    local _b=""
    if [ -f "$HNC_DIR/bin/hnc_compat.sh" ]; then
        _b=$(sh "$HNC_DIR/bin/hnc_compat.sh" busybox 2>/dev/null | head -n 1)
        [ -n "$_b" ] && [ -x "$_b" ] && { echo "$_b"; return 0; }
    fi
    for _b in /data/adb/ksu/bin/busybox /data/adb/ap/bin/busybox /data/adb/magisk/busybox; do
        [ -x "$_b" ] && { echo "$_b"; return 0; }
    done
    if command -v busybox >/dev/null 2>&1; then
        command -v busybox
        return 0
    fi
    return 1
}

https_get_stdout() {
    # $1=https_url $2=max_time $3=extra_header(optional)
    local _url="$1" _t="${2:-30}" _hdr="${3:-}" _bb=""
    case "$_url" in https://*) ;; *) return 1 ;; esac
    if command -v curl >/dev/null 2>&1; then
        if [ -n "$_hdr" ]; then
            curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time "$_t" -H "$_hdr" "$_url" 2>/dev/null && return 0
        else
            curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time "$_t" "$_url" 2>/dev/null && return 0
        fi
    fi
    if command -v wget >/dev/null 2>&1; then
        if [ -n "$_hdr" ]; then
            wget -q -T "$_t" --header="$_hdr" -O - "$_url" 2>/dev/null && return 0
        else
            wget -q -T "$_t" -O - "$_url" 2>/dev/null && return 0
        fi
    fi
    _bb=$(find_busybox) || _bb=""
    if [ -n "$_bb" ]; then
        if [ -n "$_hdr" ]; then
            "$_bb" wget -q -T "$_t" --header="$_hdr" -O - "$_url" 2>/dev/null && return 0
        else
            "$_bb" wget -q -T "$_t" -O - "$_url" 2>/dev/null && return 0
        fi
    fi
    return 1
}

https_download_file() {
    # $1=https_url $2=dst_file $3=max_time
    local _url="$1" _out="$2" _t="${3:-60}" _bb=""
    case "$_url" in https://*) ;; *) return 1 ;; esac
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time "$_t" -o "$_out" "$_url" 2>/dev/null && [ -s "$_out" ] && return 0
        rm -f "$_out" 2>/dev/null
    fi
    if command -v wget >/dev/null 2>&1; then
        wget -q -T "$_t" -O "$_out" "$_url" 2>/dev/null && [ -s "$_out" ] && return 0
        rm -f "$_out" 2>/dev/null
    fi
    _bb=$(find_busybox) || _bb=""
    if [ -n "$_bb" ]; then
        "$_bb" wget -q -T "$_t" -O "$_out" "$_url" 2>/dev/null && [ -s "$_out" ] && return 0
        rm -f "$_out" 2>/dev/null
    fi
    return 1
}

current_version() {
    if [ -f "$CUR_VERSION_FILE" ]; then
        cat "$CUR_VERSION_FILE" 2>/dev/null
    else
        echo "builtin"
    fi
}

fetch_json_field() {
    # $1=json文本 $2=字段名 → 取字符串值(裸字段, 无嵌套)
    printf '%s' "$1" | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
        | head -n 1 | sed "s/^[^:]*:[[:space:]]*\"//; s/\"$//"
}

rebind_dpi(){
    if [ -f "$HNC_DIR/bin/dpi_rebind.sh" ]; then
        iface=$(head -n 1 "$HNC_DIR/run/hotspot_iface" 2>/dev/null | tr -d ' \r\n')
        [ -z "$iface" ] && iface=wlan2
        sh "$HNC_DIR/bin/dpi_rebind.sh" "$iface" >/dev/null 2>&1 || true
    fi
}

validate_rules() {
    f="$1"
    [ -s "$f" ] || return 1
    _jg=""
    for _c in "$HNC_DIR/bin/json_guard.sh" "$MODDIR/bin/json_guard.sh" "${0%/*}/json_guard.sh"; do
        [ -f "$_c" ] && { _jg="$_c"; break; }
    done
    [ -n "$_jg" ] || return 1
    sh "$_jg" "$f" >/dev/null 2>&1 || return 1
    grep -q '"rules"[[:space:]]*:' "$f" 2>/dev/null || return 1
    first=$(tr -d ' \t\r\n' < "$f" | cut -c1 2>/dev/null)
    [ "$first" = "{" ] || return 1
    return 0
}

get_release_meta() {
    case "$API_URL" in https://*) ;; *) fail "refusing non-HTTPS API URL" ;; esac
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1 && ! find_busybox >/dev/null 2>&1; then
        fail "curl/wget/busybox unavailable on this ROM; please import rules via WebUI instead"
    fi
    RELEASE_JSON=$(https_get_stdout "$API_URL" 30 "Accept: application/vnd.github+json") \
        || fail "cannot reach $API_URL (check network/HTTPS client or import via WebUI)"
    [ -n "$RELEASE_JSON" ] || fail "empty release response"
    REMOTE_VERSION=$(fetch_json_field "$RELEASE_JSON" "tag_name")
    [ -n "$REMOTE_VERSION" ] || fail "no tag_name in release response"
    # dpi-rules.zip 附件的下载 URL(browser_url 字段)
    DL_URL=$(printf '%s' "$RELEASE_JSON" \
        | grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]*dpi-rules\.zip"' \
        | head -n 1 | sed 's/^"browser_download_url"[[:space:]]*:[[:space:]]*"//; s/"$//')
    SHA_URL=$(printf '%s' "$RELEASE_JSON" \
        | grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]*dpi-rules\.zip\.sha256"' \
        | head -n 1 | sed 's/^"browser_download_url"[[:space:]]*:[[:space:]]*"//; s/"$//')
}

case "$1" in
  --check)
    CUR=$(current_version)
    get_release_meta
    if [ "$REMOTE_VERSION" != "$CUR" ]; then AVAILABLE=yes; else AVAILABLE=no; fi
    printf '{"current":"%s","remote":"%s","update_available":"%s"}\n' \
        "$CUR" "$REMOTE_VERSION" "$AVAILABLE"
    exit 0
    ;;
  --install)
    CUR=$(current_version)
    get_release_meta
    # 先拉取远端 tag_name 再比对(旧代码在 get_release_meta 之前比对空串 $REMOTE_VERSION!)
    if [ "$REMOTE_VERSION" = "$CUR" ]; then
        echo "ok: rules already at $CUR"
        exit 0
    fi
    [ -n "$DL_URL" ] || fail "release $REMOTE_VERSION has no dpi-rules.zip attachment"
    case "$DL_URL" in https://*) ;; *) fail "refusing non-HTTPS download URL: $DL_URL" ;; esac
    [ -n "$SHA_URL" ] || fail "release $REMOTE_VERSION has no dpi-rules.zip.sha256 attachment"
    case "$SHA_URL" in https://*) ;; *) fail "refusing non-HTTPS sha256 URL: $SHA_URL" ;; esac
    log "install from $DL_URL (current=$CUR remote=$REMOTE_VERSION)"

    mkdir -p "$WORK" 2>/dev/null || fail "mkdir $WORK failed"
    https_download_file "$DL_URL" "$WORK/dpi-rules.zip" 120 \
        || fail "download zip failed (check network/SSL or import via WebUI)"
    [ -s "$WORK/dpi-rules.zip" ] || fail "downloaded zip is empty"

    https_download_file "$SHA_URL" "$WORK/rules.sha256" 30 \
        || fail "download sha256 failed"
    [ -s "$WORK/rules.sha256" ] || fail "downloaded sha256 is empty"
    EXPECT=$(awk '{print tolower($1); exit}' "$WORK/rules.sha256" 2>/dev/null)
    printf '%s' "$EXPECT" | grep -qE '^[0-9a-f]{64}$' || fail "invalid sha256 digest in manifest"
    ACTUAL=""
    _BB_BIN=$(find_busybox 2>/dev/null || true)
    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL=$(sha256sum "$WORK/dpi-rules.zip" 2>/dev/null | awk '{print tolower($1); exit}')
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL=$(shasum -a 256 "$WORK/dpi-rules.zip" 2>/dev/null | awk '{print tolower($1); exit}')
    elif [ -n "$_BB_BIN" ]; then
        ACTUAL=$("$_BB_BIN" sha256sum "$WORK/dpi-rules.zip" 2>/dev/null | awk '{print tolower($1); exit}')
    else
        fail "sha256sum/shasum/busybox unavailable; refusing unverified package"
    fi
    printf '%s' "$ACTUAL" | grep -qE '^[0-9a-f]{64}$' || fail "failed to compute package sha256"
    [ "$ACTUAL" = "$EXPECT" ] || fail "sha256 mismatch: expected $EXPECT got $ACTUAL"
    log "sha256 ok: $ACTUAL"

    # 解包前逐条检查 zip 路径(拒绝绝对路径与 ".." 防 Zip Slip); 支持系统 unzip 或 busybox unzip
    _UNZIP_MODE=""
    if command -v unzip >/dev/null 2>&1; then
        _UNZIP_MODE="sys"
    elif [ -n "$_BB_BIN" ] && "$_BB_BIN" unzip -l "$WORK/dpi-rules.zip" >/dev/null 2>&1; then
        _UNZIP_MODE="bb"
    fi
    if [ -n "$_UNZIP_MODE" ]; then
        _zip_list="$WORK/zip.list"
        if [ "$_UNZIP_MODE" = "sys" ]; then
            if ! unzip -Z1 "$WORK/dpi-rules.zip" > "$_zip_list" 2>/dev/null || [ ! -s "$_zip_list" ]; then
                unzip -l "$WORK/dpi-rules.zip" 2>/dev/null \
                    | awk '/^-+/{s++; next} s==1 && NF>=4 { sub(/^[[:space:]]*[0-9]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+/, ""); print }' \
                    > "$_zip_list" 2>/dev/null
            fi
        else
            "$_BB_BIN" unzip -l "$WORK/dpi-rules.zip" 2>/dev/null \
                | awk '/^-+/{s++; next} s==1 && NF>=4 { sub(/^[[:space:]]*[0-9]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+/, ""); print }' \
                > "$_zip_list" 2>/dev/null
        fi
        [ -s "$_zip_list" ] || fail "cannot inspect zip entries"
        _target_entry=""
        _fallback_entry=""
        while IFS= read -r _ze; do
            [ -n "$_ze" ] || continue
            case "$_ze" in
                /*|..|../*|*/..|*/../*|*\\*)
                    fail "unsafe zip entry path rejected: $_ze"
                    ;;
                */)
                    continue
                    ;;
                dpi_rules.json|*/dpi_rules.json)
                    [ -z "$_target_entry" ] && _target_entry="$_ze"
                    ;;
                *.json)
                    [ -z "$_fallback_entry" ] && _fallback_entry="$_ze"
                    ;;
            esac
        done < "$_zip_list"
        [ -z "$_target_entry" ] && _target_entry="$_fallback_entry"
        [ -n "$_target_entry" ] || fail "zip has no rules json"
        if [ "$_UNZIP_MODE" = "sys" ]; then
            unzip -p "$WORK/dpi-rules.zip" "$_target_entry" > "$WORK/rules.json" 2>/dev/null || fail "unzip extract failed"
        else
            "$_BB_BIN" unzip -p "$WORK/dpi-rules.zip" "$_target_entry" > "$WORK/rules.json" 2>/dev/null || fail "busybox unzip extract failed"
        fi
        [ -s "$WORK/rules.json" ] || fail "extracted rules json is empty"
    else
        fail "unzip/busybox unzip not available on this ROM; please import via WebUI instead"
    fi

    validate_rules "$WORK/rules.json" || fail "downloaded rules failed validation"
    NEWVER=$(grep -oE '"rules_version"[[:space:]]*:[[:space:]]*"[^"]*"' "$WORK/rules.json" 2>/dev/null \
        | head -n 1 | sed 's/.*:.*"\([^"]*\)".*/\1/')
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
