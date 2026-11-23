#!/system/bin/sh
# pair_gen.sh — Patch 2.c: 生成 PIN 配对码
#
# 用法:
#   sh pair_gen.sh             → 生成新的 PIN,写 $RUN/pair_pending,输出 JSON
#   sh pair_gen.sh url         → 生成新的 PIN,输出 http://127.0.0.1:8444/pair?prefill=<PIN> 供 action.sh 免密拉起
#   sh pair_gen.sh cancel      → 取消当前配对(删 pair_pending)
#   sh pair_gen.sh status      → 看当前配对状态
#
# 输出 JSON:
#   {"ok":true,"pin":"123456","session_id":"abc...","expiry":1713456789,"valid_sec":120}
#
# 调用方: 本机 WebUI 通过 ksu.exec 调用,获取 PIN 后弹 modal 显示给用户
# 看到 PIN → 在远端浏览器的 /pair 页输入 → httpd 读 pair_pending + 校验
# httpd 写 pair_success.<session_id> → 本机 WebUI 轮询感知配对成功

HNC_DIR=${HNC_DIR:-/data/local/hnc}

_he_loaded=0
for _he in "${MODDIR:-}/bin/hnc_env.sh" "$HNC_DIR/bin/hnc_env.sh" "${0%/*}/hnc_env.sh"; do
    case "$_he" in /bin/hnc_env.sh) continue ;; esac
    if [ -f "$_he" ]; then . "$_he"; _he_loaded=1; break; fi
done
if [ "$_he_loaded" = "0" ] && [ -z "${HNC_SKIP_PATH_HARDENING:-}" ] && [ -z "${HNC_TEST_MODE:-}" ]; then
    export PATH="/system/bin:/system/xbin:/vendor/bin:/apex/com.android.runtime/bin:${PATH:-}:/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:/data/local/hnc/bin"
fi
unset _he _he_loaded

RUN="$HNC_DIR/run"
PENDING="$RUN/pair_pending"
TMP="$RUN/pair_pending.tmp"

VALID_SEC=120  # PIN 有效期(秒),跟 pair.go 的默认一致

# ─── 辅助: JSON 转义(含字面 Tab 兼容 pitfall_lint P5) ───
json_escape() {
    printf '%s' "$1" | tr '\r\n	' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/ /g'
}

emit_err() {
    # ok=false + error 消息
    printf '{"ok":false,"error":"%s"}\n' "$(json_escape "$1")"
    exit 1
}

emit_ok() {
    printf '%s\n' "$1"
    exit 0
}

# ─── cancel ────────────────────────────────────────────────────────
if [ "$1" = "cancel" ]; then
    rm -f "$PENDING" "$TMP" 2>/dev/null
    emit_ok '{"ok":true,"cancelled":true}'
fi

# ─── status ────────────────────────────────────────────────────────
if [ "$1" = "status" ]; then
    if [ ! -f "$PENDING" ]; then
        emit_ok '{"ok":true,"active":false}'
    fi
    # 读三行
    line1=$(sed -n '1p' "$PENDING" 2>/dev/null)
    line2=$(sed -n '2p' "$PENDING" 2>/dev/null)
    line3=$(sed -n '3p' "$PENDING" 2>/dev/null)
    now=$(date +%s)
    if [ -z "$line3" ] || [ "$line3" -lt "$now" ] 2>/dev/null; then
        # 已过期
        rm -f "$PENDING" 2>/dev/null
        emit_ok '{"ok":true,"active":false,"was_expired":true}'
    fi
    remaining=$((line3 - now))
    # 为了安全,status 不返回 PIN 本身(可能 shell 日志被截屏)
    # 只返回 session_id + 剩余时间
    printf '{"ok":true,"active":true,"session_id":"%s","remaining_sec":%d,"expiry":%d}\n' \
        "$(json_escape "$line2")" "$remaining" "$line3"
    exit 0
fi

WANT_URL=0
if [ "$1" = "url" ]; then
    WANT_URL=1
fi

# ─── generate (default | url) ──────────────────────────────────────

# 建目录防御(post-fs-data 应已建,这里再兜底)
[ ! -d "$RUN" ] && mkdir -p "$RUN" 2>/dev/null

# 校验 httpd 在跑;没跑的话生成 PIN 也没用
if [ ! -s "$RUN/httpd.pid" ]; then
    emit_err "httpd not running (remote access disabled?)"
fi
pid=$(cat "$RUN/httpd.pid" 2>/dev/null)
if ! kill -0 "$pid" 2>/dev/null; then
    emit_err "httpd process dead (stale pid file)"
fi

# 生成 6 位均匀 PIN:
# 使用 od -An -N3 -tx1 读取 3 个单字节十六进制(范围 0..16777215, 远小于 mksh 有符号 32 位上限 2147483647),
# 并拒绝 >= 16000000 的尾数实现零模偏置均匀分布。
gen_pin() {
    _gp_hex=$(od -An -N3 -tx1 /dev/urandom 2>/dev/null | tr -dc '0-9a-fA-F')
    [ "${#_gp_hex}" -eq 6 ] || return 1
    _gp_num=$(( 0x$_gp_hex ))
    [ "$_gp_num" -ge 0 ] 2>/dev/null || return 1
    if [ "${1:-0}" -lt 9 ] && [ "$_gp_num" -ge 16000000 ]; then
        return 1
    fi
    printf '%06d' $(( _gp_num % 1000000 ))
}

pin=""
attempts=0
while [ -z "$pin" ] && [ $attempts -lt 10 ]; do
    attempts=$((attempts + 1))
    pin=$(gen_pin "$attempts") || pin=""
done
[ -z "$pin" ] && emit_err "random generation failed"

# 生成 session_id: 12 字符 base64url
# head -c 从 /dev/urandom 取 9 字节 → base64 12 字符(无 padding)
# 首字符强制是字母/数字(防 shell/URL 把 "-xxxx" 当参数 + 防文件名 pair_success.-xxx 的 - 被某些工具解析成选项)
sid=""
sid_tries=0
while [ -z "$sid" ] && [ $sid_tries -lt 5 ]; do
    sid_tries=$((sid_tries + 1))
    candidate=$(head -c 9 /dev/urandom | base64 2>/dev/null | tr -d '=\n' | tr '+/' '-_' | head -c 12)
    # 首字符必须是 [a-zA-Z0-9]
    first=$(printf '%s' "$candidate" | head -c 1)
    case "$first" in
        [a-zA-Z0-9]) sid="$candidate" ;;
        *) ;;
    esac
done
if [ -z "$sid" ] || [ ${#sid} -lt 8 ]; then
    emit_err "session_id generation failed"
fi

# 计算 expiry
now=$(date +%s)
expiry=$((now + VALID_SEC))

# 原子写: tmp + rename
# 先清旧 tmp(如果残留)
rm -f "$TMP" 2>/dev/null
printf '%s\n%s\n%d\n' "$pin" "$sid" "$expiry" > "$TMP" || emit_err "write tmp failed"
chmod 600 "$TMP" 2>/dev/null
mv "$TMP" "$PENDING" || emit_err "rename failed"

# 清理可能残留的 pair_success 文件(只清我们自己的 sid 以免撞掉别的)
# 这里不清,让 pair.go 成功后自己 rm + 让本机 WebUI 轮询取走
# 但清过期的旧 success marker
find "$RUN" -maxdepth 1 -name "pair_success.*" -type f -mmin +60 -delete 2>/dev/null

# 输出
if [ "$WANT_URL" = "1" ]; then
    _base="http://127.0.0.1:8444"
    if [ -f "$RUN/webui_url" ]; then
        _u=$(head -n 1 "$RUN/webui_url" 2>/dev/null | tr -d ' \t\r\n')
        case "$_u" in
            http://127.0.0.1:*|http://localhost:*) _base="${_u%/}" ;;
        esac
    fi
    printf '%s/pair?prefill=%s\n' "$_base" "$pin"
    exit 0
fi
printf '{"ok":true,"pin":"%s","session_id":"%s","expiry":%d,"valid_sec":%d}\n' \
    "$pin" "$sid" "$expiry" "$VALID_SEC"
