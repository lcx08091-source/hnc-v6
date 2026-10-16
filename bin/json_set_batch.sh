#!/system/bin/sh
# json_set_batch.sh — 一台设备多个字段的原子写(一次校验 / 一次备份 / 一次加锁)
# Usage: sh json_set_batch.sh device <MAC> <field1> <val1> [<field2> <val2> ...]
#
# 交给 hnc_json set-device-batch, 值的类型由 hnc_json 自动判断(auto: true/false/null/
# 数字原样, 其余字符串)。v5.33: 删掉 hnc_json 不可用时逐字段串行写的 legacy 回退与
# 回退计数(run/json_legacy_fallback.*), 以及与 hnc_json 重复的类型推断。

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && \
    export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC=${HNC:-/data/local/hnc}
RULES=${RULES:-$HNC/data/rules.json}
SCRIPT_DIR=${0%/*}
[ "$SCRIPT_DIR" = "$0" ] && SCRIPT_DIR="."
HNC_JSON=${HNC_JSON:-$SCRIPT_DIR/hnc_json}
export HNC

usage() {
    echo "usage: $0 device <MAC> <k> <v> [<k> <v> ...]" >&2
    exit 2
}

valid_field() {
    case "$1" in
        ''|*[!A-Za-z0-9_.-]*) return 1 ;;
        *) return 0 ;;
    esac
}

[ "$1" = "device" ] || usage
shift
MAC=${1:-}; shift || true
[ -n "$MAC" ] || { echo "missing MAC" >&2; exit 2; }
echo "$MAC" | grep -qiE '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$' || { echo "bad MAC: $MAC" >&2; exit 2; }
[ $# -ge 2 ] && [ $(( $# % 2 )) -eq 0 ] || { echo "need k v pairs" >&2; exit 2; }

mkdir -p "$HNC/data" "$HNC/run" 2>/dev/null || true
[ -f "$RULES" ] || cat > "$RULES" <<'JSON'
{"version":1,"whitelist_mode":false,"devices":{},"blacklist":[],"whitelist":[]}
JSON

# v5.11: 不落临时文件, 在位置参数里原地轮转: 每取出一对 k v, 就把 k v auto 追加到
# "$@" 末尾, 处理完 n 对后 "$@" 恰好只剩三元组(值里含换行也不会错位)。
npairs=$(( $# / 2 ))
i=0
while [ "$i" -lt "$npairs" ]; do
    K=$1; V=$2; shift 2
    valid_field "$K" || { echo "bad field: $K" >&2; exit 2; }
    set -- "$@" "$K" "$V" auto
    i=$((i + 1))
done
if [ -x "$HNC_JSON" ]; then
    "$HNC_JSON" set-device-batch "$RULES" "$MAC" "$@"
else
    sh "$HNC_JSON" set-device-batch "$RULES" "$MAC" "$@"
fi
rc=$?
[ $rc -eq 0 ] || { echo "json_set_batch: hnc_json set-device-batch failed rc=$rc" >&2; exit $rc; }
exit 0
