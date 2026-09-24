#!/system/bin/sh
# HNC hotfix20.7: status helper for optional hnc_json C bridge.
set +e
HNC_BASE="${HNC:-${HNC_DIR:-/data/local/hnc}}"
BINDIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
BIN="${HNC_JSON_C:-$BINDIR/hnc_json_c}"

machine(){
  [ -f "$1" ] || return 1
  od -An -tx1 -j18 -N2 "$1" 2>/dev/null | awk '{print $1 " " $2}'
}

# v5.11: 路径来自环境变量(HNC_JSON_C / 安装目录), 原样塞进 "%s" 时含 " 或 \ 就输出非法 JSON
json_str() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

printf '{\n'
printf '  "helper": "%s",\n' "$(json_str "$BIN")"
if [ ! -e "$BIN" ]; then
  printf '  "present": false,\n  "enabled": false,\n  "reason": "missing"\n}\n'
  exit 0
fi

M="$(machine "$BIN" 2>/dev/null || true)"
case "$M" in
  "b7 00") ARCH="aarch64"; ANDROID_ARM=true ;;
  "28 00") ARCH="arm"; ANDROID_ARM=true ;;
  "3e 00") ARCH="x86_64-host"; ANDROID_ARM=false ;;
  "03 00") ARCH="x86-host"; ANDROID_ARM=false ;;
  # v5.11: 与 bin/hnc_json hnc_json_c_available 保持一致 —— 读不出 e_machine(od 缺失)
  # 时不据此拒绝, 交给下面的 version 自检决定; 旧逻辑在这里报 not_android_arm_elf,
  # 与 hnc_json 实际会启用 helper 的行为相反。
  "") ARCH="unknown"; ANDROID_ARM=true ;;
  *) ARCH="unknown"; ANDROID_ARM=false ;;
esac

EN=false
REASON=""
if [ "${HNC_JSON_C_DISABLE:-0}" = "1" ]; then
  REASON="disabled_by_env"
elif [ ! -x "$BIN" ]; then
  REASON="not_executable"
elif [ "$ANDROID_ARM" != "true" ] && [ "${HNC_JSON_C_ALLOW_HOST:-0}" != "1" ]; then
  REASON="not_android_arm_elf"
elif "$BIN" version >/dev/null 2>&1; then
  EN=true
  REASON="ok"
else
  REASON="self_test_failed"
fi

printf '  "present": true,\n'
printf '  "executable": %s,\n' "$([ -x "$BIN" ] && echo true || echo false)"
printf '  "machine": "%s",\n' "$M"
printf '  "arch": "%s",\n' "$ARCH"
WRITE_EN=false
WRITE_REASON="disabled_by_default"
if [ "$EN" = "true" ]; then
  if [ "${HNC_JSON_C_WRITE_ENABLE:-0}" = "1" ]; then
    WRITE_EN=true
    WRITE_REASON="enabled_by_env"
  fi
else
  WRITE_REASON="helper_not_enabled"
fi

printf '  "enabled": %s,\n' "$EN"
printf '  "reason": "%s",\n' "$REASON"
printf '  "write_enabled": %s,\n' "$WRITE_EN"
printf '  "write_reason": "%s"\n' "$WRITE_REASON"
printf '}\n'
