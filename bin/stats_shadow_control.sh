#!/system/bin/sh
# stats_shadow_control.sh — HNC hotfix21.7 shadow stats runtime switch
#
# Safe control helper for the v5.2 stats migration. It only toggles a small
# runtime flag used by stats_sample.sh to decide whether to also write shadow
# stats. It does not replace legacy stats output and does not edit TC/iptables.
#
# Usage:
#   sh stats_shadow_control.sh status        # JSON by default
#   sh stats_shadow_control.sh text
#   sh stats_shadow_control.sh enable        # create run/stats_shadow.enabled
#   sh stats_shadow_control.sh disable       # remove run/stats_shadow.enabled

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}
DATA="$HNC_DIR/data"
RUN="$HNC_DIR/run"
CONFIG="$DATA/config.json"
FLAG="$RUN/stats_shadow.enabled"
MODE=${1:-json}
mkdir -p "$RUN" 2>/dev/null

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r/ /g; s/\n/ /g; s/\t/ /g'
}

config_enabled=false
if [ -f "$CONFIG" ] && grep -q '"stats_shadow_enabled"[[:space:]]*:[[:space:]]*true' "$CONFIG" 2>/dev/null; then
  config_enabled=true
fi

flag_enabled=false
[ -f "$FLAG" ] && flag_enabled=true

env_value="${HNC_STATS_SHADOW_ENABLE:-}"
env_state="unset"
case "$env_value" in
  1|true|TRUE|yes|YES) env_state="enabled" ;;
  0|false|FALSE|no|NO) env_state="disabled" ;;
esac

effective=false
reason="disabled_by_default"
case "$env_state" in
  enabled) effective=true; reason="env:HNC_STATS_SHADOW_ENABLE" ;;
  disabled) effective=false; reason="env:HNC_STATS_SHADOW_ENABLE" ;;
  *)
    if [ "$config_enabled" = true ]; then
      effective=true; reason="config:stats_shadow_enabled"
    elif [ "$flag_enabled" = true ]; then
      effective=true; reason="flag:stats_shadow.enabled"
    fi
    ;;
esac

case "$MODE" in
  enable)
    echo "enabled" > "$FLAG" 2>/dev/null || { echo "failed to write $FLAG" >&2; exit 1; }
    echo "shadow stats enabled via $FLAG"
    exit 0
    ;;
  disable)
    rm -f "$FLAG" 2>/dev/null || { echo "failed to remove $FLAG" >&2; exit 1; }
    echo "shadow stats disabled via $FLAG"
    exit 0
    ;;
  text)
    cat <<EOF2
HNC shadow stats control
status=ok
effective_enabled=$effective
reason=$reason
env_state=$env_state
env_value=$env_value
config_enabled=$config_enabled
flag_enabled=$flag_enabled
config_path=$CONFIG
flag_path=$FLAG
EOF2
    exit 0
    ;;
  json|status|*)
    cat <<EOF2
{"ok":true,"status":"ok","effective_enabled":$effective,"reason":"$(json_escape "$reason")","env_state":"$(json_escape "$env_state")","env_value":"$(json_escape "$env_value")","config_enabled":$config_enabled,"flag_enabled":$flag_enabled,"config_path":"$(json_escape "$CONFIG")","flag_path":"$(json_escape "$FLAG")"}
EOF2
    exit 0
    ;;
esac
