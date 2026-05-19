#!/system/bin/sh
# rc17_process_health.sh — lightweight HNC process health JSON
# Distinguishes main supervisor instances (PPID=1 or pidfile target) from
# temporary child shells so WebUI does not flag normal guard/watchdog helpers as duplicates.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:/data/local/hnc/bin:$PATH

HNC_DIR=${HNC_DIR:-/data/local/hnc}
RUN="$HNC_DIR/run"
NOW=$(date +%s 2>/dev/null || echo 0)
PS_OUT="$(ps -ef 2>/dev/null || ps -A 2>/dev/null)"

count_pidof(){ pidof "$1" 2>/dev/null | wc -w | tr -d ' '; }
count_lines(){ printf '%s\n' "$PS_OUT" | grep "$1" | grep -v grep | wc -l | tr -d ' '; }
# rc30.8: pidof 在 Android (toybox) 上偶尔丢失带完整路径调用的进程,
# 表现为 dpid 明明在跑但 pidof 返 0. 用 ps -ef 扫描更可靠.
# 排除自身 grep 行 + sh -c (避免把自己/包装脚本误算).
# pat 用 [x]xx 写法防 grep 自匹配.
count_proc_by_basename(){
  bn="$1"
  printf '%s\n' "$PS_OUT" | awk -v b="$bn" '
    $0 ~ b {
      # 跳过 grep 自身, 跳过 sh 包装脚本 (basename 出现在脚本路径而非可执行里)
      if ($0 ~ /[ \t](grep|awk)[ \t]/) next
      if ($0 ~ "\\.sh") next  # *.sh 不算 (那是 shell 守护脚本)
      c++
    }
    END { print c+0 }
  '
}
count_main(){
  pat="$1"
  printf '%s\n' "$PS_OUT" | awk -v p="$pat" '$0 ~ p && $3==1 {c++} END{print c+0}'
}
json_escape(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/ /g'; }
pid_alive(){ [ -n "$1" ] && kill -0 "$1" 2>/dev/null; }

HTTPD=$(count_proc_by_basename hnc_httpd)
DPID=$(count_proc_by_basename hnc_dpid)
HOTSPOTD=$(count_proc_by_basename hotspotd)
WATCHDOG_TOTAL=$(count_lines '[w]atchdog.sh')
WATCHDOG_MAIN=$(count_main '/data/local/hnc/bin/watchdog\.sh')
GUARD_TOTAL=$(count_lines '[h]nc_dpid_guard.sh')
GUARD_MAIN=$(count_main '/data/local/hnc/bin/hnc_dpid_guard\.sh')

HTTPD_PID=$(cat "$RUN/httpd.pid" 2>/dev/null)
DPID_PID=$(cat "$RUN/dpid.pid" 2>/dev/null)
DPID_CHILD_PID=$(cat "$RUN/dpid.child.pid" 2>/dev/null)
GUARD_PID=$(cat "$RUN/dpid_guard.pid" 2>/dev/null)
HOTSPOTD_PID=$(cat "$RUN/hotspotd.pid" 2>/dev/null)
WATCHDOG_PID=$(cat "$RUN/watchdog.pid" 2>/dev/null)

HTTPD_PID_OK=false; pid_alive "$HTTPD_PID" && HTTPD_PID_OK=true
DPID_PID_OK=false; pid_alive "$DPID_PID" && DPID_PID_OK=true
DPID_CHILD_PID_OK=false; pid_alive "$DPID_CHILD_PID" && DPID_CHILD_PID_OK=true
GUARD_PID_OK=false; pid_alive "$GUARD_PID" && GUARD_PID_OK=true
HOTSPOTD_PID_OK=false; pid_alive "$HOTSPOTD_PID" && HOTSPOTD_PID_OK=true
WATCHDOG_PID_OK=false; pid_alive "$WATCHDOG_PID" && WATCHDOG_PID_OK=true

STATUS=ok
DETAIL="主实例正常"
[ "$HTTPD" -ne 1 ] && STATUS=warn && DETAIL="hnc_httpd 数量异常"
[ "$DPID" -ne 1 ] && STATUS=warn && DETAIL="hnc_dpid 数量异常"
[ "$HOTSPOTD" -ne 1 ] && STATUS=warn && DETAIL="hotspotd 数量异常"
[ "$WATCHDOG_MAIN" -gt 1 ] && STATUS=warn && DETAIL="watchdog 主实例重复"
[ "$GUARD_MAIN" -gt 1 ] && STATUS=warn && DETAIL="dpid_guard 主实例重复"
[ "$WATCHDOG_TOTAL" -gt 3 ] && STATUS=warn && DETAIL="watchdog 子进程偏多"
[ "$GUARD_TOTAL" -gt 6 ] && STATUS=warn && DETAIL="dpid_guard 子进程偏多"
[ "$HOTSPOTD_PID_OK" != true ] && STATUS=warn && DETAIL="hotspotd pidfile 不可用"
# rc30.8: dpid_guard pidfile 缺失不再升 warn — rc30.0 起 Go supervisor 可能替代了 guard,
# 此时 dpid_guard.pid 自然不存在. 真正反映 dpid 健康的是上面 [ "$DPID" -ne 1 ] 检查.
# 旧 shell guard 还在用时, watchdog 会自己写 pidfile, 不缺.
[ "$WATCHDOG_PID_OK" != true ] && STATUS=warn && DETAIL="watchdog pidfile 不可用"

DETAIL_ESC=$(json_escape "$DETAIL")
cat <<EOF_JSON
{"schema_version":1,"timestamp":$NOW,"status":"$STATUS","detail":"$DETAIL_ESC","counts":{"hnc_httpd":$HTTPD,"hnc_dpid":$DPID,"hotspotd":$HOTSPOTD,"watchdog_total":$WATCHDOG_TOTAL,"watchdog_main":$WATCHDOG_MAIN,"dpid_guard_total":$GUARD_TOTAL,"dpid_guard_main":$GUARD_MAIN},"pidfiles":{"httpd":{"pid":"$HTTPD_PID","alive":$HTTPD_PID_OK},"dpid":{"pid":"$DPID_PID","alive":$DPID_PID_OK},"dpid_child":{"pid":"$DPID_CHILD_PID","alive":$DPID_CHILD_PID_OK},"dpid_guard":{"pid":"$GUARD_PID","alive":$GUARD_PID_OK},"hotspotd":{"pid":"$HOTSPOTD_PID","alive":$HOTSPOTD_PID_OK},"watchdog":{"pid":"$WATCHDOG_PID","alive":$WATCHDOG_PID_OK}}}
EOF_JSON
