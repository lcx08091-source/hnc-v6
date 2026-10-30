#!/system/bin/sh
# json_doctor.sh - hotfix18.4 JSON health report and backup restore helper
# Usage:
#   json_doctor.sh status              # default, write run/json_health.json + text report
#   json_doctor.sh list                # list JSON backups
#   json_doctor.sh restore <file>      # restore latest valid backup for file basename
#   json_doctor.sh repair              # restore invalid managed JSON files from latest valid backup
#
# This script is intentionally dependency-light for Android shell. It uses
# bin/json_guard.sh when available, and never modifies live files in status/list mode.

set +e

HNC=${HNC:-${HNC_DIR:-/data/local/hnc}}
MODDIR=${MODDIR:-/data/adb/modules/hotspot_network_control}
DATA_DIR=${DATA_DIR:-$HNC/data}
RUN_DIR=${RUN_DIR:-$HNC/run}
BACKUP_DIR=${JSON_BACKUP_DIR:-$DATA_DIR/.json_backups}
SCRIPT_DIR=${0%/*}
GUARD=${JSON_GUARD:-$SCRIPT_DIR/json_guard.sh}
HNC_JSON=${HNC_JSON:-$SCRIPT_DIR/hnc_json}
export HNC
REPORT_JSON=$RUN_DIR/json_health.json
REPORT_TXT=$RUN_DIR/json_health.txt
LOCKDIR=$HNC/run/json_doctor.lock

MANAGED_FILES="rules.json device_names.json templates.json remote_tokens.json tokens.json devices.json"
RESTORE_FILES="rules.json device_names.json templates.json remote_tokens.json"
# v5.11: 只有 rules.json 必须存在。templates.json(没建过模板)、remote_tokens.json
# (没配对过)、tokens.json(历史文件名, 新装机永远没有)不存在是常态; 旧逻辑把
# "missing" 也计入 bad, 于是 status 在几乎所有机器上恒为 degraded(rc=1, diag.sh 恒报
# JSON 健康告警), repair 也恒以 failed>0 退出。缺失的可选文件现在只报告不计坏。
REQUIRED_FILES="rules.json"
is_required() {
    case " $REQUIRED_FILES " in *" $1 "*) return 0 ;; esac
    return 1
}

mkdir -p "$RUN_DIR" "$DATA_DIR" 2>/dev/null || true

json_escape() {
    # read stdin, emit JSON string content without outer quotes
    awk 'BEGIN{ORS=""}{for(i=1;i<=length($0);i++){c=substr($0,i,1); if(c=="\\")printf "\\\\"; else if(c=="\"")printf "\\\""; else if(c=="\t")printf "\\t"; else printf "%s", c} if(NR>0) printf "\\n"}' | sed 's/\\n$//'
}

now_ts() { date +%Y-%m-%dT%H:%M:%S%z 2>/dev/null || date 2>/dev/null || echo unknown; }

validate_json() {
    f="$1"
    [ -f "$f" ] || return 2
    [ -s "$f" ] || return 3
    if [ -x "$GUARD" ]; then
        sh "$GUARD" "$f" >/dev/null 2>&1
        return $?
    fi
    awk 'BEGIN{q=0;esc=0;b=0;s=0} {for(i=1;i<=length($0);i++){c=substr($0,i,1); if(q){ if(esc){esc=0;next} if(c=="\\"){esc=1;next} if(c=="\"")q=0; next } if(c=="\""){q=1;next} if(c=="{")b++; else if(c=="}")b--; else if(c=="[")s++; else if(c=="]")s--; if(b<0||s<0)exit 1 }} END{exit (q||esc||b||s)?1:0}' "$f" >/dev/null 2>&1
}

status_word() {
    case "$1" in
        0) echo ok ;;
        2) echo missing ;;
        3) echo empty ;;
        *) echo invalid ;;
    esac
}

latest_valid_backup() {
    base="$1"
    [ -d "$BACKUP_DIR" ] || return 1
    for bak in $(ls -1t "$BACKUP_DIR/$base".*.bak 2>/dev/null); do
        validate_json "$bak"
        [ "$?" = "0" ] && { echo "$bak"; return 0; }
    done
    return 1
}

restore_one() {
    base="$1"
    case " $RESTORE_FILES " in
        *" $base "*) ;;
        *) echo "json_doctor: refusing restore for unmanaged file: $base" >&2; return 2 ;;
    esac
    bak=$(latest_valid_backup "$base") || { echo "json_doctor: no valid backup found for $base" >&2; return 1; }
    target="$DATA_DIR/$base"
    # v5.33: 交给 hnc_json replace —— 持 run/json.lock(与所有 JSON 写者同一把, 不会被
    # 并发写覆盖 / 覆盖掉刚写入的更新)、先备份现有文件(坏的也备份)、原子替换。之前这里
    # 自己实现了一份 json.lock 协议 + 自己备份 + cp/mv。
    sh "$HNC_JSON" replace "$target" < "$bak" || return 1   # sh 跑, 不靠 shebang / 执行位
    validate_json "$target"
    rc=$?
    [ "$rc" = "0" ] || { echo "json_doctor: restored file still invalid: $base" >&2; return 1; }
    echo "restored $base from $bak"
    return 0
}

write_reports() {
    tmpj="$REPORT_JSON.tmp.$$"
    tmpt="$REPORT_TXT.tmp.$$"
    bad=0
    checked=0
    ts=$(now_ts)

    {
        echo "HNC JSON health report"
        echo "time=$ts"
        echo "data_dir=$DATA_DIR"
        echo "backup_dir=$BACKUP_DIR"
        echo "guard=$GUARD"
        echo
    } > "$tmpt"

    {
        echo "{"
        echo "  \"ok\": true,"
        echo "  \"time\": \"$(printf '%s' "$ts" | json_escape)\","
        echo "  \"data_dir\": \"$(printf '%s' "$DATA_DIR" | json_escape)\","
        echo "  \"backup_dir\": \"$(printf '%s' "$BACKUP_DIR" | json_escape)\","
        echo "  \"files\": ["
    } > "$tmpj"

    first=1
    for base in $MANAGED_FILES; do
        f="$DATA_DIR/$base"
        validate_json "$f"
        rc=$?
        st=$(status_word "$rc")
        if [ "$rc" != "0" ]; then
            { [ "$rc" = "2" ] && ! is_required "$base"; } || bad=$((bad + 1))
        fi
        checked=$((checked + 1))
        size=0; mtime=""
        [ -f "$f" ] && size=$(wc -c < "$f" 2>/dev/null | tr -d ' ')
        [ -f "$f" ] && mtime=$(ls -l "$f" 2>/dev/null | awk '{print $6" "$7" "$8}')
        bak=$(latest_valid_backup "$base" 2>/dev/null)
        [ -n "$bak" ] || bak=""
        echo "$base status=$st size=$size mtime=$mtime backup=$bak" >> "$tmpt"
        [ "$first" = "1" ] || echo "    ," >> "$tmpj"
        first=0
        {
            echo "    {"
            echo "      \"name\": \"$(printf '%s' "$base" | json_escape)\","
            echo "      \"status\": \"$st\","
            echo "      \"size\": ${size:-0},"
            echo "      \"mtime\": \"$(printf '%s' "$mtime" | json_escape)\","
            echo "      \"latest_valid_backup\": \"$(printf '%s' "$bak" | json_escape)\""
            echo "    }"
        } >> "$tmpj"
    done

    {
        echo
        echo "checked=$checked"
        echo "bad=$bad"
        [ "$bad" -eq 0 ] && echo "summary=ok" || echo "summary=degraded"
    } >> "$tmpt"

    {
        echo "  ],"
        echo "  \"checked\": $checked,"
        echo "  \"bad\": $bad,"
        if [ "$bad" -eq 0 ]; then echo "  \"summary\": \"ok\""; else echo "  \"summary\": \"degraded\""; fi
        echo "}"
    } >> "$tmpj"

    mv "$tmpj" "$REPORT_JSON" 2>/dev/null || cp "$tmpj" "$REPORT_JSON" 2>/dev/null
    mv "$tmpt" "$REPORT_TXT" 2>/dev/null || cp "$tmpt" "$REPORT_TXT" 2>/dev/null
    chmod 600 "$REPORT_JSON" "$REPORT_TXT" 2>/dev/null || true
    cat "$REPORT_TXT"
    [ "$bad" -eq 0 ]
}

list_backups() {
    [ -d "$BACKUP_DIR" ] || { echo "no backup dir: $BACKUP_DIR"; return 0; }
    ls -lh "$BACKUP_DIR"/*.bak 2>/dev/null || echo "no backups"
}

repair_all() {
    repaired=0; failed=0
    for base in $RESTORE_FILES; do
        f="$DATA_DIR/$base"
        validate_json "$f"
        rc=$?
        [ "$rc" = "0" ] && continue
        # 可选文件不存在不是损坏, 不去"恢复"(否则会凭空复活用户已删掉的文件)
        [ "$rc" = "2" ] && ! is_required "$base" && continue
        echo "json_doctor: $base is $(status_word "$rc"), attempting restore" >&2
        restore_one "$base"
        r=$?
        if [ "$r" = "0" ]; then repaired=$((repaired+1)); else failed=$((failed+1)); fi
    done
    write_reports >/dev/null 2>&1 || true
    echo "repair complete: repaired=$repaired failed=$failed"
    [ "$failed" -eq 0 ]
}

acquire_lock() {
    mkdir -p "$HNC/run" 2>/dev/null || true
    if mkdir "$LOCKDIR" 2>/dev/null; then
        echo $$ > "$LOCKDIR/pid" 2>/dev/null || true
        return 0
    fi
    oldpid=$(cat "$LOCKDIR/pid" 2>/dev/null)
    if [ -n "$oldpid" ] && ! kill -0 "$oldpid" 2>/dev/null; then
        rm -rf "$LOCKDIR" 2>/dev/null
        mkdir "$LOCKDIR" 2>/dev/null && { echo $$ > "$LOCKDIR/pid" 2>/dev/null; return 0; }
    fi
    echo "json_doctor: busy" >&2
    return 1
}

release_lock() { rm -rf "$LOCKDIR" 2>/dev/null || true; }

release_all_locks() { release_lock; }
# json_doctor.lock 只让 doctor 之间互斥(两个 repair 同时跑); 写文件时的 run/json.lock
# 由 hnc_json replace 拿。
lock_for_write() {
    acquire_lock || return 1
    trap 'release_all_locks' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
}

CMD=${1:-status}
case "$CMD" in
    status|check)
        write_reports
        ;;
    list|backups)
        list_backups
        ;;
    restore)
        # 放锁统一交给 lock_for_write 设的 EXIT trap(只放一次, 不会误删别人随后拿到的锁)
        lock_for_write || exit 1
        restore_one "$2"
        exit $?
        ;;
    repair)
        lock_for_write || exit 1
        repair_all
        exit $?
        ;;
    *)
        echo "Usage: $0 [status|list|restore <file>|repair]" >&2
        exit 2
        ;;
esac
