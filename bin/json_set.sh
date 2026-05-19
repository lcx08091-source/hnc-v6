#!/system/bin/sh

# v3.5.0 alpha-0: PATH 健壮性,见 service.sh
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH
# json_set.sh — 纯 Shell JSON 字段更新工具，不依赖 python3
#
# 用法:
#   json_set.sh device  <mac> <field> <value>   # 更新 .devices[mac][field]
#   json_set.sh bl_add  <mac>                   # 加入 blacklist
#   json_set.sh bl_del  <mac>                   # 从 blacklist 删除
#   json_set.sh reset                           # 清空 devices 和 blacklist
#
# 原理：用 awk 直接做文本替换，适用于我们固定格式的 rules.json
# rules.json 格式固定可预测，不需要通用 JSON 解析器

HNC=${HNC:-/data/local/hnc}
RULES=$HNC/data/rules.json
TMP=$HNC/data/rules.tmp
SCRIPT_DIR=${0%/*}
[ "$SCRIPT_DIR" = "$0" ] && SCRIPT_DIR="."
JSON_GUARD=${JSON_GUARD:-$SCRIPT_DIR/json_guard.sh}
HNC_JSON=${HNC_JSON:-$SCRIPT_DIR/hnc_json}
JSON_BACKUP_DIR=${JSON_BACKUP_DIR:-$HNC/data/.json_backups}

# hotfix20.1: legacy fallback telemetry.
# Do not remove legacy paths yet; record when they are used so later releases
# can decide whether it is safe to prune them. Keep this best-effort and
# non-fatal because json_set.sh is used on recovery/early-boot paths.
JSON_LEGACY_FALLBACK_LOG=${JSON_LEGACY_FALLBACK_LOG:-$HNC/run/json_legacy_fallback.log}
JSON_LEGACY_FALLBACK_COUNT=${JSON_LEGACY_FALLBACK_COUNT:-$HNC/run/json_legacy_fallback.count}
json_legacy_fallback_warn() {
    local op="$1"
    local reason="$2"
    local ts cnt
    ts=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date 2>/dev/null || echo unknown)
    mkdir -p "$HNC/run" 2>/dev/null || true
    printf '%s json_set op=%s reason=%s\n' "$ts" "$op" "$reason" >> "$JSON_LEGACY_FALLBACK_LOG" 2>/dev/null || true
    if [ -f "$JSON_LEGACY_FALLBACK_COUNT" ]; then
        cnt=$(cat "$JSON_LEGACY_FALLBACK_COUNT" 2>/dev/null)
        case "$cnt" in *[!0-9]*|'') cnt=0 ;; esac
    else
        cnt=0
    fi
    cnt=$((cnt + 1))
    echo "$cnt" > "$JSON_LEGACY_FALLBACK_COUNT" 2>/dev/null || true
    # v5.3.0-rc8 P0: do not write fallback WARN to stderr.
    # hnc_httpd uses CombinedOutput() on json_set.sh hot paths; stderr text can
    # be mixed into real stdout and poison integer/JSON parsing. Keep telemetry
    # in the log/count files only.
    printf 'json_set: [WARN] hnc_json %s unavailable/failed, using legacy fallback; count=%s\n' "$op" "$cnt" \
        >> "$JSON_LEGACY_FALLBACK_LOG" 2>/dev/null || true
}

# ═══════════════════════════════════════════════════════════════
# v3.4.11 P0-2 修复:加 mkdir 文件锁,防并发写竞态
#
# 之前的问题:
#   - 所有写命令(top/device/bl_add/bl_del/reset/cfg_set/name_*)都用
#     `awk ... > "$TMP" && mv "$TMP" "$RULES"`,共用同一个 $TMP
#   - 两个并发 shell 同时写 → 第二个 mv 用半写完的临时文件覆盖 → JSON 破损
#   - shUpdate 串行 5 次 kexec 写 5 个字段,user 快速点击两次"应用"或
#     setTimeout(doRefresh, 100) 跟 user 点击交错 → 触发竞态
#
# 修复:用 mkdir 原子操作做锁(POSIX 标准,所有 ash/busybox 都支持),
# 5 秒超时(50 × 100ms)。trap 退出时自动释放。
# ═══════════════════════════════════════════════════════════════
LOCKDIR=$HNC/run/json.lock
mkdir -p $HNC/run 2>/dev/null

# v3.4.11 内部加固:sleep 0.1 在 busybox ash 不一定支持小数,
# 改用 usleep(支持微秒,busybox 大部分版本有)。usleep 也失败则 fall back
# 到 sleep 1(慢 10 倍但能用)。同时加陈旧锁检测:
# 如果锁目录存在超过 10 秒(可能是上次崩溃没释放),强制清掉再重试。
_short_sleep() {
    usleep 100000 2>/dev/null && return 0
    sleep 1
}

# v3.5.1 P0-4 修复:之前 force_break 在 2 秒后无条件 rmdir 锁目录,
# 不检查持锁进程是否还活着 → 大文件 awk 慢的时候,持锁进程 A 还在工作,
# 进程 B 强拆锁进入,A 和 B 同时 mv 到 .tmp,JSON 损坏。
#
# 修复:锁目录里写持锁 PID,force_break 之前先 kill -0 检查存活,
# 只有持锁进程已死才强拆。

acquire_lock() {
    local i=0
    local force_break=20  # 第 20 次重试时(=2 秒)考虑强拆陈旧锁
    while [ $i -lt 50 ]; do
        if mkdir "$LOCKDIR" 2>/dev/null; then
            # 成功获取锁,写自己 PID
            echo $$ > "$LOCKDIR/pid" 2>/dev/null
            # rc3.1.34 修 #3: 之前 trap 第一句 `rmdir "$LOCKDIR/pid"` 是死代码 ——
            # pid 是 echo 写的普通文件不是目录, rmdir 永远 fail 但被 2>/dev/null 吞掉.
            # 教训 #8 反模式本身. 移除死代码, 只留正确的 rm + rmdir.
            trap 'rm -f "$LOCKDIR/pid" 2>/dev/null; rmdir "$LOCKDIR" 2>/dev/null' EXIT INT TERM
            return 0
        fi
        # 第 20 次重试时检查是否真的陈旧
        if [ $i -eq $force_break ]; then
            local lock_pid
            lock_pid=$(cat "$LOCKDIR/pid" 2>/dev/null)
            if [ -z "$lock_pid" ]; then
                # 锁目录存在但没 PID 文件 — 可能是上一版残留或刚 mkdir 还没 echo
                # 给一次机会再等一轮,而不是立刻拆
                _short_sleep
                i=$((i+1))
                continue
            fi
            if kill -0 "$lock_pid" 2>/dev/null; then
                # 持锁进程还活着,不拆,继续等
                echo "json_set: lock held by alive PID $lock_pid, waiting" >&2
            else
                # 持锁进程已死,安全强拆
                echo "json_set: force-break stale lock (dead PID $lock_pid)" >&2
                rm -f "$LOCKDIR/pid" 2>/dev/null
                rmdir "$LOCKDIR" 2>/dev/null
            fi
        fi
        _short_sleep
        i=$((i+1))
    done
    return 1
}
release_lock() {
    rm -f "$LOCKDIR/pid" 2>/dev/null
    rmdir "$LOCKDIR" 2>/dev/null
}

# ═══════════════════════════════════════════════════════════════
# v3.3.0 新增：统一的 JSON 值编码函数
# 规则：
#   - true / false / null → 原样（JSON 字面量）
#   - 严格数字（整数或浮点，可带负号）→ 原样
#   - 其他一律当字符串 → 加 JSON 双引号
#
# 关键修复：原实现 `*[!0-9.-]*` 允许 "192.168.1.5" 当数字，
# 导致 IP 写入 JSON 时不带引号，破坏 JSON 格式。
# ═══════════════════════════════════════════════════════════════
json_encode() {
    local v=$1
    case "$v" in
        true|false|null)
            echo "$v" ;;
        '')
            echo '""' ;;
        *)
            # 严格数字匹配：可选负号 + 整数 + 可选小数部分
            if echo "$v" | grep -qE '^-?[0-9]+(\.[0-9]+)?$'; then
                echo "$v"
            else
                # hotfix18.0: 字符串值统一做 JSON-safe 编码。
                # 去掉控制字符，再转义反斜杠和双引号，避免 SSID/名称中
                # 的逗号、右花括号、反斜杠、引号破坏 rules.json。
                local esc
                esc=$(printf '%s' "$v" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g')
                echo "\"$esc\""
            fi
            ;;
    esac
}


# hotfix18.1: always-string JSON encoder for names/template keys.
# json_encode intentionally preserves true/false/null/numbers for rules values;
# these helpers are for fields that must always be JSON strings.
json_escape_string_inner() {
    printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g'
}
json_string_encode() {
    local esc
    esc=$(json_escape_string_inner "$1")
    echo "\"$esc\""
}

# 确保目录和文件存在
mkdir -p $HNC/data
[ -f $RULES ] || cat > $RULES << 'EOF'
{"version":1,"whitelist_mode":false,"devices":{},"blacklist":[],"whitelist":[]}
EOF

# v3.4.6: device_names.json 路径与初始化
NAMES_FILE=$HNC/data/device_names.json
ensure_names_file() {
    [ -f "$NAMES_FILE" ] || echo '{}' > "$NAMES_FILE"
}


# hotfix18.3: write-after-validate guard + automatic rollback.
json_validate_file() {
    local f="$1"
    [ -s "$f" ] || { echo "json_set: empty JSON candidate: $f" >&2; return 1; }
    if [ -x "$JSON_GUARD" ]; then
        sh "$JSON_GUARD" "$f" >/dev/null 2>&1
        return $?
    fi
    awk 'BEGIN{q=0;esc=0;b=0;s=0} {for(i=1;i<=length($0);i++){c=substr($0,i,1); if(q){ if(esc){esc=0;next} if(c=="\\"){esc=1;next} if(c=="\"")q=0; next } if(c=="\""){q=1;next} if(c=="{")b++; else if(c=="}")b--; else if(c=="[")s++; else if(c=="]")s--; if(b<0||s<0)exit 1 }} END{exit (q||esc||b||s)?1:0}' "$f"
}

json_backup_file() {
    local f="$1" base ts bak
    [ -f "$f" ] || return 0
    mkdir -p "$JSON_BACKUP_DIR" 2>/dev/null || return 0
    base=$(basename "$f")
    ts=$(date +%Y%m%d-%H%M%S 2>/dev/null || echo now)
    bak="$JSON_BACKUP_DIR/$base.$ts.$$.bak"
    cp -p "$f" "$bak" 2>/dev/null || return 0
    echo "$bak"
}

json_prune_backups() {
    mkdir -p "$JSON_BACKUP_DIR" 2>/dev/null || return 0
    (ls -1t "$JSON_BACKUP_DIR"/*.bak 2>/dev/null | sed -n '31,$p' | xargs rm -f) 2>/dev/null || true
}

guarded_commit() {
    local tmpfile="$1" target="$2" backup rc
    if ! json_validate_file "$tmpfile"; then
        echo "json_set: refusing invalid JSON candidate for $target" >&2
        rm -f "$tmpfile" 2>/dev/null
        return 1
    fi
    backup=$(json_backup_file "$target")
    mv "$tmpfile" "$target" || return 1
    chmod 600 "$target" 2>/dev/null || true
    if json_validate_file "$target"; then
        json_prune_backups
        return 0
    fi
    rc=$?
    echo "json_set: post-write validation failed for $target, rolling back" >&2
    if [ -n "$backup" ] && [ -f "$backup" ]; then
        cp -p "$backup" "$target" 2>/dev/null || true
    fi
    return $rc
}

CMD=$1

# v3.4.11 P0-2: 写命令统一加锁,读命令不加锁(避免阻塞 cfg_get / name_get)
# 注意:device_patch 不在此列表 — 它内部递归调 `sh "$0" device`,
# device 命令本身会 acquire_lock,加在外层会自己跟自己抢锁导致 5 秒超时回归

# ═══════════════════════════════════════════════════════════════
# hotfix18.1: generic safe JSON object/array helpers
#
# Covers remaining high-risk write paths:
#   - device_remove
#   - bl_add / bl_del
#   - name_set / name_del
#   - tpl_set / tpl_del
#
# These helpers avoid regex fragments like [^}]* and [^\"]* that break when
# JSON strings contain commas, braces, escaped quotes, or backslashes.
# They are still small POSIX-awk state machines, not a full JSON library.
# hotfix18.x will later replace this whole wrapper with hnc_json.
# ═══════════════════════════════════════════════════════════════

json_object_set_safe_file() {
    local file="$1" tmpfile="$2" key="$3" jval="$4"
    [ -f "$file" ] || echo '{}' > "$file"
    local keytmp="${tmpfile}.key.$$" valtmp="${tmpfile}.val.$$"
    printf '%s' "$key" > "$keytmp"
    printf '%s' "$jval" > "$valtmp"
    awk -v keyfile="$keytmp" -v valfile="$valtmp" '
    BEGIN { getline key < keyfile; close(keyfile); getline val < valfile; close(valfile) }
    function ch(i){ return substr(s,i,1) }
    function skipws(i){ while(i<=n && ch(i) ~ /[ \t\r\n]/) i++; return i }
    function strend(i,   j,c,esc){ esc=0; for(j=i+1;j<=n;j++){ c=ch(j); if(esc){esc=0; continue} if(c=="\\"){esc=1; continue} if(c=="\"") return j } return 0 }
    function valend(i,   j,c,se,depth,opn,clos){ i=skipws(i); c=ch(i); if(c=="\""){ se=strend(i); return se ? se+1 : n+1 } if(c=="{" || c=="["){ opn=c; clos=(c=="{" ? "}" : "]"); depth=0; for(j=i;j<=n;j++){ c=ch(j); if(c=="\""){ se=strend(j); if(!se) return n+1; j=se; continue } if(c==opn) depth++; else if(c==clos){ depth--; if(depth==0) return j+1 } } return n+1 } for(j=i;j<=n;j++){ c=ch(j); if(c=="," || c=="}" || c=="]") return j } return n+1 }
    function findkey(target,depth_target,start,stop,   i,c,se,after,k,depth){ fk=fs=fe=0; depth=0; for(i=1;i<=n;i++){ c=ch(i); if(c=="\""){ se=strend(i); if(!se) return 0; if(i>=start && i<=stop && depth==depth_target){ after=skipws(se+1); if(ch(after)==":"){ k=substr(s,i+1,se-i-1); if(k==target){ fk=i; fs=skipws(after+1); fe=valend(fs); return 1 } } } i=se; continue } if(c=="{" || c=="[") depth++; else if(c=="}" || c=="]") depth-- } return 0 }
    { s=s $0 "\n" }
    END {
        sub(/\n$/, "", s); n=length(s)
        if(n==0){ s="{}"; n=2 }
        if(findkey(key,1,1,n)) { print substr(s,1,fs-1) val substr(s,fe); exit }
        p=index(s,"{"); if(!p){ print s; exit 1 }
        q=skipws(p+1); comma=(ch(q)=="}" ? "" : ",")
        print substr(s,1,p) "\"" key "\": " val comma substr(s,p+1)
    }' "$file" > "$tmpfile" && guarded_commit "$tmpfile" "$file"
    local rc=$?
    rm -f "$keytmp" "$valtmp"
    return $rc
}

json_object_del_safe_file() {
    local file="$1" tmpfile="$2" key="$3"
    [ -f "$file" ] || return 0
    local keytmp="${tmpfile}.key.$$"
    printf '%s' "$key" > "$keytmp"
    awk -v keyfile="$keytmp" '
    BEGIN { getline key < keyfile; close(keyfile) }
    function ch(i){ return substr(s,i,1) }
    function skipws(i){ while(i<=n && ch(i) ~ /[ \t\r\n]/) i++; return i }
    function prevnw(i){ while(i>=1 && ch(i) ~ /[ \t\r\n]/) i--; return i }
    function strend(i,   j,c,esc){ esc=0; for(j=i+1;j<=n;j++){ c=ch(j); if(esc){esc=0; continue} if(c=="\\"){esc=1; continue} if(c=="\"") return j } return 0 }
    function valend(i,   j,c,se,depth,opn,clos){ i=skipws(i); c=ch(i); if(c=="\""){ se=strend(i); return se ? se+1 : n+1 } if(c=="{" || c=="["){ opn=c; clos=(c=="{" ? "}" : "]"); depth=0; for(j=i;j<=n;j++){ c=ch(j); if(c=="\""){ se=strend(j); if(!se) return n+1; j=se; continue } if(c==opn) depth++; else if(c==clos){ depth--; if(depth==0) return j+1 } } return n+1 } for(j=i;j<=n;j++){ c=ch(j); if(c=="," || c=="}" || c=="]") return j } return n+1 }
    function findkey(target,depth_target,start,stop,   i,c,se,after,k,depth){ fk=fs=fe=0; depth=0; for(i=1;i<=n;i++){ c=ch(i); if(c=="\""){ se=strend(i); if(!se) return 0; if(i>=start && i<=stop && depth==depth_target){ after=skipws(se+1); if(ch(after)==":"){ k=substr(s,i+1,se-i-1); if(k==target){ fk=i; fs=skipws(after+1); fe=valend(fs); return 1 } } } i=se; continue } if(c=="{" || c=="[") depth++; else if(c=="}" || c=="]") depth-- } return 0 }
    { s=s $0 "\n" }
    END {
        sub(/\n$/, "", s); n=length(s)
        if(!findkey(key,1,1,n)){ print s; exit }
        end=fe-1; after=skipws(fe); before=prevnw(fk-1)
        if(after<=n && ch(after)==",") print substr(s,1,fk-1) substr(s,after+1)
        else if(before>=1 && ch(before)==",") print substr(s,1,before-1) substr(s,end+1)
        else print substr(s,1,fk-1) substr(s,end+1)
    }' "$file" > "$tmpfile" && guarded_commit "$tmpfile" "$file"
    local rc=$?
    rm -f "$keytmp"
    return $rc
}

json_array_add_string_top_safe() {
    local field="$1" item="$2" jval
    jval=$(json_string_encode "$item")
    awk -v field="$field" -v val="$jval" '
    function ch(i){ return substr(s,i,1) }
    function skipws(i){ while(i<=n && ch(i) ~ /[ \t\r\n]/) i++; return i }
    function strend(i,   j,c,esc){ esc=0; for(j=i+1;j<=n;j++){ c=ch(j); if(esc){esc=0; continue} if(c=="\\"){esc=1; continue} if(c=="\"") return j } return 0 }
    function valend(i,   j,c,se,depth,opn,clos){ i=skipws(i); c=ch(i); if(c=="\""){ se=strend(i); return se ? se+1 : n+1 } if(c=="{" || c=="["){ opn=c; clos=(c=="{" ? "}" : "]"); depth=0; for(j=i;j<=n;j++){ c=ch(j); if(c=="\""){ se=strend(j); if(!se) return n+1; j=se; continue } if(c==opn) depth++; else if(c==clos){ depth--; if(depth==0) return j+1 } } return n+1 } for(j=i;j<=n;j++){ c=ch(j); if(c=="," || c=="}" || c=="]") return j } return n+1 }
    function findkey(target,depth_target,start,stop,   i,c,se,after,k,depth){ fk=fs=fe=0; depth=0; for(i=1;i<=n;i++){ c=ch(i); if(c=="\""){ se=strend(i); if(!se) return 0; if(i>=start && i<=stop && depth==depth_target){ after=skipws(se+1); if(ch(after)==":"){ k=substr(s,i+1,se-i-1); if(k==target){ fk=i; fs=skipws(after+1); fe=valend(fs); return 1 } } } i=se; continue } if(c=="{" || c=="[") depth++; else if(c=="}" || c=="]") depth-- } return 0 }
    { s=s $0 "\n" }
    END {
        sub(/\n$/, "", s); n=length(s)
        if(!findkey(field,1,1,n) || ch(skipws(fs))!="[") {
            p=index(s,"{"); if(!p){ print s; exit 1 }
            q=skipws(p+1); comma=(ch(q)=="}" ? "" : ",")
            print substr(s,1,p) "\"" field "\": [" val "]" comma substr(s,p+1); exit
        }
        a=skipws(fs); b=fe-1; exists=0
        for(i=skipws(a+1); i<b; ) { ve=valend(i); tok=substr(s,i,ve-i); if(tok==val) exists=1; i=skipws(ve); if(ch(i)==",") i=skipws(i+1) }
        if(exists){ print s; exit }
        q=skipws(a+1)
        if(ch(q)=="]") print substr(s,1,a) val substr(s,b)
        else print substr(s,1,b-1) "," val substr(s,b)
    }' "$RULES" > "$TMP" && atomic_write
}

json_array_del_string_top_safe() {
    local field="$1" item="$2" jval
    jval=$(json_string_encode "$item")
    awk -v field="$field" -v val="$jval" '
    function ch(i){ return substr(s,i,1) }
    function skipws(i){ while(i<=n && ch(i) ~ /[ \t\r\n]/) i++; return i }
    function strend(i,   j,c,esc){ esc=0; for(j=i+1;j<=n;j++){ c=ch(j); if(esc){esc=0; continue} if(c=="\\"){esc=1; continue} if(c=="\"") return j } return 0 }
    function valend(i,   j,c,se,depth,opn,clos){ i=skipws(i); c=ch(i); if(c=="\""){ se=strend(i); return se ? se+1 : n+1 } if(c=="{" || c=="["){ opn=c; clos=(c=="{" ? "}" : "]"); depth=0; for(j=i;j<=n;j++){ c=ch(j); if(c=="\""){ se=strend(j); if(!se) return n+1; j=se; continue } if(c==opn) depth++; else if(c==clos){ depth--; if(depth==0) return j+1 } } return n+1 } for(j=i;j<=n;j++){ c=ch(j); if(c=="," || c=="}" || c=="]") return j } return n+1 }
    function findkey(target,depth_target,start,stop,   i,c,se,after,k,depth){ fk=fs=fe=0; depth=0; for(i=1;i<=n;i++){ c=ch(i); if(c=="\""){ se=strend(i); if(!se) return 0; if(i>=start && i<=stop && depth==depth_target){ after=skipws(se+1); if(ch(after)==":"){ k=substr(s,i+1,se-i-1); if(k==target){ fk=i; fs=skipws(after+1); fe=valend(fs); return 1 } } } i=se; continue } if(c=="{" || c=="[") depth++; else if(c=="}" || c=="]") depth-- } return 0 }
    { s=s $0 "\n" }
    END {
        sub(/\n$/, "", s); n=length(s)
        if(!findkey(field,1,1,n) || ch(skipws(fs))!="["){ print s; exit }
        a=skipws(fs); b=fe-1; out=""
        for(i=skipws(a+1); i<b; ) { ve=valend(i); tok=substr(s,i,ve-i); if(tok!=val){ if(out!="") out=out ","; out=out tok } i=skipws(ve); if(ch(i)==",") i=skipws(i+1) }
        print substr(s,1,a) out substr(s,b)
    }' "$RULES" > "$TMP" && atomic_write
}

json_remove_device_safe() {
    local mac="$1"
    awk -v mac="$mac" '
    function ch(i){ return substr(s,i,1) }
    function skipws(i){ while(i<=n && ch(i) ~ /[ \t\r\n]/) i++; return i }
    function prevnw(i){ while(i>=1 && ch(i) ~ /[ \t\r\n]/) i--; return i }
    function strend(i,   j,c,esc){ esc=0; for(j=i+1;j<=n;j++){ c=ch(j); if(esc){esc=0; continue} if(c=="\\"){esc=1; continue} if(c=="\"") return j } return 0 }
    function valend(i,   j,c,se,depth,opn,clos){ i=skipws(i); c=ch(i); if(c=="\""){ se=strend(i); return se ? se+1 : n+1 } if(c=="{" || c=="["){ opn=c; clos=(c=="{" ? "}" : "]"); depth=0; for(j=i;j<=n;j++){ c=ch(j); if(c=="\""){ se=strend(j); if(!se) return n+1; j=se; continue } if(c==opn) depth++; else if(c==clos){ depth--; if(depth==0) return j+1 } } return n+1 } for(j=i;j<=n;j++){ c=ch(j); if(c=="," || c=="}" || c=="]") return j } return n+1 }
    function findkey(target,depth_target,start,stop,   i,c,se,after,k,depth){ fk=fs=fe=0; depth=0; for(i=1;i<=n;i++){ c=ch(i); if(c=="\""){ se=strend(i); if(!se) return 0; if(i>=start && i<=stop && depth==depth_target){ after=skipws(se+1); if(ch(after)==":"){ k=substr(s,i+1,se-i-1); if(k==target){ fk=i; fs=skipws(after+1); fe=valend(fs); return 1 } } } i=se; continue } if(c=="{" || c=="[") depth++; else if(c=="}" || c=="]") depth-- } return 0 }
    { s=s $0 "\n" }
    END {
        sub(/\n$/, "", s); n=length(s)
        if(!findkey("devices",1,1,n) || ch(skipws(fs))!="{"){ print s; exit }
        ds=skipws(fs); de=fe-1
        if(!findkey(mac,2,ds,de)){ print s; exit }
        end=fe-1; after=skipws(fe); before=prevnw(fk-1)
        if(after<=n && ch(after)==",") print substr(s,1,fk-1) substr(s,after+1)
        else if(before>=1 && ch(before)==",") print substr(s,1,before-1) substr(s,end+1)
        else print substr(s,1,fk-1) substr(s,end+1)
    }' "$RULES" > "$TMP" && atomic_write
}


# hotfix19.9: bridge blacklist array writes to hnc_json.
# blacklist is a top-level array of MAC strings in rules.json. hnc_json now
# provides array add/delete primitives so this high-risk legacy JSON mutation
# path can move behind the unified guarded writer while fallback stays intact.
json_blacklist_add_hnc_json() {
    local mac="$1"
    [ -x "$HNC_JSON" ] || return 127
    "$HNC_JSON" add-array-unique "$RULES" "blacklist" "$mac"
}

json_blacklist_del_hnc_json() {
    local mac="$1"
    [ -x "$HNC_JSON" ] || return 127
    "$HNC_JSON" del-array-value "$RULES" "blacklist" "$mac"
}


# hotfix20.0: bridge remote_tokens.json revoke writes to hnc_json.
# Token issuing/last_seen stays owned by Go TokensStore; shell only routes
# revoke/revoke_all through the same guarded JSON helper and keeps legacy fallback.
json_token_revoke_hnc_json() {
    local file="$1" tid="$2"
    [ -x "$HNC_JSON" ] || return 127
    "$HNC_JSON" token-revoke "$file" "$tid"
}

json_token_revoke_all_hnc_json() {
    local file="$1"
    [ -x "$HNC_JSON" ] || return 127
    "$HNC_JSON" token-revoke-all "$file"
}
case "$CMD" in
    top|device|device_remove|bl_add|bl_del|reset|cfg_set|name_set|name_del|tpl_set|tpl_del|token_revoke|token_revoke_all|token_prune)
        acquire_lock || { echo "json_set: lock timeout (5s)" >&2; exit 2; }
        ;;
esac

# ── 原子写入：先写临时文件，再 mv ──────────────────────────
atomic_write() {
    guarded_commit "$TMP" "$RULES"
}

# ═══════════════════════════════════════════════════════════════
# hotfix18.0: JSON state-machine writer for rules.json
#
# 旧 top/device 写路径用 awk 正则 `[^,}]*` 替换值。字符串里只要
# 出现逗号、右花括号、转义引号，就会提前截断，写坏 rules.json。
# 这里改成字符级扫描：识别 JSON 字符串、转义、对象/数组深度，
# 只在目标对象层级替换目标 key 的 value。
#
# 范围：top 与 device 两条最高频/最高风险写路径。
# 约束：不依赖 python/jq，兼容 Android busybox/toybox awk。
# ═══════════════════════════════════════════════════════════════
json_update_top_safe() {
    local field="$1"
    local jval="$2"
    local valtmp="${TMP}.topval.$$"
    printf '%s' "$jval" > "$valtmp"
    awk -v field="$field" -v valfile="$valtmp" '
    BEGIN { getline val < valfile; close(valfile) }
    function ch(i){ return substr(s,i,1) }
    function skipws(i){ while(i<=n && ch(i) ~ /[ \t\r\n]/) i++; return i }
    function strend(i,   j,c,esc){ esc=0; for(j=i+1;j<=n;j++){ c=ch(j); if(esc){esc=0; continue} if(c=="\\"){esc=1; continue} if(c=="\"") return j } return 0 }
    function valend(i,   j,c,se,depth,opn,clos){ i=skipws(i); c=ch(i); if(c=="\""){ se=strend(i); return se ? se+1 : n+1 } if(c=="{" || c=="["){ opn=c; clos=(c=="{" ? "}" : "]"); depth=0; for(j=i;j<=n;j++){ c=ch(j); if(c=="\""){ se=strend(j); if(!se) return n+1; j=se; continue } if(c==opn) depth++; else if(c==clos){ depth--; if(depth==0) return j+1 } } return n+1 } for(j=i;j<=n;j++){ c=ch(j); if(c=="," || c=="}" || c=="]") return j } return n+1 }
    function findkey(key,target,start,stop,   i,c,se,after,k,depth){ fk=fs=fe=0; depth=0; for(i=1;i<=n;i++){ c=ch(i); if(c=="\""){ se=strend(i); if(!se) return 0; if(i>=start && i<=stop && depth==target){ after=skipws(se+1); if(ch(after)==":"){ k=substr(s,i+1,se-i-1); if(k==key){ fk=i; fs=skipws(after+1); fe=valend(fs); return 1 } } } i=se; continue } if(c=="{" || c=="[") depth++; else if(c=="}" || c=="]") depth-- } return 0 }
    { s=s $0 "\n" }
    END {
        sub(/\n$/, "", s); n=length(s)
        if(findkey(field,1,1,n)) {
            print substr(s,1,fs-1) val substr(s,fe)
            exit
        }
        p=index(s,"{")
        if(!p){ print s; exit 1 }
        q=skipws(p+1)
        comma=(ch(q)=="}" ? "" : ",")
        print substr(s,1,p) "\"" field "\": " val comma substr(s,p+1)
    }' "$RULES" > "$TMP" && atomic_write
    local rc=$?
    rm -f "$valtmp"
    return $rc
}

json_update_device_safe() {
    local mac="$1"
    local field="$2"
    local jval="$3"
    local valtmp="${TMP}.devval.$$"
    printf '%s' "$jval" > "$valtmp"
    awk -v mac="$mac" -v field="$field" -v valfile="$valtmp" '
    BEGIN { getline val < valfile; close(valfile) }
    function ch(i){ return substr(s,i,1) }
    function skipws(i){ while(i<=n && ch(i) ~ /[ \t\r\n]/) i++; return i }
    function strend(i,   j,c,esc){ esc=0; for(j=i+1;j<=n;j++){ c=ch(j); if(esc){esc=0; continue} if(c=="\\"){esc=1; continue} if(c=="\"") return j } return 0 }
    function objend(i,   j,c,se,depth){ depth=0; for(j=i;j<=n;j++){ c=ch(j); if(c=="\""){ se=strend(j); if(!se) return 0; j=se; continue } if(c=="{") depth++; else if(c=="}"){ depth--; if(depth==0) return j } } return 0 }
    function valend(i,   j,c,se,depth,opn,clos){ i=skipws(i); c=ch(i); if(c=="\""){ se=strend(i); return se ? se+1 : n+1 } if(c=="{" || c=="["){ opn=c; clos=(c=="{" ? "}" : "]"); depth=0; for(j=i;j<=n;j++){ c=ch(j); if(c=="\""){ se=strend(j); if(!se) return n+1; j=se; continue } if(c==opn) depth++; else if(c==clos){ depth--; if(depth==0) return j+1 } } return n+1 } for(j=i;j<=n;j++){ c=ch(j); if(c=="," || c=="}" || c=="]") return j } return n+1 }
    function findkey(key,target,start,stop,   i,c,se,after,k,depth){ fk=fs=fe=0; depth=0; for(i=1;i<=n;i++){ c=ch(i); if(c=="\""){ se=strend(i); if(!se) return 0; if(i>=start && i<=stop && depth==target){ after=skipws(se+1); if(ch(after)==":"){ k=substr(s,i+1,se-i-1); if(k==key){ fk=i; fs=skipws(after+1); fe=valend(fs); return 1 } } } i=se; continue } if(c=="{" || c=="[") depth++; else if(c=="}" || c=="]") depth-- } return 0 }
    { s=s $0 "\n" }
    END {
        sub(/\n$/, "", s); n=length(s)
        if(!findkey("devices",1,1,n) || ch(skipws(fs))!="{") {
            p=index(s,"{"); if(!p){ print s; exit 1 }
            newdev="\"devices\": {\"" mac "\": {\"" field "\": " val "}}"
            q=skipws(p+1); comma=(ch(q)=="}" ? "" : ",")
            print substr(s,1,p) newdev comma substr(s,p+1)
            exit
        }
        dev_start=skipws(fs); dev_end=objend(dev_start)
        if(!dev_end){ print s; exit 1 }

        if(!findkey(mac,2,dev_start,dev_end) || ch(skipws(fs))!="{") {
            entry="\"" mac "\": {\"" field "\": " val "}"
            q=skipws(dev_start+1); comma=(ch(q)=="}" ? "" : ",")
            print substr(s,1,dev_start) entry comma substr(s,dev_start+1)
            exit
        }
        mac_start=skipws(fs); mac_end=objend(mac_start)
        if(!mac_end){ print s; exit 1 }

        if(findkey(field,3,mac_start,mac_end)) {
            print substr(s,1,fs-1) val substr(s,fe)
            exit
        }
        entry="\"" field "\": " val
        q=skipws(mac_start+1); comma=(ch(q)=="}" ? "" : ",")
        print substr(s,1,mac_start) entry comma substr(s,mac_start+1)
    }' "$RULES" > "$TMP" && atomic_write
    local rc=$?
    rm -f "$valtmp"
    return $rc
}


# ═══════════════════════════════════════════════════════════════
# hotfix18.1: generic safe JSON object/array helpers
#
# Covers remaining high-risk write paths:
#   - device_remove
#   - bl_add / bl_del
#   - name_set / name_del
#   - tpl_set / tpl_del
#
# These helpers avoid regex fragments like [^}]* and [^\"]* that break when
# JSON strings contain commas, braces, escaped quotes, or backslashes.
# They are still small POSIX-awk state machines, not a full JSON library.
# hotfix18.x will later replace this whole wrapper with hnc_json.
# ═══════════════════════════════════════════════════════════════

json_object_set_safe_file() {
    local file="$1" tmpfile="$2" key="$3" jval="$4"
    [ -f "$file" ] || echo '{}' > "$file"
    local keytmp="${tmpfile}.key.$$" valtmp="${tmpfile}.val.$$"
    printf '%s' "$key" > "$keytmp"
    printf '%s' "$jval" > "$valtmp"
    awk -v keyfile="$keytmp" -v valfile="$valtmp" '
    BEGIN { getline key < keyfile; close(keyfile); getline val < valfile; close(valfile) }
    function ch(i){ return substr(s,i,1) }
    function skipws(i){ while(i<=n && ch(i) ~ /[ \t\r\n]/) i++; return i }
    function strend(i,   j,c,esc){ esc=0; for(j=i+1;j<=n;j++){ c=ch(j); if(esc){esc=0; continue} if(c=="\\"){esc=1; continue} if(c=="\"") return j } return 0 }
    function valend(i,   j,c,se,depth,opn,clos){ i=skipws(i); c=ch(i); if(c=="\""){ se=strend(i); return se ? se+1 : n+1 } if(c=="{" || c=="["){ opn=c; clos=(c=="{" ? "}" : "]"); depth=0; for(j=i;j<=n;j++){ c=ch(j); if(c=="\""){ se=strend(j); if(!se) return n+1; j=se; continue } if(c==opn) depth++; else if(c==clos){ depth--; if(depth==0) return j+1 } } return n+1 } for(j=i;j<=n;j++){ c=ch(j); if(c=="," || c=="}" || c=="]") return j } return n+1 }
    function findkey(target,depth_target,start,stop,   i,c,se,after,k,depth){ fk=fs=fe=0; depth=0; for(i=1;i<=n;i++){ c=ch(i); if(c=="\""){ se=strend(i); if(!se) return 0; if(i>=start && i<=stop && depth==depth_target){ after=skipws(se+1); if(ch(after)==":"){ k=substr(s,i+1,se-i-1); if(k==target){ fk=i; fs=skipws(after+1); fe=valend(fs); return 1 } } } i=se; continue } if(c=="{" || c=="[") depth++; else if(c=="}" || c=="]") depth-- } return 0 }
    { s=s $0 "\n" }
    END {
        sub(/\n$/, "", s); n=length(s)
        if(n==0){ s="{}"; n=2 }
        if(findkey(key,1,1,n)) { print substr(s,1,fs-1) val substr(s,fe); exit }
        p=index(s,"{"); if(!p){ print s; exit 1 }
        q=skipws(p+1); comma=(ch(q)=="}" ? "" : ",")
        print substr(s,1,p) "\"" key "\": " val comma substr(s,p+1)
    }' "$file" > "$tmpfile" && guarded_commit "$tmpfile" "$file"
    local rc=$?
    rm -f "$keytmp" "$valtmp"
    return $rc
}

json_object_del_safe_file() {
    local file="$1" tmpfile="$2" key="$3"
    [ -f "$file" ] || return 0
    local keytmp="${tmpfile}.key.$$"
    printf '%s' "$key" > "$keytmp"
    awk -v keyfile="$keytmp" '
    BEGIN { getline key < keyfile; close(keyfile) }
    function ch(i){ return substr(s,i,1) }
    function skipws(i){ while(i<=n && ch(i) ~ /[ \t\r\n]/) i++; return i }
    function prevnw(i){ while(i>=1 && ch(i) ~ /[ \t\r\n]/) i--; return i }
    function strend(i,   j,c,esc){ esc=0; for(j=i+1;j<=n;j++){ c=ch(j); if(esc){esc=0; continue} if(c=="\\"){esc=1; continue} if(c=="\"") return j } return 0 }
    function valend(i,   j,c,se,depth,opn,clos){ i=skipws(i); c=ch(i); if(c=="\""){ se=strend(i); return se ? se+1 : n+1 } if(c=="{" || c=="["){ opn=c; clos=(c=="{" ? "}" : "]"); depth=0; for(j=i;j<=n;j++){ c=ch(j); if(c=="\""){ se=strend(j); if(!se) return n+1; j=se; continue } if(c==opn) depth++; else if(c==clos){ depth--; if(depth==0) return j+1 } } return n+1 } for(j=i;j<=n;j++){ c=ch(j); if(c=="," || c=="}" || c=="]") return j } return n+1 }
    function findkey(target,depth_target,start,stop,   i,c,se,after,k,depth){ fk=fs=fe=0; depth=0; for(i=1;i<=n;i++){ c=ch(i); if(c=="\""){ se=strend(i); if(!se) return 0; if(i>=start && i<=stop && depth==depth_target){ after=skipws(se+1); if(ch(after)==":"){ k=substr(s,i+1,se-i-1); if(k==target){ fk=i; fs=skipws(after+1); fe=valend(fs); return 1 } } } i=se; continue } if(c=="{" || c=="[") depth++; else if(c=="}" || c=="]") depth-- } return 0 }
    { s=s $0 "\n" }
    END {
        sub(/\n$/, "", s); n=length(s)
        if(!findkey(key,1,1,n)){ print s; exit }
        end=fe-1; after=skipws(fe); before=prevnw(fk-1)
        if(after<=n && ch(after)==",") print substr(s,1,fk-1) substr(s,after+1)
        else if(before>=1 && ch(before)==",") print substr(s,1,before-1) substr(s,end+1)
        else print substr(s,1,fk-1) substr(s,end+1)
    }' "$file" > "$tmpfile" && guarded_commit "$tmpfile" "$file"
    local rc=$?
    rm -f "$keytmp"
    return $rc
}

json_array_add_string_top_safe() {
    local field="$1" item="$2" jval
    jval=$(json_string_encode "$item")
    awk -v field="$field" -v val="$jval" '
    function ch(i){ return substr(s,i,1) }
    function skipws(i){ while(i<=n && ch(i) ~ /[ \t\r\n]/) i++; return i }
    function strend(i,   j,c,esc){ esc=0; for(j=i+1;j<=n;j++){ c=ch(j); if(esc){esc=0; continue} if(c=="\\"){esc=1; continue} if(c=="\"") return j } return 0 }
    function valend(i,   j,c,se,depth,opn,clos){ i=skipws(i); c=ch(i); if(c=="\""){ se=strend(i); return se ? se+1 : n+1 } if(c=="{" || c=="["){ opn=c; clos=(c=="{" ? "}" : "]"); depth=0; for(j=i;j<=n;j++){ c=ch(j); if(c=="\""){ se=strend(j); if(!se) return n+1; j=se; continue } if(c==opn) depth++; else if(c==clos){ depth--; if(depth==0) return j+1 } } return n+1 } for(j=i;j<=n;j++){ c=ch(j); if(c=="," || c=="}" || c=="]") return j } return n+1 }
    function findkey(target,depth_target,start,stop,   i,c,se,after,k,depth){ fk=fs=fe=0; depth=0; for(i=1;i<=n;i++){ c=ch(i); if(c=="\""){ se=strend(i); if(!se) return 0; if(i>=start && i<=stop && depth==depth_target){ after=skipws(se+1); if(ch(after)==":"){ k=substr(s,i+1,se-i-1); if(k==target){ fk=i; fs=skipws(after+1); fe=valend(fs); return 1 } } } i=se; continue } if(c=="{" || c=="[") depth++; else if(c=="}" || c=="]") depth-- } return 0 }
    { s=s $0 "\n" }
    END {
        sub(/\n$/, "", s); n=length(s)
        if(!findkey(field,1,1,n) || ch(skipws(fs))!="[") {
            p=index(s,"{"); if(!p){ print s; exit 1 }
            q=skipws(p+1); comma=(ch(q)=="}" ? "" : ",")
            print substr(s,1,p) "\"" field "\": [" val "]" comma substr(s,p+1); exit
        }
        a=skipws(fs); b=fe-1; exists=0
        for(i=skipws(a+1); i<b; ) { ve=valend(i); tok=substr(s,i,ve-i); if(tok==val) exists=1; i=skipws(ve); if(ch(i)==",") i=skipws(i+1) }
        if(exists){ print s; exit }
        q=skipws(a+1)
        if(ch(q)=="]") print substr(s,1,a) val substr(s,b)
        else print substr(s,1,b-1) "," val substr(s,b)
    }' "$RULES" > "$TMP" && atomic_write
}

json_array_del_string_top_safe() {
    local field="$1" item="$2" jval
    jval=$(json_string_encode "$item")
    awk -v field="$field" -v val="$jval" '
    function ch(i){ return substr(s,i,1) }
    function skipws(i){ while(i<=n && ch(i) ~ /[ \t\r\n]/) i++; return i }
    function strend(i,   j,c,esc){ esc=0; for(j=i+1;j<=n;j++){ c=ch(j); if(esc){esc=0; continue} if(c=="\\"){esc=1; continue} if(c=="\"") return j } return 0 }
    function valend(i,   j,c,se,depth,opn,clos){ i=skipws(i); c=ch(i); if(c=="\""){ se=strend(i); return se ? se+1 : n+1 } if(c=="{" || c=="["){ opn=c; clos=(c=="{" ? "}" : "]"); depth=0; for(j=i;j<=n;j++){ c=ch(j); if(c=="\""){ se=strend(j); if(!se) return n+1; j=se; continue } if(c==opn) depth++; else if(c==clos){ depth--; if(depth==0) return j+1 } } return n+1 } for(j=i;j<=n;j++){ c=ch(j); if(c=="," || c=="}" || c=="]") return j } return n+1 }
    function findkey(target,depth_target,start,stop,   i,c,se,after,k,depth){ fk=fs=fe=0; depth=0; for(i=1;i<=n;i++){ c=ch(i); if(c=="\""){ se=strend(i); if(!se) return 0; if(i>=start && i<=stop && depth==depth_target){ after=skipws(se+1); if(ch(after)==":"){ k=substr(s,i+1,se-i-1); if(k==target){ fk=i; fs=skipws(after+1); fe=valend(fs); return 1 } } } i=se; continue } if(c=="{" || c=="[") depth++; else if(c=="}" || c=="]") depth-- } return 0 }
    { s=s $0 "\n" }
    END {
        sub(/\n$/, "", s); n=length(s)
        if(!findkey(field,1,1,n) || ch(skipws(fs))!="["){ print s; exit }
        a=skipws(fs); b=fe-1; out=""
        for(i=skipws(a+1); i<b; ) { ve=valend(i); tok=substr(s,i,ve-i); if(tok!=val){ if(out!="") out=out ","; out=out tok } i=skipws(ve); if(ch(i)==",") i=skipws(i+1) }
        print substr(s,1,a) out substr(s,b)
    }' "$RULES" > "$TMP" && atomic_write
}

json_remove_device_safe() {
    local mac="$1"
    awk -v mac="$mac" '
    function ch(i){ return substr(s,i,1) }
    function skipws(i){ while(i<=n && ch(i) ~ /[ \t\r\n]/) i++; return i }
    function prevnw(i){ while(i>=1 && ch(i) ~ /[ \t\r\n]/) i--; return i }
    function strend(i,   j,c,esc){ esc=0; for(j=i+1;j<=n;j++){ c=ch(j); if(esc){esc=0; continue} if(c=="\\"){esc=1; continue} if(c=="\"") return j } return 0 }
    function valend(i,   j,c,se,depth,opn,clos){ i=skipws(i); c=ch(i); if(c=="\""){ se=strend(i); return se ? se+1 : n+1 } if(c=="{" || c=="["){ opn=c; clos=(c=="{" ? "}" : "]"); depth=0; for(j=i;j<=n;j++){ c=ch(j); if(c=="\""){ se=strend(j); if(!se) return n+1; j=se; continue } if(c==opn) depth++; else if(c==clos){ depth--; if(depth==0) return j+1 } } return n+1 } for(j=i;j<=n;j++){ c=ch(j); if(c=="," || c=="}" || c=="]") return j } return n+1 }
    function findkey(target,depth_target,start,stop,   i,c,se,after,k,depth){ fk=fs=fe=0; depth=0; for(i=1;i<=n;i++){ c=ch(i); if(c=="\""){ se=strend(i); if(!se) return 0; if(i>=start && i<=stop && depth==depth_target){ after=skipws(se+1); if(ch(after)==":"){ k=substr(s,i+1,se-i-1); if(k==target){ fk=i; fs=skipws(after+1); fe=valend(fs); return 1 } } } i=se; continue } if(c=="{" || c=="[") depth++; else if(c=="}" || c=="]") depth-- } return 0 }
    { s=s $0 "\n" }
    END {
        sub(/\n$/, "", s); n=length(s)
        if(!findkey("devices",1,1,n) || ch(skipws(fs))!="{"){ print s; exit }
        ds=skipws(fs); de=fe-1
        if(!findkey(mac,2,ds,de)){ print s; exit }
        end=fe-1; after=skipws(fe); before=prevnw(fk-1)
        if(after<=n && ch(after)==",") print substr(s,1,fk-1) substr(s,after+1)
        else if(before>=1 && ch(before)==",") print substr(s,1,before-1) substr(s,end+1)
        else print substr(s,1,fk-1) substr(s,end+1)
    }' "$RULES" > "$TMP" && atomic_write
}

# hotfix19.1: bridge top-level writes to hnc_json when available.
# This is the first runtime adoption step for the unified JSON helper. It keeps
# the legacy state-machine writer as a fallback so devices that somehow lack
# bin/hnc_json do not lose config writes.
hnc_json_type_for_value() {
    local v="$1"
    case "$v" in
        true|false) echo bool ;;
        null) echo null ;;
        *)
            if echo "$v" | grep -qE '^-?[0-9]+(\.[0-9]+)?$'; then
                echo num
            else
                echo str
            fi
            ;;
    esac
}

json_update_top_hnc_json() {
    local field="$1" value="$2" typ
    [ -x "$HNC_JSON" ] || return 127
    typ=$(hnc_json_type_for_value "$value")
    "$HNC_JSON" set-top "$RULES" "$field" "$value" "$typ"
}

# hotfix19.2: bridge top-level reads to hnc_json when available.
# hnc_json get-top returns JSON literals. json_set.sh top_get historically
# returns unquoted strings, so decode simple JSON string escapes before output.
hnc_json_decode_string_literal() {
    awk 'BEGIN{
        s=ARGV[1]; ARGV[1]="";
        if (substr(s,1,1)!="\"" || substr(s,length(s),1)!="\"") { print s; exit }
        out=""; esc=0;
        for (i=2; i<length(s); i++) {
            c=substr(s,i,1);
            if (esc) {
                if (c=="n") out=out "\n";
                else if (c=="r") out=out "\r";
                else if (c=="t") out=out "\t";
                else if (c=="b") out=out sprintf("%c",8);
                else if (c=="f") out=out sprintf("%c",12);
                else out=out c;
                esc=0; continue;
            }
            if (c=="\\") { esc=1; continue }
            out=out c;
        }
        print out;
    }' "$1"
}

json_top_get_hnc_json() {
    local key="$1" raw rc
    [ -x "$HNC_JSON" ] || return 127
    raw=$("$HNC_JSON" get-top "$RULES" "$key" 2>/dev/null)
    rc=$?
    [ $rc -eq 0 ] || return $rc
    case "$raw" in
        \"*) hnc_json_decode_string_literal "$raw" ;;
        *) printf '%s\n' "$raw" ;;
    esac
    return 0
}

# hotfix19.3: bridge per-device reads to hnc_json when available.
# hnc_json get-device returns JSON literals; json_set.sh device_get historically
# returns unquoted string values, so reuse the same decoder as top_get.
json_device_get_hnc_json() {
    local mac="$1" key="$2" raw rc
    [ -x "$HNC_JSON" ] || return 127
    raw=$("$HNC_JSON" get-device "$RULES" "$mac" "$key" 2>/dev/null)
    rc=$?
    [ $rc -eq 0 ] || return $rc
    case "$raw" in
        \"*) hnc_json_decode_string_literal "$raw" ;;
        *) printf '%s\n' "$raw" ;;
    esac
    return 0
}

# hotfix19.7: bridge device_names.json flat object writes/reads to hnc_json.
# device_names.json is a simple MAC -> name map, so hnc_json object-key is the
# unified safe path here. Legacy helpers remain as fallback.
json_name_set_hnc_json() {
    local mac="$1" name="$2"
    [ -x "$HNC_JSON" ] || return 127
    "$HNC_JSON" set-object-key "$NAMES_FILE" "$mac" "$name" str
}

json_name_get_hnc_json() {
    local mac="$1" raw rc
    [ -x "$HNC_JSON" ] || return 127
    raw=$("$HNC_JSON" get-object-key "$NAMES_FILE" "$mac" 2>/dev/null)
    rc=$?
    [ $rc -eq 0 ] || return $rc
    case "$raw" in
        \"*) hnc_json_decode_string_literal "$raw" ;;
        *) printf '%s\n' "$raw" ;;
    esac
    return 0
}

json_name_del_hnc_json() {
    local mac="$1"
    [ -x "$HNC_JSON" ] || return 127
    "$HNC_JSON" del-object-key "$NAMES_FILE" "$mac"
}


# hotfix19.8: bridge templates.json flat object writes to hnc_json.
# templates.json is a template-name -> settings-object map. hnc_json writes the
# complete object value as a validated JSON literal, avoiding legacy awk JSON
# mutation for tpl_set/tpl_del while keeping legacy fallback available.
json_tpl_set_hnc_json() {
    local tpl_file="$1" name="$2" entry_obj="$3"
    [ -x "$HNC_JSON" ] || return 127
    "$HNC_JSON" set-object-key "$tpl_file" "$name" "$entry_obj" json
}

json_tpl_del_hnc_json() {
    local tpl_file="$1" name="$2"
    [ -x "$HNC_JSON" ] || return 127
    "$HNC_JSON" del-object-key "$tpl_file" "$name"
}


case "$CMD" in

# ── 更新顶层字段（hotspot_auto / whitelist_mode 等）────────
# v3.3.0 修复：
#   1) 原 awk 正则 `($0 ~ """ field """)` 被 shell+awk 解析为字面量 " field "，
#      根本不引用 field 变量，匹配永远失败
#   2) 原字符串分支 JVAL=""$VALUE"" 经 shell 合并后等于 $VALUE，JSON 里写出裸串
#   3) 原实现只替换已存在字段；若字段不存在则无效。现补上“插入”分支
top)
    FIELD=$2; VALUE=$3
    # hotfix19.1: prefer hnc_json set-top so top-level JSON writes use the
    # unified helper. Fallback preserves hotfix18 state-machine behavior.
    if ! json_update_top_hnc_json "$FIELD" "$VALUE"; then
        json_legacy_fallback_warn "top" "writer"
        JVAL=$(json_encode "$VALUE")
        json_update_top_safe "$FIELD" "$JVAL"
    fi
    ;;


# ── 更新设备字段 ──────────────────────────────────────────
device)
    MAC=$2; FIELD=$3; VALUE=$4
    JVAL=$(json_encode "$VALUE")
    json_update_device_safe "$MAC" "$FIELD" "$JVAL"
    ;;


# ── 删除设备整条规则记录 ────────────────────────────────────
# hotfix10: cleanup_stale_rules.sh 需要按 MAC 删除 rules.json.devices[mac]
# 注意: 只删 devices 字典里的规则记录,不动 blacklist / whitelist / device_names。
device_remove)
    MAC=$2
    [ -z "$MAC" ] && { echo "device_remove: mac required" >&2; exit 1; }
    json_remove_device_safe "$MAC"
    ;;

# ── 批量更新设备多个字段（从 stdin 读 JSON patch）─────────
device_patch)
    MAC=$2
    [ -z "$MAC" ] && { echo "device_patch: mac required" >&2; exit 1; }
    # hotfix18.1: do not build a pseudo JSON string and split on comma.
    # Values may legally contain comma/right-brace/quotes. The device command
    # already does safe per-field JSON replacement and takes the lock itself.
    shift 2
    while [ $# -ge 2 ]; do
        K=$1; V=$2; shift 2
        sh "$0" device "$MAC" "$K" "$V" || exit $?
    done
    ;;

# ── 加入黑名单 ────────────────────────────────────────────
# v3.3.0 修复：
#   原实现 gsub(/\]/, ...) 会替换文件中所有的 ]，单行 JSON 下
#   把 whitelist 和 blacklist 一起污染了。改用 match+substr 精确
#   定位 "blacklist":[...] 范围。
bl_add)
    MAC=$2
    [ -z "$MAC" ] && { echo "bl_add: mac required" >&2; exit 1; }
    if ! json_blacklist_add_hnc_json "$MAC"; then
        json_legacy_fallback_warn "bl_add" "array-add"
        json_array_add_string_top_safe "blacklist" "$MAC"
    fi
    ;;

# ── 从黑名单删除 ──────────────────────────────────────────
# v3.3.0 修复：原 gsub 不加范围限制，会把 devices 块里同 MAC 的键也删掉
bl_del)
    MAC=$2
    [ -z "$MAC" ] && exit 0
    if ! json_blacklist_del_hnc_json "$MAC"; then
        json_legacy_fallback_warn "bl_del" "array-del"
        json_array_del_string_top_safe "blacklist" "$MAC"
    fi
    ;;

# ── 清空所有规则 ──────────────────────────────────────────
reset)
    cat > "$RULES" << 'EOF'
{"version":1,"whitelist_mode":false,"devices":{},"blacklist":[],"whitelist":[]}
EOF
    ;;

# ── 初始化目录结构 ────────────────────────────────────────
init_dirs)
    mkdir -p "$HNC/bin" "$HNC/api" "$HNC/webroot" "$HNC/data" "$HNC/logs" "$HNC/run"
    chmod 755 "$HNC" "$HNC/bin" "$HNC/api" "$HNC/webroot" "$HNC/data" "$HNC/logs" "$HNC/run"
    [ -f "$RULES" ] || cat > "$RULES" << 'EOF'
{"version":1,"whitelist_mode":false,"devices":{},"blacklist":[],"whitelist":[]}
EOF
    chmod 644 "$RULES"
    echo "HNC dirs initialized"
    ;;

# ── 写入 config.json 字段 ────────────────────────────────────
# rc3.1.13.2 弃用警告 (review §6 P1):
#   config.json 自 rc3.1.13 弃用, 字段全部迁移到 rules.json (用 'top' 子命令).
#   middleware 不读 config.json, 写入将被忽略. 保留命令是为了不破坏未审到的
#   调用方, 但每次调用 stderr 留痕 + boot.log 会反复出现 WARN, 让回归立即可见.
#   rc3.1.14 后若 boot.log 无此 WARN 累积则可考虑彻底删除.
cfg_set)
    KEY=$2; VAL=$3
    echo "json_set.sh: WARN: cfg_set is DEPRECATED since rc3.1.13, writes to config.json are IGNORED by middleware. Use 'top' subcommand instead. (key=$KEY caller=$(ps -o comm= -p $PPID 2>/dev/null || echo unknown))" >&2
    CFG=$HNC/data/config.json
    [ -f "$CFG" ] || echo '{}' > "$CFG"
    JVAL=$(json_encode "$VAL")
    if grep -q "\"$KEY\"" "$CFG" 2>/dev/null; then
        sed -i "s|\"$KEY\"[[:space:]]*:[[:space:]]*[^,}]*|\"$KEY\": $JVAL|g" "$CFG"
    else
        sed -i "s|}$|,\"$KEY\": $JVAL}|" "$CFG"
    fi
    echo "ok"
    ;;

# ── 读取 config.json 字段 ────────────────────────────────────
# v3.3.0 修复：原 sed 's/.*: *//' 是贪婪匹配，对 "22:00" 这种
# 含冒号的值会把 "22:" 也当分隔符吃掉，返回 "00"。
# 改用只匹配到第一个冒号的版本。
cfg_get)
    KEY=$2
    CFG=$HNC/data/config.json
    grep -o "\"$KEY\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$CFG" 2>/dev/null \
        | head -1 | sed 's/^[^:]*:[[:space:]]*//; s/^"//; s/"$//' && exit 0
    grep -o "\"$KEY\"[[:space:]]*:[[:space:]]*[^,}[:space:]]*" "$CFG" 2>/dev/null \
        | head -1 | sed 's/^[^:]*:[[:space:]]*//'
    ;;

# ── 读取 rules.json 顶层字段（v3.3.0 新增）──────────────────
top_get)
    KEY=$2
    # hotfix19.2: prefer hnc_json get-top for top-level reads. This avoids
    # grep-based reads that break on escaped quotes and keeps read/write paths
    # moving toward one JSON abstraction. Fallback preserves legacy behavior.
    if ! json_top_get_hnc_json "$KEY"; then
        json_legacy_fallback_warn "top_get" "reader"
        # 先尝试字符串字段（带引号），取引号内的完整内容
        result=$(grep -o "\"$KEY\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$RULES" 2>/dev/null \
            | head -1 | sed 's/^[^:]*:[[:space:]]*"//; s/"$//')
        if [ -n "$result" ]; then
            echo "$result"
        else
            # 数字/布尔字段
            grep -o "\"$KEY\"[[:space:]]*:[[:space:]]*[^,}[:space:]]*" "$RULES" 2>/dev/null \
                | head -1 | sed 's/^[^:]*:[[:space:]]*//'
        fi
    fi
    ;;

# ═══════════════════════════════════════════════════════════════
# v4.1.0-rc3 新增: 读取 .devices[<mac>][<key>]
# 用法: json_set.sh device_get <mac> <key>
# 用途: Go 端 actionDelaySet/Clear 需要读 per-device 的 mark_id
# 旧 bug: 之前 Go 调 top_get mark_id 读顶层是错的, mark_id 是 per-device
# ═══════════════════════════════════════════════════════════════
device_get)
    MAC=$2
    KEY=$3
    [ -z "$MAC" ] && { echo "device_get: mac required" >&2; exit 1; }
    [ -z "$KEY" ] && { echo "device_get: key required" >&2; exit 1; }
    # hotfix19.3: prefer hnc_json get-device for per-device reads. The legacy
    # fallback is intentionally kept because device_get is used by delay/clear
    # hot paths and must not hard-fail if hnc_json is unavailable.
    if ! json_device_get_hnc_json "$MAC" "$KEY"; then
        json_legacy_fallback_warn "device_get" "reader"
        # awk 扫整个文件, 找 "<mac>":{ ... "<key>": <value> ... }
        awk -v m="$MAC" -v k="$KEY" '
        BEGIN { RS="" }
        {
            idx = index($0, "\"" m "\"")
            if (idx == 0) next
            tail = substr($0, idx)
            pat = "\"" k "\"[[:space:]]*:[[:space:]]*"
            if (match(tail, pat)) {
                rest = substr(tail, RSTART + RLENGTH)
                if (match(rest, /^"[^"]*"/)) {
                    print substr(rest, RSTART + 1, RLENGTH - 2)
                    exit 0
                }
                if (match(rest, /^[^,}[:space:]]+/)) {
                    print substr(rest, RSTART, RLENGTH)
                    exit 0
                }
            }
        }
        ' "$RULES" 2>/dev/null
    fi
    ;;

# ═══════════════════════════════════════════════════════════════
# v3.4.6: 设备手动命名 (data/device_names.json)
# ═══════════════════════════════════════════════════════════════
# 文件格式（单行 JSON,扁平 MAC -> name 映射）:
#   {"e2:0d:4a:48:5d:40":"Mi-10","aa:bb:cc:dd:ee:ff":"客厅打印机"}
#
# 子命令:
#   name_set  <mac> <name>   设置或更新设备名
#   name_get  <mac>          获取设备名(找不到则空)
#   name_del  <mac>          删除条目
#   name_list                打印整个文件(供调试)
#
# 这是 v3.4.6 设备命名功能的"路线 A":手动命名,优先级最高,
# 永远凌驾于 mDNS 自动发现 / DHCP lease / MAC 兜底之上。
# ═══════════════════════════════════════════════════════════════

name_set)
    MAC=$2; NAME=$3
    [ -z "$MAC" ] && { echo "name_set: mac required" >&2; exit 1; }
    [ -z "$NAME" ] && { echo "name_set: name required" >&2; exit 1; }
    ensure_names_file
    MAC=$(echo "$MAC" | tr 'A-Z' 'a-z')
    if ! json_name_set_hnc_json "$MAC" "$NAME"; then
        json_legacy_fallback_warn "name_set" "object-set"
        JNAME=$(json_string_encode "$NAME")
        json_object_set_safe_file "$NAMES_FILE" "${NAMES_FILE}.tmp" "$MAC" "$JNAME"
    fi
    ;;

name_get)
    MAC=$2
    [ -z "$MAC" ] && exit 0
    [ -f "$NAMES_FILE" ] || exit 0
    MAC=$(echo "$MAC" | tr 'A-Z' 'a-z')
    if ! json_name_get_hnc_json "$MAC"; then
        json_legacy_fallback_warn "name_get" "object-get"
        # 提取 "mac":"name" 中的 name
        grep -o "\"$MAC\":\"[^\"]*\"" "$NAMES_FILE" 2>/dev/null \
            | head -1 \
            | sed "s/^\"$MAC\":\"//; s/\"$//"
    fi
    ;;

name_del)
    MAC=$2
    [ -z "$MAC" ] && exit 0
    [ -f "$NAMES_FILE" ] || exit 0
    MAC=$(echo "$MAC" | tr 'A-Z' 'a-z')
    if ! json_name_del_hnc_json "$MAC"; then
        json_legacy_fallback_warn "name_del" "object-del"
        json_object_del_safe_file "$NAMES_FILE" "${NAMES_FILE}.tmp" "$MAC"
    fi
    ;;

name_list)
    ensure_names_file
    cat "$NAMES_FILE"
    ;;

# ═══════════════════════════════════════════════════════════════
# 限速/延迟模板 (data/templates.json)
# ═══════════════════════════════════════════════════════════════
# 文件格式（单行 JSON,name -> 字段对象映射）:
#   {"游戏":{"down_mbps":50,"up_mbps":20,"delay_ms":0,"jitter_ms":0,"loss_pct":0},
#    "办公":{"down_mbps":10,"up_mbps":5,"delay_ms":0,"jitter_ms":0,"loss_pct":0}}
#
# 子命令:
#   tpl_set  <name> <down_mbps> <up_mbps> <delay_ms> <jitter_ms> <loss_pct>
#     整体设置一个模板(新建或覆盖)。数字参数必须是非负整数或浮点。
#   tpl_del  <name>
#     删除一个模板。不存在则 no-op。
#   tpl_list
#     输出整个 templates.json(供 WebUI 读取)。
#
# 设计选择:
#   - 独立文件,不污染 rules.json(rules 已经承载 11+ 字段,再加 templates 会膨胀)
#   - 和 device_names.json 同级,同样"扁平 name -> value"的映射结构
#   - value 是对象而非字符串,awk 操作参考 device 命令的嵌套对象模式
# ═══════════════════════════════════════════════════════════════

tpl_set)
    NAME=$2
    DOWN=${3:-0}; UP=${4:-0}; DELAY=${5:-0}; JITTER=${6:-0}; LOSS=${7:-0}
    [ -z "$NAME" ] && { echo "tpl_set: name required" >&2; exit 1; }

    # 数字参数白名单:非负整数或浮点
    for _val in "$DOWN" "$UP" "$DELAY" "$JITTER" "$LOSS"; do
        case "$_val" in
            ''|*[!0-9.]*|.*|*..*)
                echo "tpl_set: invalid number: $_val" >&2
                exit 1 ;;
        esac
    done

    TPL_FILE=$HNC/data/templates.json
    [ -f "$TPL_FILE" ] || echo '{}' > "$TPL_FILE"

    # hotfix19.8: prefer hnc_json for template writes. Template values are JSON
    # objects, so pass them as validated JSON literals instead of strings. The
    # hotfix18.1 safe writer remains as fallback for older installs.
    ENTRY_OBJ="{\"down_mbps\":$DOWN,\"up_mbps\":$UP,\"delay_ms\":$DELAY,\"jitter_ms\":$JITTER,\"loss_pct\":$LOSS}"
    if ! json_tpl_set_hnc_json "$TPL_FILE" "$NAME" "$ENTRY_OBJ"; then
        json_legacy_fallback_warn "tpl_set" "object-set-json"
        NAME_KEY=$(json_escape_string_inner "$NAME")
        json_object_set_safe_file "$TPL_FILE" "${TPL_FILE}.tmp" "$NAME_KEY" "$ENTRY_OBJ"
    fi
    ;;

tpl_del)
    NAME=$2
    [ -z "$NAME" ] && exit 0
    TPL_FILE=$HNC/data/templates.json
    [ -f "$TPL_FILE" ] || exit 0
    if ! json_tpl_del_hnc_json "$TPL_FILE" "$NAME"; then
        json_legacy_fallback_warn "tpl_del" "object-del"
        NAME_KEY=$(json_escape_string_inner "$NAME")
        json_object_del_safe_file "$TPL_FILE" "${TPL_FILE}.tmp" "$NAME_KEY"
    fi
    ;;

tpl_list)
    TPL_FILE=$HNC/data/templates.json
    if [ -f "$TPL_FILE" ]; then
        cat "$TPL_FILE"
    else
        echo '{}'
    fi
    ;;

# ═══ v4.0 Patch 2.a: token 管理命令 ═══════════════════════════════
# tokens.json 是 Map by TokenID:
#   {"version":1,"tokens":{"<TokenID>":{"hash":"...","created":...,
#     "last_seen":...,"label":"...","ip_hint":"...","revoked":false}}}
# 文件权限 600(敏感数据)。写入用 tmp+mv 原子,配合 acquire_lock 保证并发安全。
# 与 httpd 协同: httpd 每次 auth 前 stat tokens.json,mtime 变就 reload。

token_revoke)
    # 用法: token_revoke <TokenID>
    # 把指定 TokenID 的 revoked 设为 true。TokenID 不存在时静默(幂等)。
    TID=$2
    if [ -z "$TID" ]; then
        echo "Usage: json_set.sh token_revoke <TokenID>" >&2
        exit 1
    fi
    # TokenID 严格 base64url [A-Za-z0-9_-],防注入
    case "$TID" in
        *[!A-Za-z0-9_-]*|"")
            echo "token_revoke: invalid TokenID format" >&2
            exit 1
            ;;
    esac
    TOKENS_FILE=$HNC/data/remote_tokens.json
    TOKENS_TMP=$HNC/data/remote_tokens.tmp
    [ -f "$TOKENS_FILE" ] || echo '{"version":1,"tokens":{}}' > "$TOKENS_FILE"

    # hotfix20.0: prefer hnc_json for token revoke. This keeps Go TokensStore
    # as the owner of token issue/last_seen while replacing the fragile shell
    # mutation path with guarded validate/backup/commit. Legacy fallback remains.
    if ! json_token_revoke_hnc_json "$TOKENS_FILE" "$TID"; then
        json_legacy_fallback_warn "token_revoke" "token-revoke"
        # 策略: 用 awk 状态机进入 "TokenID":{ 对象后改 revoked:false -> true
        # POSIX awk(busybox/toybox 通用), 不用 gawk match(,,arr)
        awk -v tid="$TID" '
        BEGIN { in_target = 0; depth = 0 }
        {
            line = $0
            if (in_target) {
                brace_delta = 0
                for (i = 1; i <= length(line); i++) {
                    c = substr(line, i, 1)
                    if (c == "{") brace_delta++
                    else if (c == "}") brace_delta--
                }
                sub(/"revoked"[ \t]*:[ \t]*false/, "\"revoked\": true", line)
                depth += brace_delta
                if (depth <= 0) in_target = 0
            } else {
                pat = "\"" tid "\"[ \t]*:[ \t]*\\{"
                if (match(line, pat)) {
                    in_target = 1
                    depth = 0
                    for (i = 1; i <= length(line); i++) {
                        c = substr(line, i, 1)
                        if (c == "{") depth++
                        else if (c == "}") depth--
                    }
                    if (depth <= 0) in_target = 0
                    sub(/"revoked"[ \t]*:[ \t]*false/, "\"revoked\": true", line)
                }
            }
            print line
        }
        ' "$TOKENS_FILE" > "$TOKENS_TMP" && guarded_commit "$TOKENS_TMP" "$TOKENS_FILE"
    fi
    chmod 600 "$TOKENS_FILE" 2>/dev/null
    ;;
token_revoke_all)
    # 所有 tokens[*].revoked 从 false 改 true
    TOKENS_FILE=$HNC/data/remote_tokens.json
    TOKENS_TMP=$HNC/data/remote_tokens.tmp
    [ -f "$TOKENS_FILE" ] || echo '{"version":1,"tokens":{}}' > "$TOKENS_FILE"
    if ! json_token_revoke_all_hnc_json "$TOKENS_FILE"; then
        json_legacy_fallback_warn "token_revoke_all" "token-revoke-all"
        awk '
        { gsub(/"revoked"[ \t]*:[ \t]*false/, "\"revoked\": true"); print }
        ' "$TOKENS_FILE" > "$TOKENS_TMP" && guarded_commit "$TOKENS_TMP" "$TOKENS_FILE"
    fi
    chmod 600 "$TOKENS_FILE" 2>/dev/null
    ;;
token_prune)
    # 维护命令:移除 last_seen > 90 天 + revoked=true 且 last_seen > 30 天 的条目
    # json_set.sh 的 shell awk 实现 token_prune 过于脆弱(多行 JSON + busybox/toybox
    # 语法差异),改为 touch marker,让 httpd daily GC goroutine 用 Go json 库做。
    PRUNE_REQ="$HNC/run/httpd_prune_request"
    mkdir -p "$HNC/run" 2>/dev/null
    touch "$PRUNE_REQ" 2>/dev/null
    echo "token_prune requested (httpd GC will execute on next cycle)"
    ;;

*)
    echo "Usage: json_set.sh {device|device_remove|bl_add|bl_del|reset|init_dirs|cfg_set|cfg_get|top|top_get|name_set|name_get|name_del|name_list|tpl_set|tpl_del|tpl_list|token_revoke|token_revoke_all|token_prune} [args...]"
    exit 1
    ;;
esac
