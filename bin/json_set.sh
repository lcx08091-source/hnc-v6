#!/system/bin/sh

# v3.5.0 alpha-0: PATH 健壮性,见 service.sh
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH
# json_set.sh — rules.json / device_names.json / templates.json 的命令行入口
#
# 用法:
#   json_set.sh top          <field> <value>          # 顶层字段(用户自由文本字段恒为字符串)
#   json_set.sh top_get      <field>                  # 读顶层字段(字符串去引号; 不存在输出空)
#   json_set.sh device       <mac> <field> <value>    # 写 .devices[mac][field](自动判类型)
#   json_set.sh device_get   <mac> <field>            # 读 .devices[mac][field]
#   json_set.sh device_remove <mac>                   # 删 .devices[mac] 整条(不动黑白名单 / 名字)
#   json_set.sh bl_add|bl_del <mac>                   # 黑名单增删
#   json_set.sh reset                                 # 清空规则(写前备份)
#   json_set.sh init_dirs                             # 建目录 + 初始 rules.json
#   json_set.sh name_set <mac> <name> | name_get <mac> | name_del <mac> | name_list
#   json_set.sh tpl_set <name> <down> <up> <delay> <jitter> <loss> | tpl_del <name> | tpl_list
#   json_set.sh token_revoke <TokenID> | token_revoke_all | token_prune   # 排队给 httpd
#   (多字段原子写用 json_set_batch.sh device <mac> <k> <v> ...)
#
# v5.33: 读写一律交给 bin/hnc_json(校验 → 持 run/json.lock → 备份 → 原子替换 → 写后
# 校验)。之前这里还有一整套 awk 状态机 writer / grep reader 作「hnc_json 不可用时的
# 回退」, 外加自己的一把 json.lock、回退计数(run/json_legacy_fallback.*)、已弃用的
# cfg_set / cfg_get 与没人调用的 device_patch —— 全部删除(回退计数在真机上长期为 0,
# 见 v5.9.3 BUG-008)。hnc_json 跑不起来 = 安装不完整, 命令直接失败、不再静默改走旧写法。

HNC=${HNC:-${HNC_DIR:-/data/local/hnc}}
RULES=$HNC/data/rules.json
SCRIPT_DIR=${0%/*}
[ "$SCRIPT_DIR" = "$0" ] && SCRIPT_DIR="."
HNC_JSON=${HNC_JSON:-$SCRIPT_DIR/hnc_json}
export HNC

# 一律用 sh 跑, 不靠文件的 shebang(#!/system/bin/sh): 运行期 /system/bin 可能被卸
# (SukiSU), CI 的 Linux 上也没有这个路径; 也不靠执行位(模块解包后权限偶尔丢)。
hj() {
    sh "$HNC_JSON" "$@"
}

# 确保目录和文件存在
mkdir -p "$HNC/data" "$HNC/run" 2>/dev/null
[ -f "$RULES" ] || cat > "$RULES" << 'EOF'
{"version":1,"whitelist_mode":false,"devices":{},"blacklist":[],"whitelist":[]}
EOF

# v3.4.6: device_names.json 路径与初始化
NAMES_FILE=$HNC/data/device_names.json
ensure_names_file() {
    [ -f "$NAMES_FILE" ] || echo '{}' > "$NAMES_FILE"
}

# v5.11: 这些顶层字段是用户自由文本, 语义上永远是字符串, 不能按值猜类型。
# 按值推断时热点密码 "12345678"(8 位纯数字, 很常见)会被写成数字 12345678,
# hotspot_autostart.sh 的 get_rule_str 只认 "key": "..." 字符串 → 读空 → 开机自启
# 退回系统设置/默认密码; "01234567" 推成非法数字字面量 → 写入被拒 → WebUI 报
# "save pass failed"; SSID 叫 "true"/"null" 会被写成布尔/null。
json_top_field_is_string() {
    case "$1" in
        hotspot_ssid|hotspot_pass|hotspot_iface|clsact_bpf_mode) return 0 ;;
    esac
    return 1
}

# hnc_json 的读命令返回 JSON 字面量; 本脚本的读命令历来输出去引号的字符串,
# 这里解码简单的 JSON 字符串转义。
decode_json_literal() {
    case "$1" in
        \"*) ;;
        *) printf '%s\n' "$1"; return 0 ;;
    esac
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

# 读: rc 3(键 / 设备不存在)是正常空答案 → 输出空、退 0(v5.9.3 BUG-008)。
# 其余非零(锁超时 / 文件坏 / 缺失)原样退出。
read_literal() {
    raw=$(hj "$@" 2>/dev/null)
    rc=$?
    [ "$rc" -eq 3 ] && exit 0
    [ "$rc" -eq 0 ] || exit "$rc"
    decode_json_literal "$raw"
}

CMD=$1

case "$CMD" in

top)
    FIELD=$2; VALUE=$3
    [ -z "$FIELD" ] && { echo "top: field required" >&2; exit 1; }
    TYP=auto
    json_top_field_is_string "$FIELD" && TYP=str
    hj set-top "$RULES" "$FIELD" "$VALUE" "$TYP"
    ;;

top_get)
    [ -z "$2" ] && exit 0
    read_literal get-top "$RULES" "$2"
    ;;

device)
    MAC=$2; FIELD=$3; VALUE=$4
    [ -z "$MAC" ] && { echo "device: mac required" >&2; exit 1; }
    [ -z "$FIELD" ] && { echo "device: field required" >&2; exit 1; }
    hj set-device "$RULES" "$MAC" "$FIELD" "$VALUE" auto
    ;;

# v4.1.0-rc3: 读 .devices[<mac>][<key>](Go 端 actionDelaySet/Clear 读 per-device mark_id)
device_get)
    [ -z "$2" ] && { echo "device_get: mac required" >&2; exit 1; }
    [ -z "$3" ] && { echo "device_get: key required" >&2; exit 1; }
    read_literal get-device "$RULES" "$2" "$3"
    ;;

# hotfix10: cleanup_stale_rules.sh 按 MAC 删除 rules.json.devices[mac]
device_remove)
    [ -z "$2" ] && { echo "device_remove: mac required" >&2; exit 1; }
    hj del-device "$RULES" "$2"
    ;;

bl_add)
    [ -z "$2" ] && { echo "bl_add: mac required" >&2; exit 1; }
    hj add-array-unique "$RULES" blacklist "$2"
    ;;

bl_del)
    [ -z "$2" ] && exit 0
    hj del-array-value "$RULES" blacklist "$2"
    ;;

# 清空所有规则。v5.11 起写前备份 + 原子替换(误点「清空」后 json_doctor 可恢复)。
reset)
    printf '%s\n' '{"version":1,"whitelist_mode":false,"devices":{},"blacklist":[],"whitelist":[]}' \
        | hj replace "$RULES"
    ;;

init_dirs)
    mkdir -p "$HNC/bin" "$HNC/webroot" "$HNC/data" "$HNC/logs" "$HNC/run"
    # v5.9.3 BUG-009:目录权限分级收紧。
    # 顶层 + data/logs/run 存的是 rules.json / tokens.json / local_admin.secret
    # 这类东西,0755 让任何能 traverse 进来的非 root 进程(adb shell uid 2000、
    # 其它 root 模块)都能列目录;更要命的是历史上引导脚本继承 magiskd 的
    # umask=0,裸 `mkdir -p` 直接建成 0777 —— 无 sticky 位时别人可以 unlink
    # 掉 run/local_admin.secret 再写一个自己的,伪造 X-HNC-Local-Admin 拿到
    # root 级写 API。这里改 700(只有 root 能进)。
    # bin/webroot 是可执行/静态资源,保持 755(HNC 全部组件以 root 运行,
    # httpd 与 KSU WebUI 读的都是模块目录而不是这里,755 纯粹是保守选择)。
    chmod 700 "$HNC" "$HNC/data" "$HNC/logs" "$HNC/run" 2>/dev/null
    chmod 755 "$HNC/bin" "$HNC/webroot" 2>/dev/null
    chmod 644 "$RULES"
    echo "HNC dirs initialized"
    ;;

# ═══════════════════════════════════════════════════════════════
# v3.4.6: 设备手动命名 (data/device_names.json, 扁平 MAC -> name)
#   {"e2:0d:4a:48:5d:40":"Mi-10","aa:bb:cc:dd:ee:ff":"客厅打印机"}
# 手动命名优先级最高, 凌驾于 mDNS / DHCP / MAC 兜底之上。
# ═══════════════════════════════════════════════════════════════

name_set)
    MAC=$2; NAME=$3
    [ -z "$MAC" ] && { echo "name_set: mac required" >&2; exit 1; }
    [ -z "$NAME" ] && { echo "name_set: name required" >&2; exit 1; }
    ensure_names_file
    MAC=$(echo "$MAC" | tr 'A-Z' 'a-z')
    hj set-object-key "$NAMES_FILE" "$MAC" "$NAME" str
    ;;

name_get)
    [ -z "$2" ] && exit 0
    [ -f "$NAMES_FILE" ] || exit 0
    MAC=$(echo "$2" | tr 'A-Z' 'a-z')
    read_literal get-object-key "$NAMES_FILE" "$MAC"
    ;;

name_del)
    [ -z "$2" ] && exit 0
    [ -f "$NAMES_FILE" ] || exit 0
    MAC=$(echo "$2" | tr 'A-Z' 'a-z')
    hj del-object-key "$NAMES_FILE" "$MAC"
    ;;

name_list)
    ensure_names_file
    cat "$NAMES_FILE"
    ;;

# ═══════════════════════════════════════════════════════════════
# 限速/延迟模板 (data/templates.json, name -> 字段对象)
#   {"游戏":{"down_mbps":50,"up_mbps":20,"delay_ms":0,"jitter_ms":0,"loss_pct":0}}
# 独立文件, 不污染 rules.json。
# ═══════════════════════════════════════════════════════════════

tpl_set)
    # v5.11: 模板名先去控制字符, 写 / 删用同一个键
    NAME=$(printf '%s' "$2" | tr -d '\000-\037')
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
    hj set-object-key "$TPL_FILE" "$NAME" \
        "{\"down_mbps\":$DOWN,\"up_mbps\":$UP,\"delay_ms\":$DELAY,\"jitter_ms\":$JITTER,\"loss_pct\":$LOSS}" json
    ;;

tpl_del)
    NAME=$(printf '%s' "$2" | tr -d '\000-\037')
    [ -z "$NAME" ] && exit 0
    TPL_FILE=$HNC/data/templates.json
    [ -f "$TPL_FILE" ] || exit 0
    hj del-object-key "$TPL_FILE" "$NAME"
    ;;

tpl_list)
    TPL_FILE=$HNC/data/templates.json
    if [ -f "$TPL_FILE" ]; then
        cat "$TPL_FILE"
    else
        echo '{}'
    fi
    ;;

# ═══ v4.0 Patch 2.a → v5.9.0: token 管理命令(marker 桥) ═══════════
# remote_tokens.json 的唯一运行期写者是 hnc_httpd(Go TokensStore)。shell 只追加一行
# TokenID(或 ALL)到 run/token_revoke.request, httpd 在启动时 / 每请求鉴权前 / 60s
# 兜底消费。httpd 不在则无人能用 token 鉴权, 不存在生效窗口。一行追加写(O_APPEND,
# 远小于 PIPE_BUF)本身不会交错, v5.33 起不再为它拿 json.lock。

token_revoke)
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
    REVOKE_REQ="$HNC/run/token_revoke.request"
    if printf '%s\n' "$TID" >> "$REVOKE_REQ" 2>/dev/null; then
        chmod 600 "$REVOKE_REQ" 2>/dev/null
        echo "token_revoke queued (httpd applies on next request/startup)"
    else
        echo "token_revoke: cannot write $REVOKE_REQ" >&2
        exit 1
    fi
    ;;
token_revoke_all)
    REVOKE_REQ="$HNC/run/token_revoke.request"
    if printf '%s\n' "ALL" >> "$REVOKE_REQ" 2>/dev/null; then
        chmod 600 "$REVOKE_REQ" 2>/dev/null
        echo "token_revoke_all queued (httpd applies on next request/startup)"
    else
        echo "token_revoke_all: cannot write $REVOKE_REQ" >&2
        exit 1
    fi
    ;;
token_prune)
    # 维护命令: touch marker, 由 httpd daily GC goroutine 用 Go json 库清理过期 token。
    touch "$HNC/run/httpd_prune_request" 2>/dev/null
    echo "token_prune requested (httpd GC will execute on next cycle)"
    ;;

*)
    echo "Usage: json_set.sh {top|top_get|device|device_get|device_remove|bl_add|bl_del|reset|init_dirs|name_set|name_get|name_del|name_list|tpl_set|tpl_del|tpl_list|token_revoke|token_revoke_all|token_prune} [args...]"
    exit 1
    ;;
esac
