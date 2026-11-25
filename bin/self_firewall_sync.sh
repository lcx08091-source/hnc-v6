#!/system/bin/sh
# self_firewall_sync.sh — HNC v6.x 本机应用防火墙 (HNC_SELF_UID) 与本机 DNS 拦截 (HNC_SELF_DNS) 同步器
#
# 用法:
#   sh bin/self_firewall_sync.sh apply [--dry-run]   # 从 data/self_firewall.json 恢复双栈 OUTPUT 规则(空规则自动拆链)
#   sh bin/self_firewall_sync.sh flush [--dry-run]   # 干净摘除并销毁 HNC_SELF_UID / HNC_SELF_DNS 双栈子链
#
# 安全铁律:
#   1. 硬性拒绝 appId = uid % 100000 < 10000 及受保护的 Root 管理器 / WebView / 宿主包名(含多用户与 SDK 沙盒反查);
#   2. HNC_SELF_UID 首条仅放行 -o lo -j RETURN (严禁无目的地址豁免 8443,8444,8080 导致公网端口穿透);
#   3. appId 在 10000..19999 (含多用户/双开) 自动协同封禁 SDK Sandbox (uid + 10000);
#   4. HNC_SELF_DNS 仅在 filter/OUTPUT 对 UDP/TCP :53 执行标签长度前缀 hex -j DROP (严禁 REJECT / :853 / mangle);
#   5. 通过内存管道调用 iptables-restore / ip6tables-restore -w 2 --noflush, 零 run/ tmpfs 常驻文件。

[ -z "${HNC_SKIP_PATH_HARDENING:-}" ] && [ -z "${HNC_TEST_MODE:-}" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:${PATH:-}:/data/local/hnc/bin

HNC_DIR=${HNC_DIR:-/data/local/hnc}
if [ -f "$HNC_DIR/bin/hnc_env.sh" ]; then
    . "$HNC_DIR/bin/hnc_env.sh"
elif [ -f "${0%/*}/hnc_env.sh" ]; then
    . "${0%/*}/hnc_env.sh"
fi

SF_JSON="$HNC_DIR/data/self_firewall.json"
SF_PKGS_LIST="${HNC_PACKAGES_LIST:-/data/system/packages.list}"
SF_LOCK="$HNC_DIR/run/self_firewall.lock"
LOG="$HNC_DIR/logs/service.log"

SF_MODE="apply"
SF_DRY=0
for _arg in "$@"; do
    case "$_arg" in
        apply) SF_MODE="apply" ;;
        flush|remove|clean|off) SF_MODE="flush" ;;
        --dry-run) SF_DRY=1 ;;
        *)
            echo "Usage: $0 {apply|flush} [--dry-run]" >&2
            exit 2
            ;;
    esac
done
unset _arg

sf_log() {
    [ -d "$HNC_DIR/logs" ] || mkdir -p "$HNC_DIR/logs" 2>/dev/null || true
    echo "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null) [self_firewall] $*" >> "$LOG" 2>/dev/null || true
}

sf_is_wait_flag_err() {
    case "$(printf '%s' "$1" | tr 'A-Z' 'a-z')" in
        *unknown\ option*|*unrecognized\ option*|*invalid\ option*|*option\ \"-w\"*|*option\ \'-w\'*|*wait*interval*)
            return 0
            ;;
    esac
    return 1
}

sf_is_xt_string_unsupported() {
    case "$(printf '%s' "$1" | tr 'A-Z' 'a-z')" in
        *xt_string*|*ipt_string*|*ip6t_string*|*string*|*couldn\'t\ load\ match*|*no\ chain/target/match\ by\ that\ name*)
            return 0
            ;;
    esac
    return 1
}

sf_is_ipv6_unsupported() {
    _sf6_m=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
    case "$_sf6_m" in
        *ip6tables*not\ found*|*address\ family\ not\ supported*|*eafnosupport*|*can\'t\ initialize\ ip6tables\ table*|*table\ \'filter\'\ does\ not\ exist*|*table\ \`filter\'\ does\ not\ exist*|*ip6table_filter*)
            unset _sf6_m
            return 0
            ;;
        *ip6_tables*)
            case "$_sf6_m" in
                *does\ not\ exist*|*no\ such\ file*|*not\ found*)
                    unset _sf6_m
                    return 0
                    ;;
            esac
            ;;
    esac
    unset _sf6_m
    return 1
}

IPT=${HNC_IPT:-"iptables -w 2"}
IP6T=${HNC_IP6T:-"ip6tables -w 2"}
IPT_RESTORE=${HNC_IPT_RESTORE:-"iptables-restore"}
IP6T_RESTORE=${HNC_IP6T_RESTORE:-"ip6tables-restore"}

if [ -z "${HNC_IPT:-}" ] && [ -z "${HNC_TEST_MODE:-}" ] && [ "$SF_DRY" != "1" ]; then
    if command -v iptables >/dev/null 2>&1; then
        iptables -w 2 -t filter -L -n >/dev/null 2>&1
        if [ $? -eq 2 ]; then
            iptables -w -t filter -L -n >/dev/null 2>&1
            [ $? -eq 2 ] && IPT="iptables" || IPT="iptables -w"
        fi
    fi
fi
if [ -z "${HNC_IP6T:-}" ] && [ -z "${HNC_TEST_MODE:-}" ] && [ "$SF_DRY" != "1" ]; then
    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -w 2 -t filter -L -n >/dev/null 2>&1
        if [ $? -eq 2 ]; then
            ip6tables -w -t filter -L -n >/dev/null 2>&1
            [ $? -eq 2 ] && IP6T="ip6tables" || IP6T="ip6tables -w"
        fi
    fi
fi

SF_V6_OK=0
if [ "$SF_DRY" = "1" ]; then
    SF_V6_OK=1
elif [ -n "${HNC_IP6T:-}" ] || [ -n "${HNC_IP6T_RESTORE:-}" ]; then
    SF_V6_OK=1
elif command -v "${IP6T%% *}" >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    _sf_v6_probe=$($IP6T -t filter -L -n 2>&1 >/dev/null)
    if [ $? -eq 0 ]; then
        SF_V6_OK=1
    elif ! sf_is_ipv6_unsupported "$_sf_v6_probe"; then
        SF_V6_OK=1
    fi
    unset _sf_v6_probe
fi

sf_lock() {
    [ "$SF_DRY" = "1" ] && return 0
    mkdir -p "$HNC_DIR/run" 2>/dev/null || true
    _sf_n=0
    while ! mkdir "$SF_LOCK" 2>/dev/null; do
        _sf_lp=$(cat "$SF_LOCK/pid" 2>/dev/null)
        _sf_ts=$(cat "$SF_LOCK/ts" 2>/dev/null)
        _sf_now=$(date +%s 2>/dev/null || echo 0)
        if [ -n "$_sf_lp" ] && ! kill -0 "$_sf_lp" 2>/dev/null; then
            rm -rf "$SF_LOCK" 2>/dev/null || true
            continue
        fi
        case "$_sf_ts:$_sf_now" in
            *[!0-9:]*|:*) ;;
            *)
                if [ "$_sf_ts" -gt 0 ] && [ $((_sf_now - _sf_ts)) -ge 30 ]; then
                    rm -rf "$SF_LOCK" 2>/dev/null || true
                    continue
                fi
                ;;
        esac
        _sf_n=$((_sf_n + 1))
        [ "$_sf_n" -ge 30 ] && return 1
        sleep 0.1 2>/dev/null || sleep 1
    done
    echo "$$" > "$SF_LOCK/pid" 2>/dev/null || true
    date +%s > "$SF_LOCK/ts" 2>/dev/null || true
    return 0
}

sf_unlock() {
    [ "$SF_DRY" = "1" ] && return 0
    if [ "$(cat "$SF_LOCK/pid" 2>/dev/null)" = "$$" ]; then
        rm -rf "$SF_LOCK" 2>/dev/null || true
    fi
    return 0
}

if ! sf_lock; then
    sf_log "WARN: self_firewall.lock timeout"
    echo "SELF_FIREWALL=lock_timeout"
    exit 11
fi
trap 'sf_unlock' EXIT
trap 'sf_unlock; trap - EXIT; exit 130' INT
trap 'sf_unlock; trap - EXIT; exit 143' TERM

SF_LAST_ERR=""

sf_run_ipt() {
    if [ "$SF_DRY" = "1" ]; then
        echo "DRY: $*"
        return 0
    fi
    "$@" 2>/dev/null
}

_sf_restore_with_wait_fallback() {
    _sfw_bin="$1"
    _sfw_data="$2"
    # shellcheck disable=SC2086
    _sfw_err=$(printf '%s' "$_sfw_data" | $_sfw_bin -w 2 --noflush 2>&1 >/dev/null)
    _sfw_rc=$?
    if [ "$_sfw_rc" -eq 0 ]; then
        SF_LAST_ERR=""
        return 0
    fi
    if [ "$_sfw_rc" -eq 2 ] || sf_is_wait_flag_err "$_sfw_err"; then
        # shellcheck disable=SC2086
        _sfw_err2=$(printf '%s' "$_sfw_data" | $_sfw_bin -w --noflush 2>&1 >/dev/null)
        _sfw_rc2=$?
        if [ "$_sfw_rc2" -eq 0 ]; then
            SF_LAST_ERR=""
            return 0
        fi
        if [ "$_sfw_rc2" -eq 2 ] || sf_is_wait_flag_err "$_sfw_err2"; then
            # shellcheck disable=SC2086
            _sfw_err3=$(printf '%s' "$_sfw_data" | $_sfw_bin --noflush 2>&1 >/dev/null)
            _sfw_rc3=$?
            if [ "$_sfw_rc3" -eq 0 ]; then
                SF_LAST_ERR=""
                return 0
            fi
            SF_LAST_ERR="${_sfw_err3:-$_sfw_err}"
            return "$_sfw_rc3"
        fi
        SF_LAST_ERR="${_sfw_err2:-$_sfw_err}"
        return "$_sfw_rc2"
    fi
    SF_LAST_ERR="$_sfw_err"
    return "$_sfw_rc"
}

sf_pipe_restore() {
    _sfr_bin="$1"
    _sfr_payload="$2"
    if [ "$SF_DRY" = "1" ]; then
        printf 'DRY_RESTORE(%s):\n%s' "$_sfr_bin" "$_sfr_payload"
        return 0
    fi
    _sfr_cmd0="${_sfr_bin%% *}"
    if ! command -v "$_sfr_cmd0" >/dev/null 2>&1 && [ ! -x "$_sfr_cmd0" ]; then
        SF_LAST_ERR="$_sfr_cmd0 not found"
        return 127
    fi
    _sf_restore_with_wait_fallback "$_sfr_bin" "$_sfr_payload" && return 0
    _sfr_orig_err="$SF_LAST_ERR"
    case "$_sfr_payload" in
        *REJECT*)
            _sfr_drop=$(printf '%s' "$_sfr_payload" | sed -e 's/-j REJECT --reject-with [^ ]*/-j DROP/g' -e 's/-j REJECT$/-j DROP/g')
            if [ "$_sfr_drop" != "$_sfr_payload" ]; then
                _sf_restore_with_wait_fallback "$_sfr_bin" "$_sfr_drop" && return 0
            fi
            ;;
    esac
    [ -n "$SF_LAST_ERR" ] || SF_LAST_ERR="$_sfr_orig_err"
    return 1
}

sf_detach_chain_one() {
    _sfd_ipt="$1"
    _sfd_ch="$2"
    [ -n "$_sfd_ipt" ] || return 0
    _sfd_i=0
    # shellcheck disable=SC2086
    while sf_run_ipt $_sfd_ipt -t filter -D OUTPUT -j "$_sfd_ch"; do
        _sfd_i=$((_sfd_i + 1))
        [ "$_sfd_i" -ge 16 ] && break
        [ "$SF_DRY" = "1" ] && break
    done
    # shellcheck disable=SC2086
    sf_run_ipt $_sfd_ipt -t filter -F "$_sfd_ch" || true
    # shellcheck disable=SC2086
    sf_run_ipt $_sfd_ipt -t filter -X "$_sfd_ch" || true
}

sf_ensure_link_one() {
    _sfl_ipt="$1"
    _sfl_ch="$2"
    [ -n "$_sfl_ipt" ] || { SF_LAST_ERR="empty iptables cmd"; return 1; }
    if [ "$SF_DRY" = "1" ]; then
        echo "DRY: $_sfl_ipt -t filter -I OUTPUT 1 -j $_sfl_ch"
        return 0
    fi
    _sfl_cmd0="${_sfl_ipt%% *}"
    if ! command -v "$_sfl_cmd0" >/dev/null 2>&1 && [ ! -x "$_sfl_cmd0" ]; then
        SF_LAST_ERR="$_sfl_cmd0 not found"
        return 127
    fi
    SF_LAST_ERR=""
    # shellcheck disable=SC2086
    if $_sfl_ipt -t filter -C OUTPUT -j "$_sfl_ch" >/dev/null 2>&1; then
        return 0
    fi
    # shellcheck disable=SC2086
    $_sfl_ipt -t filter -N "$_sfl_ch" >/dev/null 2>&1 || true
    # shellcheck disable=SC2086
    _sfl_err=$($_sfl_ipt -t filter -I OUTPUT 1 -j "$_sfl_ch" 2>&1 >/dev/null)
    _sfl_rc=$?
    if [ "$_sfl_rc" -ne 0 ]; then
        SF_LAST_ERR="$_sfl_err"
        return "$_sfl_rc"
    fi
    return 0
}

sf_flush_all() {
    sf_detach_chain_one "$IPT" HNC_SELF_UID
    sf_detach_chain_one "$IPT" HNC_SELF_DNS
    if [ "$SF_V6_OK" = "1" ]; then
        sf_detach_chain_one "$IP6T" HNC_SELF_UID
        sf_detach_chain_one "$IP6T" HNC_SELF_DNS
    fi
}

if [ "$SF_MODE" = "flush" ]; then
    sf_flush_all
    sf_log "flushed HNC_SELF_UID and HNC_SELF_DNS"
    echo "SELF_FIREWALL=off"
    exit 0
fi

if [ ! -s "$SF_JSON" ]; then
    sf_flush_all
    echo "SELF_FIREWALL=off"
    exit 0
fi

_SF_PKGS_IN="/dev/null"
[ -r "$SF_PKGS_LIST" ] && _SF_PKGS_IN="$SF_PKGS_LIST"

sf_detect_cell_only_vpn() {
    if [ "${HNC_SELF_FW_CELL_VPN:-}" = "1" ]; then
        return 0
    fi
    if [ "${HNC_SELF_FW_CELL_VPN:-}" = "0" ]; then
        return 1
    fi
    if [ -n "${HNC_TEST_MODE:-}" ] && [ -z "${HNC_SELF_FW_ROUTES_TEXT:-}" ]; then
        return 1
    fi
    _sfr_ap=""
    if [ -r "$HNC_DIR/run/hnc_state" ]; then
        _sfr_st=$(cat "$HNC_DIR/run/hnc_state" 2>/dev/null)
        case "$_sfr_st" in
            ACTIVE:*) _sfr_ap=${_sfr_st#ACTIVE:} ;;
        esac
    fi
    _sfr_txt=""
    if [ -n "${HNC_SELF_FW_ROUTES_TEXT:-}" ]; then
        _sfr_txt="$HNC_SELF_FW_ROUTES_TEXT"
    elif command -v ip >/dev/null 2>&1; then
        _sfr_txt="$(ip -4 route show table all 2>/dev/null; ip -6 route show table all 2>/dev/null)"
    fi
    if [ -z "$_sfr_txt" ] && [ -r /proc/net/route ]; then
        _sfr_txt=$(awk 'NR>1 && $2=="00000000" && $8=="00000000" { print "default dev " $1 }' /proc/net/route 2>/dev/null)
    fi
    [ -n "$_sfr_txt" ] || { unset _sfr_ap _sfr_st _sfr_txt; return 1; }

    printf '%s\n' "$_sfr_txt" | awk -v ap="$_sfr_ap" '
        {
            r0 = $1
            if (r0 == "unicast") r0 = $2
            if (r0 != "default" && r0 != "0.0.0.0/0" && r0 != "0.0.0.0/1" && r0 != "128.0.0.0/1" && r0 != "::/0" && r0 != "::/1" && r0 != "8000::/1") {
                next
            }
            for (i = 1; i < NF; i++) {
                if ($i == "dev") {
                    d = $(i + 1)
                    if (d == "" || d == "lo") continue
                    if (d ~ /^(tun[0-9]+|tap[0-9]+|ppp[0-9]+|wg[0-9]+|ipsec[0-9a-z_]*|xfrm[0-9]+|tailscale[0-9]*|utun[0-9]*|sing_tun[0-9]*|Meta)$/) {
                        has_vpn = 1
                        continue
                    }
                    p = d
                    sub(/^v4-/, "", p)
                    sub(/^clat4-/, "", p)
                    if ((ap != "" && (d == ap || p == ap)) || d ~ /^(ap[0-9]*|ap_br_[a-z0-9_]+|softap[0-9]+|swlan[0-9]+)$/) {
                        continue
                    }
                    if (p ~ /^(rmnet|ccmni|seth_|sipa_eth|gti[0-9]|wwan)/ || d ~ /^clat4/) {
                        has_cell = 1
                    } else if (p ~ /^(wlan|eth|usb|rndis|ncm|enx)/) {
                        has_wifi = 1
                    }
                }
            }
        }
        END {
            exit ((has_vpn && has_cell && !has_wifi) ? 0 : 1)
        }
    '
    _sfr_rc=$?
    unset _sfr_ap _sfr_st _sfr_txt
    return "$_sfr_rc"
}

_SF_CELL_VPN=0
if sf_detect_cell_only_vpn; then
    _SF_CELL_VPN=1
fi

_SF_PARSED=$(awk -v pkgs_file="$_SF_PKGS_IN" -v cell_vpn="$_SF_CELL_VPN" '
    function is_protected_pkg(p) {
        p = tolower(p)
        return (p == "me.weishu.kernelsu" || p == "com.rifsxd.ksunext" || p == "com.sukisu.ultra" || \
                p == "io.github.vvb2060.magisk" || p == "com.topjohnwu.magisk" || p == "me.bmax.apatch" || \
                p == "com.google.android.webview" || p == "com.android.webview" || p == "com.agy")
    }
    function is_valid_tgt_chars(s,    j, n, c) {
        n = length(s)
        if (n < 2) return 0
        for (j = 1; j <= n; j++) {
            c = substr(s, j, 1)
            if (index("0123456789abcdefABCDEF:.[]", c) == 0) return 0
        }
        return 1
    }
    function is_public_dns_ip(ip) {
        ip = tolower(ip)
        return (ip == "8.8.8.8" || ip == "8.8.4.4" || ip == "1.1.1.1" || ip == "1.0.0.1" || \
                ip == "9.9.9.9" || ip == "149.112.112.112" || ip == "223.5.5.5" || ip == "223.6.6.6" || \
                ip == "119.29.29.29" || ip == "119.28.28.28" || ip == "182.254.116.116" || \
                ip == "114.114.114.114" || ip == "114.114.115.115" || ip == "180.76.76.76" || \
                ip == "2001:4860:4860::8888" || ip == "2001:4860:4860::8844" || \
                ip == "2606:4700:4700::1111" || ip == "2606:4700:4700::1001" || \
                ip == "2400:3200::1" || ip == "2400:3200:baba::1" || ip == "2402:4e00::")
    }
    function is_forbidden_ip(ip,    low, nb, oct, o1, o2) {
        low = tolower(ip)
        if (low == "" || low == "127.0.0.1" || low == "::1" || low == "0.0.0.0" || low == "::") return 1
        if (is_public_dns_ip(low)) return 1
        if (index(low, ":") > 0) {
            if (low ~ /^(fe[89ab]|fc|fd|ff)/) return 1
            return 0
        }
        nb = split(low, oct, ".")
        if (nb != 4) return 1
        if (oct[1] !~ /^[0-9]+$/ || oct[2] !~ /^[0-9]+$/ || oct[3] !~ /^[0-9]+$/ || oct[4] !~ /^[0-9]+$/) return 1
        o1 = oct[1] + 0; o2 = oct[2] + 0
        if (o1 == 0 || o1 == 10 || o1 == 127 || o1 >= 224) return 1
        if (o1 == 169 && o2 == 254) return 1
        if (o1 == 172 && o2 >= 16 && o2 <= 31) return 1
        if (o1 == 192 && o2 == 168) return 1
        if (o1 == 100 && o2 >= 64 && o2 <= 127) return 1
        if (o1 == 198 && (o2 == 18 || o2 == 19)) return 1
        return 0
    }
    function filter_valid_targets(csv,    n, arr, i, rawt, ip, prt, rb, c1, pnum, out) {
        if (csv == "") return ""
        n = split(csv, arr, ",")
        out = ""
        for (i = 1; i <= n; i++) {
            rawt = arr[i]
            if (!is_valid_tgt_chars(rawt)) continue
            ip = rawt; prt = ""
            if (substr(rawt, 1, 1) == "[") {
                rb = index(rawt, "]")
                if (rb <= 2) continue
                ip = substr(rawt, 2, rb - 2)
                if (substr(rawt, rb + 1, 1) == ":") prt = substr(rawt, rb + 2)
            } else {
                c1 = index(rawt, ":")
                if (c1 > 0 && index(substr(rawt, c1 + 1), ":") == 0) {
                    ip = substr(rawt, 1, c1 - 1)
                    prt = substr(rawt, c1 + 1)
                }
            }
            if (is_forbidden_ip(ip)) continue
            if (prt != "") {
                if (prt !~ /^[0-9]+$/) continue
                pnum = prt + 0
                if (pnum < 1 || pnum > 65535 || pnum == 53 || pnum == 853 || pnum == 8080 || pnum == 8443 || pnum == 8444) continue
            }
            out = (out == "" ? rawt : out "," rawt)
        }
        return out
    }
    function build_dns_hex(dom,    nb, labs, i, L, out) {
        dom = tolower(dom)
        sub(/^\*\./, "", dom)
        sub(/\.$/, "", dom)
        if (dom == "" || length(dom) > 253 || dom == "localhost" || dom ~ /\.localhost$/ || dom ~ /\.local$/) return ""
        if (dom ~ /[^a-z0-9.-]/ || dom ~ /^\./ || dom ~ /\.\./ || dom !~ /\./ || dom ~ /^[0-9.]+$/) return ""
        nb = split(dom, labs, ".")
        if (nb < 2) return ""
        out = ""
        for (i = 1; i <= nb; i++) {
            L = length(labs[i])
            if (L < 1 || L > 63 || substr(labs[i], 1, 1) == "-" || substr(labs[i], L, 1) == "-") return ""
            out = out sprintf("|%02x|%s", L, labs[i])
        }
        return out "|00|"
    }
    FILENAME == pkgs_file {
        if (NF >= 2 && $2 ~ /^[0-9]+$/) {
            u = $2 + 0
            pa = u % 100000
            if (is_protected_pkg($1)) {
                prot_uid[u] = 1
                if (pa >= 10000 && pa < 90000) {
                    prot_appid[pa] = 1
                    if (pa <= 19999) prot_appid[pa + 10000] = 1
                }
            }
        }
        next
    }
    {
        json = json " " $0
    }
    END {
        # 轻量词法扫描提取 JSON token 序列
        len = length(json)
        nt = 0
        i = 1
        while (i <= len) {
            c = substr(json, i, 1)
            if (c == " " || c == "\t" || c == "\r" || c == "\n") { i++; continue }
            if (c == "{" || c == "}" || c == "[" || c == "]" || c == ":" || c == ",") {
                tok_type[++nt] = c
                tok_val[nt] = c
                i++
                continue
            }
            if (c == "\"") {
                i++
                s = ""
                while (i <= len) {
                    ch = substr(json, i, 1)
                    if (ch == "\\") {
                        s = s substr(json, i + 1, 1)
                        i += 2
                        continue
                    }
                    if (ch == "\"") { i++; break }
                    s = s ch
                    i++
                }
                tok_type[++nt] = "S"
                tok_val[nt] = s
                continue
            }
            s = ""
            while (i <= len) {
                ch = substr(json, i, 1)
                if (ch == " " || ch == "\t" || ch == "\r" || ch == "\n" || \
                    ch == "{" || ch == "}" || ch == "[" || ch == "]" || ch == ":" || ch == "," || ch == "\"") break
                s = s ch
                i++
            }
            tok_type[++nt] = "L"
            tok_val[nt] = s
        }

        section = ""
        in_rule = 0
        in_targets = 0
        rcnt = 0
        dcnt = 0
        cur_uid = 0; cur_pkg = ""; cur_mode = ""; cur_tgts = ""

        for (k = 1; k <= nt; k++) {
            tt = tok_type[k]; tv = tok_val[k]
            if (section == "" && tt == "S" && tok_type[k+1] == ":" && tok_type[k+2] == "[") {
                if (tv == "uid_rules" || tv == "blocked_domains") {
                    section = tv
                    k += 2
                    continue
                }
            }
            if (section == "uid_rules") {
                if (!in_rule && tt == "]") { section = ""; continue }
                if (!in_rule && tt == "{") {
                    in_rule = 1; in_targets = 0
                    cur_uid = 0; cur_pkg = ""; cur_mode = ""; cur_tgts = ""
                    continue
                }
                if (in_rule) {
                    if (in_targets) {
                        if (tt == "]") { in_targets = 0; continue }
                        if (tt == "S" && tv != "") {
                            cur_tgts = (cur_tgts == "" ? tv : cur_tgts "," tv)
                        }
                        continue
                    }
                    if (tt == "}") {
                        in_rule = 0
                        m = tolower(cur_mode)
                        if (cur_pkg ~ /^(uid:|isolated:)/) cur_pkg = ""
                        valid_tgts = filter_valid_targets(cur_tgts)
                        app_id = cur_uid % 100000
                        # C064 + B026 + B007: 严格拒绝 appId < 10000 或 >= 90000 (隔离进程) 及受保护包; 允许 mode=="allow" 带合法 block_targets
                        if (cur_uid >= 10000 && cur_uid <= 99999999 && app_id >= 10000 && app_id < 90000 && \
                            !(cur_uid in prot_uid) && !(app_id in prot_appid) && !is_protected_pkg(cur_pkg) && \
                            ((m == "allow" && valid_tgts != "") || m == "block_cleartext" || m == "block_cellular" || m == "block_all")) {
                            rcnt++
                            r_uid[rcnt] = cur_uid
                            r_mode[rcnt] = m
                            r_tgts[rcnt] = valid_tgts
                            seen_uid[cur_uid] = 1
                        }
                        continue
                    }
                    if (tt == "S" && tok_type[k+1] == ":") {
                        key = tv
                        vt = tok_type[k+2]; vv = tok_val[k+2]
                        if (key == "uid" && (vt == "L" || vt == "S") && vv ~ /^[0-9]+$/) {
                            cur_uid = vv + 0; k += 2; continue
                        }
                        if (key == "pkg" && vt == "S") {
                            cur_pkg = tolower(vv); k += 2; continue
                        }
                        if (key == "mode" && vt == "S") {
                            cur_mode = tolower(vv); k += 2; continue
                        }
                        if (key == "block_targets" && vt == "[") {
                            in_targets = 1; k += 2; continue
                        }
                    }
                }
                continue
            }
            if (section == "blocked_domains") {
                if (tt == "]") { section = ""; continue }
                if (tt == "S" && tok_type[k+1] != ":") {
                    hx = build_dns_hex(tv)
                    if (hx != "" && !(hx in seen_hex)) {
                        seen_hex[hx] = 1
                        d_hex[++dcnt] = hx
                    }
                } else if (tt == "S" && tv == "domain" && tok_type[k+1] == ":" && tok_type[k+2] == "S") {
                    hx = build_dns_hex(tok_val[k+2])
                    if (hx != "" && !(hx in seen_hex)) {
                        seen_hex[hx] = 1
                        d_hex[++dcnt] = hx
                    }
                    k += 2
                }
            }
        }

        printf "META %d %d\n", rcnt, dcnt
        if (rcnt > 0) {
            for (fam = 4; fam <= 6; fam += 2) {
                tag = (fam == 4 ? "UID4" : "UID6")
                print tag " *filter"
                print tag " :HNC_SELF_UID - [0:0]"
                # C063: 链首仅保留 -o lo -j RETURN, 移除 8443,8444,8080 无目的地址 RETURN 绕过规则
                print tag " -A HNC_SELF_UID -o lo -j RETURN"
                for (r = 1; r <= rcnt; r++) {
                    nu = 1; ulist[1] = r_uid[r]
                    app_id = r_uid[r] % 100000
                    sb_uid = r_uid[r] + 10000
                    # C064: 多用户/双开应用 appId 在 10000..19999 时自动配对 SDK Sandbox (uid + 10000)
                    if (app_id >= 10000 && app_id <= 19999 && sb_uid <= 99999999 && \
                        !(sb_uid in seen_uid) && !(sb_uid in prot_uid) && !((sb_uid % 100000) in prot_appid)) {
                        ulist[++nu] = sb_uid
                    }
                    ntg = split(r_tgts[r], tarr, ",")
                    for (ui = 1; ui <= nu; ui++) {
                        u = ulist[ui]
                        for (ti = 1; ti <= ntg; ti++) {
                            rawt = tarr[ti]
                            if (!is_valid_tgt_chars(rawt)) continue
                            ip = rawt; prt = ""
                            if (substr(rawt, 1, 1) == "[") {
                                rb = index(rawt, "]")
                                if (rb <= 2) continue
                                ip = substr(rawt, 2, rb - 2)
                                if (substr(rawt, rb + 1, 1) == ":") prt = substr(rawt, rb + 2)
                            } else {
                                c1 = index(rawt, ":")
                                if (c1 > 0 && index(substr(rawt, c1 + 1), ":") == 0) {
                                    ip = substr(rawt, 1, c1 - 1)
                                    prt = substr(rawt, c1 + 1)
                                }
                            }
                            is6 = (index(ip, ":") > 0 ? 1 : 0)
                            if ((fam == 6 && !is6) || (fam == 4 && is6)) continue
                            if (is_forbidden_ip(ip)) continue
                            if (prt != "" && prt ~ /^[0-9]+$/) {
                                pnum = prt + 0
                                if (pnum >= 1 && pnum <= 65535 && pnum != 53 && pnum != 853 && pnum != 8443 && pnum != 8444 && pnum != 8080) {
                                    printf "%s -A HNC_SELF_UID -d %s -p tcp --dport %d -m owner --uid-owner %d -j REJECT --reject-with tcp-reset\n", tag, ip, pnum, u
                                    printf "%s -A HNC_SELF_UID -d %s -p udp --dport %d -m owner --uid-owner %d -j REJECT\n", tag, ip, pnum, u
                                }
                            } else if (prt == "") {
                                printf "%s -A HNC_SELF_UID -d %s -m owner --uid-owner %d -j REJECT\n", tag, ip, u
                            }
                        }
                        if (r_mode[r] == "block_cleartext") {
                            printf "%s -A HNC_SELF_UID -p tcp -m multiport --dports 80,8080,8000,8008,8888 -m owner --uid-owner %d -j REJECT --reject-with tcp-reset\n", tag, u
                        } else if (r_mode[r] == "block_cellular") {
                            printf "%s -A HNC_SELF_UID -o rmnet+ -m owner --uid-owner %d -j REJECT\n", tag, u
                            printf "%s -A HNC_SELF_UID -o ccmni+ -m owner --uid-owner %d -j REJECT\n", tag, u
                            printf "%s -A HNC_SELF_UID -o seth_w+ -m owner --uid-owner %d -j REJECT\n", tag, u
                            printf "%s -A HNC_SELF_UID -o clat4+ -m owner --uid-owner %d -j REJECT\n", tag, u
                            printf "%s -A HNC_SELF_UID -o v4-+ -m owner --uid-owner %d -j REJECT\n", tag, u
                            if (cell_vpn == 1) {
                                printf "%s -A HNC_SELF_UID -o tun+ -m owner --uid-owner %d -j REJECT\n", tag, u
                                printf "%s -A HNC_SELF_UID -o Meta -m owner --uid-owner %d -j REJECT\n", tag, u
                                printf "%s -A HNC_SELF_UID -o wg+ -m owner --uid-owner %d -j REJECT\n", tag, u
                                printf "%s -A HNC_SELF_UID -o utun+ -m owner --uid-owner %d -j REJECT\n", tag, u
                                printf "%s -A HNC_SELF_UID -o sing_tun+ -m owner --uid-owner %d -j REJECT\n", tag, u
                            }
                        } else if (r_mode[r] == "block_all") {
                            printf "%s -A HNC_SELF_UID -m owner --uid-owner %d -j REJECT\n", tag, u
                        }
                    }
                }
                print tag " COMMIT"
            }
        }
        if (dcnt > 0) {
            print "DNS *filter"
            print "DNS :HNC_SELF_DNS - [0:0]"
            for (d = 1; d <= dcnt; d++) {
                printf "DNS -A HNC_SELF_DNS -p udp --dport 53 -m string --algo bm --icase --hex-string \"%s\" -j DROP\n", d_hex[d]
                printf "DNS -A HNC_SELF_DNS -p tcp --dport 53 -m string --algo bm --icase --hex-string \"%s\" -j DROP\n", d_hex[d]
            }
            print "DNS COMMIT"
        }
    }
' "$_SF_PKGS_IN" "$SF_JSON" 2>/dev/null)

_SF_META=$(printf '%s\n' "$_SF_PARSED" | sed -n 's/^META //p' | head -n 1)
_SF_UCNT=${_SF_META%% *}
_SF_DCNT=${_SF_META#* }
case "$_SF_UCNT" in ''|*[!0-9]*) _SF_UCNT=0 ;; esac
case "$_SF_DCNT" in ''|*[!0-9]*) _SF_DCNT=0 ;; esac

if [ "$_SF_UCNT" -eq 0 ] && [ "$_SF_DCNT" -eq 0 ]; then
    sf_flush_all
    echo "SELF_FIREWALL=off"
    exit 0
fi

# C065: 严格核验双栈 restore 与 OUTPUT 挂载退出码, 同时保留缺 xt_string 或无 IPv6 filter 表的内核降级容错
_SF_RC=0

if [ "$_SF_UCNT" -gt 0 ]; then
    _SF_UID4=$(printf '%s\n' "$_SF_PARSED" | sed -n 's/^UID4 //p')
    _SF_UID6=$(printf '%s\n' "$_SF_PARSED" | sed -n 's/^UID6 //p')
    if sf_pipe_restore "$IPT_RESTORE" "${_SF_UID4}
"; then
        if ! sf_ensure_link_one "$IPT" HNC_SELF_UID; then
            sf_log "ERROR: ipv4 hook HNC_SELF_UID failed: $SF_LAST_ERR"
            _SF_RC=1
        fi
    else
        sf_log "ERROR: ipv4 restore HNC_SELF_UID failed: $SF_LAST_ERR"
        _SF_RC=1
    fi
    if [ "$SF_V6_OK" = "1" ]; then
        if sf_pipe_restore "$IP6T_RESTORE" "${_SF_UID6}
"; then
            if ! sf_ensure_link_one "$IP6T" HNC_SELF_UID; then
                if sf_is_ipv6_unsupported "$SF_LAST_ERR"; then
                    sf_log "WARN: ipv6 filter unsupported during HNC_SELF_UID hook, degraded to v4"
                else
                    sf_log "ERROR: ipv6 hook HNC_SELF_UID failed: $SF_LAST_ERR"
                    _SF_RC=1
                fi
            fi
        elif sf_is_ipv6_unsupported "$SF_LAST_ERR"; then
            sf_log "WARN: ipv6 filter unsupported during HNC_SELF_UID restore, degraded to v4"
        else
            sf_log "ERROR: ipv6 restore HNC_SELF_UID failed: $SF_LAST_ERR"
            _SF_RC=1
        fi
    fi
else
    sf_detach_chain_one "$IPT" HNC_SELF_UID
    [ "$SF_V6_OK" = "1" ] && sf_detach_chain_one "$IP6T" HNC_SELF_UID
fi

if [ "$_SF_DCNT" -gt 0 ]; then
    _SF_DNS_BODY=$(printf '%s\n' "$_SF_PARSED" | sed -n 's/^DNS //p')
    if sf_pipe_restore "$IPT_RESTORE" "${_SF_DNS_BODY}
"; then
        if ! sf_ensure_link_one "$IPT" HNC_SELF_DNS; then
            sf_log "ERROR: ipv4 hook HNC_SELF_DNS failed: $SF_LAST_ERR"
            _SF_RC=1
        fi
    elif sf_is_xt_string_unsupported "$SF_LAST_ERR"; then
        sf_log "WARN: xt_string missing on ipv4 kernel, HNC_SELF_DNS degraded (UID rules kept)"
        sf_detach_chain_one "$IPT" HNC_SELF_DNS
    else
        sf_log "ERROR: ipv4 restore HNC_SELF_DNS failed: $SF_LAST_ERR"
        _SF_RC=1
    fi
    if [ "$SF_V6_OK" = "1" ]; then
        if sf_pipe_restore "$IP6T_RESTORE" "${_SF_DNS_BODY}
"; then
            if ! sf_ensure_link_one "$IP6T" HNC_SELF_DNS; then
                if sf_is_ipv6_unsupported "$SF_LAST_ERR"; then
                    sf_log "WARN: ipv6 filter unsupported during HNC_SELF_DNS hook, degraded"
                else
                    sf_log "ERROR: ipv6 hook HNC_SELF_DNS failed: $SF_LAST_ERR"
                    _SF_RC=1
                fi
            fi
        elif sf_is_xt_string_unsupported "$SF_LAST_ERR" || sf_is_ipv6_unsupported "$SF_LAST_ERR"; then
            sf_log "WARN: xt_string or ipv6 filter unsupported on v6 kernel, HNC_SELF_DNS v6 degraded"
            sf_detach_chain_one "$IP6T" HNC_SELF_DNS
        else
            sf_log "ERROR: ipv6 restore HNC_SELF_DNS failed: $SF_LAST_ERR"
            _SF_RC=1
        fi
    fi
else
    sf_detach_chain_one "$IPT" HNC_SELF_DNS
    [ "$SF_V6_OK" = "1" ] && sf_detach_chain_one "$IP6T" HNC_SELF_DNS
fi

sf_log "applied uid_rules=$_SF_UCNT blocked_domains=$_SF_DCNT v6=$SF_V6_OK rc=$_SF_RC"
if [ "$_SF_RC" -ne 0 ]; then
    echo "SELF_FIREWALL=error uid_rules=$_SF_UCNT blocked_domains=$_SF_DCNT"
    exit "$_SF_RC"
fi
echo "SELF_FIREWALL=on uid_rules=$_SF_UCNT blocked_domains=$_SF_DCNT"
exit 0
