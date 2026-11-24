#!/system/bin/sh
# self_firewall_sync.sh — HNC v6.x 本机应用防火墙 (HNC_SELF_UID) 与本机 DNS 拦截 (HNC_SELF_DNS) 同步器
#
# 用法:
#   sh bin/self_firewall_sync.sh apply [--dry-run]   # 从 data/self_firewall.json 恢复双栈 OUTPUT 规则(空规则自动拆链)
#   sh bin/self_firewall_sync.sh flush [--dry-run]   # 干净摘除并销毁 HNC_SELF_UID / HNC_SELF_DNS 双栈子链
#
# 安全铁律:
#   1. 硬性拒绝 uid < 10000 及受保护的 Root 管理器 / WebView / 宿主包名;
#   2. HNC_SELF_UID 第 1~3 条恒为 -o lo -j RETURN 与 8443,8444,8080 双向 RETURN;
#   3. 10000 <= uid <= 19999 自动协同封禁 SDK Sandbox (uid + 10000);
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

IPT=${HNC_IPT:-"iptables -w 2"}
IP6T=${HNC_IP6T:-"ip6tables -w 2"}
IPT_RESTORE=${HNC_IPT_RESTORE:-"iptables-restore"}
IP6T_RESTORE=${HNC_IP6T_RESTORE:-"ip6tables-restore"}

if [ -z "${HNC_IPT:-}" ] && [ -z "${HNC_TEST_MODE:-}" ] && [ "$SF_DRY" != "1" ]; then
    if command -v iptables >/dev/null 2>&1; then
        iptables -w 2 -t filter -L -n >/dev/null 2>&1 || IPT="iptables"
    fi
fi
if [ -z "${HNC_IP6T:-}" ] && [ -z "${HNC_TEST_MODE:-}" ] && [ "$SF_DRY" != "1" ]; then
    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -w 2 -t filter -L -n >/dev/null 2>&1 || IP6T="ip6tables"
    fi
fi

SF_V6_OK=0
if [ "$SF_DRY" = "1" ]; then
    SF_V6_OK=1
elif command -v "${IP6T%% *}" >/dev/null 2>&1 && $IP6T -t filter -L -n >/dev/null 2>&1; then
    SF_V6_OK=1
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

sf_run_ipt() {
    if [ "$SF_DRY" = "1" ]; then
        echo "DRY: $*"
        return 0
    fi
    "$@" 2>/dev/null
}

sf_pipe_restore() {
    _sfr_bin="$1"
    _sfr_payload="$2"
    if [ "$SF_DRY" = "1" ]; then
        printf 'DRY_RESTORE(%s):\n%s' "$_sfr_bin" "$_sfr_payload"
        return 0
    fi
    command -v "$_sfr_bin" >/dev/null 2>&1 || return 1
    printf '%s' "$_sfr_payload" | "$_sfr_bin" -w 2 --noflush 2>/dev/null && return 0
    printf '%s' "$_sfr_payload" | "$_sfr_bin" -w --noflush 2>/dev/null && return 0
    printf '%s' "$_sfr_payload" | "$_sfr_bin" --noflush 2>/dev/null && return 0
    case "$_sfr_payload" in
        *REJECT*)
            _sfr_drop=$(printf '%s' "$_sfr_payload" | sed -e 's/-j REJECT --reject-with [^ ]*/-j DROP/g' -e 's/-j REJECT$/-j DROP/g')
            printf '%s' "$_sfr_drop" | "$_sfr_bin" -w 2 --noflush 2>/dev/null && return 0
            printf '%s' "$_sfr_drop" | "$_sfr_bin" --noflush 2>/dev/null && return 0
            ;;
    esac
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
    [ -n "$_sfl_ipt" ] || return 0
    if [ "$SF_DRY" = "1" ]; then
        echo "DRY: $_sfl_ipt -t filter -I OUTPUT 1 -j $_sfl_ch"
        return 0
    fi
    # shellcheck disable=SC2086
    $_sfl_ipt -t filter -C OUTPUT -j "$_sfl_ch" 2>/dev/null \
        || $_sfl_ipt -t filter -I OUTPUT 1 -j "$_sfl_ch" 2>/dev/null
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

_SF_PARSED=$(awk -v pkgs_file="$_SF_PKGS_IN" '
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
            if (is_protected_pkg($1)) {
                prot_uid[u] = 1
                if (u >= 10000 && u <= 19999) prot_uid[u + 10000] = 1
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
                        if (cur_uid >= 10000 && cur_uid <= 99999999 && !(cur_uid in prot_uid) && !is_protected_pkg(cur_pkg) && \
                            (m == "block_cleartext" || m == "block_cellular" || m == "block_all")) {
                            rcnt++
                            r_uid[rcnt] = cur_uid
                            r_mode[rcnt] = m
                            r_tgts[rcnt] = cur_tgts
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
                print tag " -A HNC_SELF_UID -o lo -j RETURN"
                print tag " -A HNC_SELF_UID -p tcp -m multiport --sports 8443,8444,8080 -j RETURN"
                print tag " -A HNC_SELF_UID -p tcp -m multiport --dports 8443,8444,8080 -j RETURN"
                for (r = 1; r <= rcnt; r++) {
                    nu = 1; ulist[1] = r_uid[r]
                    if (r_uid[r] >= 10000 && r_uid[r] <= 19999 && !((r_uid[r] + 10000) in seen_uid)) {
                        ulist[++nu] = r_uid[r] + 10000
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
                            if (ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0" || ip == "::") continue
                            if (prt != "" && prt ~ /^[0-9]+$/) {
                                pnum = prt + 0
                                if (pnum >= 1 && pnum <= 65535 && pnum != 8443 && pnum != 8444) {
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

_SF_RC=0

if [ "$_SF_UCNT" -gt 0 ]; then
    _SF_UID4=$(printf '%s\n' "$_SF_PARSED" | sed -n 's/^UID4 //p')
    _SF_UID6=$(printf '%s\n' "$_SF_PARSED" | sed -n 's/^UID6 //p')
    if sf_pipe_restore "$IPT_RESTORE" "${_SF_UID4}
"; then
        sf_ensure_link_one "$IPT" HNC_SELF_UID || _SF_RC=1
    else
        _SF_RC=1
    fi
    if [ "$SF_V6_OK" = "1" ]; then
        if sf_pipe_restore "$IP6T_RESTORE" "${_SF_UID6}
"; then
            sf_ensure_link_one "$IP6T" HNC_SELF_UID || true
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
        sf_ensure_link_one "$IPT" HNC_SELF_DNS || true
    fi
    if [ "$SF_V6_OK" = "1" ]; then
        if sf_pipe_restore "$IP6T_RESTORE" "${_SF_DNS_BODY}
"; then
            sf_ensure_link_one "$IP6T" HNC_SELF_DNS || true
        fi
    fi
else
    sf_detach_chain_one "$IPT" HNC_SELF_DNS
    [ "$SF_V6_OK" = "1" ] && sf_detach_chain_one "$IP6T" HNC_SELF_DNS
fi

sf_log "applied uid_rules=$_SF_UCNT blocked_domains=$_SF_DCNT v6=$SF_V6_OK rc=$_SF_RC"
echo "SELF_FIREWALL=on uid_rules=$_SF_UCNT blocked_domains=$_SF_DCNT"
exit "$_SF_RC"
