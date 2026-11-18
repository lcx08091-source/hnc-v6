#!/system/bin/sh
# v5.20: bin/hnc_iface.sh —— 唯一权威热点接口探测器(多机型 fixture)
#
# 桩: dumpsys / ip / iptables 走 PATH 拦截, 读 $FX 下的 fixture 文件;
#     /sys/class/net 与 /proc/net/arp 走 HNC_SYS_NET / HNC_PROC_NET_ARP。

IFSCRIPT="$HNC_REPO_ROOT/bin/hnc_iface.sh"

fx_init() {
    FX="$HNC_TEST_DIR/fx"
    rm -rf "$FX"; mkdir -p "$FX/sys" "$FX/mock" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/logs"
    echo '{"version":1,"devices":{}}' > "$HNC_TEST_DIR/data/rules.json"
    printf 'IP address       HW type     Flags       HW address            Mask     Device\n' > "$FX/arp"
    : > "$FX/ip_addr"; : > "$FX/ip_route"; : > "$FX/route_get"; : > "$FX/calls"
    cat > "$FX/mock/dumpsys" <<'M'
#!/bin/sh
echo "dumpsys $*" >> "$FX/calls"
case "$1" in
    tethering) cat "$FX/dumpsys_tethering" 2>/dev/null ;;
    connectivity) cat "$FX/dumpsys_conn" 2>/dev/null ;;
    wifi) cat "$FX/dumpsys_wifi" 2>/dev/null ;;
esac
exit 0
M
    cat > "$FX/mock/ip" <<'M'
#!/bin/sh
echo "ip $*" >> "$FX/calls"
case "$*" in
    "-4 -o addr show") cat "$FX/ip_addr" ;;
    "route show table all") cat "$FX/ip_route" ;;
    "route get "*) cat "$FX/route_get" ;;
esac
exit 0
M
    cat > "$FX/mock/iptables" <<'M'
#!/bin/sh
echo "iptables $*" >> "$FX/calls"
cat "$FX/tetherctrl" 2>/dev/null
exit 0
M
    chmod +x "$FX/mock/"*
    export FX
}
# link <name> <up|down> [ipv4]
link() {
    mkdir -p "$FX/sys/$1"
    if [ "$2" = up ]; then echo 0x1003 > "$FX/sys/$1/flags"; else echo 0x1002 > "$FX/sys/$1/flags"; fi
    [ -n "$3" ] && echo "7: $1    inet $3/24 brd 0.0.0.0 scope global $1\\       valid_lft forever preferred_lft forever" >> "$FX/ip_addr"
    return 0
}
defroute() { echo "default via 1.2.3.4 dev $1 table $1 proto static" >> "$FX/ip_route"; }
upstream() { echo "1.1.1.1 dev $1 table 1003 src 10.0.0.2 uid 0" > "$FX/route_get"; defroute "$1"; }
neigh() { printf '%s 0x1 0x2 %s * %s\n' "$1" "$3" "$2" >> "$FX/arp"; }
tether_state() {  # 追加 "  <if> - <State> - lastError = 0"
    [ -f "$FX/dumpsys_tethering" ] || printf 'Tethering:\n  Tether state:\n' > "$FX/dumpsys_tethering"
    echo "    $1 - $2 - lastError = 0" >> "$FX/dumpsys_tethering"
}
irun() {
    HNC_DIR="$HNC_TEST_DIR" HNC_SKIP_PATH_HARDENING=1 HNC_SYS_NET="$FX/sys" HNC_PROC_NET_ARP="$FX/arp" \
    PATH="$FX/mock:$PATH" sh "$IFSCRIPT" "$@" 2>/dev/null
}
jf() { sed -n "s/.*\"$1\":\\(\"[^\"]*\"\\|\\[[^]]*\\]\\|[a-z0-9]*\\).*/\\1/p" "$HNC_TEST_DIR/run/iface_detect.json" 2>/dev/null | head -n1; }

# ─── ColorOS 16(RMX5010): wlan2 热点 + wlan0 STA + rmnet_data2 上游 ───────────
test_start "hnc_iface: ColorOS wlan2 via dumpsys tethering, upstream rmnet_data2=cell"
fx_init
link wlan0 up 192.168.1.20; link wlan2 up 10.201.76.1; link rmnet_data2 up 10.97.46.161
upstream rmnet_data2; defroute wlan0
tether_state wlan2 TetheredState
echo "  Current upstream interface(s): [rmnet_data2]" >> "$FX/dumpsys_tethering"
out=$(irun detect)
assert_eq "wlan2" "$out" "iface" && assert_eq '"tethering"' "$(jf method)" "method" \
  && assert_eq '"rmnet_data2"' "$(jf upstream)" "upstream" && assert_eq '"cell"' "$(jf upstream_class)" "upstream_class" \
  && assert_eq "wlan2" "$(cat "$HNC_TEST_DIR/run/hotspot_iface")" "hotspot_iface hint" \
  && assert_json_valid "$HNC_TEST_DIR/run/iface_detect.json" && test_pass

# ─── Pixel(Tensor): wlan1 热点, tethering dumpsys 不可用 → dumpsys wifi softap ──
test_start "hnc_iface: Pixel wlan1 via dumpsys wifi mApInterfaceName"
fx_init
link wlan0 up 192.168.1.20; link wlan1 up 192.168.73.1; link rmnet1 up 10.1.1.2
upstream rmnet1; defroute wlan0
printf 'Dump of SoftApManager id=1\ncurrent StateMachine mode: StartedState\nmApInterfaceName: wlan1\nmIfaceIsUp: true\n' > "$FX/dumpsys_wifi"
out=$(irun detect)
assert_eq "wlan1" "$out" && assert_eq '"wifi_softap"' "$(jf method)" && assert_eq '"cell"' "$(jf upstream_class)" "Tensor rmnet1 is cell" && test_pass

# ─── 老 Pixel / MTK: ap0, 所有服务都拿不到 → 名字扫描 ────────────────────────
test_start "hnc_iface: ap0 found by scan when no service answers"
fx_init
link wlan0 up 192.168.1.20; link ap0 up 192.168.43.1; link ccmni1 up 10.64.1.2
upstream ccmni1; defroute wlan0
neigh 192.168.43.77 ap0 aa:bb:cc:dd:ee:01
out=$(irun detect)
assert_eq "ap0" "$out" && assert_eq '"scan"' "$(jf method)" && assert_eq "false" "$(jf authoritative)" && test_pass

# ─── MTK: ap0 TetheredState + ccmni1 上游 ───────────────────────────────────
test_start "hnc_iface: MediaTek ap0 + ccmni upstream"
fx_init
link ap0 up 192.168.43.1; link ccmni1 up 10.64.1.2
upstream ccmni1
tether_state ap0 TetheredState
out=$(irun detect)
assert_eq "ap0" "$out" && assert_eq '"ccmni1"' "$(jf upstream)" && assert_eq '"cell"' "$(jf upstream_class)" && test_pass

# ─── Samsung: swlan0, 只有 tetherctrl; Wi-Fi 上游的回程规则 -i wlan0 在最前 ──
test_start "hnc_iface: Samsung swlan0 via tetherctrl, never the wlan0 return rule"
fx_init
link wlan0 up 192.168.1.20; link swlan0 up 192.168.195.1
upstream wlan0
cat > "$FX/tetherctrl" <<'T'
Chain tetherctrl_FORWARD (1 references)
 pkts bytes target     prot opt in     out     source               destination
  120  9000 ACCEPT     all  --  wlan0  swlan0  0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED
    0     0 DROP       all  --  swlan0 wlan0   0.0.0.0/0            0.0.0.0/0            state INVALID
   80  7000 ACCEPT     all  --  swlan0 wlan0   0.0.0.0/0            0.0.0.0/0
T
out=$(irun detect)
assert_eq "swlan0" "$out" && assert_eq '"tetherctrl"' "$(jf method)" && assert_eq '"wifi"' "$(jf upstream_class)" && test_pass

test_start "hnc_iface: tetherctrl skips RELATED,ESTABLISHED return rule even without route info"
fx_init
link wlan1 up 192.168.195.1
cat > "$FX/tetherctrl" <<'T'
  120  9000 ACCEPT     all  --  wlan0  wlan1   0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED
   80  7000 ACCEPT     all  --  wlan1  wlan0   0.0.0.0/0            0.0.0.0/0
T
out=$(irun detect)
assert_eq "wlan1" "$out" && test_pass

# ─── USB 共享 only: 上报 rndis0, 但不当作 Wi-Fi 热点口 ─────────────────────
test_start "hnc_iface: USB rndis0 tethering reported, not chosen"
fx_init
link rndis0 up 192.168.42.129; link rmnet_data0 up 10.1.1.2
upstream rmnet_data0
tether_state rndis0 TetheredState
irun detect >/dev/null; rc=$?
assert_eq 1 "$rc" "no wifi hotspot → exit 1" && assert_eq '""' "$(jf iface)" \
  && assert_eq '["rndis0"]' "$(jf usb_tether)" && test_pass

test_start "hnc_iface: wlan2 + USB rndis0 + BT bt-pan all reported"
fx_init
link wlan2 up 10.201.76.1; link rndis0 up 192.168.42.129; link bt-pan up 192.168.44.1; link rmnet_data0 up 10.1.1.2
upstream rmnet_data0
tether_state rndis0 TetheredState; tether_state bt-pan TetheredState; tether_state wlan2 TetheredState
out=$(irun detect)
assert_eq "wlan2" "$out" && assert_eq '["rndis0"]' "$(jf usb_tether)" && assert_eq '["bt-pan"]' "$(jf bt_tether)" \
  && assert_eq '["wlan2"]' "$(jf wifi_tether)" && test_pass

# ─── 双 Wi-Fi(STA+STA): wlan1 是副 STA(有 default route, 路由器在 ARP)→ 不是热点 ─
test_start "hnc_iface: secondary STA wlan1 with default route is never picked"
fx_init
link wlan0 up 192.168.1.20; link wlan1 up 192.168.5.20
defroute wlan0; defroute wlan1; upstream wlan0
neigh 192.168.5.1 wlan1 aa:bb:cc:dd:ee:02
irun detect >/dev/null; rc=$?
assert_eq 1 "$rc" && assert_not_contains "$(cat "$FX/calls")" "dumpsys" "no candidates → no dumpsys" && test_pass

# ─── 热点关: 无候选 → 不跑 dumpsys, 不兜底 wlan0 ────────────────────────────
test_start "hnc_iface: hotspot off → empty, cheap (no dumpsys), never wlan0"
fx_init
link wlan0 up 192.168.1.20; link wlan2 down
upstream wlan0
irun detect >/dev/null; rc=$?
assert_eq 1 "$rc" && assert_eq '"none"' "$(jf method)" && assert_not_contains "$(cat "$FX/calls")" "dumpsys" && test_pass

# ─── wlan0 做 AP(单接口老机型): 只有权威来源才返回 ───────────────────────────
test_start "hnc_iface: wlan0 as AP only from authoritative source"
fx_init
link wlan0 up 192.168.43.1; link rmnet_data0 up 10.1.1.2
upstream rmnet_data0
neigh 192.168.43.50 wlan0 aa:bb:cc:dd:ee:03
irun detect >/dev/null; rc1=$?
tether_state wlan0 TetheredState
out=$(irun detect)
assert_eq 1 "$rc1" "scan must not pick wlan0" && assert_eq "wlan0" "$out" && assert_eq "true" "$(jf wlan0_ap)" && test_pass

# ─── 用户偏好 ─────────────────────────────────────────────────────────────
test_start "hnc_iface: user override wins; invalid override falls through"
fx_init
link wlan2 up 10.201.76.1; link wlan3 up 10.9.9.1; link rmnet_data0 up 10.1.1.2
upstream rmnet_data0
tether_state wlan2 TetheredState
echo '{"version":1,"hotspot_iface":"wlan3","devices":{}}' > "$HNC_TEST_DIR/data/rules.json"
o1=$(irun detect); m1=$(jf method)
echo '{"version":1,"hotspot_iface":"wlan9","devices":{}}' > "$HNC_TEST_DIR/data/rules.json"
o2=$(irun detect); s2=$(jf override_state)
assert_eq "wlan3" "$o1" && assert_eq '"override"' "$m1" && assert_eq "wlan2" "$o2" && assert_eq '"invalid"' "$s2" && test_pass

# ─── Android 8–10: dumpsys connectivity tethering ───────────────────────────
test_start "hnc_iface: legacy dumpsys connectivity tethering fallback"
fx_init
link wlan0 up 192.168.43.1; link rmnet_data0 up 10.1.1.2
upstream rmnet_data0
printf 'Tethering:\n  Tether state:\n    wlan0 - TetheredState - lastError = 0\n  Upstream wanted: true\n  Current upstream interface: rmnet_data0\n' > "$FX/dumpsys_conn"
out=$(irun detect)
assert_eq "wlan0" "$out" && assert_contains "$(cat "$FX/calls")" "dumpsys connectivity tethering" && test_pass

# ─── get: 缓存命中不跑 dumpsys; 候选变化(热点换口)立即重探 ────────────────
test_start "hnc_iface get: cache hit is cheap, candidate change re-detects"
fx_init
link wlan2 up 10.201.76.1; link rmnet_data0 up 10.1.1.2
upstream rmnet_data0
tether_state wlan2 TetheredState
irun get >/dev/null
: > "$FX/calls"
o1=$(irun get); c1=$(grep -c dumpsys "$FX/calls")
# 热点重开到 wlan1(wlan2 消失)
rm -rf "$FX/sys/wlan2"; : > "$FX/ip_addr"; rm -f "$FX/dumpsys_tethering"
link wlan1 up 192.168.73.1; link rmnet_data0 up 10.1.1.2
tether_state wlan1 TetheredState
o2=$(irun get)
assert_eq "wlan2" "$o1" && assert_eq 0 "$c1" "cache hit must not call dumpsys" && assert_eq "wlan1" "$o2" && test_pass

# ─── 分类表 ───────────────────────────────────────────────────────────────
test_start "hnc_iface classify: cross-SoC upstream + AP names"
fx_init
r=""
for n in rmnet_data0 rmnet1 ccmni2 seth_lte0 sipa_eth0 wwan0 v4-rmnet_data0 r_rmnet_data0 rmnet_ipa0 \
         ap0 ap_br_wlan2 swlan0 softap0 wlan1 wigig0 wlan0 rndis0 usb0 ncm0 bt-pan eth0 p2p-wlan0-0 ifb0 dummy0; do
    r="$r $n=$(irun classify "$n")"
done
exp=" rmnet_data0=cell rmnet1=cell ccmni2=cell seth_lte0=cell sipa_eth0=cell wwan0=cell v4-rmnet_data0=ignore r_rmnet_data0=ignore rmnet_ipa0=ignore ap0=ap ap_br_wlan2=ap swlan0=ap softap0=ap wlan1=ap_maybe wigig0=ap_maybe wlan0=wifi_sta rndis0=usb usb0=usb ncm0=usb bt-pan=bt eth0=eth p2p-wlan0-0=p2p ifb0=ignore dummy0=ignore"
assert_eq "$exp" "$r" && test_pass

# ─── device_detect.sh 走新探测器 ─────────────────────────────────────────────
test_start "device_detect iface delegates to hnc_iface.sh"
fx_init
link wlan2 up 10.201.76.1; link rmnet_data0 up 10.1.1.2
upstream rmnet_data0
tether_state wlan2 TetheredState
out=$(HNC_DIR="$HNC_TEST_DIR" HNC_SKIP_PATH_HARDENING=1 HNC_SYS_NET="$FX/sys" HNC_PROC_NET_ARP="$FX/arp" \
      PATH="$FX/mock:$PATH" sh "$HNC_TEST_DIR/bin/device_detect.sh" iface 2>/dev/null)
assert_eq "wlan2" "$out" && assert_file_exists "$HNC_TEST_DIR/run/iface_detect.json" && test_pass

# ─── v5.20.1: 手机开 VPN(本机出口 tun0), 热点上游仍是蜂窝 ─────────────────────
# 真机 RMX5010: 自检"上游出口"显示 tun0, 而 dumpsys tethering 报 rmnet_data3。
test_start "hnc_iface VPN: tethering upstream rmnet_data3 wins over local tun0"
fx_init
link wlan0 up 192.168.1.20; link wlan2 up 10.201.76.1; link rmnet_data3 up 10.97.46.161; link tun0 up 172.19.0.1
upstream tun0; defroute rmnet_data3
tether_state wlan2 TetheredState
echo "  Current upstream interface(s): [rmnet_data3,v4-rmnet_data3]" >> "$FX/dumpsys_tethering"
out=$(irun detect)
assert_eq "wlan2" "$out" "iface" \
  && assert_eq '"rmnet_data3"' "$(jf upstream)" "upstream = 热点上游" \
  && assert_eq '"cell"' "$(jf upstream_class)" \
  && assert_eq '"tethering"' "$(jf upstream_source)" \
  && assert_eq '"rmnet_data3"' "$(jf tether_upstream)" \
  && assert_eq '"tun0"' "$(jf local_upstream)" "本机出口" \
  && assert_eq '"vpn"' "$(jf local_upstream_class)" \
  && assert_eq 'true' "$(jf vpn_active)" \
  && assert_json_valid "$HNC_TEST_DIR/run/iface_detect.json" && test_pass

test_start "hnc_iface VPN: no tethering upstream line → physical default-route iface (not tun0)"
fx_init
link wlan2 up 10.201.76.1; link rmnet_data3 up 10.97.46.161; link tun0 up 172.19.0.1
upstream tun0; defroute rmnet_data3
tether_state wlan2 TetheredState
out=$(irun detect)
assert_eq "wlan2" "$out" && assert_eq '"rmnet_data3"' "$(jf upstream)" \
  && assert_eq '"route_physical"' "$(jf upstream_source)" && assert_eq '""' "$(jf tether_upstream)" \
  && assert_eq 'true' "$(jf vpn_active)" && assert_eq '"cell"' "$(jf upstream_class)" && test_pass

test_start "hnc_iface VPN: hotspot off, VPN over Wi-Fi STA → upstream wlan0 (wifi preferred over cell)"
fx_init
link wlan0 up 192.168.1.20; link rmnet_data3 up 10.97.46.161; link tun0 up 172.19.0.1
upstream tun0; defroute rmnet_data3; defroute wlan0
irun detect >/dev/null
assert_eq '"wlan0"' "$(jf upstream)" && assert_eq '"wifi"' "$(jf upstream_class)" \
  && assert_eq '"tun0"' "$(jf local_upstream)" && assert_eq 'true' "$(jf vpn_active)" \
  && assert_json_valid "$HNC_TEST_DIR/run/iface_detect.json" && test_pass

test_start "hnc_iface no VPN: vpn_active=false, upstream_source=route, local_upstream=upstream"
fx_init
link wlan0 up 192.168.1.20; link rmnet_data0 up 10.1.1.2
upstream rmnet_data0
irun detect >/dev/null
assert_eq 'false' "$(jf vpn_active)" && assert_eq '"route"' "$(jf upstream_source)" \
  && assert_eq '"rmnet_data0"' "$(jf local_upstream)" && assert_eq '"rmnet_data0"' "$(jf upstream)" && test_pass
