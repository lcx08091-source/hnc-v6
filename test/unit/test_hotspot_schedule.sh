#!/system/bin/sh
# v5.12: hotspot_schedule.sh —— 定时开关热点 / 只在充电时开热点

SCRIPT="$HNC_REPO_ROOT/bin/hotspot_schedule.sh"

seed() {  # $1=time_enable $2=start $3=end $4=charging_only
mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs"
cat > "$HNC_TEST_DIR/data/rules.json" <<JSON
{
  "version": 1,
  "hotspot_time_enable": $1,
  "hotspot_time_start": "$2",
  "hotspot_time_end": "$3",
  "hotspot_charging_only": $4,
  "devices": {}
}
JSON
}
run() { HNC_DIR="$HNC_TEST_DIR" sh "$SCRIPT" "$@" 2>/dev/null; }

test_start "schedule: disabled → allowed, no state file"
seed false "08:00" "23:00" false
run --check && [ ! -f "$HNC_TEST_DIR/run/hotspot_schedule.last" ] && test_pass || test_fail "should allow when disabled"

test_start "schedule: inside normal window → allowed"
seed true "08:00" "23:00" false
HNC_SCHED_NOW=12:30 run --check && test_pass || test_fail "12:30 in 08-23"

test_start "schedule: outside normal window → denied"
seed true "08:00" "23:00" false
HNC_SCHED_NOW=23:00 run --check && test_fail "23:00 should be outside (right-open)" || test_pass

test_start "schedule: overnight window 22:00-07:00"
seed true "22:00" "07:00" false
HNC_SCHED_NOW=23:30 run --check && HNC_SCHED_NOW=06:59 run --check && ! HNC_SCHED_NOW=12:00 run --check && test_pass || test_fail "overnight window wrong"

test_start "schedule: charging_only denies when not charging"
seed false "" "" true
HNC_SCHED_CHARGING=0 run --check && test_fail "should deny" || { HNC_SCHED_CHARGING=1 run --check && test_pass || test_fail "should allow when charging"; }

test_start "schedule: charging detected from power_supply sysfs"
seed false "" "" true
mkdir -p "$HNC_TEST_DIR/ps/battery" "$HNC_TEST_DIR/ps/usb"
echo Discharging > "$HNC_TEST_DIR/ps/battery/status"; echo USB > "$HNC_TEST_DIR/ps/usb/type"; echo 1 > "$HNC_TEST_DIR/ps/usb/online"
HNC_POWER_SUPPLY_DIR="$HNC_TEST_DIR/ps" run --check && test_pass || test_fail "usb online should count as charging"

test_start "schedule: edge-triggered — stop only on on→off transition"
seed true "08:00" "23:00" false
echo "ACTIVE:wlan2" > "$HNC_TEST_DIR/run/hnc_state"
HNC_SCHED_NOW=12:00 run >/dev/null            # 首次: 只记录 on
o1=$(HNC_SCHED_NOW=12:05 run --dry-run)
echo on > "$HNC_TEST_DIR/run/hotspot_schedule.last"
o2=$(HNC_SCHED_NOW=23:10 run --dry-run)
assert_contains "$(cat "$HNC_TEST_DIR/run/hotspot_schedule.last")" "on" && \
  assert_contains "$o1" "no transition" && \
  assert_contains "$o2" "ACTION: stop hotspot" && test_pass

test_start "schedule: first run never starts hotspot by itself"
seed true "08:00" "23:00" false
echo "PENDING" > "$HNC_TEST_DIR/run/hnc_state"
o=$(HNC_SCHED_NOW=12:00 run --dry-run)
assert_contains "$o" "first run: record only" && test_pass

test_start "schedule: invalid time is ignored (allowed)"
seed true "25:99" "xx" false
HNC_SCHED_NOW=03:00 run --check && test_pass || test_fail "invalid window must not lock hotspot off"
