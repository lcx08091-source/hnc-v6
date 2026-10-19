# A8 审查记录：hnc_watchdog 与 dpid 支撑包

基线：v5.33.0-rc2

## 范围

- `src/dpid/cmd/hnc_watchdog/` 下全部非测试文件：actionstats、app_qos、budget、duties、m4_owner、m5、main、native、offload_sched、online_minutes、power
- `src/dpid/` 下：devscan、neigh、nlroute（netlink 解析）、procfind、devname（含 oui_table.txt 加载）、ifacehint、clockhwm、tzlocal、activity、hostname

## 已审文件

## Bug

