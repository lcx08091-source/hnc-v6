# HNC hotspotd

v5.33 起 hotspotd 只剩两件事(设备发现只有 Go 看门狗一份,C 版发现代码已删):

1. **硬件加速兜底** —— offload 调度(`scheduler.c` / `upstream.c` / `platform.c`)与 BPF
   适配器(`offload/`)。netlink 只订阅链路事件(`RTMGRP_LINK`):换网(WiFi↔4G、VPN 上下线)
   时即时请求重探主上游。
2. **控制接口** `run/hotspotd.sock`(0600,root):

   | 命令 | 作用 |
   |---|---|
   | `GET_DEVICES` | 原样回 `data/devices.json`(看门狗写的) |
   | `REFRESH` | touch `run/devices.refresh`,看门狗的设备发现写者立刻全量扫一次(`SIGUSR1` 同) |
   | `STATUS` | `running:1 devices:N pid:P`(N 数 `devices.json`) |
   | `OFFLOAD_NOTIFY_LIMIT <mac> <0\|1>` / `OFFLOAD_REFRESH` / `OFFLOAD_STATUS` / `OFFLOAD_DISABLE_GLOBAL` / `OFFLOAD_RESTORE_GLOBAL` | offload 调度器 |
   | `QUIT` | 退出 |

   旧参数 `--no-discovery`(v5.31–v5.32)照收、无作用。

v5.33 之前的设备发现(邻居表事件 + ARP 全量扫、DHCP / mDNS 名字解析、mDNS worker、
`hostname_cache.c` / `oui_override.c` / `mdns_worker.c`、写 `devices.json`)整块删除,
对应能力在 `src/dpid/devscan` / `src/dpid/devname` 与看门狗 `m4_owner.go`。

## 构建

CI(`.github/workflows/build.yml`)每次用 NDK 从源码编(arm64 + armv7,链接 libbpf 静态库)。本地:

```bash
export ANDROID_NDK=/path/to/android-ndk-r27c
bash build.sh arm64          # 或 arm
```

只验逻辑时可以用本机 gcc 编(不带 BPF 适配器,offload 走 null 适配器),见
`test/sim/simnet.sh` 的 `hotspotd start`。

## 测试

- `test/test_hotspotd_ipc.c`:`#define HNC_TEST_MODE` 后 include `hotspotd.c`,测真实的
  `handle_client` / `nl_process` / `count_devices_in_file_at`(接进
  `test/unit/test_v533_hotspotd_ipc_c.sh`,本机没有 cc 时跳过)。
- `test/test_mdns_parse.c`:`mdns_resolve`(独立二进制,Go 名字解析调用它)的响应解析。
