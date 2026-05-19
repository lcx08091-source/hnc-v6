# HNC hotspotd · rc3.1.15 源码

netlink RTGRP_NEIGH 事件驱动的设备发现 daemon，HNC v3.5+ 起默认启用。

## 本次改动 (rc3.1.15)

第三方 AI review 发现的三项防御深度问题（不是真实可利用漏洞，但代码风格统一 + 防御深度）：

| 文件 | 改动 | 修法 |
|---|---|---|
| `hotspotd.c` | `try_mdns_resolve` popen → fork+execlp + ip 防御性验证 | 跟 dumpsys 路径风格统一，未来引入第三方 ip 来源也不变 RCE |
| `hotspotd.c` | `update_traffic_stats` popen → fork+execlp | 同上风格统一 |
| `hostname_cache.c` | 反 escape 加 `\uXXXX` BMP 解析 | 写入 (`hnc_json_escape`) 和读出对称，control char 不再变成 6 字符字面量 |

## GitHub Actions 自动构建

push 到 main/master 或手动从 Actions 页面 dispatch 即可触发构建。NDK r26d，目标 Android API 21+，arm64-v8a。

构建产物：
- 每次 push: artifact `hotspotd-arm64`（保留 30 天，从 Actions Run 页面下载）
- 打 tag (`git tag rc3.1.15 && git push --tags`): 自动发 GitHub Release

要本地构建：

```bash
export ANDROID_NDK=/path/to/android-ndk-r26d
bash build.sh arm64
# 输出: prebuilt/arm64/hotspotd
```

## 装到 HNC 模块

```bash
# 把 GitHub Release 下载的 hotspotd-arm64 推到设备
adb push hotspotd-arm64 /sdcard/hotspotd
adb shell su -c 'cp /sdcard/hotspotd /data/adb/modules/hotspot_network_control/bin/hotspotd && chmod 755 /data/adb/modules/hotspot_network_control/bin/hotspotd'
# 重启服务
adb shell su -c 'sh /data/adb/modules/hotspot_network_control/service.sh restart'
# 真机验证不崩溃
adb shell su -c 'tail -f /data/local/hnc/logs/service.log'
```

## 真机长跑验证

C 改动比 Go/shell 风险高，建议改完装机后跑 24+h 看：

- `/data/local/hnc/logs/service.log` 没有 `C daemon hotspotd` 反复重启
- `/data/local/hnc/data/devices.json` mtime 持续更新（设备能被发现）
- `/data/local/hnc/data/hostname_cache.json` 内容正常（hostname 解析稳）
- 无 OOM 痕迹（`logcat -d | grep -i 'lowmem\|killed'`）

## 历史 (rc3.1.x 系列)

主仓库已经迭代到 rc3.1.14。hotspotd C 部分跟主仓库 daemon/ 目录同步，但因为 NDK 编译需要独立工作流，分这个 repo 单独管。
