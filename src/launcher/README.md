# HNC Launcher (C)

`hnc_launcher` 和 `fork_probe` 是 HNC v5.3.0 引入的 C 程序,替代之前的 Go `hnc_dpid_supervisor`。

## 为什么用 C

ColorOS 16 + SukiSU 内核组合上,Go runtime 的 `fork+execv` 路径(`CLONE_VM|CLONE_VFORK`)会被某条内核策略拦下报 EPERM。但同环境下标准 C `fork() + execv()` **100% 工作**。

测试矩阵(2026-05 Realme RMX5010):

| 启动器 | ColorOS 16 + SukiSU | 普通 Android 11+ |
|---|---|---|
| Go `hnc_dpid_supervisor` | FAIL (EPERM) | OK |
| Shell `hnc_dpid_guard.sh` | OK | OK |
| **C `hnc_launcher`** | **OK** | OK |

C launcher 在所有环境都能工作,所以现在是首选。v5.33 起 shell guard 与 Go supervisor
都已删除: C launcher 不能用时走 direct(Go 看门狗直接盯 `hnc_dpid`,见
`src/dpid/cmd/hnc_watchdog/m5.go`)。

## 两个程序的关系

```
service.sh 启动序:
    1. fork_probe /system/bin/true   <- 探测 C fork+execv 行不行
       └─ exit 0 -> 走 C launcher
       └─ exit !=0 -> direct(看门狗直接盯 hnc_dpid)

    2. exec hnc_launcher               <- 长期运行, 守护 hnc_dpid
       └─ fork hnc_dpid
       └─ dpid 死了 -> 退避重启
       └─ 60s 内挂 5 次 -> 写 run/dpid.crashflag, 120s 冷却自愈后清标志恢复
```

`fork_probe` 是一次性诊断工具,跑完就退。`hnc_launcher` 是长期 daemon。

## 文件清单

- **`fork_probe.c`** (~150 行) — 探针。fork + execv + waitpid,完整报告每一步成功/失败
- **`hnc_launcher.c`** (~380 行) — daemon。fork dpid + 信号处理 + crash loop 冷却自愈 + 单实例锁
- **`build.sh`** — NDK / host 编译脚本(自动从 `../../module.prop` 注入 `-DHNC_VERSION`)

## 编译

```bash
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/26.1.10909125
sh ./build.sh           # 编到当前目录
sh ./build.sh install   # 编完拷贝到 ../../bin/
```

需要 NDK r23+(任何含 API 24 sysroot 的版本都行)。

## hnc_launcher 关键行为

### 启动

```sh
nohup /data/local/hnc/bin/hnc_launcher >> /data/local/hnc/logs/dpid_launcher.log 2>&1 &
```

启动后:
1. 检查 `dpid_guard.pid`,如果有别的 launcher 在跑则直接退
2. 检查 `run/dpid.crashflag` 中最近 60s 内有效崩溃时间戳行数,达到 5 次则先冷却 120s 并清除标志(单行 armed 标记不触发误罚站)
3. fork 出 `hnc_dpid`,写 pid 文件,进入监督循环

### Crash loop 冷却自愈

- 滑动窗口 60 秒(`CRASH_WINDOW_SEC`)
- 窗口内累计 5 次崩溃或 `fork` 失败 -> 追加时间戳至 `run/dpid.crashflag` -> 进入 120 秒冷却自愈(`cooldown_sleep(120)`)
- 冷却结束后自动 `unlink` 清除 `run/dpid.crashflag`、重置计数与退避并恢复拉起 `hnc_dpid`

### 信号

- SIGTERM/SIGINT/SIGHUP -> 优雅退出。如果 dpid 子进程还在,向它 SIGTERM 然后 waitpid
- SIGCHLD -> 不在 handler 里 reap,留给主循环的 `waitpid()` 阻塞返回
- SIGPIPE -> 忽略(写日志文件磁盘满时不至于挂)

### 退出码

| code | 含义 |
|---|---|
| 0 | 正常退出(dpid rc=0,或收到 SIGTERM) |
| 1 | 单实例检测失败或致命初始化错误 |
| 2 | 命令行参数错 |

## fork_probe 用法

```bash
fork_probe /system/bin/true
fork_probe /system/bin/id
```

输出形如:

```
=== fork_probe v1 ===
self pid=12345
target=/system/bin/true
[1/3] calling fork()...
  fork OK, child pid=12346
[2/3] calling execv(/system/bin/true)...
  fork OK, in child (pid=12346, ppid=12345)
[3/3] waiting for child...
  child exited 0  SUCCESS!
=== RESULT: C fork+execv WORKS on this device ===
```

`./service.sh` 只看 exit code,不看 stdout。

## 调试

```bash
# 看 launcher 日志
tail -f /data/local/hnc/logs/dpid_launcher.log

# 查看近期崩溃计数标志
cat /data/local/hnc/run/dpid.crashflag

# 手动清理标志并重启 launcher
rm -f /data/local/hnc/run/dpid.crashflag
killall hnc_launcher  # ./service.sh sentinel 会自动重启
```

## 编译要求

- Android NDK r23+(用到的 API 都很基础,任何版本都行)
- API level 24+(Android 7.0+)
- 动态 PIE 链接(`-fPIE -pie`,**不是** `-static`)

**rc30.12.34 文档修正**:本文件之前写 "静态链接(`-static`)",这是
v5.2 时期的实情。rc30.12.28 三修之后改用普通 PIE 动态链接 — 因为
NDK 的 Bionic libc 静态链接时会出现 TLS segment underaligned 问题,导致
launcher 在某些 KSU 版本上启动失败。`./build.sh` 自己的注释已经写清楚这段
历史,但本 README 没跟。本版同步。

动态链接的可靠性来源:`/system/lib64/` 在 post-fs-data 阶段早已 mount,
这是 Android 启动流程的硬保证,launcher 启动时不会找不到 libc。
之前 README 担心的 "/system/lib64 未 mount 完" 是不存在的问题。

`fork_probe` 一直是动态链接,这个没变。

## 版本

`hnc_launcher`: `0.1.0-<HNC_VERSION>` (由 `./build.sh` 从 `module.prop` 自动注入 `-DHNC_VERSION`,支持 `--version`)
`fork_probe`: 0.1.0 (稳定不动)

`0.1.0-` 引擎前缀稳定保留,后缀随 HNC 模块版本同步对齐。

## License

同 HNC 主项目(待 Ling 选型,见仓库根 `LICENSE.TODO`)。
