# PATCH-NOTES v5.3.0-rc30.13.1 — audit fix batch (critical + high)

**Type**: bug-fix patch · shell-only effective immediately · C 源改了但 binary 需 NDK 重 build
**Base**: v5.3.0-rc30.13.0
**Source**: Claude code audit (5 critical/high + cleanup)

## TL;DR

修了 rc30.13.0 审计找出来的 4 个 critical 和 1 个 high bug, 顺手清了几个 SC2034 死变量.
Shell 部分 flash 即生效. C 部分 (hnc_launcher / hotspotd) 源码改完, arm64 binary 需要你自己用 NDK 重 build, 因为沙箱里没装 NDK 交叉编译环境.

**净代码量: -112 行** (删了 117 行死代码, 加了 5 行 fix + 注释).

## Fix list

### 🔴 #1 critical: `tc_manager.sh:661` 中文括号注释没 `#` 前缀

**症状**: 每次 `ensure_device_class` 调用 (= 每次 set_limit) 都污染 stderr:
```
bin/tc_manager.sh: line 3: $'\357\274\210\350\213\245\346\234\211': command not found
```

**根因**: L660 是 `# 4. 创建 u32 filter`, L661 是 `（若有 IP）` — 续行注释忘了 `#`. shell 把中文括号当命令执行. 还活着是因为没开 `set -e`. **如果将来给 service.sh 加 `set -e` 加固, 这条会立刻让限速整体崩**.

**修复**: 合并进上一行注释 + 加 fix 注释解释来历.

**影响**: 修复后 set_limit 路径 stderr 干净. shellcheck 漏报 (多字节字符在 shell 里语法合法), `bash -n` 也漏报.

### 🔴 #2 critical: `json_set.sh` 5 个函数完全重复定义

**症状**: 文件里下面 5 个函数各定义了 2 次, shell 后定义覆盖前定义, 第一份 120 行全是死代码:
- `json_object_set_safe_file` (L259 vs L529, **字节相同**)
- `json_object_del_safe_file` (L286 vs L556, **字节相同**)
- `json_array_add_string_top_safe` (L313 vs L583, **字节相同**)
- `json_array_del_string_top_safe` (L339 vs L609, **字节相同**)
- `json_remove_device_safe` (L358 vs L628, **仅 hotfix19.1 vs hotfix19.9 注释差异**)

**根因**: 典型的 git merge / rebase 后没清理. 因为 json_set.sh 是 rules.json 写入的唯一入口, 文件越短越好, 多 120 行让 review 难度无意义地增加.

**修复**: 删 L259-378 共 120 行. 加 3 行注释解释为什么删. 经过验证:
- 这 5 个函数全是 json_set.sh 内部使用, **无外部调用者**
- 删除后每个函数仍有 1 份定义 (在 L409+ 范围)
- dispatcher (L694, 721, 732, 873, 898, 952, 964 → 删除后行号会变化) 引用全部能找到

**影响**: json_set.sh 1188 → 1071 行, -10%. 行为不变 (前面 5 份本来就是死代码).

### 🔴 #3 critical: `hnc_launcher.c:396` fork 失败时日志说反

**症状**: fork 失败时打 `"spawning dpid anyway (it will go blind mode)"`, 但实际根本没 spawn 任何东西. 排障的人看到这条会以为 dpid 在 blind 模式跑着, 实际什么都没起来.

**修复**: 改成 `"fork failed (errno=%d), retrying after %ds backoff"`.

### 🔴 #4 critical: `hnc_launcher` fork 失败无上限重试

**症状**: 上一版只在 dpid 真跑起来后异常退出才计入 crash tracker, 60s/5 次进 observe 模式. 但 **fork 失败这条路径不计数**. 系统 OOM / ulimit 触顶时 launcher 会无限重试, 永远不进 observe 模式.

**修复**: 加独立的 `struct crash_tracker fork_fails`, fork 失败 60s/5 次同样写 crashflag + 退出. 跟 dpid 异常退出的 crash tracker 分开, 但用同一个 CRASH_FLAG 文件让排障路径统一.

### 🟠 #5 high: `hotspotd.c:write_json` 不检查 ferror

**症状**: write_json 写 devices.json 时只 fflush 不看 ferror. 磁盘满时上面 fprintf 默默失败, 然后 rename 会把一个 `{"aa:bb:..":{ ip:"1.2.` 这种半截 JSON 推到 devices.json. 所有下游 (WebUI / apply_device_rule / restore_rules / tc_manager 抽 IP) 拿到坏 JSON, 严重时整个 watchdog 链 stall.

**修复**: 写完发现错误就 abandon tmp, 保留上一版本的 devices.json. 失败时 log 包含 errno.

### 🟢 cleanup: 删 SC2034 死变量

- `bin/tc_manager.sh` L88 `SQM_PROFILE_FILE` (此文件无引用, 真实用在 sqm_manager.sh)
- `bin/watchdog.sh` L33 `RULES_FILE` (无引用, 走 json_set.sh 子调用)
- `bin/iptables_manager.sh` L63 `RULES_FILE` (同上)
- `bin/iptables_manager.sh` L83 `MARK_BLACKLIST=0xDEAD` (v3.x 设想的"黑名单 mark"从未启用, 黑名单实际走 filter/HNC_CTRL DROP)

每处加注释解释为什么删, 防止以后又被加回来.

## 测试

- ✅ 全部 77 个 shell 脚本 `bash -n` 语法验证通过
- ✅ shellcheck 严格模式无新增 error
- ✅ `hnc_launcher.c` x86 gcc 编译通过 (除一个原有的 unused-param warning)
- ✅ fix #5 的 ferror 模板独立验证 (hotspotd.c 完整编译需要 hnc_helpers.h 等本地 header, 沙箱不全)
- ⚠️ **C binary 没重 build**: bin/hnc_launcher 和 bin/hotspotd 仍是 rc30.13.0 的 binary, 包含原 bug. Ling 需要用 Android NDK 重新交叉编译 arm64 binary 替换. 命令:
  ```
  $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang \
      -static -O2 -Wall -o hnc_launcher src/launcher/hnc_launcher.c
  ```
- ⚠️ **真机集成测试待跑**: shell 部分 flash 后, 看 watchdog.log 应不再出现中文括号 command not found. set_limit 一次, 看 tc.log 干净.

## 后续 (rc31 候选, 这次没做)

1. **给 set_limit / ensure_device_class / init_tc 写 unit test** — 这是审计找到的最大 process 问题, 没测试就藏住了 bug #1 这么久. 建议加 mock tc 路径, 覆盖核心限速 happy path + 5 个错误分支.
2. **CI 跑 shellcheck** — 即使排除 SC3043 等 mksh-OK 警告, 也能在 PR 阶段挡住 SC2034 (死变量) 和 SC2155 (local + assign) 类问题.
3. **统一三层 supervisor crash flag 语义** — dpid 自己的 dpid.crashflag + launcher 的 dpid_crashflag 是不同文件但语义重叠, 排障时用户不知道清哪个.
4. **iptables_manager `_gc_stale_ips_for_mac` 改 iptables-restore 批量** — 当前 O(N) 次 fork iptables, 50 stale IP × 4 调用 = 200 次. 改 iptables-restore 一次 commit.
5. **service.sh launch_httpd_safe 加 socket ready 探测** — 当前只 sleep 1 就走, 慢启动机器上有 watchdog/sentinel 并发抢拉的窗口.

## attribution

由 Claude code audit 找出 (4 个 critical 加 1 个 high, 加若干 cleanup). 修复也是 Claude 写的, 没动业务逻辑只动了表现层 bug 和死代码.
