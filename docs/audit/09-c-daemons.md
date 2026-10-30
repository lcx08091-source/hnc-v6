# A9 审查记录：C 守护进程 / 工具 / BPF

- 基线版本：v5.33.0-rc2
- 审查员前缀：A9
- 范围：
  - `daemon/hotspotd/`：hotspotd.c、mdns_resolve.c、platform.c/.h、scheduler.c/.h、upstream.c/.h、hnc_helpers.c/.h、offload/*.c/.h、tools/*.c、build.sh
  - `src/launcher/`：hnc_launcher.c、fork_probe.c、build.sh
  - `daemon/clsact_ctl/`：main.c、build.sh
  - `daemon/tc_netlink/`：hnc_tc_ingress.c、build.sh
  - `src/dpid/bpf/hnc_clsact.bpf.c`
- 重点：缓冲区越界 / off-by-one / strncpy 不补 '\0' / snprintf 截断、整数溢出、有符号无符号比较；netlink 遍历长度校验；mDNS 压缩指针；unix socket 控制接口（权限、对端校验、请求长度、命令解析）；fork/exec/waitpid、信号处理、O_CLOEXEC；pidfile 竞争；重启退避；32 位时间溢出；错误路径资源释放；BPF 边界检查
- 只记录、不改代码

## 已审文件

## Bug

### A9-001 [P2][确认] platform.c `prop_exists` 用 8 字节栈缓冲接 `__system_property_get`，属性值 ≥8 字符即栈溢出，hotspotd 启动即崩
- **位置**：`daemon/hotspotd/platform.c:79-83`（`prop_exists`），调用点 `daemon/hotspotd/platform.c:187-201`（`classify_rom`）；同类：`platform.c:86-92` `prop_get_int` 用 `buf[32]`
- **触发 / 现象**：`hnc_scheduler_init()` → `platform_probe()` → `classify_rom()` 依次 `prop_exists("ro.build.version.oplusrom")`、`"ro.build.version.magic"`、`"ro.build.version.emui"` 等。bionic 的 `__system_property_get` 按值长度 `memcpy(len+1)` 写入，契约要求缓冲 ≥ `PROP_VALUE_MAX`(92)。荣耀 MagicOS（`ro.build.version.magic`≈`MagicOS_9.0.0`，14 字节）、华为 EMUI（`ro.build.version.emui`≈`EmotionUI_14.2.0`，17 字节）等非 ColorOS ROM 上写穿 `buf[8]`；ColorOS 的 `V16.0.0` 恰好 8 字节（含 NUL）侥幸不溢出，版本串再长一位也会溢出。NDK 默认 `-fstack-protector-strong` → `__stack_chk_fail` abort，hotspotd 每次启动在 init 阶段崩溃，看门狗反复拉起。已用 ASAN + 模拟 bionic 语义的 `__system_property_get` 复现：`WRITE of size 14 ... in prop_exists platform.c:82`。
- **原因**：
  ```c
  static int prop_exists(const char *name)
  {
      char buf[8];
      return __system_property_get(name, buf) > 0;
  }
  ```
- **建议修复**：`prop_exists` / `prop_get_int` 的缓冲统一改为 `char buf[PROP_VALUE_MAX]`（或改用 `__system_property_find(name) != NULL` 判存在）。

### A9-002 [P2][确认] OFFLOAD_STATUS 序列化按未截断的 `disabled_upstream_count` 读 8 元素数组，越界读栈
- **位置**：`daemon/hotspotd/scheduler.c:942-946`（`hnc_scheduler_summary_to_json`）；来源 `daemon/hotspotd/offload/adapter_bpf.c:461`、`daemon/hotspotd/scheduler.c:905`
- **触发 / 现象**：adapter_bpf 的已禁用集合上限是 `MAX_DISABLED_UPSTREAMS=32`，`bpf_disable_global` 会把 limit_map 的每个 key 都 `disabled_set_add`，PER_UPSTREAM 模式下每次上游切换（VPN 重连换 ifindex、WiFi↔蜂窝）也只加不减（restore 只走 restore_global）。集合超过 8 个后，`bpf_status` 只拷 8 个元素但 `disabled_upstream_count` 原样给出 9..32，`get_summary` 同样只截断拷贝不截断计数；`summary_to_json` 循环 `i < s->disabled_upstream_count` 读 `disabled_upstream_ifindex[8..31]`：先读到结构体后续字段，20 以后读出 `handle_client` 栈上 `summ` 之外的内存，作为整数吐进 OFFLOAD_STATUS JSON（数据错误 + 栈内容泄露给调用方）。UBSan：`scheduler.c:945: index 8 out of bounds for type 'int [8]'`；count=32 时 ASAN 报 `stack-buffer-overflow READ of size 4`。
- **原因**：
  ```c
  // adapter_bpf.c bpf_status
  out->disabled_upstream_count = s.disabled_upstream_count;   /* 最多 32, 未截断 */
  // scheduler.c summary_to_json
  for (int i = 0; i < s->disabled_upstream_count && p < end; i++)
      written = snprintf(p, ..., "%s%d", i ? "," : "", s->disabled_upstream_ifindex[i]);
  ```
- **建议修复**：`summary_to_json` 的循环上界取 `min(count, 8)`（数组容量），或在 `bpf_status` / `get_summary` 里把计数一并截断（另设 `disabled_upstream_total` 表示真实总数）。

### A9-003 [P3][确认] nl_process 把剩余长度强转 unsigned 传给 NLMSG_OK，负长度防线失效，未对齐的末条消息导致越界读
- **位置**：`daemon/hotspotd/hotspotd.c:111`
- **触发 / 现象**：一个数据报里最后一条消息的 `nlmsg_len` 不是 4 的倍数且恰好等于剩余长度时，`NLMSG_NEXT` 按对齐长度扣减，`n` 变成 -1..-3；`(unsigned)n` 变成约 4G，`NLMSG_OK` 的 `len >= sizeof(nlmsghdr)` 检查通过，接着读 `buf` 之外的 `nlmsg_len`，若栈上垃圾恰好像合法头，还会按垃圾长度继续跳。用 socketpair 喂 8189 字节、`nlmsg_len=8189` 的报文，ASAN 报 `stack-buffer-overflow READ of size 4 ... nl_process hotspotd.c:111`。内核自己发的 RTM_*LINK 都是对齐的，伪造单播需要 CAP_NET_ADMIN（且代码没用 recvfrom 校验 `nl_pid==0`），所以实际只算健壮性缺陷。
- **原因**：
  ```c
  ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
  ...
  for (; NLMSG_OK(nlh, (unsigned)n); nlh = NLMSG_NEXT(nlh, n)) {
  ```
  宏里 `(len) >= (int)sizeof(struct nlmsghdr)` 本来靠有符号比较挡住负数，强转后变成无符号比较。
- **建议修复**：去掉 `(unsigned)` 强转，用 `int len = (int)n;` 传给 `NLMSG_OK/NLMSG_NEXT`；顺带用 `recvfrom` 校验来源 `nl_pid == 0`。
