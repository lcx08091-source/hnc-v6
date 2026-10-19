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
