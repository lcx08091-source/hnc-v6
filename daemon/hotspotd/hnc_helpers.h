/* hnc_helpers.h — HNC shared C helpers
 *
 * v3.6 Commit 2:把 hotspotd.c 里的纯 helper 函数提取到这个文件,
 * 主代码和测试都 #include,彻底消除 v3.5.1 P1-3 和 v3.5.2 P1-A 的复制 drift。
 * v5.33: C 版设备发现删除后(只留 Go 版), 只剩 offload 代码(platform.c /
 * upstream.c)用的 json_escape 与 run_cmd_timeout。
 *
 * 设计原则:
 *   1) 所有函数都是纯函数或只依赖传入的参数/文件路径
 *   2) 不依赖 hotspotd.c 的全局状态(g_devs / g_log 等)
 *   3) 不依赖 hotspotd.c 的 macro 定义(DEVICE_NAMES_JSON 等),路径由调用方传入
 *   4) 测试代码可以直接 #include 这个头文件,link hnc_helpers.o,跟主代码跑同一个实现
 */

#ifndef HNC_HELPERS_H
#define HNC_HELPERS_H

#include <stddef.h>
#include <time.h>

/* ══════════════════════════════════════════════════════════
 * json_escape — JSON 字符串转义
 *
 * 转义 " \ \n \r \t 和 0x00-0x1f 控制字符。
 * 非 ASCII 字节(UTF-8 多字节)原样保留。
 * 如果 dst_size 不够,会回退到最近完整 UTF-8 字符边界(不留残缺 continuation)。
 * 输出始终 NUL-terminated。
 * ══════════════════════════════════════════════════════════ */
void hnc_json_escape(const char *src, char *dst, size_t dst_size);

/* ══════════════════════════════════════════════════════════
 * hnc_run_cmd_timeout — 带总超时的子进程执行 (v5.9.0)
 *
 * fork + execvp 运行 argv,捕获 stdout 到 buf(NUL 终结),子进程 stderr
 * 重定向 /dev/null。总超时 timeout_ms(必须 >0),超时 SIGKILL 子进程,
 * 已读到的部分输出保留返回。waitpid 带 EINTR 重试循环。
 *
 * 骨架提取自(已删的)hotspotd.c try_ns_dhcp_resolve 的 fork+select+SIGKILL
 * 模式, 并补上 waitpid EINTR 循环。诞生动机:upstream.c Tier1 的
 * popen("ip route get …") 没有超时 —— ip 被 ROM 挂起时会把调用线程永久拖死。
 *
 * 返回:>=0 读到的字节数(超时/截断也算成功返回,调用方按内容判断);
 *       -1 参数非法或 pipe/fork 失败。
 * ══════════════════════════════════════════════════════════ */
int hnc_run_cmd_timeout(char *const argv[], char *buf, size_t cap, int timeout_ms);

#endif /* HNC_HELPERS_H */
