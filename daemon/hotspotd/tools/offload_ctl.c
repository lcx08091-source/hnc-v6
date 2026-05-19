/* tools/offload_ctl.c — adapter 真机验证 CLI
 *
 * 不依赖 hotspotd / scheduler, 直接驱动 adapter 接口, 用于:
 *   1) v5.0 alpha.1 阶段的真机 sanity check
 *   2) 用户在 hotspotd 出问题时手动救援 (类似 v4.x 的 bpf_offload_disable)
 *   3) 上报 bug 时收集 status / errno 信息
 *
 * 用法:
 *   offload_ctl status
 *       打印当前 adapter 元数据 + status() 结果, 不修改任何状态
 *
 *   offload_ctl refresh
 *       触发 refresh_active() — 阻塞 5s 做 stats 双采样, 输出 active 判定
 *
 *   offload_ctl disable_upstream <ifname|ifindex>
 *       触发 disable_upstream — 写 limit=0
 *
 *   offload_ctl restore_upstream <ifname|ifindex>
 *       触发 restore_upstream — 写 limit=U64_MAX
 *
 *   offload_ctl disable_global
 *   offload_ctl restore_global
 *       全局开关 (遍历整个 limit_map)
 *
 *   offload_ctl probe
 *       只跑 platform_probe + adapter probe matrix, 不 init
 *
 *   offload_ctl self_check
 *       验证 adapter init + self_check 通过 (schema 兼容)
 *
 * 退出码:
 *   0       成功
 *   非 0    各 OFFLOAD_E* 错误码 (见 adapter.h)
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include "../platform.h"
#include "../offload/adapter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <net/if.h>

extern offload_adapter_t *g_adapters[];

/* 解析 ifname 或 ifindex → ifindex
 * 数字串 → atoi
 * 非数字 → if_nametoindex
 * 失败 → 返 0 */
static int parse_ifindex(const char *s)
{
    if (s == NULL || s[0] == '\0') return 0;
    int all_digit = 1;
    for (const char *p = s; *p; p++) {
        if (!isdigit((unsigned char)*p)) { all_digit = 0; break; }
    }
    if (all_digit) return atoi(s);
    unsigned int idx = if_nametoindex(s);
    return (int)idx;
}

static int do_probe(void)
{
    if (platform_probe() != 0) {
        fprintf(stderr, "platform_probe failed\n");
        return 1;
    }
    printf("Platform: vendor=%s rom=%s api=%d kernel=%s\n",
           platform_soc_vendor_str(g_platform.soc_vendor),
           platform_rom_str(g_platform.rom),
           g_platform.android_api,
           g_platform.kernel_release);
    printf("Offload presence: bpf=%d mtk_ppe=%d nss=%d bpf_syscall_ok=%d\n",
           g_platform.has_bpf_tethering,
           g_platform.has_mtk_ppe,
           g_platform.has_samsung_nss,
           g_platform.bpf_syscall_ok);

    printf("\nAdapter probe matrix:\n");
    for (int i = 0; g_adapters[i] != NULL; i++) {
        offload_adapter_t *a = g_adapters[i];
        int rc = a->probe ? a->probe() : -1;
        printf("  [%d] %-8s type=%-10s gran=%-12s probe=%s\n",
               i, a->name,
               offload_type_str(a->type),
               offload_gran_str(a->granularity),
               rc == 0 ? "MATCH" : "no");
    }

    offload_adapter_t *sel = offload_select_adapter();
    printf("\nSelected: %s\n", sel ? sel->name : "(none)");
    return 0;
}

/* 公共预备: probe + select + init (失败立刻退出) */
static offload_adapter_t *prep_adapter(void)
{
    if (platform_probe() != 0) {
        fprintf(stderr, "platform_probe failed\n");
        exit(1);
    }
    offload_adapter_t *a = offload_select_adapter();
    if (a == NULL) {
        fprintf(stderr, "no adapter selected\n");
        exit(1);
    }
    offload_err_t e = a->init();
    if (e != OFFLOAD_OK) {
        fprintf(stderr, "adapter %s init failed: %s\n", a->name, offload_err_str(e));
        exit(e);
    }
    return a;
}

static int do_self_check(void)
{
    offload_adapter_t *a = prep_adapter();
    offload_err_t e = a->self_check ? a->self_check() : OFFLOAD_OK;
    printf("self_check: adapter=%s result=%s\n", a->name, offload_err_str(e));
    a->shutdown();
    return (int)e;
}

static int do_status(void)
{
    offload_adapter_t *a = prep_adapter();

    offload_status_t st;
    memset(&st, 0, sizeof(st));
    if (a->status) a->status(&st);

    printf("Adapter\n");
    printf("  name           : %s\n", a->name);
    printf("  type           : %s\n", offload_type_str(a->type));
    printf("  granularity    : %s\n", offload_gran_str(a->granularity));
    printf("\n");
    printf("Status (cached, last refresh %ld)\n", (long)st.last_refresh_ts);
    printf("  active         : %s\n", st.active ? "yes" : "no");
    printf("  delta_bytes    : %llu\n",
           (unsigned long long)st.last_delta_bytes);
    printf("  global_disable : %s\n", st.globally_disabled ? "yes" : "no");
    printf("  per-upstream disable count : %d\n", st.disabled_upstream_count);
    for (int i = 0; i < st.disabled_upstream_count; i++) {
        char name[IFNAMSIZ] = {0};
        if (if_indextoname((unsigned int)st.disabled_upstream_ifindex[i], name) == NULL)
            snprintf(name, sizeof(name), "?");
        printf("    [%d] ifindex=%d (%s)\n",
               i, st.disabled_upstream_ifindex[i], name);
    }

    a->shutdown();
    return 0;
}

static int do_refresh(void)
{
    offload_adapter_t *a = prep_adapter();
    if (a->refresh_active == NULL) {
        fprintf(stderr, "adapter %s: refresh_active not implemented\n", a->name);
        a->shutdown();
        return 1;
    }
    fprintf(stderr, "[ctl] refreshing (will block ~5s)...\n");
    offload_err_t e = a->refresh_active();
    if (e != OFFLOAD_OK) {
        fprintf(stderr, "refresh_active: %s\n", offload_err_str(e));
        a->shutdown();
        return (int)e;
    }
    /* 跑完后立刻 status 看新值 */
    offload_status_t st;
    memset(&st, 0, sizeof(st));
    a->status(&st);
    printf("active=%d delta_bytes=%llu refresh_ts=%ld\n",
           st.active,
           (unsigned long long)st.last_delta_bytes,
           (long)st.last_refresh_ts);
    a->shutdown();
    return 0;
}

static int do_disable_upstream(const char *arg)
{
    int ifindex = parse_ifindex(arg);
    if (ifindex <= 0) {
        fprintf(stderr, "invalid ifname/ifindex: %s\n", arg);
        return OFFLOAD_EINVAL;
    }
    offload_adapter_t *a = prep_adapter();
    if (a->granularity < OFFLOAD_GRAN_PER_UPSTREAM ||
        a->disable_upstream == NULL) {
        fprintf(stderr, "adapter %s does not support per-upstream disable\n", a->name);
        a->shutdown();
        return OFFLOAD_ENOTSUP;
    }
    offload_err_t e = a->disable_upstream(ifindex);
    printf("disable_upstream(%d): %s\n", ifindex, offload_err_str(e));
    a->shutdown();
    return (int)e;
}

static int do_restore_upstream(const char *arg)
{
    int ifindex = parse_ifindex(arg);
    if (ifindex <= 0) {
        fprintf(stderr, "invalid ifname/ifindex: %s\n", arg);
        return OFFLOAD_EINVAL;
    }
    offload_adapter_t *a = prep_adapter();
    if (a->restore_upstream == NULL) {
        fprintf(stderr, "adapter %s does not support per-upstream restore\n", a->name);
        a->shutdown();
        return OFFLOAD_ENOTSUP;
    }
    offload_err_t e = a->restore_upstream(ifindex);
    printf("restore_upstream(%d): %s\n", ifindex, offload_err_str(e));
    a->shutdown();
    return (int)e;
}

static int do_disable_global(void)
{
    offload_adapter_t *a = prep_adapter();
    if (a->disable_global == NULL) {
        fprintf(stderr, "adapter %s does not support global disable\n", a->name);
        a->shutdown();
        return OFFLOAD_ENOTSUP;
    }
    offload_err_t e = a->disable_global();
    printf("disable_global: %s\n", offload_err_str(e));
    a->shutdown();
    return (int)e;
}

static int do_restore_global(void)
{
    offload_adapter_t *a = prep_adapter();
    if (a->restore_global == NULL) {
        fprintf(stderr, "adapter %s does not support global restore\n", a->name);
        a->shutdown();
        return OFFLOAD_ENOTSUP;
    }
    offload_err_t e = a->restore_global();
    printf("restore_global: %s\n", offload_err_str(e));
    a->shutdown();
    return (int)e;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s <command> [args]\n"
        "\n"
        "commands:\n"
        "  probe                              show platform + adapter matrix\n"
        "  self_check                         verify adapter schema\n"
        "  status                             show adapter status (cached)\n"
        "  refresh                            run refresh_active (blocks 5s)\n"
        "  disable_upstream <ifname|ifindex>  write limit=0\n"
        "  restore_upstream <ifname|ifindex>  write limit=U64_MAX\n"
        "  disable_global                     write 0 to all entries\n"
        "  restore_global                     write U64_MAX to all entries\n"
        "\n"
        "exit codes:\n"
        "  0   OK\n"
        "  1   ENOTSUP\n"
        "  2   EPERM\n"
        "  3   EINVAL\n"
        "  4   ENOENT\n"
        "  5   EAGAIN\n"
        "  99  EINTERNAL\n",
        prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(argv[0]); return 1; }

    const char *cmd = argv[1];

    if (strcmp(cmd, "probe") == 0)            return do_probe();
    if (strcmp(cmd, "self_check") == 0)       return do_self_check();
    if (strcmp(cmd, "status") == 0)           return do_status();
    if (strcmp(cmd, "refresh") == 0)          return do_refresh();
    if (strcmp(cmd, "disable_global") == 0)   return do_disable_global();
    if (strcmp(cmd, "restore_global") == 0)   return do_restore_global();

    if (strcmp(cmd, "disable_upstream") == 0) {
        if (argc < 3) { usage(argv[0]); return OFFLOAD_EINVAL; }
        return do_disable_upstream(argv[2]);
    }
    if (strcmp(cmd, "restore_upstream") == 0) {
        if (argc < 3) { usage(argv[0]); return OFFLOAD_EINVAL; }
        return do_restore_upstream(argv[2]);
    }

    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        usage(argv[0]);
        return 0;
    }

    fprintf(stderr, "unknown command: %s\n\n", cmd);
    usage(argv[0]);
    return 1;
}
