/* tools/platform_probe.c — 独立诊断工具
 *
 * 在目标设备上跑一次, 输出 platform 探测结果。可作为:
 *   - v5.0 alpha.1 第一阶段的现场验证
 *   - 用户上报兼容性问题时的 sanity check
 *   - hnc_httpd /api/diag/platform 的 fallback (httpd 没起来时)
 *
 * 用法:
 *   ./platform_probe              # JSON 单行
 *   ./platform_probe --pretty     # 人读多行
 *
 * 编译:
 *   见 ../build.sh, 走 build_platform_probe 分支
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include "../platform.h"
#include "../offload/adapter.h"

#include <stdio.h>
#include <string.h>

extern offload_adapter_t *g_adapters[];

static void print_pretty(void)
{
    printf("=== HNC v5.0 Platform Probe ===\n\n");

    printf("SoC\n");
    printf("  vendor    : %s\n", platform_soc_vendor_str(g_platform.soc_vendor));
    printf("  raw       : %s\n", g_platform.soc_vendor_raw);
    printf("  model     : %s\n", g_platform.soc_model);
    printf("  hardware  : %s\n", g_platform.soc_hardware);
    printf("\n");

    printf("Android\n");
    printf("  api       : %d\n", g_platform.android_api);
    printf("  release   : %s\n", g_platform.android_release);
    printf("\n");

    printf("ROM\n");
    printf("  id        : %s\n", platform_rom_str(g_platform.rom));
    printf("  name      : %s\n", g_platform.rom_name);
    printf("  version   : %s\n", g_platform.rom_version);
    printf("\n");

    printf("Kernel\n");
    printf("  release   : %s\n", g_platform.kernel_release);
    printf("  parsed    : %d.%d.%d\n",
           g_platform.kernel_major,
           g_platform.kernel_minor,
           g_platform.kernel_patch);
    printf("\n");

    printf("Offload subsystems\n");
    printf("  bpf_tethering         : %s\n", g_platform.has_bpf_tethering ? "yes" : "no");
    printf("  bpf_tethering_partial : %s\n", g_platform.has_bpf_tethering_partial ? "yes" : "no");
    printf("  mtk_ppe               : %s\n", g_platform.has_mtk_ppe ? "yes" : "no");
    printf("  samsung_nss           : %s\n", g_platform.has_samsung_nss ? "yes" : "no");
    printf("  bpf_syscall_ok        : %s\n", g_platform.bpf_syscall_ok ? "yes" : "no");
    printf("\n");

    printf("APEX\n");
    if (g_platform.apex_connectivity_version == -1)
        printf("  connectivity : present (version not parsed)\n");
    else if (g_platform.apex_connectivity_version == 0)
        printf("  connectivity : absent\n");
    else
        printf("  connectivity : v%d\n", g_platform.apex_connectivity_version);
    printf("\n");

    printf("Adapter selection\n");
    offload_adapter_t *a = offload_select_adapter();
    if (a) {
        printf("  selected : %s (type=%s gran=%s)\n",
               a->name,
               offload_type_str(a->type),
               offload_gran_str(a->granularity));
    } else {
        printf("  selected : <none>\n");
    }
    printf("\n");

    printf("Adapter probe matrix\n");
    for (int i = 0; g_adapters[i] != NULL; i++) {
        offload_adapter_t *ad = g_adapters[i];
        int rc = ad->probe ? ad->probe() : -1;
        printf("  [%d] %-8s probe=%s\n",
               i, ad->name,
               rc == 0 ? "MATCH" : "no");
    }
}

int main(int argc, char **argv)
{
    int pretty = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pretty") == 0 ||
            strcmp(argv[i], "-p") == 0) pretty = 1;
        else if (strcmp(argv[i], "--help") == 0 ||
                 strcmp(argv[i], "-h") == 0) {
            fprintf(stderr,
                "usage: %s [--pretty]\n"
                "  default: single-line JSON\n"
                "  --pretty: human-readable multi-line\n", argv[0]);
            return 0;
        }
    }

    if (platform_probe() != 0) {
        fprintf(stderr, "platform_probe() failed\n");
        return 1;
    }

    if (pretty) {
        print_pretty();
        return 0;
    }

    char buf[4096];
    int n = platform_dump_json(buf, sizeof(buf));
    if (n < 0) {
        fprintf(stderr, "platform_dump_json: buffer too small\n");
        return 1;
    }
    fwrite(buf, 1, (size_t)n, stdout);
    fputc('\n', stdout);
    return 0;
}
