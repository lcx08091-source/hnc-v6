/* platform.c — HNC v5.0 平台探测实现
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>

/* Android bionic: 系统属性读取
 * NDK 21+ / Termux clang 一直有, bionic 编译器自动定义 __ANDROID__
 * (用 ANDROID 宏不可靠, Termux 不传 -DANDROID 但仍是 bionic 平台) */
#if defined(__ANDROID__)
#include <sys/system_properties.h>
#else
/* 非 bionic host build (普通 Linux gcc) 时桩出 __system_property_get */
static int __system_property_get(const char *name, char *value)
{
    (void)name;
    value[0] = '\0';
    return 0;
}
#endif

/* bpf() syscall 测试用 */
#include <linux/bpf.h>
#ifndef __NR_bpf
#  if defined(__aarch64__)
#    define __NR_bpf 280
#  elif defined(__arm__)
#    define __NR_bpf 386
#  elif defined(__x86_64__)
#    define __NR_bpf 321
#  else
#    error "unknown arch, define __NR_bpf"
#  endif
#endif

/* ══════════════════════════════════════════════════════════
 * 全局缓存
 * ══════════════════════════════════════════════════════════ */
platform_info_t g_platform = {0};

/* ══════════════════════════════════════════════════════════
 * 属性读取小工具
 * ══════════════════════════════════════════════════════════ */

/* 读 ro.* 属性到 dst。返回实际长度, 0 = 不存在。
 * dst_size 至少 PROP_VALUE_MAX (=92) 才安全, 我们都用 64 够用。 */
static int prop_get(const char *name, char *dst, size_t dst_size)
{
    char buf[128];
    int n = __system_property_get(name, buf);
    if (n <= 0) {
        if (dst_size > 0) dst[0] = '\0';
        return 0;
    }
    /* truncate to dst_size-1, keep NUL */
    if ((size_t)n >= dst_size) n = (int)dst_size - 1;
    memcpy(dst, buf, n);
    dst[n] = '\0';
    return n;
}

/* 读 ro.* 属性, 返回是否非空 */
static int prop_exists(const char *name)
{
    char buf[8];
    return __system_property_get(name, buf) > 0;
}

/* 读整数属性 */
static int prop_get_int(const char *name, int dflt)
{
    char buf[32];
    int n = __system_property_get(name, buf);
    if (n <= 0) return dflt;
    return atoi(buf);
}

/* ══════════════════════════════════════════════════════════
 * SoC 识别
 *
 * 优先级:
 *   1) ro.soc.manufacturer (Android 12+ 标准属性)
 *   2) ro.hardware (历史属性, 通常 "qcom"/"mt6989"/"exynos*")
 *   3) ro.product.board (SoC codename, 例 "kalama" "sm8550")
 * ══════════════════════════════════════════════════════════ */

static plat_soc_vendor_t classify_soc_vendor(const char *manuf,
                                             const char *hw,
                                             const char *board)
{
    /* manuf 是 Android 12+ 标准, 优先 */
    if (manuf && manuf[0]) {
        if (strcasecmp(manuf, "QTI") == 0 ||
            strcasecmp(manuf, "Qualcomm") == 0)        return PLAT_SOC_QCOM;
        if (strcasecmp(manuf, "Mediatek") == 0)        return PLAT_SOC_MTK;
        if (strcasecmp(manuf, "Samsung") == 0)         return PLAT_SOC_SAMSUNG;
        if (strcasecmp(manuf, "HiSilicon") == 0)       return PLAT_SOC_HISI;
        if (strcasecmp(manuf, "Google") == 0)          return PLAT_SOC_GOOGLE;
    }

    /* hw 老属性 fallback */
    if (hw && hw[0]) {
        if (strncasecmp(hw, "qcom", 4) == 0)           return PLAT_SOC_QCOM;
        if (strncasecmp(hw, "mt", 2) == 0)             return PLAT_SOC_MTK;
        if (strncasecmp(hw, "exynos", 6) == 0)         return PLAT_SOC_SAMSUNG;
        if (strncasecmp(hw, "kirin", 5) == 0)          return PLAT_SOC_HISI;
        if (strncasecmp(hw, "gs", 2) == 0)             return PLAT_SOC_GOOGLE;  /* gs101..gs401 */
    }

    /* board codename 兜底 */
    if (board && board[0]) {
        /* 高通最近几代 codename: kona/lahaina/taro/kalama/pineapple/sun */
        const char *qcom_codenames[] = {
            "kona", "lahaina", "taro", "kalama", "pineapple", "sun",
            "msmnile", "sdm", "sm6", "sm7", "sm8", NULL
        };
        for (int i = 0; qcom_codenames[i]; i++)
            if (strncasecmp(board, qcom_codenames[i], strlen(qcom_codenames[i])) == 0)
                return PLAT_SOC_QCOM;
        if (strncasecmp(board, "mt", 2) == 0)          return PLAT_SOC_MTK;
        if (strncasecmp(board, "exynos", 6) == 0)      return PLAT_SOC_SAMSUNG;
    }

    return PLAT_SOC_UNKNOWN;
}

static void probe_soc(void)
{
    char manuf[HNC_PLATFORM_STR_LEN] = {0};
    char hw[HNC_PLATFORM_STR_LEN] = {0};
    char board[HNC_PLATFORM_STR_LEN] = {0};
    char model[HNC_PLATFORM_STR_LEN] = {0};

    prop_get("ro.soc.manufacturer", manuf, sizeof(manuf));
    prop_get("ro.hardware", hw, sizeof(hw));
    prop_get("ro.product.board", board, sizeof(board));
    prop_get("ro.soc.model", model, sizeof(model));

    g_platform.soc_vendor = classify_soc_vendor(manuf, hw, board);

    /* soc_vendor_raw 优先 manuf, fallback hw */
    if (manuf[0]) snprintf(g_platform.soc_vendor_raw,
                            sizeof(g_platform.soc_vendor_raw), "%s", manuf);
    else          snprintf(g_platform.soc_vendor_raw,
                            sizeof(g_platform.soc_vendor_raw), "%s", hw);

    /* soc_model 优先 ro.soc.model, fallback ro.product.board */
    if (model[0]) snprintf(g_platform.soc_model,
                            sizeof(g_platform.soc_model), "%s", model);
    else          snprintf(g_platform.soc_model,
                            sizeof(g_platform.soc_model), "%s", board);

    snprintf(g_platform.soc_hardware, sizeof(g_platform.soc_hardware), "%s", hw);
}

/* ══════════════════════════════════════════════════════════
 * ROM 识别
 *
 * 启发式优先级(按特征明显度):
 *   ColorOS:  ro.build.version.oplusrom / ro.oplus.os.version_id
 *   HyperOS:  ro.mi.os.version.code / ro.miui.ui.version.name
 *   OneUI:    ro.build.version.oneui / sys.oneui.version
 *   HarmonyOS NEXT: ro.build.version.magic / ro.huawei.harmonyos.version
 *   EMUI:     ro.build.version.emui
 *   VivoOS:   ro.vivo.os.version / ro.vivo.product.subseries
 *   AOSP:     ro.product.brand=google AND 没有任何上面的 vendor 属性
 * ══════════════════════════════════════════════════════════ */

static plat_rom_t classify_rom(void)
{
    if (prop_exists("ro.build.version.oplusrom") ||
        prop_exists("ro.oplus.os.version_id"))           return PLAT_ROM_COLOROS;

    if (prop_exists("ro.mi.os.version.code") ||
        prop_exists("ro.miui.ui.version.name"))          return PLAT_ROM_HYPEROS;

    if (prop_exists("ro.build.version.oneui") ||
        prop_exists("sys.oneui.version"))                return PLAT_ROM_ONEUI;

    if (prop_exists("ro.build.version.magic") ||
        prop_exists("ro.huawei.harmonyos.version"))      return PLAT_ROM_HARMONY;

    if (prop_exists("ro.build.version.emui"))            return PLAT_ROM_EMUI;

    if (prop_exists("ro.vivo.os.version"))               return PLAT_ROM_VIVO;

    /* AOSP 判定: brand=google 或 brand=lineage */
    char brand[64] = {0};
    prop_get("ro.product.brand", brand, sizeof(brand));
    if (strcasecmp(brand, "google") == 0 ||
        strcasecmp(brand, "lineage") == 0 ||
        strcasecmp(brand, "graphene") == 0)              return PLAT_ROM_AOSP;

    return PLAT_ROM_UNKNOWN;
}

static void probe_rom(void)
{
    g_platform.rom = classify_rom();

    switch (g_platform.rom) {
    case PLAT_ROM_COLOROS:
        snprintf(g_platform.rom_name, sizeof(g_platform.rom_name), "ColorOS");
        prop_get("ro.build.version.oplusrom", g_platform.rom_version,
                 sizeof(g_platform.rom_version));
        if (!g_platform.rom_version[0])
            prop_get("ro.oplus.os.version_id", g_platform.rom_version,
                     sizeof(g_platform.rom_version));
        break;
    case PLAT_ROM_HYPEROS:
        snprintf(g_platform.rom_name, sizeof(g_platform.rom_name), "HyperOS");
        prop_get("ro.mi.os.version.name", g_platform.rom_version,
                 sizeof(g_platform.rom_version));
        if (!g_platform.rom_version[0])
            prop_get("ro.miui.ui.version.name", g_platform.rom_version,
                     sizeof(g_platform.rom_version));
        break;
    case PLAT_ROM_ONEUI:
        snprintf(g_platform.rom_name, sizeof(g_platform.rom_name), "OneUI");
        prop_get("ro.build.version.oneui", g_platform.rom_version,
                 sizeof(g_platform.rom_version));
        break;
    case PLAT_ROM_HARMONY:
        snprintf(g_platform.rom_name, sizeof(g_platform.rom_name), "HarmonyOS");
        prop_get("ro.build.version.magic", g_platform.rom_version,
                 sizeof(g_platform.rom_version));
        if (!g_platform.rom_version[0])
            prop_get("ro.huawei.harmonyos.version", g_platform.rom_version,
                     sizeof(g_platform.rom_version));
        break;
    case PLAT_ROM_EMUI:
        snprintf(g_platform.rom_name, sizeof(g_platform.rom_name), "EMUI");
        prop_get("ro.build.version.emui", g_platform.rom_version,
                 sizeof(g_platform.rom_version));
        break;
    case PLAT_ROM_VIVO:
        snprintf(g_platform.rom_name, sizeof(g_platform.rom_name), "OriginOS");
        prop_get("ro.vivo.os.version", g_platform.rom_version,
                 sizeof(g_platform.rom_version));
        break;
    case PLAT_ROM_AOSP:
        snprintf(g_platform.rom_name, sizeof(g_platform.rom_name), "AOSP");
        prop_get("ro.build.version.release", g_platform.rom_version,
                 sizeof(g_platform.rom_version));
        break;
    default:
        snprintf(g_platform.rom_name, sizeof(g_platform.rom_name), "unknown");
        prop_get("ro.build.version.release", g_platform.rom_version,
                 sizeof(g_platform.rom_version));
        break;
    }
}

/* ══════════════════════════════════════════════════════════
 * Android API + Kernel
 * ══════════════════════════════════════════════════════════ */

static void probe_android(void)
{
    g_platform.android_api = prop_get_int("ro.build.version.sdk", 0);
    prop_get("ro.build.version.release", g_platform.android_release,
             sizeof(g_platform.android_release));
}

static void probe_kernel(void)
{
    struct utsname u;
    if (uname(&u) != 0) {
        snprintf(g_platform.kernel_release, sizeof(g_platform.kernel_release),
                 "unknown");
        return;
    }
    /* 显式 strncpy + NUL 截断, 避免 snprintf("%s") 触发 -Wformat-truncation
     * (utsname.release 标准 65 字节, kernel_release 我们只留 64) */
    strncpy(g_platform.kernel_release, u.release, sizeof(g_platform.kernel_release) - 1);
    g_platform.kernel_release[sizeof(g_platform.kernel_release) - 1] = '\0';

    /* parse "6.6.102-android16-..." → 6, 6, 102 */
    int maj = 0, min = 0, pat = 0;
    sscanf(u.release, "%d.%d.%d", &maj, &min, &pat);
    g_platform.kernel_major = maj;
    g_platform.kernel_minor = min;
    g_platform.kernel_patch = pat;
}

/* ══════════════════════════════════════════════════════════
 * Offload 子系统探测
 * ══════════════════════════════════════════════════════════ */

static int path_exists(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0;
}

static void probe_offload(void)
{
    /* BPF tethering (高通 / AOSP 主流) */
    int has_tether_dir = path_exists("/sys/fs/bpf/tethering");
    int has_limit_map  = path_exists("/sys/fs/bpf/tethering/map_offload_tether_limit_map");

    g_platform.has_bpf_tethering         = has_limit_map ? 1 : 0;
    g_platform.has_bpf_tethering_partial = (has_tether_dir && !has_limit_map) ? 1 : 0;

    /* MTK PPE/HNAT */
    g_platform.has_mtk_ppe =
        (path_exists("/sys/kernel/debug/hnat") ||
         path_exists("/proc/sys/net/nf_conntrack_hnat_offload") ||
         path_exists("/sys/module/mtk_ppe") ||
         path_exists("/sys/module/mtk_hnat"))
        ? 1 : 0;

    /* 三星 NSS - 探测点未确认, v5.2 补 */
    g_platform.has_samsung_nss = 0;

    /* bpf() syscall 实测
     * 试着 BPF_OBJ_GET 一个已知 pin 路径(用 limit_map 当 canary)。
     * 成功 → SELinux 允许 + bpf syscall 可用; 失败 → 拒绝/不可用。
     * 注意: 这只测 read 路径, 写权限要等 adapter init() 时再验。 */
    g_platform.bpf_syscall_ok = 0;
    if (has_limit_map) {
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        const char *path = "/sys/fs/bpf/tethering/map_offload_tether_limit_map";
        attr.pathname = (uint64_t)(uintptr_t)path;
        long fd = syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
        if (fd >= 0) {
            g_platform.bpf_syscall_ok = 1;
            close((int)fd);
        }
    }
}

/* ══════════════════════════════════════════════════════════
 * APEX 版本(可选, 仅 Android 12+ 有意义)
 *
 * 走 dpm/pm 命令成本太高, 这里只读 apex_info.xml 的快路径。
 * 如果路径不在或解析失败, 留 0(scheduler 不依赖此字段, 仅诊断显示)。
 * ══════════════════════════════════════════════════════════ */

static void probe_apex(void)
{
    g_platform.apex_connectivity_version = 0;
    /* /apex/com.android.tethering/etc/apex_info 的存在性即可作为
     * Connectivity APEX 启用的指示。版本号要解析 apex_manifest.pb,
     * 二进制 protobuf 不值得在 hotspotd 内做; 留给 hnc_httpd 走 pm 命令 */
    if (path_exists("/apex/com.android.tethering")) {
        g_platform.apex_connectivity_version = -1;  /* 表示"启用但未解析具体版本" */
    }
}

/* ══════════════════════════════════════════════════════════
 * 入口
 * ══════════════════════════════════════════════════════════ */

int platform_probe(void)
{
    memset(&g_platform, 0, sizeof(g_platform));
    probe_soc();
    probe_android();
    probe_rom();
    probe_kernel();
    probe_offload();
    probe_apex();
    return 0;
}

/* ══════════════════════════════════════════════════════════
 * 枚举字符串
 * ══════════════════════════════════════════════════════════ */

const char *platform_soc_vendor_str(plat_soc_vendor_t v)
{
    switch (v) {
    case PLAT_SOC_UNKNOWN: return "unknown";
    case PLAT_SOC_QCOM:    return "qcom";
    case PLAT_SOC_MTK:     return "mtk";
    case PLAT_SOC_SAMSUNG: return "samsung";
    case PLAT_SOC_HISI:    return "hisi";
    case PLAT_SOC_GOOGLE:  return "google";
    case PLAT_SOC_OTHER:   return "other";
    }
    return "invalid";
}

const char *platform_rom_str(plat_rom_t r)
{
    switch (r) {
    case PLAT_ROM_UNKNOWN: return "unknown";
    case PLAT_ROM_AOSP:    return "aosp";
    case PLAT_ROM_COLOROS: return "coloros";
    case PLAT_ROM_HYPEROS: return "hyperos";
    case PLAT_ROM_ONEUI:   return "oneui";
    case PLAT_ROM_EMUI:    return "emui";
    case PLAT_ROM_HARMONY: return "harmony";
    case PLAT_ROM_VIVO:    return "vivo";
    case PLAT_ROM_OTHER:   return "other";
    }
    return "invalid";
}

/* ══════════════════════════════════════════════════════════
 * JSON 序列化
 *
 * 简单字符串拼接, 不引入 cJSON 依赖。所有字段都是已知 ASCII 安全
 * (从 prop 来的字符串可能含 utf-8, 但不含 " 或 \, 这里不做转义,
 * 调用方需保证 prop_get 返回的是 ASCII。如果将来要严格,接 hnc_helpers
 * 的 hnc_json_escape)。
 *
 * 输出示例:
 * {
 *   "soc": {"vendor":"qcom","model":"sun","hardware":"qcom","raw":"QTI"},
 *   "android": {"api":36,"release":"16"},
 *   "rom": {"id":"coloros","name":"ColorOS","version":"15.0.1"},
 *   "kernel": {"release":"6.6.102","major":6,"minor":6,"patch":102},
 *   "offload": {
 *     "bpf_tethering": true,
 *     "bpf_tethering_partial": false,
 *     "mtk_ppe": false,
 *     "samsung_nss": false,
 *     "bpf_syscall_ok": true
 *   },
 *   "apex_connectivity": -1
 * }
 * ══════════════════════════════════════════════════════════ */

int platform_dump_json(char *buf, size_t buf_size)
{
    if (buf == NULL || buf_size == 0) return -1;

    int n = snprintf(buf, buf_size,
        "{"
        "\"soc\":{\"vendor\":\"%s\",\"model\":\"%s\",\"hardware\":\"%s\",\"raw\":\"%s\"},"
        "\"android\":{\"api\":%d,\"release\":\"%s\"},"
        "\"rom\":{\"id\":\"%s\",\"name\":\"%s\",\"version\":\"%s\"},"
        "\"kernel\":{\"release\":\"%s\",\"major\":%d,\"minor\":%d,\"patch\":%d},"
        "\"offload\":{"
            "\"bpf_tethering\":%s,"
            "\"bpf_tethering_partial\":%s,"
            "\"mtk_ppe\":%s,"
            "\"samsung_nss\":%s,"
            "\"bpf_syscall_ok\":%s"
        "},"
        "\"apex_connectivity\":%d"
        "}",
        platform_soc_vendor_str(g_platform.soc_vendor),
        g_platform.soc_model,
        g_platform.soc_hardware,
        g_platform.soc_vendor_raw,
        g_platform.android_api,
        g_platform.android_release,
        platform_rom_str(g_platform.rom),
        g_platform.rom_name,
        g_platform.rom_version,
        g_platform.kernel_release,
        g_platform.kernel_major,
        g_platform.kernel_minor,
        g_platform.kernel_patch,
        g_platform.has_bpf_tethering ? "true" : "false",
        g_platform.has_bpf_tethering_partial ? "true" : "false",
        g_platform.has_mtk_ppe ? "true" : "false",
        g_platform.has_samsung_nss ? "true" : "false",
        g_platform.bpf_syscall_ok ? "true" : "false",
        g_platform.apex_connectivity_version
    );

    if (n < 0 || (size_t)n >= buf_size) return -1;
    return n;
}
