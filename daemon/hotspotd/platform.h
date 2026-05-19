/* platform.h — HNC v5.0 平台探测
 *
 * 启动时探测一次,缓存到 g_platform。后续模块直接读结构体字段,
 * 不再调 popen/getprop/读 sysfs。
 *
 * 探测范围:
 *   - SoC vendor / model         (ro.product.board / ro.hardware)
 *   - Android API level          (ro.build.version.sdk)
 *   - ROM 名 / 大版本             (ro.build.version.release / ColorOS / HyperOS / OneUI)
 *   - Kernel 版本                 (uname -r)
 *   - 各 offload 子系统是否存在   (sysfs 探测)
 *   - bpf() syscall 可访问性      (实际尝试 BPF_OBJ_GET)
 *
 * 数据来源:
 *   __system_property_get (bionic, 优先)
 *   /system/build.prop  parse (fallback)
 *   uname(2)
 *   stat(2) 目录/文件存在性
 *
 * 所有探测都是只读, 不修改系统状态。
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef HNC_PLATFORM_H
#define HNC_PLATFORM_H

#include <stdint.h>
#include <stddef.h>

#define HNC_PLATFORM_STR_LEN  64

typedef enum {
    PLAT_SOC_UNKNOWN = 0,
    PLAT_SOC_QCOM    = 1,
    PLAT_SOC_MTK     = 2,
    PLAT_SOC_SAMSUNG = 3,
    PLAT_SOC_HISI    = 4,
    PLAT_SOC_GOOGLE  = 5,    /* Tensor */
    PLAT_SOC_OTHER   = 99,
} plat_soc_vendor_t;

typedef enum {
    PLAT_ROM_UNKNOWN  = 0,
    PLAT_ROM_AOSP     = 1,    /* Pixel / GrapheneOS / LineageOS */
    PLAT_ROM_COLOROS  = 2,    /* OPPO / OnePlus / realme */
    PLAT_ROM_HYPEROS  = 3,    /* 小米(MIUI 接班) */
    PLAT_ROM_ONEUI    = 4,    /* 三星 */
    PLAT_ROM_EMUI     = 5,    /* 华为(老) */
    PLAT_ROM_HARMONY  = 6,    /* HarmonyOS NEXT */
    PLAT_ROM_VIVO     = 7,    /* OriginOS / FuntouchOS */
    PLAT_ROM_OTHER    = 99,
} plat_rom_t;

typedef struct {
    /* === SoC === */
    plat_soc_vendor_t  soc_vendor;
    char               soc_vendor_raw[HNC_PLATFORM_STR_LEN];   /* "qcom" / "mt6989" 原始 */
    char               soc_model[HNC_PLATFORM_STR_LEN];        /* "sm8750" / "mt6989" */
    char               soc_hardware[HNC_PLATFORM_STR_LEN];     /* ro.hardware */

    /* === Android === */
    int                android_api;          /* ro.build.version.sdk, 例 36 = Android 16 */
    char               android_release[16];  /* "16" */

    /* === ROM === */
    plat_rom_t         rom;
    char               rom_name[HNC_PLATFORM_STR_LEN];   /* "ColorOS" */
    char               rom_version[HNC_PLATFORM_STR_LEN];/* "16.0" 或厂商完整版本号 */

    /* === Kernel === */
    char               kernel_release[HNC_PLATFORM_STR_LEN];   /* "6.6.102" */
    int                kernel_major;
    int                kernel_minor;
    int                kernel_patch;

    /* === Offload 子系统探测 === */
    /* /sys/fs/bpf/tethering/map_offload_tether_limit_map 存在 */
    int                has_bpf_tethering;
    /* /sys/fs/bpf/tethering/ 路径存在但 limit_map 不存在 (旧 schema/部分 ROM) */
    int                has_bpf_tethering_partial;
    /* MTK PPE: /sys/kernel/debug/hnat/ 或 /proc/sys/net/nf_conntrack_hnat_offload */
    int                has_mtk_ppe;
    /* 三星 NSS: 探测点待 v5.2 确定 */
    int                has_samsung_nss;
    /* 实际尝试 bpf(BPF_OBJ_GET) 是否成功(SELinux 允许 + bpf syscall 可用) */
    int                bpf_syscall_ok;

    /* === Connectivity APEX 版本(若可探测) === */
    int                apex_connectivity_version;   /* 0 = 未探到 */
} platform_info_t;

/* 全局缓存。在 main() 早期调 platform_probe() 之后才有效。 */
extern platform_info_t g_platform;

/* ══════════════════════════════════════════════════════════
 * platform_probe — 一次性探测, 填充 g_platform
 *
 * 返回 0 = 成功(即使部分字段未填也算成功), 非 0 = 严重错误。
 * 实际上几乎不会失败, 探测失败的字段保持 0/空字符串。
 * ══════════════════════════════════════════════════════════ */
int platform_probe(void);

/* ══════════════════════════════════════════════════════════
 * platform_dump_json — 把 g_platform 序列化为 JSON 字符串
 *
 * 写到 buf, 最多 buf_size 字节(含末尾 NUL)。
 * 用于 /api/diag/platform 接口和 /data/local/hnc/data/platform.json 缓存。
 *
 * 返回写入字节数(不含 NUL), 缓冲区不足返回 -1。
 * ══════════════════════════════════════════════════════════ */
int platform_dump_json(char *buf, size_t buf_size);

/* ══════════════════════════════════════════════════════════
 * platform_*_str — 枚举值 → 字符串(JSON 输出 + 日志用)
 * ══════════════════════════════════════════════════════════ */
const char *platform_soc_vendor_str(plat_soc_vendor_t v);
const char *platform_rom_str(plat_rom_t r);

#endif /* HNC_PLATFORM_H */
