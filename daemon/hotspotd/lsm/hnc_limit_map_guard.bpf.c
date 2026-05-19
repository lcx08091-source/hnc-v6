// SPDX-License-Identifier: GPL-2.0
//
// hnc_limit_map_guard.bpf.c — HNC v5.1 Plan B (kprobe)
//
// ColorOS kernel 6.6.102 禁用 CONFIG_FUNCTION_TRACER -> BPF LSM / fentry
// 都无法 attach (ENOTSUPP)。改用 kprobe 机制(依赖 CONFIG_KPROBES=y,
// ColorOS 有)。
//
// kprobe 只能观察,不能拦截。策略改为"快速 counter-write":
//   - kprobe 在 security_bpf 入口触发
//   - 检测条件: cmd=BPF_MAP_UPDATE_ELEM && map_id=protected && val=U64_MAX
//   - 不命中: 不做事
//   - 命中: 发 ringbuf 事件 -> userspace 毫秒级重写 limit_map[ifindex]=0
//
// 相比 LSM active 差一个"从事件上报到 userspace 完成 write"的窗口(~1-10ms),
// 相比 passive 60s 精度高 6000 倍。实际效果足够。

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define U64_MAX 0xFFFFFFFFFFFFFFFFULL
#define BPF_MAP_UPDATE_ELEM_CMD 2

// ─── 控制 map (userspace 写,kernel 读) ────────────────────
struct hnc_lsm_ctrl {
    __u32 protected_map_id;
    __u32 protected_ifindex;
    __u32 hotspotd_pid;
    __u32 enabled;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct hnc_lsm_ctrl);
    __uint(max_entries, 1);
} hnc_ctrl_map SEC(".maps");

// ─── 事件 ringbuf ─────────────────────────────────────────
struct hnc_lsm_event {
    __u64 ts_ns;
    __u32 caller_pid;
    __u32 caller_uid;
    __u64 attempted_value;
    __u32 ifindex;
    __u32 verdict;       // 在 kprobe 模式下 verdict 恒=1 (观察到可疑 write)
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} hnc_lsm_events SEC(".maps");

// ─── 主 hook: kprobe/security_bpf ─────────────────────────
// security_bpf(int cmd, union bpf_attr *attr, unsigned int size)
//
// kprobe BPF_KPROBE 宏自动解 ctx->di/si/dx (x86) 或 x0/x1/x2 (arm64)

SEC("kprobe/security_bpf")
int BPF_KPROBE(hnc_check_bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    if (cmd != BPF_MAP_UPDATE_ELEM_CMD)
        return 0;

    __u32 ckey = 0;
    struct hnc_lsm_ctrl *ctrl = bpf_map_lookup_elem(&hnc_ctrl_map, &ckey);
    if (!ctrl || ctrl->protected_map_id == 0)
        return 0;

    // ─── 1. 反查 map_fd -> bpf_map * -> map id ───────
    __u32 map_fd = BPF_CORE_READ(attr, map_fd);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files) return 0;

    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt) return 0;

    __u32 max_fds = BPF_CORE_READ(fdt, max_fds);
    if (map_fd >= max_fds) return 0;
    map_fd &= 0xFFFF;
    if (map_fd >= max_fds) return 0;

    struct file **fdarr = BPF_CORE_READ(fdt, fd);
    if (!fdarr) return 0;

    struct file *fp = NULL;
    bpf_probe_read_kernel(&fp, sizeof(fp), &fdarr[map_fd]);
    if (!fp) return 0;

    struct bpf_map *map = (struct bpf_map *)BPF_CORE_READ(fp, private_data);
    if (!map) return 0;

    __u32 mid = BPF_CORE_READ(map, id);
    if (mid != ctrl->protected_map_id)
        return 0;

    // ─── 2. 检查 key (ifindex) ──────────────────────
    __u64 key_uptr = BPF_CORE_READ(attr, key);
    __u32 ifindex = 0;
    bpf_probe_read_user(&ifindex, sizeof(ifindex), (void *)key_uptr);
    if (ifindex != ctrl->protected_ifindex)
        return 0;

    // ─── 3. 白名单 hotspotd ──────────────────────────
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 caller_tgid = pid_tgid >> 32;
    if (caller_tgid == ctrl->hotspotd_pid)
        return 0;

    // ─── 4. 读 value ────────────────────────────────
    __u64 val_uptr = BPF_CORE_READ(attr, value);
    __u64 val = 0;
    bpf_probe_read_user(&val, sizeof(val), (void *)val_uptr);

    // ─── 5. 只对 U64_MAX (fast path 启用值) 告警 ────
    if (val != U64_MAX)
        return 0;

    // ─── 6. 发事件, userspace 立刻 counter-write ───
    struct hnc_lsm_event *ev = bpf_ringbuf_reserve(
        &hnc_lsm_events, sizeof(*ev), 0);
    if (ev) {
        ev->ts_ns = bpf_ktime_get_ns();
        ev->caller_pid = caller_tgid;
        ev->caller_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        ev->attempted_value = val;
        ev->ifindex = ifindex;
        ev->verdict = 1;  // "检测到可疑 write, 已通知 userspace"
        bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
        bpf_ringbuf_submit(ev, 0);
    }

    return 0;  // kprobe retval 无效, kernel 照常继续
}

char _license[] SEC("license") = "GPL";
