# hnc_tc_ingress — raw-rtnetlink tc ingress+mirred installer

Single-binary ARM64 Android tool that installs a `clsact` qdisc plus a
`matchall` + `mirred egress redirect` filter on a given interface, **talking
directly to the kernel rtnetlink socket**. It never execs `/system/bin/tc`.

This is the HNC v5.0 "direction B" fix for the ColorOS-16 boot-time race in
which the ROM's customised `/system/bin/tc` binary pre-rejects the `ingress`
keyword for 30–45 s after `wlan2` comes UP. The kernel itself always accepts
the message, so bypassing the ROM's `tc` gives us a clean install at T+0.

---

## What it does

Equivalent to these two shell commands, but via raw netlink only:

```sh
tc qdisc  add dev <iface> clsact
tc filter add dev <iface> ingress prio <prio> protocol all matchall \
    action mirred egress redirect dev <ifb_iface>
```

The tool is **idempotent**: running it a second time with the same arguments
succeeds (kernel returns `EEXIST`, which the tool treats as success).

## Usage

```
hnc_tc_ingress <iface> <ifb_iface> [prio]
```

| Arg         | Meaning                                               |
|-------------|-------------------------------------------------------|
| `iface`     | Upstream iface to attach clsact + ingress filter to (e.g. `wlan2`) |
| `ifb_iface` | IFB redirect target (e.g. `ifb0`) — must already exist and be UP |
| `prio`      | Filter priority, integer in `[1..65535]`. Default `1`. |

**Preconditions the caller must satisfy:**

- `iface` exists (the tool does not wait for it).
- `ifb_iface` exists and is UP (`ip link add ifb0 type ifb; ip link set ifb0 up` upstream).
- The caller runs as root (or has `CAP_NET_ADMIN`).

Example:

```sh
hnc_tc_ingress wlan2 ifb0         # prio defaults to 1
hnc_tc_ingress wlan2 ifb0 1
hnc_tc_ingress wlan2 ifb0 49151   # explicit prio
```

## Return codes

| RC | Meaning                                                       |
|----|---------------------------------------------------------------|
| 0  | Installed OK, or already present (idempotent `EEXIST`)        |
| 1  | `iface` not found (`if_nametoindex` == 0)                     |
| 2  | `ifb_iface` not found                                         |
| 3  | Netlink error — kernel rejection (`EPERM`, `EINVAL`, `EOPNOTSUPP`, …) or I/O failure |
| 4  | CLI / usage error (bad argc, bad prio value)                  |

`stdout` is deliberately left empty so callers can capture it without noise.
`stderr` carries a single log line per operation (prefixed `hnc_tc_ingress:`)
and a kernel-error string on RC 3.

## Build

Requires Android NDK r25 or later (tested with r27c).

```sh
export ANDROID_NDK=/path/to/android-ndk-r27c
bash build.sh              # → out/arm64/hnc_tc_ingress
bash build.sh arm64        # same
bash build.sh arm          # 32-bit ARM
bash build.sh x86_64       # Android x86_64 emulator
bash build.sh host         # Linux x86_64, for dev / debug
```

Expected output of the arm64 build:

```
out/arm64/hnc_tc_ingress: ELF 64-bit LSB pie executable, ARM aarch64, ...,
                          dynamically linked, interpreter /system/bin/linker64, stripped
```

Size: roughly 8 KB stripped. The binary dynamically links against bionic
(`libc.so`, `libdl.so`) via the Android linker — this is the blessed
portability path on Android; fully-static linking against bionic is not
supported.

## Design notes

**Wire-format fidelity.** The tool's outgoing netlink bytes are byte-for-byte
identical to what iproute2's `tc` produces for the equivalent commands. This
was verified with `strace -x -e sendto,sendmsg` by running both `tc` and this
tool and diffing the payloads (only the random `nlmsg_seq` field differs).
Because the wire format is identical, any kernel that accepts iproute2 `tc`
will accept this tool.

**Idempotency.** The request uses `NLM_F_CREATE | NLM_F_EXCL`, so the kernel
returns `-EEXIST` if the qdisc or filter is already present at the given
`(parent, prio)` tuple. The ACK path converts `-EEXIST` to success. We never
issue a `DEL`; callers that need to replace a filter should `tc filter del`
first (the existing HNC `tc_manager.sh` already does this).

**Parent constant.** `tcm_parent = 0xFFFFFFF2` is `TC_H_CLSACT |
TC_H_MIN_INGRESS` and is the exact value iproute2 emits for the
`dev <iface> ingress` short-hand. Handle for the clsact qdisc itself is
`0xFFFF0000` (major 0xFFFF, minor 0), matching iproute2.

**`tcm_info` byte order.** The lower 16 bits hold the L2 protocol in
**network byte order**, because the kernel compares this value directly
against `htons(ETH_P_ALL)` when routing the filter to a classifier chain.
The upper 16 bits are the priority as a plain integer. We build this as
`TC_H_MAKE((uint32_t)prio << 16, htons(ETH_P_ALL))`.

**No external dependencies.** Pure libc + Linux uapi headers. No libnl, no
libmnl, no libbpf. Three tiny helpers (`addattr_l`, `addattr_nest`,
`addattr_nest_end`) handle all the nlattr plumbing; they are patterned after
iproute2's `lib/libnetlink.c` (GPL-2.0).

## Limitations

- **No hardware-offload flags.** `TCA_MATCHALL_FLAGS` (`skip_hw`, `skip_sw`)
  is not emitted. For software-path redirect to IFB this is irrelevant; if
  a future HNC use-case needs it, add one more `addattr_l` before the
  `nest_end` calls.
- **Single action.** Only one `mirred egress redirect` action is installed
  (action index 1). Multi-action chains would need another `addattr_nest`
  loop — not currently needed by HNC.
- **No delete path.** Add-only. `tc filter del` remains the caller's job.
- **No `NETLINK_EXT_ACK`.** We don't opt into extended ACK, so on modern
  kernels we miss the "why exactly was this rejected" string. The numeric
  errno and `strerror()` are usually enough for debugging.
- **Kernel floor.** Requires kernel ≥ 4.5 (when `clsact` was introduced).
  HNC's target device (Linux 6.6.102) is far above this. Older kernels
  would need the legacy `ingress` qdisc path (`parent ffff:`), which is
  intentionally not implemented here — `tc_manager.sh` already has that
  fallback in its shell path.

## Files

| File               | Purpose                                        |
|--------------------|------------------------------------------------|
| `hnc_tc_ingress.c` | Single-file C source (~530 lines with docs)    |
| `build.sh`         | NDK cross-compile driver (arm64/arm/x86_64/host) |
| `README.md`        | This file                                      |
| `test_cases.md`    | Manual test matrix + expected output          |

## License

GPL-2.0. The nlattr helpers (`addattr_l`, `addattr_nest`,
`addattr_nest_end`) are patterned after iproute2's `lib/libnetlink.c`, which
is itself GPL-2.0.
