# HNC v5.0 BPF LSM Limit Map Guard

## 目的
通过 BPF LSM 拦截 `system_server` 对 tethering `limit_map` 的覆盖写入,
让 hotspotd 写入的 `0` 值持久生效,真正关闭 BPF tethering offload fast path。

## 文件
- `vmlinux.h` (3.3 MB) — 从 ColorOS 16 / kernel 6.6.102 / RMX5010 真机 dump
  的 BPF Type Format C 头文件。CI build BPF 程序需要此文件做 CO-RE 重定位。
- `hnc_limit_map_guard.bpf.c` — BPF LSM 程序源码,attach 到 `lsm/bpf` 钩子。
- `hnc_lsm_loader.c` (TBD, Stage 2C) — userspace loader,集成到 hotspotd。

## Build (CI)
GitHub Actions 中编译,需要 clang-15+ 和 libbpf-dev:
```bash
clang -O2 -g -target bpf \
  -D__TARGET_ARCH_arm64 \
  -I. \
  -c hnc_limit_map_guard.bpf.c \
  -o hnc_limit_map_guard.bpf.o
llvm-strip -g hnc_limit_map_guard.bpf.o
```

## 真机部署
- Build artifact `hnc_limit_map_guard.bpf.o` 安装到 `/data/local/hnc/bpf/`
- post-fs-data.sh 负责拷贝 + chmod 644

## 重新生成 vmlinux.h
当 ColorOS 主版本升级或换设备时,需要重新 dump:
```sh
# 真机 (su)
cp /sys/kernel/btf/vmlinux /sdcard/Download/vmlinux.btf
# host (Linux)
bpftool btf dump file vmlinux.btf format c > vmlinux.h
```

## 设计文档
见项目根 `HACKING.md` 或 `docs/HNC-BPF-LSM-design-v1.md`。
