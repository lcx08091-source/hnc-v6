# HNC v5.3.0-rc29.1 源码

本目录包含两个 Go 二进制的完整源码,供审计、修改、自行编译:

```
src/
├── dpid/         hnc_dpid (DPI 守护) 源码
│   └── ...       → bin/hnc_dpid
└── hnc_httpd/    HTTP API daemon 源码
    └── ...       → daemon/hnc_httpd/hnc_httpd
```

## 编译要求

- **Go**: dpid 用 1.22+,hnc_httpd 用 1.25+ (因为依赖 golang.org/x/crypto v0.50.0)
- **目标**: Android ARM64 静态二进制

## 编译 hnc_dpid (rc29.1)

```bash
cd src/dpid
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags="-s -w" \
  -o ../../bin/hnc_dpid ./cmd/dpid
```

输出体积约 2.5 MB。

验证版本:
```bash
./bin/hnc_dpid -version
# 期望: hnc_dpid 0.5.1-rc29.1-l3-flow
```

## 编译 hnc_httpd

```bash
cd src/hnc_httpd
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags="-s -w" \
  -o ../../daemon/hnc_httpd/hnc_httpd .
```

输出体积约 6.7 MB。

## 主要变更点

### dpid rc29.1 vs rc20.1 基线

约 +1700 行 Go,涉及:

- `capture/bpf.go` — cBPF 双协议(IPv4 + IPv6)
- `capture/parse.go` — IPv6 包解析、EventFlow、JA4 计算
- `capture/ja4.go` — JA4 输入提取 (FoxIO 算法)
- `capture/iface.go` — `InterfaceNets()` 暴露接口网段
- `output/rule.go` — `ip_matchers / ipv6_matchers / priority / sub_categories` 规则解析
- `output/classify.go` — host / IP / IPv6 三类匹配 + priority 排序
- `output/state.go` — schema 2.0、Writer、`clientLookupLocked()` (只查不创)
- `output/flow.go` — 30s 桶流持续性检测
- `output/dfp.go` — JA4 库 + 计算
- `output/conntrack.go` — `/proc/net/nf_conntrack` 解析
- `cmd/dpid/main.go` — `-write-blind-state` flag + hotspot 网段注入

### hnc_httpd rc29.1 改动

仅 2 处:
- `action.go` — 加 `case "cleanup_offline_devices"`
- `action_v5.go` — 加 `actionCleanupOfflineDevices`

其他 .go 跟 rc28.1.1 保持一致(没改的就是没改)。

## License

跟主模块同许可。
