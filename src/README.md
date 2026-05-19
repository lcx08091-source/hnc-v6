# HNC 源码目录

本目录包含 HNC 模块所有可独立编译的源代码,供审计、修改、自行编译。

```
src/
├── dpid/         hnc_dpid (Go) — DPI 守护进程
│   └── ...       → bin/hnc_dpid
├── hnc_httpd/    hnc_httpd (Go) — HTTP API daemon
│   └── ...       → daemon/hnc_httpd/hnc_httpd
└── launcher/     hnc_launcher + fork_probe (C) — DPID 守护进程 + fork 探针
    └── ...       → bin/hnc_launcher + bin/fork_probe
```

二进制位置说明:
- `bin/` 下的是 Android arm64 二进制,直接被 service.sh / watchdog 调用
- `daemon/hnc_httpd/hnc_httpd` 单独放是因为它需要带着 `web/` embed 资源一起

---

## 当前版本对照

<!-- rc30.12.29: 文档版本号统一同步 module.prop -->

| 组件 | 版本 | 位置 |
|---|---|---|
| 主模块 | `v5.3.0-rc30.12.29` | `module.prop` |
| hnc_httpd | `v5.3.0-rc30.12.29` | 二进制 strings 找 `main.version=` |
| hnc_dpid | `0.5.3-rc30.12.3-iface-retry` | `src/dpid/cmd/dpid/main.go` |
| hnc_launcher | `0.1.0-rc30.12.29` | `src/launcher/hnc_launcher.c` |

---

## 编译要求

| 组件 | 工具链 | 备注 |
|---|---|---|
| hnc_dpid | Go 1.22+ | 纯 Go,无 CGO |
| hnc_httpd | Go 1.22+ | 依赖 `golang.org/x/crypto v0.31.0` |
| hnc_launcher / fork_probe | Android NDK r23+ (API 24+) | 静态链接 C |

**目标平台**: Android arm64-v8a (`aarch64-linux-android`)

---

## 编译 hnc_dpid

```bash
cd src/dpid

# Android arm64 静态二进制
CGO_ENABLED=0 GOOS=android GOARCH=arm64 \
    go build -trimpath -ldflags="-s -w" \
    -o ../../bin/hnc_dpid ./cmd/dpid

# 验证版本
strings ../../bin/hnc_dpid | grep "iface-retry"
# 期望: 0.5.3-rc30.12.3-iface-retry
```

输出体积约 3 MB。

---

## 编译 hnc_httpd

`build.sh` 会自动从 `module.prop` 读 version 注入二进制:

```bash
cd daemon/hnc_httpd
sh build.sh
```

或手动:

```bash
cd daemon/hnc_httpd
VERSION=$(grep '^version=' ../../module.prop | cut -d= -f2)
CGO_ENABLED=0 GOOS=android GOARCH=arm64 \
    go build -trimpath \
    -ldflags="-s -w -X main.version=$VERSION" \
    -o hnc_httpd .
```

输出体积约 6.2 MB。

### 关于 `src/hnc_httpd/` vs `daemon/hnc_httpd/`

两个目录的 Go 源码内容**完全一致**。`src/hnc_httpd/` 是源码归档(给审计 / 修改用),`daemon/hnc_httpd/` 是 build 产物输出目录(因为 zip 安装时需要把二进制放在固定位置)。

任何代码改动**必须两边同时更新**,否则会出现源码二进制不一致的事故。

### 关于 web/ 资源

`hnc_httpd` 用 Go `//go:embed` 把以下文件打进二进制:

- `web/app.html` — 远程访问场景的 SPA 入口
- `web/app.js` — JS 主体
- `web/style.css` — 样式
- `web/pair.html` — 配对页

两个目录(`src/` 和 `daemon/`)都需要带 `web/` 子目录才能 embed 成功,否则 build 会报:

```
embed.go:5:12: pattern web/app.html: no matching files found
```

---

## 编译 hnc_launcher + fork_probe (C)

详见 `src/launcher/README.md`。要点:

```bash
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/26.1.10909125  # 或你的 NDK 路径
cd src/launcher
sh build.sh install     # install 模式会把编出来的二进制拷到 ../../bin/
```

`fork_probe` 是动态链接(运行时 dlopen libc),`hnc_launcher` 是静态链接(post-fs-data 早期 /system/lib64 可能未 mount)。

---

## 离线 / 可复现构建

当前**还不是完全 hermetic build**:

- `daemon/hnc_httpd` 需要从 GOPROXY 下载 `golang.org/x/crypto v0.31.0`
- `src/dpid` 是纯 Go 无外部依赖,可以离线 build

如果需要完全离线 build,在有网的机器跑一次 `go mod vendor` 把依赖固化:

```bash
cd daemon/hnc_httpd
go mod vendor
# 之后离线机器 go build 会用 vendor/ 而不是 GOPROXY
```

---

## 编译产物验证

完整 build 完一套后,期望:

```bash
# 1. 版本一致性
sh bin/version_consistency_check.sh
# 期望: [OK] x4, failures=0 warnings=0

# 2. 二进制都是 arm64
file bin/hnc_dpid bin/hnc_launcher bin/fork_probe daemon/hnc_httpd/hnc_httpd
# 期望全部含 "ELF 64-bit ... ARM aarch64"

# 3. 版本字符串注入正确
strings daemon/hnc_httpd/hnc_httpd | grep "v5.3.0-rc30"
strings bin/hnc_dpid | grep "iface-retry"
strings bin/hnc_launcher | grep "0.1.0-rc30.12"
```

---

## 主要历史变更点

### rc30.12.18 (当前)

- middleware.go 改成默认拒绝:isPublicPath 白名单 + 其他全要 cookie
- `auth_required` 不再有放行匿名语义,service.sh 自动迁移老配置

### rc30.12.16

- service.sh `launch_httpd_safe()` 函数统一处理 remote_enabled
- sentinel 块移到 DPID_LAUNCHER 定义之后
- src/dpid 源码同步到 rc30.12.3-iface-retry,加字符串 fallback

### rc30.12

- 引入 C `hnc_launcher` 替代 Go `hnc_dpid_supervisor`(ColorOS 16 + SukiSU 上 Go fork 报 EPERM)
- 增加 `fork_probe` 启动时探测 C fork+execv 是否可用

### rc29.1

- DPI L3 per-flow app/category 标签
- JA4 算法、IPv6 解析、conntrack 关联

详细 changelog 见 `CHANGELOG.md`。

---

## License

跟主模块同许可。
