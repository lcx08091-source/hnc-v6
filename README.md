# Hotspot Network Control (HNC)

> 给 Android 个人热点加上**对每台连接客户端**的限速、延迟、黑名单管理。

**[截图占位:WebUI 设备列表]**

---

## 这是给谁的

**适合你**,如果:

- 你经常开热点给别人用,想限制某些设备占带宽
- 你有 root(KernelSU / SukiSU Ultra / Magisk)
- 你能接受一个还在迭代中的工具

**不适合你**,如果:

- 你没有 root,或不想刷面具
- 你想要"装了就永远 work"的商用级产品
- 你的设备是冷门 OEM 且不愿配合 debug

---

## 能做什么

- 看到每台连热点的设备:MAC、IP、品牌(OUI 数据库)、hostname(DHCP / mDNS 解析)
- 给单个设备限**下载 / 上传**速度(基于 tc HTB + BPF LSM 双重拦截)
- 给单个设备加**延迟 / 丢包**(弱网模拟)
- **拉黑**设备(iptables REJECT)
- **白名单模式**(仅允许指定 MAC 连接)
- 实时流量统计、按日历史曲线
- **远程 WebUI**(手机在别处时,电脑浏览器远程管理)

**[截图占位:限速面板]**

---

## 它独特在哪

| 特性 | 说明 |
|---|---|
| **BPF 内核级拦截** | LSM kprobe 监视 `security_bpf`,在 Android framework 试图开启 BPF offload 绕过时 100μs 内回写拦截 |
| **自愈式网络栈** | ColorOS / MIUI 等 OEM 会私自清外部 tc 规则,HNC 三层防御(set_limit 前自检 + watchdog 60 秒巡检 + full_restore 兜底) |
| **双向精准限速** | 下行走 tc HTB + iptables MARK,上行走 wlan2 ingress pref 1 mirred → ifb0 htb,测速精度 ±2% |
| **真正认真的远程访问** | 自签 ECDSA P-256 证书 + bcrypt + Token/Secret 分离 + SameSite + CSRF + DNS rebinding 防御 |
| **零依赖** | 不需要装额外 App、不需要 Xposed、不需要云服务 |

---

## 不能做什么(重要)

- **iOS 的"私有 WiFi 地址"** 会用随机 MAC,每次连接看起来是不同设备 → 限速规则失效
- **限速对 QUIC 的弹性大**(YouTube / Google),实际感受可能比设定数字松一点
- 同一时刻只管一个热点 SSID(不支持双频段并发)
- 限速精度约 **±10% in-app, ±2% speedtest**,不是商用 QoS 级
- 不能识别"哪个 App 在用流量",只能识别哪个**设备**在用

---

## 兼容性

| 维度 | 要求 |
|---|---|
| Android | 13+(需 BPF + cgroup v2) |
| 内核 | 5.10+,启用 `CONFIG_NET_SCH_HTB`、`CONFIG_NETFILTER_XT_TARGET_MARK`、`CONFIG_KPROBES` |
| Root | KernelSU 11485+ / SukiSU Ultra / Magisk 26+ |
| 架构 | arm64(armv8) |

**ROM 实测情况(持续更新)**: 见 [COMPATIBILITY.md](COMPATIBILITY.md)。

如果你的 ROM 没在表里,先装上看看 WebUI 顶部的**能力提示条** —— 它会告诉你当前设备实际能用哪些功能。

---

## 安装

1. 从 [Releases](https://github.com/lcx08091-source/hnc-v5/releases) 下载最新 zip
2. 在 KernelSU / Magisk Manager 里"从本地安装",选 zip
3. 重启
4. 手机浏览器打开 `http://127.0.0.1:8444/`(或通过 KSU WebUI 入口)
5. 第一次会提示配对 —— 按屏幕提示走

---

## 第一次用(3 步)

**[GIF 占位 或 3 张连续截图]**

---

## 出问题了

1. **收集诊断**:
   ```sh
   su -c 'sh /data/local/hnc/bin/diag.sh' > /sdcard/hnc_diag.txt
   ```
2. 在 [Issues](https://github.com/lcx08091-source/hnc-v5/issues) 开一个 bug,附 `hnc_diag.txt`
3. 说明:
   - 哪个 ROM / 哪台设备 / 内核版本
   - 做了什么操作之后出现了什么现象
   - 预期行为是什么

---

## 隐私

- 所有数据(MAC、hostname、流量统计)**只存本地** `/data/local/hnc/`
- 模块**不向任何外部服务器发送任何数据**
- 远程 WebUI 默认只监听 `127.0.0.1`,需要你手动在设置里开启 LAN 访问
- 开启 LAN 访问后必须 token 配对(bcrypt + 一次性 PIN + 速率限制)

---

## 项目状态

- **版本**: v5.3.0-rc30.12.35 (2026-05-20) <!-- 手动维护, 跟 module.prop 同步 -->
- **主测设备**: realme GT 7 Pro / ColorOS 16 / kernel 6.6.102 / SukiSU Ultra
- **代码规模**: C 9.9K + Go 19K + Shell 17K + HTML/JS 12K ≈ 5.8 万行
- 由 **Ling** 维护。架构和大量代码与 Claude(Anthropic)协作完成,详见 [HACKING.md](HACKING.md) 的开发笔记。

---

## 贡献

欢迎 bug 报告、兼容性反馈、PR。详见 [CONTRIBUTING.md](CONTRIBUTING.md)。

安全漏洞请**不要**在公开 issue 报告,按 [SECURITY.md](SECURITY.md) 的流程私下沟通。
