# HNC — Hotspot Network Control

> Android hotspot management, per-device traffic control, network policies, and monitoring.

> Android 热点管理、设备级流量控制、网络策略与监控工具。

[English](#english) · [中文](#中文)

---

<a id="english"></a>

# English

## Overview

HNC (Hotspot Network Control) is an open-source Android networking toolkit
designed for rooted devices.

It provides per-device hotspot management, traffic shaping, network
policies, client identification, weak-network simulation, traffic
statistics, DPI-based application identification, and a web-based
management interface.

HNC is designed for users who want more control over Android hotspot
traffic than the stock Android hotspot implementation provides.

> **Status:** Actively developed. Compatibility depends on the Android OEM,
> kernel configuration, root framework, and networking implementation.

---

## Who is HNC for?

### HNC may be a good fit if you:

- Frequently share your mobile hotspot with other devices.
- Need to control the bandwidth used by individual clients.
- Want per-device upload and download traffic limits.
- Need to simulate latency or packet loss for testing.
- Want to block or allow specific hotspot clients.
- Have a rooted Android device.
- Are comfortable using an actively developed system-level networking tool.

### HNC is probably not a good fit if you:

- Do not have root access.
- Do not want to modify the Android system networking environment.
- Expect a commercial-grade "install once and never troubleshoot"
  networking product.
- Use a highly customized or uncommon OEM ROM and cannot provide
  compatibility/debugging information.

---

## Features

### Hotspot Client Management

HNC can discover and display connected hotspot clients, including:

- MAC address
- IP address
- Hostname
- Manufacturer information through OUI lookup
- DHCP / mDNS-derived information
- Connection state
- Per-device traffic statistics

### Per-Device Traffic Control

HNC supports individual traffic policies for hotspot clients:

- Download bandwidth limits
- Upload bandwidth limits
- Network latency simulation
- Packet-loss simulation
- Device blocking
- MAC-based allowlists
- Per-device policy management

Traffic shaping is implemented using Linux/Android networking facilities
such as `tc`, HTB, iptables, IFB, and related kernel mechanisms.

### Traffic Statistics

HNC provides:

- Real-time traffic statistics
- Per-device traffic accounting
- Daily traffic history
- Historical traffic charts
- Upload/download rate information
- Runtime health information

### Web Management Interface

HNC includes a web-based management interface that can be accessed from
the local device and, when explicitly enabled, from another device on
the LAN.

The WebUI provides access to:

- Connected devices
- Traffic controls
- Device policies
- DPI/application information
- Statistics
- Runtime health
- System capabilities
- Configuration
- Remote management

---

## Application Identification / DPI

HNC includes an optional DPI subsystem for application-level traffic
identification.

The DPI engine uses packet-level information and protocol metadata rather
than decrypting application payloads.

Current components include:

- `AF_PACKET` packet capture
- DNS inspection
- TLS ClientHello / SNI extraction
- JA4 fingerprinting
- Rule-based domain/IP matching
- Application attribution
- Optional QUIC Initial analysis through nDPI integration

The DPI subsystem is intended to identify which application or service is
associated with observed network traffic.

It does **not** provide full payload decryption.

---

## What makes HNC different?

| Feature | Description |
|---|---|
| **Kernel-level BPF protection** | Uses LSM/kprobe-based monitoring around BPF-related operations to prevent Android framework networking mechanisms from bypassing traffic-control policies in supported environments. |
| **Self-healing networking** | Multiple recovery layers detect and restore traffic-control rules that may be removed by OEM networking components. |
| **Bidirectional traffic shaping** | Uses different traffic-control paths for download and upload shaping, including HTB, iptables marks, ingress redirection, and IFB where supported. |
| **Remote management security** | Remote management includes TLS, authentication, token-based pairing, CSRF protections, SameSite controls, and DNS-rebinding defenses. |
| **Low dependency footprint** | HNC does not require a separate companion application, Xposed framework, or cloud service for its core functionality. |
| **Capability detection** | HNC detects available kernel/networking capabilities and can degrade gracefully when a feature is unavailable. |
| **Runtime recovery** | Background watchdog and launcher components monitor critical services and attempt automatic recovery. |

---

## Architecture

HNC uses several cooperating components rather than a single monolithic
process.

```text
                         ┌─────────────────────────┐
                         │       User / Browser    │
                         │  KSU WebUI / Web Client  │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │       hnc_httpd         │
                         │       Go HTTP Server     │
                         │                         │
                         │  REST API + WebUI + TLS │
                         └────────────┬────────────┘
                                      │
                ┌─────────────────────┼─────────────────────┐
                │                     │                     │
                ▼                     ▼                     ▼
        ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
        │   hotspotd   │      │  hnc_dpid    │      │ hnc_watchdog │
        │      C       │      │      Go      │      │      Go      │
        │              │      │              │      │              │
        │ Device       │      │ DPI / packet │      │ Process      │
        │ discovery    │      │ inspection   │      │ supervision  │
        │ Netlink      │      │ DNS / TLS    │      │ Recovery     │
        │ DHCP / mDNS  │      │ App rules    │      │ Health       │
        │ Statistics   │      │              │      │              │
        └──────┬───────┘      └──────────────┘      └──────────────┘
               │
               ▼
        ┌───────────────────────────────────────┐
        │        Android / Linux Networking     │
        │                                       │
        │  tc / HTB / IFB / iptables / BPF     │
        │  netlink / kernel interfaces / WLAN  │
        └───────────────────────────────────────┘

Core Components

hotspotd

Written in C.

Responsibilities include:

Hotspot client discovery

Netlink monitoring

DHCP/mDNS information processing

OUI lookup

Device state management

Traffic statistics


hnc_dpid

Written in Go.

Responsibilities include:

DPI packet capture

DNS inspection

TLS metadata extraction

SNI processing

JA4 fingerprinting

Application identification

Rule matching


hnc_httpd

Written in Go.

Responsibilities include:

HTTP server

REST API

WebUI delivery

Authentication

Pairing

TLS / remote access

Runtime state presentation

Action dispatching


The WebUI is embedded into the HTTP server.

hnc_watchdog

Written in Go.

Responsibilities include:

Process supervision

Health monitoring

Automatic recovery

Network-change handling

Traffic-control restoration

Runtime alerts


hnc_launcher

Written in C.

The launcher provides a native fork() / execv() path for supervising components in environments where the Android runtime or OEM security configuration interferes with Go process creation.

This is particularly relevant to certain Android/OEM/root-framework combinations.


---

Networking Stack

HNC integrates with several Android/Linux networking mechanisms:

Android Hotspot
      │
      ▼
   wlan interface
      │
      ├── netlink
      │
      ├── DHCP / mDNS
      │
      ├── iptables / netfilter
      │
      ├── tc / HTB
      │
      ├── IFB / ingress redirection
      │
      ├── BPF / LSM-related controls
      │
      └── AF_PACKET
              │
              ▼
          DPI Engine

Because HNC operates close to the Android/Linux networking stack, compatibility can vary substantially between devices and ROMs.


---

Requirements

Android

Android 13 or newer

BPF and cgroup v2 support required for relevant features


Kernel

Linux kernel 5.10 or newer

Required networking features must be enabled


The current compatibility requirements include:

CONFIG_NET_SCH_HTB
CONFIG_NETFILTER_XT_TARGET_MARK
CONFIG_KPROBES

Additional kernel capabilities may be required by individual features.

Root

Supported root environments include:

KernelSU

SukiSU Ultra

Magisk 26+

KernelSU 11485+ for the currently tested configuration


Architecture

ARM64 / ARMv8


For detailed device and ROM compatibility information, see:

Compatibility Matrix



---

Compatibility

Android networking behavior varies significantly between OEMs.

Known factors include:

OEM modifications to Android networking

Kernel configuration

BPF offload behavior

cgroup configuration

Root framework behavior

Interface naming

Firewall implementation

Wi-Fi chipset behavior

Network switching between Wi-Fi, cellular, and VPN interfaces


HNC therefore performs runtime capability detection where possible.

If your ROM is not listed in the compatibility matrix, you can still test HNC and use the capability information displayed by the WebUI.

See:

COMPATIBILITY.md


---

Known Limitations

Please read these limitations before installing HNC.

Randomized client MAC addresses

Some clients, particularly iOS devices using private Wi-Fi addresses, may present different randomized MAC addresses.

This can cause a device to appear as a different client and therefore prevent persistent per-device policies from matching as expected.

QUIC traffic

Traffic shaping behavior can vary for QUIC-based applications and services.

For some applications, actual perceived bandwidth may differ from the configured limit.

Single hotspot network

The current implementation manages one hotspot SSID at a time and does not provide simultaneous multi-band hotspot control.

Traffic shaping accuracy

Traffic shaping is not intended to provide carrier-grade or enterprise-grade QoS guarantees.

Typical observed accuracy depends on the traffic path and test method.

Application-level traffic identification

HNC can identify devices and, where DPI rules allow, applications/services.

It cannot guarantee identification of every application or encrypted traffic flow.


---

Installation

1. Download the latest release from:

GitHub Releases


2. Install the ZIP using KernelSU or Magisk.


3. Reboot the device.


4. Open the local WebUI:

http://127.0.0.1:8444/

You can also access HNC through the relevant KSU WebUI entry.


5. Complete the initial pairing process shown by the WebUI.



> HNC requires root access and modifies system-level networking behavior. Do not install it on a device where you cannot recover from networking configuration changes.




---

First Run

After installation:

1. Open the WebUI.


2. Allow HNC to complete its initial capability detection.


3. Check the device list.


4. Verify that the hotspot interface is detected correctly.


5. Apply a small test bandwidth limit to a test client.


6. Verify the resulting traffic behavior.


7. Only then configure more advanced policies.



For remote management, enable LAN access only when needed and complete the pairing/authentication process.


---

Diagnostics

When reporting a problem, collect both runtime and environment diagnostics.

Basic health check

su -c 'sh /data/local/hnc/bin/diag.sh' > /sdcard/hnc_diag.txt

Environment report

su -c 'sh /data/local/hnc/bin/diag/diag.sh' > /sdcard/hnc_env.txt

The environment report is particularly useful for compatibility issues involving:

Android version

ROM

Kernel

Root framework

Kernel capabilities

Interface configuration



---

Troubleshooting

Before opening an issue:

1. Run the diagnostic commands above.


2. Check the WebUI capability/status information.


3. Confirm the Android version.


4. Confirm the kernel version.


5. Confirm the root framework and version.


6. Confirm the hotspot interface name.


7. Check whether the problem reproduces after a clean reboot.



When opening an issue, include:

Device model

Android version

ROM / OEM skin

Kernel version

Root framework

HNC version

What you were trying to do

What actually happened

Expected behavior

Relevant diagnostic output


Please remove sensitive information before posting diagnostic files.

Open issues here:

GitHub Issues


---

Privacy

HNC is designed to operate locally.

Local data

HNC stores information such as:

MAC addresses

Hostnames

Device state

Traffic statistics

Runtime information


under:

/data/local/hnc/

External communication

The HNC module does not require an external cloud service for its core operation.

WebUI

The WebUI listens on:

127.0.0.1

by default.

LAN access must be explicitly enabled.

When remote access is enabled, HNC uses authentication and pairing mechanisms intended to prevent unauthorized access.


---

Security

HNC runs with elevated privileges and interacts directly with Android/Linux networking components.

Security is therefore an important part of the project's development and maintenance process.

Security-sensitive areas include:

Web API authentication and authorization

Remote WebUI access

Token management

Privileged shell execution

Traffic-control rules

Firewall rules

Background daemons

Configuration files

Root-level system interaction

Network input processing


HNC includes security-related controls such as:

TLS for remote management

Token-based authentication

Pairing

bcrypt-based credential protection

CSRF protection

SameSite controls

DNS rebinding defenses

Input validation

Permission and ownership checks

Runtime recovery and failure handling


Reporting a vulnerability

Do not report security vulnerabilities through public GitHub Issues.

Please follow the process described in:

SECURITY.md


---

Development

HNC is a multi-language Android/Linux networking project.

Main technologies

C

Go

Shell

HTML

CSS

JavaScript


Networking technologies

Linux netlink

tc

HTB

IFB

iptables / netfilter

BPF

LSM / kprobe

AF_PACKET

DNS

TLS metadata

mDNS

DHCP


Repository structure

hnc-v6/
├── .github/
│   └── workflows/
├── META-INF/
├── bin/
├── daemon/
├── data/
├── docs/
├── patches/
├── src/
├── test/
├── third_party/
├── third_party_build/
├── third_party_prebuilt/
├── tools/
├── webroot/
├── module.prop
├── post-fs-data.sh
├── service.sh
├── uninstall.sh
├── ARCHITECTURE.md
├── CHANGELOG.md
├── COMPATIBILITY.md
├── SECURITY.md
└── README.md

For deeper architectural information, see:

ARCHITECTURE.md


---

CI and Testing

The project uses CI for build and static validation.

Depending on the change, validation may include:

Shell syntax checks
Go formatting / vet / tests
Android ARM64 cross-compilation
JavaScript syntax checks
Build artifact validation
Runtime configuration checks

Changes affecting runtime behavior should be tested on real Android hardware whenever possible.


---

Contributing

Contributions are welcome.

Useful ways to contribute include:

Reporting bugs

Testing on additional devices

Reporting ROM compatibility

Improving documentation

Improving tests

Reviewing code

Fixing bugs

Improving networking compatibility

Proposing new features


Compatibility reports

If you test HNC on a new device or ROM, include:

Device model

Android version

ROM

Kernel version

Root framework

HNC version

Working / partially working / broken features


Add compatible devices to:

COMPATIBILITY.md

Pull requests

Before submitting a significant change:

1. Read ARCHITECTURE.md.


2. Understand the affected component.


3. Keep changes scoped where possible.


4. Run the relevant CI/local checks.


5. Test behavior on real hardware when applicable.


6. Document compatibility or behavioral changes.




---

Documentation

Key project documentation:

Architecture

Compatibility Matrix

Security Policy

Changelog

Evolution History


Additional engineering notes and historical design documents are available in the repository.


---

Project Status

HNC is actively maintained and continues to evolve across:

Networking

Traffic control

Android compatibility

DPI

WebUI

Runtime reliability

Security

Diagnostics

Performance


The exact release version is generated by the project's build/release workflow.

For the latest release, see:

GitHub Releases


---

License

The repository currently does not present a finalized license file.

See:

LICENSE.TODO

Please check the repository's licensing status before redistributing or incorporating HNC into another project.


---

Acknowledgements

HNC is maintained as an independent open-source project.

Development has involved AI-assisted engineering and review, including Claude and GPT-based tools. All project changes remain subject to maintainer review, testing, and project-specific validation.


---

<a id="中文"></a>

中文

项目简介

HNC（Hotspot Network Control）是一套面向 Root Android 设备的 开源热点网络管理与流量控制工具。

HNC 提供设备级热点管理、上下行限速、网络策略、客户端识别、 弱网模拟、流量统计、DPI 应用识别以及 Web 管理界面等功能。

HNC 主要面向希望获得比 Android 原生热点更精细网络控制能力的用户。

> **项目状态：**持续开发中。实际功能取决于 Android OEM、内核配置、 Root 框架以及具体网络实现。




---

适合哪些人？

如果你：

经常使用手机热点并分享给其他设备；

希望限制某些设备占用的带宽；

需要对不同设备分别设置上传/下载速度；

需要模拟延迟或丢包环境；

希望拉黑或允许指定热点客户端；

拥有 Root Android 设备；

可以接受一个仍在持续迭代的系统级网络工具；


那么 HNC 可能适合你。

如果你：

没有 Root；

不希望修改 Android 系统网络环境；

希望获得“安装后永远无需维护”的商用级产品体验；

使用非常特殊的 OEM ROM，同时无法配合进行兼容性调试；


那么 HNC 可能不适合你。


---

核心功能

热点客户端管理

HNC 可以识别并显示连接到热点的设备，包括：

MAC 地址

IP 地址

Hostname

基于 OUI 的厂商信息

DHCP / mDNS 信息

设备连接状态

单设备流量统计


单设备流量控制

HNC 支持针对单个热点客户端设置网络策略：

下载限速

上传限速

网络延迟模拟

丢包模拟

设备拉黑

基于 MAC 的白名单

单设备策略管理


流量控制主要使用 Linux / Android 网络机制，包括：

tc

HTB

iptables

IFB

BPF

相关内核网络机制


流量统计

HNC 提供：

实时流量统计

单设备流量统计

每日流量记录

历史流量曲线

上下行速率

运行健康状态


Web 管理界面

HNC 内置 WebUI，可以在手机本机访问，并可以在显式开启 LAN 访问后通过局域网中的其他设备进行管理。

WebUI 提供：

在线设备列表

流量控制

设备策略

DPI / 应用识别信息

流量统计

运行健康

系统能力检测

配置

远程管理



---

应用识别 / DPI

HNC 包含可选的 DPI 流量识别组件。

DPI 主要通过数据包和协议元数据进行应用/服务识别，而不是对 应用层数据进行解密。

当前相关组件包括：

AF_PACKET 抓包

DNS 查询分析

TLS ClientHello / SNI 提取

JA4 指纹

域名/IP 规则匹配

应用归属

可选的 nDPI QUIC Initial 分析


DPI 的主要目标是判断观察到的网络流量属于哪个应用或服务。

它不提供完整的应用层数据解密能力。


---

HNC 的特点

特性	说明

BPF 内核级控制	在支持的环境中通过 LSM/kprobe 等机制监视与 BPF 相关的操作，减少 Android 网络机制绕过流量控制策略的可能性。
自愈式网络栈	通过多层恢复机制检测并恢复可能被 OEM 网络组件删除的流量控制规则。
双向流量控制	根据上下行网络路径使用 HTB、iptables mark、ingress 重定向、IFB 等机制进行流量控制。
远程管理安全机制	包含 TLS、身份认证、Token 配对、CSRF 防护、SameSite 控制以及 DNS Rebinding 防护。
低依赖	核心功能不需要额外 Companion App、Xposed 或云服务。
能力检测	自动检测当前设备支持的网络能力，并在部分功能不可用时进行能力降级。
运行时自愈	Watchdog 与 Launcher 负责监控关键后台服务，并在故障时尝试恢复。



---

整体架构

HNC 并不是单一进程，而是由多个相互协作的组件组成。

┌─────────────────────────┐
                         │     用户 / 浏览器       │
                         │ KSU WebUI / Web Client  │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │       hnc_httpd         │
                         │       Go HTTP Server     │
                         │                         │
                         │ REST API + WebUI + TLS │
                         └────────────┬────────────┘
                                      │
                ┌─────────────────────┼─────────────────────┐
                │                     │                     │
                ▼                     ▼                     ▼
        ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
        │   hotspotd   │      │  hnc_dpid    │      │ hnc_watchdog │
        │      C       │      │      Go      │      │      Go      │
        │              │      │              │      │              │
        │ 设备发现     │      │ DPI / 抓包   │      │ 进程守护     │
        │ Netlink      │      │ DNS / TLS    │      │ 故障恢复     │
        │ DHCP / mDNS  │      │ 应用识别     │      │ 健康检查     │
        │ 流量统计     │      │ 规则匹配     │      │              │
        └──────┬───────┘      └──────────────┘      └──────────────┘
               │
               ▼
        ┌───────────────────────────────────────┐
        │          Android / Linux 网络栈       │
        │                                       │
        │  tc / HTB / IFB / iptables / BPF     │
        │  netlink / kernel interfaces / WLAN  │
        └───────────────────────────────────────┘

核心组件

hotspotd

C 语言实现。

主要负责：

热点设备发现

Netlink 监听

DHCP / mDNS 信息处理

OUI 查询

设备状态管理

流量统计


hnc_dpid

Go 语言实现。

主要负责：

DPI 抓包

DNS 分析

TLS 元数据提取

SNI 处理

JA4 指纹

应用识别

规则匹配


hnc_httpd

Go 语言实现。

主要负责：

HTTP 服务

REST API

WebUI

身份认证

配对

TLS / 远程访问

状态展示

Action 调度


WebUI 静态资源会被嵌入 HTTP 服务。

hnc_watchdog

Go 语言实现。

主要负责：

进程守护

健康检查

自动恢复

网络变化处理

流量控制规则恢复

运行状态告警


hnc_launcher

C 语言实现。

负责在部分 Android/OEM/Root 环境下通过原生 fork() / execv() 路径启动和守护相关组件。


---

网络技术栈

HNC 与 Android/Linux 网络栈的多个层级进行交互：

Android Hotspot
      │
      ▼
   wlan interface
      │
      ├── netlink
      │
      ├── DHCP / mDNS
      │
      ├── iptables / netfilter
      │
      ├── tc / HTB
      │
      ├── IFB / ingress redirection
      │
      ├── BPF / LSM-related controls
      │
      └── AF_PACKET
              │
              ▼
          DPI Engine

由于 HNC 工作在 Android/Linux 网络栈较底层的位置， 不同设备之间可能存在明显的兼容性差异。


---

系统要求

Android

Android 13 或更高版本

相关功能需要 BPF 和 cgroup v2 支持


内核

Linux Kernel 5.10+

需要启用相关网络功能


目前主要兼容性要求包括：

CONFIG_NET_SCH_HTB
CONFIG_NETFILTER_XT_TARGET_MARK
CONFIG_KPROBES

不同功能可能还需要额外的内核能力。

Root

目前主要支持：

KernelSU

SukiSU Ultra

Magisk 26+

当前测试环境中的 KernelSU 11485+


架构

ARM64 / ARMv8


详细兼容性请查看：

COMPATIBILITY.md


---

兼容性

Android 不同 OEM 对网络栈的修改差异很大。

可能影响 HNC 的因素包括：

OEM 对 Android 网络栈的修改；

内核配置；

BPF offload 行为；

cgroup 配置；

Root 框架行为；

网络接口命名；

防火墙实现；

Wi-Fi 芯片行为；

Wi-Fi / 蜂窝网络 / VPN 之间的网络切换。


因此 HNC 会尽可能进行运行时能力检测。

如果你的 ROM 不在兼容性列表中，可以直接测试， WebUI 会显示当前设备实际检测到的能力。

详细信息：

COMPATIBILITY.md


---

已知限制

随机 MAC 地址

部分客户端，尤其是启用了私有 Wi-Fi 地址的 iOS 设备， 可能使用随机 MAC 地址。

因此同一设备可能被识别为不同客户端，从而导致单设备规则 无法持续匹配。

QUIC

基于 QUIC 的应用和服务可能具有较强的带宽弹性。

因此部分应用的实际体验可能与配置的限速值存在差异。

单热点网络

当前实现一次管理一个热点 SSID，不支持同时管理多个热点 频段。

限速精度

HNC 并不以运营商级或企业级 QoS 精度为目标。

实际精度会受到网络路径、内核、OEM 实现以及测试方式影响。

应用识别

HNC 可以识别设备，并在 DPI 规则允许的情况下识别应用/服务。

但无法保证对所有应用和所有加密流量进行准确识别。


---

安装

1. 从 GitHub Releases 下载最新版本：

Releases


2. 使用 KernelSU 或 Magisk 安装 ZIP。


3. 重启设备。


4. 手机浏览器访问：

http://127.0.0.1:8444/

也可以通过相应的 KSU WebUI 入口进入。


5. 按 WebUI 提示完成首次配对。



> HNC 需要 Root 权限，并会修改系统级网络行为。 请不要在无法恢复网络配置的设备上盲目安装。




---

首次使用

安装完成后：

1. 打开 WebUI。


2. 等待首次能力检测完成。


3. 检查热点设备列表。


4. 确认热点接口被正确识别。


5. 选择一个测试设备设置较低的限速。


6. 验证实际网络效果。


7. 再开始配置更复杂的策略。



如果需要远程管理，请只在必要时开启 LAN 访问， 并完成 WebUI 的配对/认证流程。


---

故障诊断

遇到问题时，建议同时收集运行状态和环境信息。

基础健康检查

su -c 'sh /data/local/hnc/bin/diag.sh' > /sdcard/hnc_diag.txt

环境信息

su -c 'sh /data/local/hnc/bin/diag/diag.sh' > /sdcard/hnc_env.txt

环境报告对于以下兼容性问题尤其有帮助：

Android 版本

ROM

Kernel

Root 框架

Kernel 能力

网络接口配置



---

故障排查

提交 Issue 前建议：

1. 执行上述诊断命令；


2. 检查 WebUI 的能力/状态信息；


3. 确认 Android 版本；


4. 确认 Kernel 版本；


5. 确认 Root 框架及版本；


6. 确认热点接口名称；


7. 重启后再次确认问题是否存在。



提交 Issue 时请提供：

设备型号

Android 版本

ROM / OEM

Kernel 版本

Root 框架

HNC 版本

进行了什么操作

实际出现什么现象

预期行为

相关诊断信息


发布诊断文件前，请删除其中可能包含的敏感信息。

Issue：

GitHub Issues


---

隐私

HNC 主要设计为本地运行。

本地数据

HNC 可能在本地保存：

MAC 地址

Hostname

设备状态

流量统计

运行状态信息


默认存储目录：

/data/local/hnc/

外部通信

HNC 的核心功能不依赖外部云服务。

WebUI

WebUI 默认监听：

127.0.0.1

如需局域网访问，需要用户主动开启。

开启远程访问后，HNC 会使用认证和配对机制限制未经授权的访问。


---

安全

HNC 运行于较高权限环境，并直接与 Android/Linux 网络组件进行交互。

因此安全性是项目开发与维护的重要组成部分。

安全敏感区域包括：

Web API 认证与授权

远程 WebUI

Token 管理

高权限 Shell 执行

流量控制规则

防火墙规则

后台守护进程

配置文件

Root 级系统操作

网络输入处理


项目包含以下安全相关机制：

TLS

Token 身份认证

配对机制

bcrypt 凭据保护

CSRF 防护

SameSite 控制

DNS Rebinding 防护

输入验证

权限/文件所有权检查

运行时故障恢复


报告安全漏洞

请不要通过公开 GitHub Issue 报告安全漏洞。

请按照：

SECURITY.md

中的流程进行报告。


---

开发

HNC 是一个多语言 Android/Linux 网络项目。

主要语言

C

Go

Shell

HTML

CSS

JavaScript


网络技术

Linux Netlink

tc

HTB

IFB

iptables / netfilter

BPF

LSM / kprobe

AF_PACKET

DNS

TLS 元数据

mDNS

DHCP


仓库结构

hnc-v6/
├── .github/
│   └── workflows/
├── META-INF/
├── bin/
├── daemon/
├── data/
├── docs/
├── patches/
├── src/
├── test/
├── third_party/
├── third_party_build/
├── third_party_prebuilt/
├── tools/
├── webroot/
├── module.prop
├── post-fs-data.sh
├── service.sh
├── uninstall.sh
├── ARCHITECTURE.md
├── CHANGELOG.md
├── COMPATIBILITY.md
├── SECURITY.md
└── README.md

深入架构说明：

ARCHITECTURE.md


---

CI 与测试

项目使用 CI 进行构建和静态检查。

根据修改内容，验证项目可能包括：

Shell 语法检查
Go 格式化 / vet / tests
Android ARM64 交叉编译
JavaScript 语法检查
构建产物检查
运行时配置检查

涉及运行行为的修改，应尽可能在真实 Android 硬件上验证。


---

参与贡献

欢迎参与 HNC 的开发与维护。

你可以通过以下方式参与：

提交 Bug

测试新的设备

提交 ROM 兼容性信息

改进文档

增加测试

参与代码审查

修复 Bug

改进网络兼容性

提出新功能


提交兼容性信息

如果你在新的设备或 ROM 上测试 HNC，请提供：

设备型号

Android 版本

ROM

Kernel 版本

Root 框架

HNC 版本

正常 / 部分正常 / 不工作功能


并将结果补充到：

COMPATIBILITY.md

提交 Pull Request

在提交较大的修改之前：

1. 阅读 ARCHITECTURE.md；


2. 理解受影响组件；


3. 尽可能保持修改范围明确；


4. 运行对应的 CI / 本地检查；


5. 涉及运行行为时进行真机测试；


6. 记录兼容性或行为变化。




---

文档

主要项目文档：

架构说明

兼容性矩阵

安全策略

更新日志

项目演化历史


其他工程记录和历史设计文档可以在仓库中找到。


---

项目状态

HNC 目前仍在持续维护和开发，主要涉及：

网络控制

流量整形

Android 兼容性

DPI

WebUI

运行稳定性

安全

诊断

性能优化


具体版本号由项目构建/发布流程自动生成。

最新版本：

GitHub Releases


---

License

当前仓库尚未提供最终确定的 License 文件。

详见：

LICENSE.TODO

在重新发布、二次开发或将 HNC 集成到其他项目之前， 请确认当前仓库的授权状态。


---

致谢

HNC 是一个独立维护的开源项目。

项目开发过程中使用了 AI 辅助开发和代码审查工具， 包括 Claude 和 GPT 系列工具。

所有代码变更仍需要经过维护者审查、测试以及项目自身的验证流程。


---

English / 中文导航

English

Overview

Features

Architecture

Requirements

Compatibility

Installation

Diagnostics

Security

Development

Contributing


中文

项目简介

核心功能

整体架构

系统要求

兼容性

安装

故障诊断

安全

开发

参与贡献
