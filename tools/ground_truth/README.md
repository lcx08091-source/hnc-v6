# HNC Ground Truth 抓包工具

为 HNC 规则库提供高质量数据的工具集.

## 文件

- `capture.sh` - Termux/root 跑 tcpdump + dumpsys 同时抓包
- `analyze.py` - 解析 pcap, 按 App 归因 SNI/IP/端口
- `sni_to_rules.py` - 简化版规则生成器
- `sni_to_rules_v2.py` - 精细分类版规则生成器

## 用法

详见 PATCH-NOTES-v5.3.0-rc28.1.md.

## 依赖

- Termux + root
- `pkg install tcpdump`
- Python 端: `pip install scapy --break-system-packages`
