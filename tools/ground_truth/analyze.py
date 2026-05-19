#!/usr/bin/env python3
"""
analyze.py - 解析 capture.sh 抓的 pcap + foreground 日志, 生成"App → 域名/IP/端口"映射

依赖: scapy (pip install scapy)
用法:
    python3 analyze.py trace-xxx.pcap foreground-xxx.log [meta-xxx.json]

输出:
    sni-ground-truth-result.json
"""

import sys
import os
import json
import struct
import re
import argparse
from collections import defaultdict
from datetime import datetime


def parse_foreground_log(log_path):
    """解析前台日志: 每行 'TS PKG_NAME', 返回 list[(ts, pkg)]"""
    events = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            try:
                ts = int(parts[0])
                pkg = parts[1].strip()
                if pkg and pkg != 'unknown':
                    events.append((ts, pkg))
            except ValueError:
                continue
    return events


def package_at_time(events, ts):
    """二分查找时刻 ts 时的前台 App"""
    if not events:
        return 'unknown'
    # 找最大的 event_ts <= ts
    best = 'unknown'
    for ev_ts, pkg in events:
        if ev_ts <= ts:
            best = pkg
        else:
            break
    return best


def extract_sni_from_tls_clienthello(payload):
    """从 TLS ClientHello 提 SNI. 简化版, 只处理最常见结构"""
    try:
        # TLS Record: type(1) + version(2) + length(2) + handshake
        if len(payload) < 6:
            return None
        if payload[0] != 0x16:  # not handshake
            return None
        # Handshake: type(1) + length(3) + ...
        hs_off = 5
        if len(payload) < hs_off + 4:
            return None
        if payload[hs_off] != 0x01:  # not ClientHello
            return None
        # ClientHello body: ver(2) + random(32) + sid_len(1) + sid + cipher_len(2) + ciphers + comp_len(1) + comps + ext_len(2) + exts
        p = hs_off + 4 + 2 + 32  # past version + random
        if p >= len(payload):
            return None
        sid_len = payload[p]
        p += 1 + sid_len
        if p + 2 > len(payload):
            return None
        cipher_len = struct.unpack('>H', payload[p:p+2])[0]
        p += 2 + cipher_len
        if p >= len(payload):
            return None
        comp_len = payload[p]
        p += 1 + comp_len
        if p + 2 > len(payload):
            return None
        ext_len = struct.unpack('>H', payload[p:p+2])[0]
        p += 2
        ext_end = min(p + ext_len, len(payload))
        # 遍历 extensions, 找 type=0 (SNI)
        while p + 4 <= ext_end:
            ext_type = struct.unpack('>H', payload[p:p+2])[0]
            ext_data_len = struct.unpack('>H', payload[p+2:p+4])[0]
            p += 4
            if ext_type == 0:  # SNI
                # SNI extension: list_len(2) + entries (type(1) + name_len(2) + name)
                if p + 2 > len(payload):
                    return None
                # list_len = struct.unpack('>H', payload[p:p+2])[0]
                p += 2
                if p + 3 > len(payload):
                    return None
                # name_type = payload[p]  # 0 = host_name
                name_len = struct.unpack('>H', payload[p+1:p+3])[0]
                p += 3
                if p + name_len > len(payload):
                    return None
                sni = payload[p:p+name_len].decode('ascii', errors='replace')
                # 校验合法域名
                if re.match(r'^[a-zA-Z0-9._-]+$', sni) and '.' in sni:
                    return sni.lower()
                return None
            p += ext_data_len
        return None
    except Exception:
        return None


def extract_quic_sni(payload):
    """简化 QUIC SNI 提取 - 检测 Long header + version
    完整解密需 HKDF/AES-GCM, 此处只检测是否是 QUIC Initial 包"""
    try:
        if len(payload) < 7:
            return None
        first = payload[0]
        if first & 0x80 == 0:  # short header
            return None
        if first & 0x40 == 0:  # fixed bit
            return None
        # 提 version (4 bytes after first byte)
        version = struct.unpack('>I', payload[1:5])[0]
        return ('QUIC', version)
    except Exception:
        return None


def parse_dns_query(payload):
    """从 DNS 包提 query name (只处理 query, 不处理 answer)"""
    try:
        if len(payload) < 12:
            return None
        # DNS header: id(2) + flags(2) + qdcount(2) + ancount(2) + nscount(2) + arcount(2)
        flags = struct.unpack('>H', payload[2:4])[0]
        qdcount = struct.unpack('>H', payload[4:6])[0]
        if qdcount == 0:
            return None
        is_response = (flags & 0x8000) != 0
        if is_response:  # 只处理 query
            return None
        # Query: name + type(2) + class(2)
        p = 12
        labels = []
        while p < len(payload):
            length = payload[p]
            if length == 0:
                break
            if length & 0xc0:  # 压缩指针
                return None
            p += 1
            if p + length > len(payload):
                return None
            try:
                labels.append(payload[p:p+length].decode('ascii'))
            except UnicodeDecodeError:
                return None
            p += length
        if not labels:
            return None
        name = '.'.join(labels).lower()
        if not re.match(r'^[a-z0-9._-]+$', name) or '.' not in name:
            return None
        return name
    except Exception:
        return None


def analyze_pcap(pcap_path, foreground_events):
    """主分析函数"""
    try:
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP, Raw
    except ImportError:
        print("❌ 需要 scapy: pip install scapy", file=sys.stderr)
        sys.exit(1)
    
    print(f"读取 pcap: {pcap_path}", file=sys.stderr)
    packets = rdpcap(pcap_path)
    print(f"总包数: {len(packets)}", file=sys.stderr)
    
    # 数据结构: { pkg -> { 'sni': Counter, 'flows': set((ip,port,proto)), 'dns': Counter, 'quic_count': int } }
    apps_data = defaultdict(lambda: {
        'sni': defaultdict(int),
        'flows': defaultdict(int),  # (ip, port, proto) -> count
        'dns_queries': defaultdict(int),
        'quic_count': 0,
        'tls_count': 0,
        'first_ts': None,
        'last_ts': None,
    })
    
    n_processed = 0
    n_with_sni = 0
    n_dns = 0
    n_quic = 0
    
    for pkt in packets:
        if not (IP in pkt or IPv6 in pkt):
            continue
        
        # 时间戳
        ts = int(pkt.time)
        pkg = package_at_time(foreground_events, ts)
        
        # IP/IPv6
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
        else:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        
        # TCP / UDP
        if TCP in pkt:
            proto = 'tcp'
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            payload = bytes(pkt[TCP].payload) if pkt[TCP].payload else b''
        elif UDP in pkt:
            proto = 'udp'
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            payload = bytes(pkt[UDP].payload) if pkt[UDP].payload else b''
        else:
            continue
        
        n_processed += 1
        data = apps_data[pkg]
        
        if data['first_ts'] is None:
            data['first_ts'] = ts
        data['last_ts'] = ts
        
        # 判方向: 一般本机 IP 是 192.168/10.*/172.16-31.* 之类
        is_outbound = is_local_ip(src) and not is_local_ip(dst)
        is_inbound = is_local_ip(dst) and not is_local_ip(src)
        
        remote_ip = dst if is_outbound else (src if is_inbound else dst)
        remote_port = dport if is_outbound else (sport if is_inbound else dport)
        
        # 记录 (remote_ip, port, proto) 流统计
        data['flows'][(remote_ip, remote_port, proto)] += 1
        
        # 提 SNI
        if dport == 443 and proto == 'tcp' and len(payload) > 50:
            sni = extract_sni_from_tls_clienthello(payload)
            if sni:
                data['sni'][sni] += 1
                data['tls_count'] += 1
                n_with_sni += 1
        elif dport == 443 and proto == 'udp' and len(payload) > 30:
            # QUIC Initial 检测 (不解密)
            q = extract_quic_sni(payload)
            if q is not None:
                data['quic_count'] += 1
                n_quic += 1
        elif (dport == 53 or sport == 53) and proto == 'udp' and len(payload) > 12:
            name = parse_dns_query(payload)
            if name:
                data['dns_queries'][name] += 1
                n_dns += 1
    
    print(f"已处理: {n_processed}, SNI: {n_with_sni}, DNS: {n_dns}, QUIC Init: {n_quic}", file=sys.stderr)
    return apps_data


def is_local_ip(ip):
    """判断是不是本机/内网 IP"""
    if ':' in ip:  # IPv6
        return ip.startswith('fe80:') or ip.startswith('::1') or ip == '::'
    if not ip:
        return False
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        a = int(parts[0])
        b = int(parts[1])
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        if a == 127:
            return True
        if a == 100 and 64 <= b <= 127:  # carrier-grade NAT
            return True
        return False
    except ValueError:
        return False


def build_output(apps_data, meta_data):
    """生成最终 JSON"""
    apps_list = []
    for pkg, data in apps_data.items():
        if pkg == 'unknown' or not data['sni'] and not data['flows']:
            continue
        
        # SNI 列表 (按计数降序)
        domains = []
        for sni, count in sorted(data['sni'].items(), key=lambda x: -x[1]):
            domains.append({
                'sni': sni,
                'count': count,
                'source': 'tls-sni',
            })
        
        # DNS 列表
        dns_list = []
        for name, count in sorted(data['dns_queries'].items(), key=lambda x: -x[1])[:50]:
            dns_list.append({'name': name, 'count': count})
        
        # 流量 IP 聚合 (按 IP/24 + 端口范围合并)
        flows_agg = defaultdict(lambda: {'count': 0, 'ports': set(), 'proto': set()})
        for (ip, port, proto), count in data['flows'].items():
            if ':' in ip:  # IPv6, /48 聚合
                key = ':'.join(ip.split(':')[:3]) + '::/48'
            else:  # IPv4, /24 聚合
                key = '.'.join(ip.split('.')[:3]) + '.0/24'
            flows_agg[key]['count'] += count
            flows_agg[key]['ports'].add(port)
            flows_agg[key]['proto'].add(proto)
        
        ip_flows = []
        for cidr, info in sorted(flows_agg.items(), key=lambda x: -x[1]['count'])[:30]:
            ports = sorted(info['ports'])
            ip_flows.append({
                'cidr': cidr,
                'count': info['count'],
                'protos': sorted(info['proto']),
                'port_min': min(ports),
                'port_max': max(ports),
                'port_count': len(ports),
                'sample_ports': ports[:10],
            })
        
        app = {
            'package_name': pkg,
            'observation_count': sum(data['sni'].values()) + sum(data['dns_queries'].values()),
            'tls_sni_count': data['tls_count'],
            'quic_initial_count': data['quic_count'],
            'first_seen_ts': data['first_ts'],
            'last_seen_ts': data['last_ts'],
            'foreground_seconds': (data['last_ts'] - data['first_ts'] + 1) if data['first_ts'] else 0,
            'domains': domains,
            'dns_queries': dns_list,
            'ip_flow_groups': ip_flows,
        }
        apps_list.append(app)
    
    apps_list.sort(key=lambda a: -a['observation_count'])
    
    output = {
        'schema_version': '1.0',
        'tool': 'sni-ground-truth-analyzer',
        'generated_at': datetime.now().isoformat(),
        'source_meta': meta_data or {},
        'app_count': len(apps_list),
        'apps': apps_list,
    }
    return output


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('pcap', help='path to .pcap file')
    ap.add_argument('log', help='path to foreground log file')
    ap.add_argument('--meta', help='path to meta.json file', default=None)
    ap.add_argument('-o', '--output', help='output JSON', default='sni-ground-truth-result.json')
    args = ap.parse_args()
    
    print(f"读取前台日志: {args.log}", file=sys.stderr)
    foreground_events = parse_foreground_log(args.log)
    print(f"前台事件数: {len(foreground_events)}", file=sys.stderr)
    if foreground_events:
        unique_pkgs = set(e[1] for e in foreground_events)
        print(f"前台 App: {len(unique_pkgs)} 个", file=sys.stderr)
        for p in sorted(unique_pkgs):
            print(f"  - {p}", file=sys.stderr)
    
    meta_data = None
    if args.meta and os.path.exists(args.meta):
        with open(args.meta) as f:
            meta_data = json.load(f)
    
    apps_data = analyze_pcap(args.pcap, foreground_events)
    
    output = build_output(apps_data, meta_data)
    
    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ 写入: {args.output}", file=sys.stderr)
    print(f"   {output['app_count']} 个 App", file=sys.stderr)
    for app in output['apps'][:5]:
        print(f"   {app['package_name']}: {len(app['domains'])} 个 SNI, {len(app['ip_flow_groups'])} 个 IP 段", file=sys.stderr)


if __name__ == '__main__':
    main()
