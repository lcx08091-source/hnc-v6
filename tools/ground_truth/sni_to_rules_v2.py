#!/usr/bin/env python3
"""把 sni-labeler 导出转成 HNC dpi_rules.json - v2 精细版

改进:
- 严格过滤乱码 SNI
- 按用途分类 (核心/CDN/广告/反外挂/崩溃 等)
- 区分"App 专属"和"共享 SDK"
- 输出按 confidence 分级 (high/medium/low)
- 标注每条规则的证据来源 + 计数
"""

import json
import re
import sys
from collections import defaultdict, Counter

# 已知 App 元数据 (扩展到 30+ 常见 App)
APP_META = {
    # 视频
    'com.ss.android.ugc.aweme': {'name': '抖音', 'category': 'video', 'publisher': 'bytedance'},
    'com.smile.gifmaker': {'name': '快手', 'category': 'video', 'publisher': 'kuaishou'},
    'tv.danmaku.bili': {'name': '哔哩哔哩', 'category': 'video', 'publisher': 'bilibili'},
    'com.kuaishou.nebula': {'name': '快手极速版', 'category': 'video', 'publisher': 'kuaishou'},
    'com.ss.android.ugc.aweme.lite': {'name': '抖音极速版', 'category': 'video', 'publisher': 'bytedance'},
    # 社交
    'com.tencent.mobileqq': {'name': 'QQ', 'category': 'social', 'publisher': 'tencent'},
    'com.tencent.mm': {'name': '微信', 'category': 'social', 'publisher': 'tencent'},
    # 游戏 - 腾讯
    'com.tencent.tmgp.sgame': {'name': '王者荣耀', 'category': 'game', 'publisher': 'tencent'},
    'com.tencent.tmgp.codev': {'name': '无畏契约', 'category': 'game', 'publisher': 'tencent'},
    'com.tencent.tmgp.pubgmhd': {'name': '和平精英', 'category': 'game', 'publisher': 'tencent'},
    'com.tencent.tmgp.cf': {'name': '穿越火线手游', 'category': 'game', 'publisher': 'tencent'},
    'com.tencent.tmgp.cod': {'name': '使命召唤手游', 'category': 'game', 'publisher': 'tencent'},
    'com.tencent.lolm': {'name': '英雄联盟手游', 'category': 'game', 'publisher': 'tencent'},
    'com.tencent.luoke': {'name': '洛克王国', 'category': 'game', 'publisher': 'tencent'},
    # 游戏 - 米哈游
    'com.miHoYo.Yuanshen': {'name': '原神', 'category': 'game', 'publisher': 'mihoyo'},
    'com.miHoYo.GenshinImpact': {'name': '原神(国际)', 'category': 'game', 'publisher': 'mihoyo'},
    'com.miHoYo.hkrpg': {'name': '崩坏星穹铁道', 'category': 'game', 'publisher': 'mihoyo'},
    'com.miHoYo.bh3': {'name': '崩坏3', 'category': 'game', 'publisher': 'mihoyo'},
    # 游戏 - 网易
    'com.netease.party': {'name': '蛋仔派对', 'category': 'game', 'publisher': 'netease'},
    'com.netease.onmyoji': {'name': '阴阳师', 'category': 'game', 'publisher': 'netease'},
    'com.netease.dwrg': {'name': '第五人格', 'category': 'game', 'publisher': 'netease'},
    'com.netease.hyxd': {'name': '永劫无间手游', 'category': 'game', 'publisher': 'netease'},
}

# 共享 SDK / 平台域名 - 不应该归到某个具体 App
SHARED_SDK_SUFFIXES = {
    # 腾讯系共享
    'crashsight.qq.com': '腾讯崩溃上报',
    'perfsight.qq.com': '腾讯性能监控',
    'snowflake.qq.com': '腾讯风控',
    'gcloud.qq.com': '腾讯云端配置',
    'rdelivery.qq.com': '腾讯灰度发布',
    'gtimg.cn': '腾讯 CDN',
    'gtimg.com': '腾讯 CDN',
    'qpic.cn': '腾讯图片 CDN',
    # 测试 / 检测域名
    'example.com': '网络检测',
    'google.com': '网络检测',
    'gstatic.com': 'Google 资源',
    # 厂商系统
    'samsung.com': '三星系统',
    'huawei.com': '华为系统',
    'xiaomi.com': '小米系统',
    'oppo.com': 'OPPO 系统',
    'vivo.com': 'vivo 系统',
}

def is_real_sni(s):
    if not s: return False
    if not re.match(r'^[a-z0-9._-]+$', s): return False
    if '.' not in s: return False
    if s.startswith('-') or s.startswith('.'): return False
    if s.endswith('.'): return False
    if re.match(r'^[\d.]+$', s): return False
    return True

def get_root_suffix(sni):
    """提取根域: api.live.amemv.com -> amemv.com"""
    parts = sni.split('.')
    if len(parts) >= 3 and parts[-1] in ('cn','hk','tw') and parts[-2] in ('com','net','org'):
        return '.'.join(parts[-3:])
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return sni

def is_shared_sdk(suffix):
    return suffix in SHARED_SDK_SUFFIXES

def classify_purpose(sni):
    s = sni.lower()
    if 'crashsight' in s or 'crashlytics' in s or 'sentry' in s:
        return 'crash'
    if 'perfsight' in s or 'beacon' in s or '.log.' in s or 'log-' in s:
        return 'telemetry'
    if 'tgpa' in s or 'anticheat' in s:
        return 'anticheat'
    if 'snowflake' in s:
        return 'risk'
    if 'cloudctrl' in s or 'rdelivery' in s:
        return 'config'
    if 'doubleclick' in s or 'googlead' in s or 'gdt.qq.com' in s:
        return 'ad'
    if 'umeng' in s or 'mmstat' in s:
        return 'analytics'
    if 'cdn' in s or '-pic' in s or '.pic.' in s or 'static' in s or 'vod' in s:
        return 'cdn'
    if 'example.com' in s or s == 'google.com' or 'gstatic.com' in s:
        return 'system_probe'
    return 'core'

def main():
    if len(sys.argv) < 2:
        print("用法: python3 sni_to_rules_v2.py <export.json> [-o output.json]")
        sys.exit(1)
    
    in_path = sys.argv[1]
    out_path = 'dpi_rules_v2.json'
    if '-o' in sys.argv:
        out_path = sys.argv[sys.argv.index('-o') + 1]
    
    with open(in_path) as f:
        data = json.load(f)
    
    rules = []
    shared_sdk_observations = defaultdict(int)
    
    for app in data.get('apps', []):
        pkg = app.get('package_name', '')
        label = app.get('app_label', '')
        
        # 元数据
        meta = APP_META.get(pkg, {})
        name = meta.get('name', label or pkg)
        category = meta.get('category', 'other')
        publisher = meta.get('publisher', '')
        
        # 提真实 SNI
        suffix_counter = Counter()         # 给 App 专属的后缀计数
        purpose_breakdown = defaultdict(lambda: defaultdict(int))  # purpose -> suffix -> count
        full_sni_list = []
        gibberish = 0
        
        for dom in app.get('domains', []):
            sni = dom.get('sni', '')
            count = dom.get('count', 0)
            if not is_real_sni(sni):
                gibberish += 1
                continue
            suffix = get_root_suffix(sni)
            purpose = classify_purpose(sni)
            
            if is_shared_sdk(suffix):
                shared_sdk_observations[suffix] += count
                continue  # 不归到这个 App
            
            suffix_counter[suffix] += count
            purpose_breakdown[purpose][suffix] += count
            full_sni_list.append({'sni': sni, 'count': count, 'purpose': purpose})
        
        if not suffix_counter:
            continue
        
        # 计算 confidence: 观察次数高 → high, 中等 → medium, 低 → low
        total_obs = sum(suffix_counter.values())
        if total_obs >= 50:
            confidence = 'high'
        elif total_obs >= 10:
            confidence = 'medium'
        else:
            confidence = 'low'
        
        # 后缀分级 - 出现 ≥ 3 次的是 strong, 否则 weak
        strong = [s for s, c in suffix_counter.most_common() if c >= 3]
        weak = [s for s, c in suffix_counter.most_common() if c < 3]
        
        rule = {
            'name': name,
            'package_name': pkg,
            'category': category,
            'publisher': publisher,
            'confidence': confidence,
            'source': 'sni-labeler-ground-truth',
            'observation_count': total_obs,
            'gibberish_filtered': gibberish,
            'suffixes': {
                'strong': strong,    # 出现 >= 3 次, 高置信
                'weak': weak,        # 出现 1-2 次, 低置信
            },
            'purpose_breakdown': {p: dict(d) for p, d in purpose_breakdown.items()},
            # 完整 SNI 列表 (前 30 个), 给人类审计用
            'top_observed_sni': sorted(full_sni_list, key=lambda x: -x['count'])[:30],
        }
        rules.append(rule)
    
    # 输出
    output = {
        'schema_version': '2.0',
        'tool': 'sni-to-rules-v2',
        'source_export': data.get('exported_at', ''),
        'source_device': data.get('device_model', ''),
        'app_count': len(rules),
        'shared_sdk_observations': dict(shared_sdk_observations),
        'rules': rules,
    }
    
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print(f"✅ 写入 {out_path}")
    print()
    print(f"App 规则: {len(rules)}")
    for r in rules:
        print(f"  ━ {r['name']} ({r['category']}, {r['confidence']}, {r['observation_count']} obs)")
        if r['suffixes']['strong']:
            print(f"     STRONG: {', '.join(r['suffixes']['strong'])}")
        if r['suffixes']['weak']:
            wk = r['suffixes']['weak']
            print(f"     WEAK:   {', '.join(wk[:5])}{' ... ' + str(len(wk)-5) + ' more' if len(wk) > 5 else ''}")
        if r['gibberish_filtered'] > 0:
            print(f"     (过滤乱码 {r['gibberish_filtered']} 条)")
    
    if shared_sdk_observations:
        print()
        print(f"共享 SDK / 平台域名 (不归到任何 App):")
        for suf, cnt in sorted(shared_sdk_observations.items(), key=lambda x: -x[1]):
            name = SHARED_SDK_SUFFIXES.get(suf, '?')
            print(f"  {cnt:3d}  {suf:30s}  -> {name}")


if __name__ == '__main__':
    main()
