#!/usr/bin/env python3
"""把 sni-labeler 导出的 JSON 转成 HNC dpi_rules.json 增量"""
import json
import re
import sys
from collections import defaultdict

# 已知 app 的人类可读名 + 分类映射 (基于 package_name)
APP_MAPPING = {
    'com.ss.android.ugc.aweme': ('抖音', 'video'),
    'com.smile.gifmaker': ('快手', 'video'),
    'com.tencent.mobileqq': ('QQ', 'social'),
    'com.tencent.mm': ('微信', 'social'),
    'com.tencent.tmgp.sgame': ('王者荣耀', 'game'),
    'com.tencent.tmgp.codev': ('无畏契约', 'game'),
    'com.tencent.tmgp.pubgmhd': ('和平精英', 'game'),
    'com.tencent.luoke': ('洛克王国', 'game'),
    'com.miHoYo.Yuanshen': ('原神', 'game'),
    'com.miHoYo.GenshinImpact': ('原神(国际)', 'game'),
    'com.miHoYo.hkrpg': ('崩坏：星穹铁道', 'game'),
    'com.netease.party': ('蛋仔派对', 'game'),
    'tv.danmaku.bili': ('哔哩哔哩', 'video'),
}


def sni_to_suffix(sni):
    """把 SNI 转成 HNC 后缀: 去掉前面的特定子域, 留 2 级根域"""
    parts = sni.split('.')
    if len(parts) < 2:
        return None
    # 中国大陆常见: xxx.cn 是顶级, xxx.com.cn 是次级
    # 简化: 取最后 2 段 (xxx.com) 或 3 段 (xxx.com.cn)
    if len(parts) >= 3 and parts[-2] in ('com', 'gov', 'net', 'edu', 'org') and parts[-1] in ('cn', 'hk', 'tw'):
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def is_valid_sni(s):
    if not s or '.' not in s:
        return False
    if not re.match(r'^[a-z0-9._-]+$', s):
        return False
    return True


def main():
    if len(sys.argv) < 2:
        print("用法: python3 sni_to_rules.py <sni_export.json> [-o output.json]")
        sys.exit(1)
    
    in_path = sys.argv[1]
    out_path = 'dpi_rules_increment.json'
    if '-o' in sys.argv:
        out_path = sys.argv[sys.argv.index('-o') + 1]
    
    with open(in_path) as f:
        data = json.load(f)
    
    rules = []
    
    for app in data.get('apps', []):
        pkg = app.get('package_name', '')
        label = app.get('app_label', '')
        
        # 用已知映射, 或者用 package 推断
        if pkg in APP_MAPPING:
            name, category = APP_MAPPING[pkg]
        else:
            name = label or pkg
            # 根据 pkg 猜分类
            if 'game' in pkg.lower() or 'tmgp' in pkg.lower() or 'mihoyo' in pkg.lower():
                category = 'game'
            elif 'aweme' in pkg.lower() or 'douyin' in pkg.lower() or 'kuaishou' in pkg.lower() or 'bili' in pkg.lower():
                category = 'video'
            elif 'tencent' in pkg.lower() or 'qq' in pkg.lower() or 'weixin' in pkg.lower():
                category = 'social'
            else:
                category = 'other'
        
        # 抽 SNI 后缀, 按出现次数计
        suffix_counts = defaultdict(int)
        for dom in app.get('domains', []):
            sni = dom.get('sni', '')
            if not is_valid_sni(sni):
                continue
            suffix = sni_to_suffix(sni)
            if suffix:
                suffix_counts[suffix] += dom.get('count', 1)
        
        if not suffix_counts:
            continue
        
        # 取出现次数 >= 2 的后缀, 限制最多 30 个
        top_suffixes = sorted(suffix_counts.items(), key=lambda x: -x[1])
        suffixes = [s for s, c in top_suffixes[:30] if c >= 2]
        if not suffixes:
            # 兜底: 至少给一个最热的
            suffixes = [top_suffixes[0][0]] if top_suffixes else []
        
        if suffixes:
            rule = {
                'name': name,
                'package_name': pkg,
                'category': category,
                'confidence': 'high',
                'source': 'sni-labeler-ground-truth',
                'suffixes': suffixes,
                'observation_count': app.get('observation_count', 0),
            }
            rules.append(rule)
    
    output = {
        'schema_version': '1.0',
        'tool': 'sni-to-rules',
        'source_export': data.get('exported_at', ''),
        'source_device': data.get('device_model', ''),
        'rules': rules,
    }
    
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print(f"✅ 写入 {out_path}")
    print(f"   {len(rules)} 条规则")
    for rule in rules:
        print(f"   - {rule['name']} ({rule['category']}): {len(rule['suffixes'])} 个后缀")


if __name__ == '__main__':
    main()
