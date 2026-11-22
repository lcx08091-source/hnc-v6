// signal_rf_tables.go — HNC v6.0.0 · Vector: 3GPP NR-ARFCN / EARFCN 全频段映射、运营商 PLMN 与共建共享 (MOCN) 识别表
//
// 技术依据:
//   - 3GPP TS 38.104 (5G NR FR1 / FR2 下行 NR-ARFCN 栅格与频段定义)
//   - 3GPP TS 36.101 (4G E-UTRA 下行 EARFCN 频段定义)
//   - ITU-T E.212 / 中国四大运营商 PLMN (46000/01/03/11/15/20 等) 及移广 700MHz/2.6GHz、电联 3.5GHz/2.1GHz 共建共享特征
package main

import (
	"math"
	"strconv"
	"strings"
)

type rfBandSpec struct {
	Band    string
	LoARFCN int
	HiARFCN int
	FreqMHz int
}

// nrDownlinkBands 覆盖国内四大运营商及港澳台/日韩/欧美主流 5G NR 频段 (3GPP TS 38.104)。
var nrDownlinkBands = []rfBandSpec{
	{Band: "n71", LoARFCN: 123400, HiARFCN: 130400, FreqMHz: 600},
	{Band: "n28", LoARFCN: 151600, HiARFCN: 160600, FreqMHz: 700},
	{Band: "n20", LoARFCN: 158200, HiARFCN: 164200, FreqMHz: 800},
	{Band: "n5", LoARFCN: 173800, HiARFCN: 178800, FreqMHz: 850},
	{Band: "n8", LoARFCN: 185000, HiARFCN: 192000, FreqMHz: 900},
	{Band: "n3", LoARFCN: 361000, HiARFCN: 376000, FreqMHz: 1800},
	{Band: "n39", LoARFCN: 376000, HiARFCN: 384000, FreqMHz: 1900},
	{Band: "n2", LoARFCN: 386000, HiARFCN: 398000, FreqMHz: 1900},
	{Band: "n34", LoARFCN: 402000, HiARFCN: 405000, FreqMHz: 2000},
	{Band: "n1", LoARFCN: 422000, HiARFCN: 434000, FreqMHz: 2100},
	{Band: "n66", LoARFCN: 422000, HiARFCN: 440000, FreqMHz: 2100},
	{Band: "n40", LoARFCN: 460000, HiARFCN: 480000, FreqMHz: 2300},
	{Band: "n41", LoARFCN: 499200, HiARFCN: 537999, FreqMHz: 2600},
	{Band: "n7", LoARFCN: 524000, HiARFCN: 538000, FreqMHz: 2600},
	{Band: "n78", LoARFCN: 620000, HiARFCN: 653333, FreqMHz: 3500},
	{Band: "n77", LoARFCN: 620000, HiARFCN: 680000, FreqMHz: 3700},
	{Band: "n79", LoARFCN: 693334, HiARFCN: 733333, FreqMHz: 4900},
	{Band: "n258", LoARFCN: 2016667, HiARFCN: 2070832, FreqMHz: 26000},
	{Band: "n257", LoARFCN: 2054166, HiARFCN: 2104165, FreqMHz: 28000},
	{Band: "n261", LoARFCN: 2070833, HiARFCN: 2084999, FreqMHz: 28000},
	{Band: "n260", LoARFCN: 2229166, HiARFCN: 2279165, FreqMHz: 39000},
}

// lteDownlinkBands 覆盖主流 4G LTE FDD/TDD 下行 EARFCN 范围 (3GPP TS 36.101)。
var lteDownlinkBands = []rfBandSpec{
	{Band: "B1", LoARFCN: 0, HiARFCN: 599, FreqMHz: 2100},
	{Band: "B2", LoARFCN: 600, HiARFCN: 1199, FreqMHz: 1900},
	{Band: "B3", LoARFCN: 1200, HiARFCN: 1949, FreqMHz: 1800},
	{Band: "B4", LoARFCN: 1950, HiARFCN: 2399, FreqMHz: 1700},
	{Band: "B5", LoARFCN: 2400, HiARFCN: 2649, FreqMHz: 850},
	{Band: "B7", LoARFCN: 2750, HiARFCN: 3449, FreqMHz: 2600},
	{Band: "B8", LoARFCN: 3450, HiARFCN: 3799, FreqMHz: 900},
	{Band: "B12", LoARFCN: 5010, HiARFCN: 5179, FreqMHz: 700},
	{Band: "B17", LoARFCN: 5730, HiARFCN: 5849, FreqMHz: 700},
	{Band: "B20", LoARFCN: 6150, HiARFCN: 6449, FreqMHz: 800},
	{Band: "B26", LoARFCN: 8690, HiARFCN: 9039, FreqMHz: 850},
	{Band: "B28", LoARFCN: 9210, HiARFCN: 9659, FreqMHz: 700},
	{Band: "B34", LoARFCN: 36200, HiARFCN: 36349, FreqMHz: 2000},
	{Band: "B38", LoARFCN: 37750, HiARFCN: 38249, FreqMHz: 2600},
	{Band: "B39", LoARFCN: 38250, HiARFCN: 38649, FreqMHz: 1900},
	{Band: "B40", LoARFCN: 38650, HiARFCN: 39649, FreqMHz: 2300},
	{Band: "B41", LoARFCN: 39650, HiARFCN: 41589, FreqMHz: 2600},
	{Band: "B66", LoARFCN: 66436, HiARFCN: 67335, FreqMHz: 2100},
}

var bandCenterFreqMHz = map[string]int{
	"n71": 600, "n28": 700, "n20": 800, "n5": 850, "n8": 900,
	"n3": 1800, "n39": 1900, "n2": 1900, "n34": 2000, "n1": 2100,
	"n66": 2100, "n40": 2300, "n41": 2600, "n38": 2600, "n7": 2600,
	"n78": 3500, "n77": 3700, "n79": 4900, "n257": 28000, "n258": 26000,
	"n260": 39000, "n261": 28000,
	"B1": 2100, "B2": 1900, "B3": 1800, "B4": 1700, "B5": 850,
	"B7": 2600, "B8": 900, "B12": 700, "B17": 700, "B20": 800,
	"B26": 850, "B28": 700, "B34": 2000, "B38": 2600, "B39": 1900,
	"B40": 2300, "B41": 2600, "B66": 2100,
}

func nrBandFromARFCN(arfcn int, mccmnc string) (string, int) {
	if arfcn <= 0 || arfcn == sigUnavailable {
		return "", 0
	}
	mcc := ""
	if len(mccmnc) >= 3 {
		mcc = mccmnc[:3]
	}
	isNorthAmerica := mcc == "310" || mcc == "311" || mcc == "312" || mcc == "302"
	isJapan := mcc == "440" || mcc == "441"

	// 处理重叠频段优先级: 北美优先 n66/n77, 日本优先 n77, 中国大陆/亚太/欧洲默认优先 n1/n41/n78。
	if isNorthAmerica && arfcn >= 422000 && arfcn <= 440000 {
		return "n66", 2100
	}
	if (isNorthAmerica || isJapan) && arfcn >= 620000 && arfcn <= 680000 {
		return "n77", 3700
	}
	for _, b := range nrDownlinkBands {
		if arfcn >= b.LoARFCN && arfcn <= b.HiARFCN {
			return b.Band, b.FreqMHz
		}
	}
	return "", 0
}

func lteBandFromEARFCN(earfcn int) (string, int) {
	if earfcn < 0 || earfcn == sigUnavailable {
		return "", 0
	}
	for _, b := range lteDownlinkBands {
		if earfcn >= b.LoARFCN && earfcn <= b.HiARFCN {
			return b.Band, b.FreqMHz
		}
	}
	return "", 0
}

func lookupBandFreqMHz(band string) int {
	if f, ok := bandCenterFreqMHz[band]; ok {
		return f
	}
	return 0
}

type plmnCarrierEntry struct {
	Full  string
	Short string
}

var plmnCarrierMap = map[string]plmnCarrierEntry{
	// 中国大陆 (MCC 460)
	"46000": {Full: "中国移动", Short: "移动"},
	"46002": {Full: "中国移动", Short: "移动"},
	"46004": {Full: "中国移动", Short: "移动"},
	"46007": {Full: "中国移动", Short: "移动"},
	"46008": {Full: "中国移动", Short: "移动"},
	"46013": {Full: "中国移动", Short: "移动"},
	"46020": {Full: "中国移动", Short: "移动"},
	"46015": {Full: "中国广电", Short: "广电"},
	"46001": {Full: "中国联通", Short: "联通"},
	"46006": {Full: "中国联通", Short: "联通"},
	"46009": {Full: "中国联通", Short: "联通"},
	"46010": {Full: "中国联通", Short: "联通"},
	"46003": {Full: "中国电信", Short: "电信"},
	"46005": {Full: "中国电信", Short: "电信"},
	"46011": {Full: "中国电信", Short: "电信"},
	"46012": {Full: "中国电信", Short: "电信"},
	"46059": {Full: "中国电信", Short: "电信"},
	// 中国香港 (MCC 454)
	"45400": {Full: "香港 CSL", Short: "CSL"},
	"45403": {Full: "3 香港", Short: "3HK"},
	"45406": {Full: "数码通 SmarTone", Short: "数码通"},
	"45412": {Full: "中国移动香港", Short: "CMHK"},
	"45419": {Full: "香港电讯 HKT", Short: "HKT"},
	// 中国澳门 (MCC 455)
	"45501": {Full: "澳门电讯 CTM", Short: "CTM"},
	"45502": {Full: "中国电信（澳门）", Short: "澳门电信"},
	"45507": {Full: "中国电信（澳门）", Short: "澳门电信"},
	// 中国台湾 (MCC 466)
	"46601": {Full: "远传电信", Short: "远传"},
	"46605": {Full: "亚太电信", Short: "亚太"},
	"46689": {Full: "台湾之星", Short: "台星"},
	"46692": {Full: "中华电信", Short: "中华"},
	"46697": {Full: "台湾大哥大", Short: "台哥大"},
	// 日韩及欧美常见漫游网络
	"44010":  {Full: "NTT Docomo", Short: "Docomo"},
	"44011":  {Full: "Rakuten Mobile", Short: "Rakuten"},
	"44020":  {Full: "SoftBank", Short: "SoftBank"},
	"44050":  {Full: "KDDI au", Short: "au"},
	"44051":  {Full: "KDDI au", Short: "au"},
	"45005":  {Full: "SK Telecom", Short: "SKT"},
	"45006":  {Full: "LG U+", Short: "LGU+"},
	"45008":  {Full: "KT", Short: "KT"},
	"310260": {Full: "T-Mobile", Short: "T-Mobile"},
	"310410": {Full: "AT&T", Short: "AT&T"},
	"311480": {Full: "Verizon", Short: "Verizon"},
}

func cleanOperatorToken(s string) string {
	v := strings.TrimSpace(s)
	if v == "" || strings.EqualFold(v, "null") || strings.EqualFold(v, "unknown") || v == "----" {
		return ""
	}
	// 清理部分 ROM 附带的冗余制式后缀 (如 "中国移动 5G", "CMCC 5GA")
	for _, suf := range []string{" 5G-A", " 5GA", " 5G", " 4G", " HD"} {
		if strings.HasSuffix(strings.ToUpper(v), suf) {
			v = strings.TrimSpace(v[:len(v)-len(suf)])
		}
	}
	return v
}

// normalizeCarrierAndMOCN 统一归一化运营商全称、顶栏短名及共建共享 (MOCN) 说明。
func normalizeCarrierAndMOCN(alphaLong, alphaShort, mccmnc, primaryBand, bandCombo string) (carrierFull, carrierShort, sharingMode string) {
	longClean := cleanOperatorToken(alphaLong)
	shortClean := cleanOperatorToken(alphaShort)
	plmn := strings.TrimSpace(mccmnc)

	if entry, ok := plmnCarrierMap[plmn]; ok {
		carrierFull = entry.Full
		carrierShort = entry.Short
	}

	combinedUpper := strings.ToUpper(longClean + " " + shortClean)
	if carrierFull == "" {
		switch {
		case strings.Contains(combinedUpper, "中国广电") || strings.Contains(combinedUpper, "BROADNET") || combinedUpper == "CBN" || strings.Contains(combinedUpper, " CBN"):
			carrierFull, carrierShort = "中国广电", "广电"
		case strings.Contains(combinedUpper, "中国移动") || strings.Contains(combinedUpper, "CMHK"):
			if strings.Contains(combinedUpper, "CMHK") || strings.Contains(combinedUpper, "香港") {
				carrierFull, carrierShort = "中国移动香港", "CMHK"
			} else {
				carrierFull, carrierShort = "中国移动", "移动"
			}
		case strings.Contains(combinedUpper, "CHINA MOBILE") || strings.Contains(combinedUpper, "CMCC"):
			carrierFull, carrierShort = "中国移动", "移动"
		case strings.Contains(combinedUpper, "中国联通") || strings.Contains(combinedUpper, "CHINA UNICOM") || strings.Contains(combinedUpper, "UNICOM") || strings.Contains(combinedUpper, "CUCC") || strings.Contains(combinedUpper, "CHN-UNICOM"):
			carrierFull, carrierShort = "中国联通", "联通"
		case strings.Contains(combinedUpper, "中国电信") || strings.Contains(combinedUpper, "CHINA TELECOM") || strings.Contains(combinedUpper, "CHN-CT") || strings.Contains(combinedUpper, "CTCC"):
			carrierFull, carrierShort = "中国电信", "电信"
		default:
			if longClean != "" {
				carrierFull = longClean
			} else {
				carrierFull = shortClean
			}
			if shortClean != "" && len([]rune(shortClean)) <= 6 {
				carrierShort = shortClean
			} else if len([]rune(carrierFull)) <= 6 {
				carrierShort = carrierFull
			}
		}
	}

	combo := primaryBand
	if bandCombo != "" {
		combo = bandCombo
	}
	hasBand := func(target string) bool {
		for _, tok := range strings.Split(combo, "+") {
			if strings.TrimSpace(tok) == target {
				return true
			}
		}
		return false
	}

	// 识别国内四大运营商典型的 MOCN 异网漫游 / 共建共享基站场景
	switch carrierFull {
	case "中国移动":
		if hasBand("n28") && hasBand("n41") {
			sharingMode = "2.6GHz+700MHz 移广双载波共享"
		} else if hasBand("n28") || hasBand("B28") {
			sharingMode = "700MHz 移广共建共享"
		}
	case "中国广电":
		if hasBand("n41") || hasBand("B3") || hasBand("B39") || hasBand("B40") || hasBand("B41") {
			sharingMode = "共享移动基站接入 (MOCN)"
		} else if hasBand("n28") {
			sharingMode = "700MHz 移广共建共享"
		}
	case "中国电信", "中国联通":
		if hasBand("n78") {
			sharingMode = "3.5GHz 电联共建共享"
		} else if hasBand("n1") {
			sharingMode = "2.1GHz 电联共建共享"
		}
	}
	return carrierFull, carrierShort, sharingMode
}

// describeBandTrait 将冷冰冰的频段代号翻译成普通用户秒懂的物理覆盖与网速特性说明。
func describeBandTrait(primaryBand, bandCombo string, totalBWMHz, caCount int, isWifi bool) string {
	if isWifi {
		switch primaryBand {
		case "6GHz":
			return "Wi-Fi 6E/7 6GHz 超宽频段 · 干扰极少、近距速率极高，穿墙衰减较快"
		case "5GHz":
			return "5GHz 高速频段 · 信道干净网速快，隔两堵墙后信号衰减明显"
		default:
			return "2.4GHz 穿墙频段 · 覆盖远穿墙稳，但易受蓝牙与邻居家路由器同频干扰"
		}
	}
	bwSuffix := ""
	if totalBWMHz > 0 {
		bwSuffix = "（总带宽 " + strconv.Itoa(totalBWMHz) + "MHz）"
	}
	if caCount >= 2 && bandCombo != "" {
		if strings.Contains(bandCombo, "n41") && strings.Contains(bandCombo, "n28") {
			return "5G-A 高低频黄金双载波聚合 " + bandCombo + bwSuffix + " · 兼顾 2.6GHz 极速大带宽与 700MHz 强穿墙稳上行"
		}
		if strings.Count(bandCombo, "n78") >= 2 {
			return "5G-A 3.5GHz 双百兆载波聚合 " + bandCombo + bwSuffix + " · 电联旗舰满血高速通道，下行峰值翻倍"
		}
		if strings.Contains(bandCombo, "n41") && strings.Contains(bandCombo, "n79") {
			return "5G-A 2.6GHz+4.9GHz 大容量多载波聚合 " + bandCombo + bwSuffix + " · 商圈场馆高密极速通道"
		}
		return "多载波聚合通道 " + bandCombo + bwSuffix + " · 多条射频车道并行收发，网速上限与抗抖动显著提升"
	}
	switch primaryBand {
	case "n28", "B28", "B5", "B8", "n5", "n8", "n20", "B20", "n71":
		return "700–900MHz 黄金低频穿墙频段" + bwSuffix + " · 室内深处、电梯与地下车库信号稳，单载波峰值带宽适中"
	case "n41":
		return "2.6GHz 移动/广电主力高速频段" + bwSuffix + " · 兼顾百兆级高速吞吐与良好的城区室内覆盖"
	case "n78", "n77":
		return "3.5GHz 电信/联通黄金主力频段" + bwSuffix + " · 百兆大带宽网速极快，室内深处隔墙略有衰减"
	case "n79":
		return "4.9GHz 高频超大容量频段" + bwSuffix + " · 体育馆、商场与交通枢纽专享高速车道，穿墙能力较弱"
	case "n1", "B1", "n3", "B3", "n66", "B66":
		return "1.8–2.1GHz 中频均衡频段" + bwSuffix + " · 远距覆盖与上下行对称度均衡，常见于城区稳态覆盖与电联补盲"
	case "B40", "n40", "B41", "B38", "n38", "B39", "n39", "B34", "n34":
		return "2.3–2.6GHz 室内分布与容量频段" + bwSuffix + " · 常见于写字楼、商场室分微基站覆盖"
	default:
		if strings.HasPrefix(primaryBand, "n25") || strings.HasPrefix(primaryBand, "n26") {
			return "毫米波超高频极速频段" + bwSuffix + " · 近距视距千兆峰值，遮挡易衰减"
		}
		return ""
	}
}

// build4DSignalLabels 生成普通用户一眼看懂的四维射频体感标签。
func build4DSignalLabels(rsrp, sinr, rsrq int, hasRSRQ bool, alpha float64, isWifi bool, wifiRSSI int) (rsrpLbl, sinrLbl, rsrqLbl string, speedPct int, speedTxt string) {
	speedPct = int(math.Round(alpha * 100))
	if speedPct < 35 {
		speedPct = 35
	}
	if speedPct > 100 {
		speedPct = 100
	}
	switch {
	case speedPct >= 95:
		speedTxt = "可跑满套餐峰值"
	case speedPct >= 80:
		speedTxt = "约发挥 " + strconv.Itoa(speedPct) + "% 潜力"
	case speedPct >= 55:
		speedTxt = "弱网保护上限 " + strconv.Itoa(speedPct) + "%"
	default:
		speedTxt = "保连接防断流 (" + strconv.Itoa(speedPct) + "%)"
	}

	if isWifi {
		switch {
		case wifiRSSI >= -58:
			rsrpLbl = "极强（贴近主路由）"
		case wifiRSSI >= -68:
			rsrpLbl = "良好（穿一堵墙）"
		case wifiRSSI >= -77:
			rsrpLbl = "一般（隔墙衰减）"
		default:
			rsrpLbl = "偏弱（边缘易抖动）"
		}
		return rsrpLbl, "Wi-Fi 信道", "自动协商", speedPct, speedTxt
	}

	switch {
	case rsrp >= -85:
		rsrpLbl = "极强"
	case rsrp >= -95:
		rsrpLbl = "良好"
	case rsrp >= -105:
		rsrpLbl = "一般"
	case rsrp >= -115:
		rsrpLbl = "偏弱"
	default:
		rsrpLbl = "极弱"
	}

	switch {
	case sinr >= 20:
		sinrLbl = "极纯净"
	case sinr >= 13:
		sinrLbl = "纯净"
	case sinr >= 3:
		sinrLbl = "轻度干扰"
	case sinr >= -3:
		sinrLbl = "干扰明显"
	default:
		sinrLbl = "嘈杂易跳Ping"
	}

	if !hasRSRQ {
		rsrqLbl = "正常"
	} else {
		switch {
		case rsrq >= -10:
			rsrqLbl = "基站空闲"
		case rsrq >= -14:
			rsrqLbl = "负载正常"
		case rsrq >= -17:
			rsrqLbl = "晚高峰偏忙"
		default:
			rsrqLbl = "基站拥塞"
		}
	}
	return rsrpLbl, sinrLbl, rsrqLbl, speedPct, speedTxt
}
