// fg_engagement.go — v5.28 B4: 交互节拍(「人在用」还是「挂后台」, 影子运行)。
//
// 在 fg_model 每轮已经算好的特征(fgFeat: 新建连接速率 / 请求-响应突发 /
// 心跳占比 / 下行速率 / Bulk)上, 给每个 (设备, 应用) 一个三态标签:
//
//	interactive —— 人在操作: 新建连接频繁(点开页面、刷新、搜索)或
//	               请求-响应突发多;
//	passive    —— 在看 / 在听, 没在操作: 下行持续且几乎没有新请求;
//	background —— 后台: 只剩心跳级流量, 或大文件下载特征。
//
// 依据与阈值(常量, 拍脑袋 + 真机观察的量级, 本版无真值 —— 前台真值只告诉
// 「哪个 App 在前台」, 不告诉「有没有人在操作」): 新建连接 6 次/分钟是刷
// feed 的量级(静置播放几乎不新建); 请求-响应突发 8 次/轮是滚动页面; 心跳
// 占比 0.8 以上 = 基本只剩 keepalive; 4 kbps 以下 = 心跳级速率; 150 kbps
// 下行持续 = 流媒体观看的量级。
//
// 输出: /api/devices[].fg.engagement(新字段)与前台时间线每段
// fgSession.Eng + 汇总 engagement_mix(影子, 前端按需展示; 行为由单元
// 测试锁定, 供人工判断分布是否合理)。
package main

// ── 节拍阈值(依据见文件头) ───────────────────────────────────────────
const (
	fgEngInterNewPerMin = 6.0    // 新建连接 ≥ 6/分钟 → 人在操作
	fgEngInterRR        = 8      // 请求-响应突发 ≥ 8 次/轮 → 人在操作
	fgEngBgHBShare      = 0.8    // 心跳占比 ≥ 0.8 → 后台
	fgEngBgBps          = 4000   // 总速率 < 4 kbps → 后台(心跳级)
	fgEngPassiveDnBps   = 150000 // 下行 ≥ 150 kbps 且无操作信号 → 在看/在听
)

// fgEngagementOf 纯函数: 一轮特征 → 节拍标签(顺序: 操作 > 后台 > 被动)。
func fgEngagementOf(f fgFeat) string {
	if f.NewPerMin >= fgEngInterNewPerMin || f.RR >= fgEngInterRR {
		return "interactive"
	}
	if f.Bulk || f.HBShare >= fgEngBgHBShare || f.DnBps+f.UpBps < fgEngBgBps {
		return "background"
	}
	if f.DnBps >= fgEngPassiveDnBps {
		return "passive"
	}
	return "unknown"
}

// fgEngIdx 三态直方图的下标(interactive/passive/background, unknown 不计)。
func fgEngIdx(eng string) int {
	switch eng {
	case "interactive":
		return 0
	case "passive":
		return 1
	case "background":
		return 2
	}
	return -1
}

// fgEngDominant 直方图里占比最多的标签(平票按 interactive > passive >
// background 的既定次序, 与 fgEngagementOf 的优先级一致)。
func fgEngDominant(n [3]int) string {
	best, bi := 0, -1
	for i, c := range n {
		if c > best {
			best, bi = c, i
		}
	}
	switch bi {
	case 0:
		return "interactive"
	case 1:
		return "passive"
	case 2:
		return "background"
	}
	return ""
}
