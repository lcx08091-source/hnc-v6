// pair_guard.go — v5.22 配对(PIN)防爆破: 审计 + 告警 + 一次性 PIN 失败熔断
//
// 叠加在 ratelimit.go 的限流之上(那里管"能不能试"), 这里管"试了之后留痕":
//
//  1. 审计: 每次被比对的失败尝试(格式错 / PIN 错)、每次触发的 IP 锁定、全局上限
//     拒绝、PIN 熔断, 都写 logs/audit.log(tid=anon action=pair_verify ...)。
//     被比对的尝试数受 per-IP(5 次/10 分钟)与全局(20 次/分钟)双重上限约束,
//     审计行数因此有界; "已锁定仍在请求"的入口短路不逐条写(否则攻击者每秒 20 行
//     刷满 /data), 只在锁定发生那一刻写一条。
//  2. 告警: kind=auth_bruteforce 追加到 run/alerts.jsonl(/api/alerts 铃铛),
//     同一窗口(pairAlertWindow)内只发一条, 后续事件只计数。
//  3. 熔断: 同一个配对码(按 session_id)累计 pairBurnAfter 次 PIN 错误即作废
//     (删除 run/pair_pending), 主人需重新生成。配合 per-IP / 全局限流, 单个 PIN
//     最多被猜 pairBurnAfter 次, 命中率 ≤ 1e-5, 与攻击者能控制多少源地址无关。
//
// 安全告警不受 alerts_config 的 enabled 总开关控制: 它是"有人在撞配对码"的唯一
// 可见信号, 关掉设备上线告警不应连带关掉它。

package main

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"hnc.io/dpid/alert"
)

const (
	pairBurnAfter      = 10               // 同一配对码累计 PIN 错误上限, 超过即作废
	pairAlertWindow    = 10 * time.Minute // auth_bruteforce 告警去重窗口
	pairMaxValiditySec = 600              // pair_pending 的 expiry 不得超过 now+600s(pair_gen.sh 写 120s)
	authBruteforceKind = "auth_bruteforce"
)

type pairGuardState struct {
	mu        sync.Mutex
	sidFails  map[string]int // session_id → PIN 错误次数
	lastAlert time.Time
	suppress  int // 去重窗口内被吞掉的事件数(下一条告警里带出)
}

var pairGuard = &pairGuardState{sidFails: map[string]int{}}

// pairAudit 写一条配对审计(tid=anon)。
func pairAudit(hncDir, ip, result, detail string) {
	auditLog(hncDir, "anon", "pair_verify", map[string]string{"ip": ip}, result, detail)
}

// pairAlert 发 auth_bruteforce 告警, pairAlertWindow 内只发一条。返回是否真的发出。
func pairAlert(hncDir, ip, reason string, extra map[string]interface{}) bool {
	now := time.Now()
	pairGuard.mu.Lock()
	if !pairGuard.lastAlert.IsZero() && now.Sub(pairGuard.lastAlert) < pairAlertWindow {
		pairGuard.suppress++
		pairGuard.mu.Unlock()
		return false
	}
	suppressed := pairGuard.suppress
	pairGuard.suppress = 0
	pairGuard.lastAlert = now
	pairGuard.mu.Unlock()

	if extra == nil {
		extra = map[string]interface{}{}
	}
	extra["reason"] = reason
	if suppressed > 0 {
		extra["suppressed_since_last"] = suppressed
	}
	a := alert.Alert{
		ID:     authBruteforceKind + "_" + strconv.FormatInt(now.Unix(), 10),
		Ts:     now.Unix(),
		Kind:   authBruteforceKind,
		IP:     ip,
		Detail: "远程配对码疑似被暴力尝试(" + reason + "), 来源 " + ip + "。如非本人操作, 请在本机取消配对并检查「WebUI 访问控制」",
		Extra:  extra,
	}
	cfg := alert.NewConfig(hncDir)
	if err := puAppendAlert(cfg.AlertsJSONLPath, a); err != nil {
		log.Printf("pair_guard: append alert failed: %v", err)
	}
	return true
}

// consumePinAttemptAudited 包装 ConsumePinAttempt: 本次调用若触发了 IP 锁定 /
// 全局上限, 写审计 + 告警。计数器差分可能把并发请求的事件记到别的请求头上, 只
// 影响审计里的归属 IP, 不影响限流本身。
func (s *server) consumePinAttemptAudited(ip string) (bool, int64, int) {
	lk0, gh0 := s.limiter.PinCounters()
	ok, retry, rem := s.limiter.ConsumePinAttempt(ip)
	if ok {
		return ok, retry, rem
	}
	lk1, gh1 := s.limiter.PinCounters()
	switch {
	case lk1 > lk0:
		pairAudit(s.hncDir, ip, "error", "ip locked out for "+int64ToStr(retry)+"s (too many pin failures)")
		pairAlert(s.hncDir, ip, "单个来源连续输错", map[string]interface{}{"lock_sec": retry})
	case gh1 > gh0:
		// 全局上限: 每次被拒都会走到这里, 审计也去重 —— 只在告警真正发出时写一条
		if pairAlert(s.hncDir, ip, "全局尝试次数超限", map[string]interface{}{"retry_sec": retry}) {
			pairAudit(s.hncDir, ip, "error", "global pin attempt cap reached")
		}
	}
	return ok, retry, rem
}

// pairRecordFailure 记录一次被比对的失败(格式错 sid="" / PIN 错)。
// 返回 true 表示本次失败导致配对码被熔断作废。
func (s *server) pairRecordFailure(ip, sid, reason string) bool {
	pairAudit(s.hncDir, ip, "error", reason)
	if sid == "" {
		return false
	}
	pairGuard.mu.Lock()
	pairGuard.sidFails[sid]++
	n := pairGuard.sidFails[sid]
	if len(pairGuard.sidFails) > 64 { // 有界: 旧 sid 早已过期, 整体清空即可
		pairGuard.sidFails = map[string]int{sid: n}
	}
	pairGuard.mu.Unlock()
	if n < pairBurnAfter {
		return false
	}
	pendingPath := filepath.Join(s.hncDir, "run", "pair_pending")
	if err := os.Remove(pendingPath); err != nil && !os.IsNotExist(err) {
		_ = os.WriteFile(pendingPath, nil, 0600) // 兜底: 清空 → readPairPending 判 malformed
	}
	pairGuard.mu.Lock()
	delete(pairGuard.sidFails, sid)
	pairGuard.mu.Unlock()
	pairAudit(s.hncDir, ip, "error", "pairing code burned after "+strconv.Itoa(n)+" wrong pins")
	pairAlert(s.hncDir, ip, "配对码累计输错 "+strconv.Itoa(n)+" 次已作废", map[string]interface{}{"failures": n})
	return true
}

// pairRecordSuccess 配对成功: 审计 + 清该 sid 的失败计数。
func (s *server) pairRecordSuccess(ip, sid, tokenID string) {
	pairGuard.mu.Lock()
	delete(pairGuard.sidFails, sid)
	pairGuard.mu.Unlock()
	pairAudit(s.hncDir, ip, "ok", "paired tid="+TokenIDLogPrefix(tokenID))
}
