// tokens.go - remote_tokens.json 读写与内存 Map 维护
//
// Patch 2.a 核心数据结构(按 v4_0_design_v2.1 §3.1):
//   tokens.json 是 Map by TokenID,不是数组
//   Map 结构的好处: 并发撤销安全、O(1) 查找
//
// 同步策略(按设计文档 §8.1):
//   httpd 内存保有 tokensMap 运行时副本
//   每次 API 进入 middleware 时先 stat tokens.json
//   如果 mtime 变 → 重载 tokens.json 到 tokensMap
//   否则用内存副本
//
// 并发安全:
//   内部用 sync.RWMutex 保护 tokensMap
//   读操作(verify)持 RLock,写操作(update_last_seen / revoke)持 Lock
//   tokens.json 的磁盘写是由 json_set.sh 做的,不由 httpd 做
//   httpd 唯一会写磁盘的路径: issueToken / updateLastSeen, 详见对应函数注释

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Token 对应 tokens.json 里 tokens[<TokenID>] 的 value
type Token struct {
	Hash     string `json:"hash"`       // bcrypt(Secret, cost=10)
	Created  int64  `json:"created"`    // Unix ts,首次签发
	LastSeen int64  `json:"last_seen"`  // Unix ts,最后一次成功验证
	Label    string `json:"label"`      // "Chrome on Mac" 等,User-Agent 启发式
	IPHint   string `json:"ip_hint"`    // 配对时的 remote IP,不参与鉴权
	Revoked  bool   `json:"revoked"`    // 撤销后 true,保留记录作审计
}

// tokensFile 是 tokens.json 的顶层 JSON 结构
type tokensFile struct {
	Version int              `json:"version"`
	Tokens  map[string]Token `json:"tokens"`
}

// TokensStore 是内存中的 tokens 状态。支持 stat/mtime 同步。
type TokensStore struct {
	path     string       // tokens.json 的绝对路径
	mu       sync.RWMutex
	tokens   map[string]Token
	lastRead int64        // 上次 reload 时的文件 mtime(Unix ns)
	// rc3.1.33 修 #10/#29: dirty 集合记录"本进程改过的 token id".
	// saveAtomicLocked merge 时只反向删除 dirty 集合外的、磁盘上已不存在的 token,
	// 避免把刚 PutIfAbsent 还没落盘的 token 当成"shell 删的"误删.
	// 任何走 saveAtomicLocked 的写路径 (PutIfAbsent / Put / Prune / Flush) 成功后清空.
	dirty    map[string]bool
}

// NewTokensStore 创建 store。首次会尝试从磁盘 load;文件不存在视为空 store,不报错。
// path 一般是 $HNC_DIR/data/remote_tokens.json
func NewTokensStore(path string) *TokensStore {
	s := &TokensStore{
		path:   path,
		tokens: make(map[string]Token),
		dirty:  make(map[string]bool),
	}
	_ = s.reload() // 首次 load,失败则保持空
	return s
}

// reload 无条件从磁盘读 tokens.json 覆盖内存。调用者不需持锁。
// v2.a hotfix (Gemini 2.2): 用 double-check 防惊群效应:
// 多个并发协程同时 SyncIfChanged 发现 mtime 变了都进来 reload,
// 实际只需要一个协程做。进入 Lock 后再 stat 一次,如果已经被别人 reload 过就直接返回。
// rc3.1.13.2 修 P1 (review §鉴权-1):
//   原顺序 Read 然后 Stat 存在窄窗口竞态 — 如果在 ReadFile 之后 Stat 之前
//   外部又写一次, 新 mtime 被记 lastRead, 内存里却是旧数据, 后续 Sync 跳过
//   → 新写入永远丢. 改 Stat-Read-Stat 三明治, 两次 Stat 不一致就重试.
func (s *TokensStore) reload() error {
	const maxRetry = 3
	var data []byte
	var newMtime int64
	for attempt := 0; attempt < maxRetry; attempt++ {
		st1, err := os.Stat(s.path)
		if err != nil {
			if os.IsNotExist(err) {
				s.mu.Lock()
				s.tokens = make(map[string]Token)
				s.lastRead = 0
				s.mu.Unlock()
				return nil
			}
			return fmt.Errorf("stat tokens.json: %w", err)
		}
		data, err = os.ReadFile(s.path)
		if err != nil {
			if os.IsNotExist(err) {
				s.mu.Lock()
				s.tokens = make(map[string]Token)
				s.lastRead = 0
				s.mu.Unlock()
				return nil
			}
			return fmt.Errorf("read tokens.json: %w", err)
		}
		st2, err := os.Stat(s.path)
		if err != nil {
			return fmt.Errorf("stat2 tokens.json: %w", err)
		}
		if st1.ModTime().Equal(st2.ModTime()) && st1.Size() == st2.Size() {
			newMtime = st2.ModTime().UnixNano()
			break
		}
		// 文件在 read 期间又被改, 重试. 最后一次仍不一致也用最新结果(稀少情况).
		if attempt == maxRetry-1 {
			newMtime = st2.ModTime().UnixNano()
		}
	}

	var tf tokensFile
	if err := json.Unmarshal(data, &tf); err != nil {
		return fmt.Errorf("parse tokens.json: %w", err)
	}
	if tf.Tokens == nil {
		tf.Tokens = make(map[string]Token)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Double-check: 并发场景下别的协程可能已经 reload 过
	// 比较 mtime,如果内存中的 lastRead 已经是最新或更新,就跳过
	if s.lastRead >= newMtime {
		return nil
	}
	s.tokens = tf.Tokens
	s.lastRead = newMtime
	// rc3.1.33 修 #10/#29: reload 把 tokens map 整体替换, 之前 dirty 集合
	// 引用的"待落盘"token 现在已经是磁盘版本了, 清空避免反向 merge 误保留
	if s.dirty != nil && len(s.dirty) > 0 {
		s.dirty = make(map[string]bool)
	}
	return nil
}

// SyncIfChanged 检查磁盘 mtime,变了才 reload。
// 调用者应在每次 API 请求进入 middleware 时调一次。
// 如果 stat 失败(文件被删),tokens 会被清空。
func (s *TokensStore) SyncIfChanged() error {
	st, err := os.Stat(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.mu.Lock()
			if len(s.tokens) > 0 {
				s.tokens = make(map[string]Token)
			}
			s.lastRead = 0
			s.mu.Unlock()
			return nil
		}
		return err
	}
	s.mu.RLock()
	need := st.ModTime().UnixNano() != s.lastRead
	s.mu.RUnlock()
	if need {
		return s.reload()
	}
	return nil
}

// Get 按 TokenID 查 token。返回 (token, exists)。
// 会持 RLock,不会导致 reload。调用者应先调 SyncIfChanged。
func (s *TokensStore) Get(tokenID string) (Token, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[tokenID]
	return t, ok
}

// Count 返回当前 token 总数(包括 revoked)。诊断用。
func (s *TokensStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tokens)
}

// CountActive 返回未撤销且未硬过期的 token 数。WebUI 显示用。
func (s *TokensStore) CountActive() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now().Unix()
	n := 0
	for _, t := range s.tokens {
		if !t.Revoked && (now-t.LastSeen) <= hardExpireSec {
			n++
		}
	}
	return n
}

// 硬过期相关常量
// rc3.1.14 抽 const (review P3): 之前 hardExpireSec=60d 跟 Prune 内
// hardExpire=90d 各写一处, 关系靠肉眼读. 实际语义:
//   - 60d 后 last_seen, middleware 拒绝鉴权 (hardExpireSec)
//   - 60d~90d 这 30 天保留 token 记录给审计 (revokedExpire 配合)
//   - 90d 后 prune 物理删除 (hardExpirePruneSec)
const (
	hardExpireSec      = 60 * 86400 // middleware 拒绝鉴权门槛
	hardExpirePruneSec = 90 * 86400 // 物理删除门槛 (含 30 天审计窗口)
	revokedExpireSec   = 30 * 86400 // 撤销后保留多久才 prune
)

// saveAtomic 把内存 tokens 写回磁盘。用 tmp + rename 原子保证。
// 注意: httpd 写 tokens.json 跟 json_set.sh 写是两个进程,
// 理论上可能产生 last-write-wins 冲突。但 httpd 只做两件写操作:
//   1. issueToken: 加新条目
//   2. updateLastSeen: 改现有条目的 last_seen
// json_set.sh 做 token_revoke/token_revoke_all/token_prune。
// 实际冲突场景:
//   - 主人撤销 token + httpd 正好 updateLastSeen 同一条 → 一方覆盖
//   - 缓解: updateLastSeen 在 middleware 里只做内存,每 N 秒或 logout 时才 saveAtomic
//     (见 saveLoop),大幅减小冲突窗口
// saveAtomicLocked 把内存全量序列化覆盖磁盘.
// rc3.1.13.2 修 P1 (review §鉴权-2): 之前 Go 端的 Put/Revoke 直接全量覆盖,
// 如果 shell (json_set.sh token_revoke) 在 Go 内存操作期间写了磁盘,
// Go 的覆盖会把 shell 的修改抹掉. 修法: 写盘前 stat + read 一次磁盘,
// 把磁盘上"我们没见过的"修改 (其他 token 被 shell 加/改) 合并进内存,
// 然后再写盘. 我们自己改的 token (在 s.dirty 集合) 优先级更高.
// 注: 这只能减小窗口, 真正的解决方案是引入文件锁 (flock). 但 Android
// 不一定支持 flock 跨 fork 的语义, 暂时用 merge 兜底.
//
// rc3.1.33 修 #10/#29 (review §最终轮): 加反向 merge.
// 之前正向 merge 漏了 "shell token_revoke_all 把磁盘清空, 但 Go 内存还有
// 全量 token" 的场景 — 30s 后 SaveLoop 触发, diskTf.Tokens={} 循环不进入,
// s.tokens 原样写回磁盘 → 撤销失效. 现在反向迭代 s.tokens, 不在 s.dirty
// 集合的、磁盘上已删的 token 视为 "shell 主动删除", 同步删除内存版本.
// dirty 集合保护的是"本进程刚 Put 还没第一次落盘"的 token (例如 IssueToken
// 的 PutIfAbsent 第一次写, 或者循环里 Prune 后批量改).
//
// 调用者持 Lock
func (s *TokensStore) saveAtomicLocked() error {
	// 先尝试合并磁盘最新数据 (防 Go-shell 写竞态)
	var diskTokens map[string]Token
	if st, err := os.Stat(s.path); err == nil {
		diskMtime := st.ModTime().UnixNano()
		if diskMtime > s.lastRead {
			// 磁盘有我们没见过的修改, 读进来跟内存合并
			if data, err := os.ReadFile(s.path); err == nil {
				var diskTf tokensFile
				if json.Unmarshal(data, &diskTf) == nil && diskTf.Tokens != nil {
					diskTokens = diskTf.Tokens
					// 策略: 磁盘上有但内存没有的 token → 加进内存
					//       磁盘上 revoked=true 但内存里 revoked=false → 信磁盘 (shell 撤销了)
					//       其他冲突字段保持内存版本 (我们正要写的)
					for tid, dt := range diskTokens {
						mt, ok := s.tokens[tid]
						if !ok {
							s.tokens[tid] = dt
							continue
						}
						if dt.Revoked && !mt.Revoked {
							mt.Revoked = true
							s.tokens[tid] = mt
						}
					}
					// rc3.1.33 修 #10/#29: 反向 merge.
					// 内存有但磁盘完全没有的 token, 如果 *不在 dirty 集合*, 视为
					// shell (json_set.sh token_revoke / token_revoke_all) 主动删除,
					// 同步从内存删. dirty 集合里的是本进程刚 Put 还没首次落盘的,
					// 必须保留 (本次 save 会把它们写下去).
					var toDelete []string
					for tid := range s.tokens {
						if _, onDisk := diskTokens[tid]; !onDisk && !s.dirty[tid] {
							toDelete = append(toDelete, tid)
						}
					}
					for _, tid := range toDelete {
						delete(s.tokens, tid)
					}
				}
			}
		}
	}

	tf := tokensFile{
		Version: 1,
		Tokens:  s.tokens,
	}
	data, err := json.MarshalIndent(&tf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal tokens: %w", err)
	}
	// 保证父目录存在
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("chmod: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	// 更新自己的 mtime cache,避免下次 SyncIfChanged 误重载
	st, err := os.Stat(s.path)
	if err == nil {
		s.lastRead = st.ModTime().UnixNano()
	}
	// rc3.1.33 修 #10/#29: 落盘成功 → dirty 清空
	// (下一次 saveAtomicLocked 之前新 Put 的会重新加进 dirty)
	if len(s.dirty) > 0 {
		s.dirty = make(map[string]bool)
	}
	return nil
}

// ErrTokenIDCollision 表示 PutIfAbsent 时 TokenID 已存在
var ErrTokenIDCollision = errors.New("TokenID collision")

// PutIfAbsent 原子性地插入 token,如果 TokenID 已存在返回 ErrTokenIDCollision。
// v2.a hotfix (Gemini 2.1): 取代之前的 "RLock check + Lock put" 两步模式,
// 消除 TOCTOU 竞态。两个并发 IssueToken 即使生成相同 TokenID(2^64 概率≈0),
// 也只会一个成功,另一个拿到 ErrTokenIDCollision 触发外层重试。
func (s *TokensStore) PutIfAbsent(tokenID string, t Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tokens[tokenID]; exists {
		return ErrTokenIDCollision
	}
	s.tokens[tokenID] = t
	// rc3.1.33 修 #10/#29: 标 dirty, 防 saveAtomicLocked 反向 merge 误删
	s.dirty[tokenID] = true
	return s.saveAtomicLocked()
}

// Put 写入一个 token(新增或覆盖)。立即持久化到磁盘。
// 历史 API 保留,给测试用;生产代码应该优先用 PutIfAbsent。
func (s *TokensStore) Put(tokenID string, t Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[tokenID] = t
	// rc3.1.33 修 #10/#29: 标 dirty
	s.dirty[tokenID] = true
	return s.saveAtomicLocked()
}

// UpdateLastSeen 更新某 TokenID 的 last_seen 到当前时间。仅内存,不立即持盘。
// middleware 里每次成功验证都调。saveLoop 会定期把内存同步回磁盘。
func (s *TokensStore) UpdateLastSeen(tokenID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tokens[tokenID]; ok {
		t.LastSeen = time.Now().Unix()
		s.tokens[tokenID] = t
		// rc3.1.33 修 #10/#29: 标 dirty 防 SaveLoop Flush 时反向 merge 误删.
		// 这里是高频路径 (每个 API 都跑), 但 dirty 只是 map[string]bool 写入,
		// O(1), 跟 mu.Lock 同 critical section, 零额外开销.
		s.dirty[tokenID] = true
	}
}

// Flush 主动把内存写回磁盘。saveLoop 用,logout 用。
func (s *TokensStore) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveAtomicLocked()
}

// SaveLoop 周期把内存 last_seen 变化同步回磁盘。
// 每 30 秒 flush 一次,避免每请求都写盘(I/O 开销 + 跟 json_set.sh 冲突)。
// 设计文档 §3.2 注释: 冲突窗口从每请求缩到 30 秒。
// Prune 删除 tokens 中过期条目:
//   - last_seen 超过 90 天 的条目直接删除
//   - revoked=true 且 last_seen 超过 30 天 的条目删除(审计过期)
//
// 这是 json_set.sh token_prune 的实际实现(shell 那边只 touch marker,
// 让 httpd 在 pruneLoop 里用 Go json 库可靠执行)。
//
// 返回被删除的数量。
func (s *TokensStore) Prune() (removed int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	hardExpire := int64(hardExpirePruneSec)
	revokedExpire := int64(revokedExpireSec)

	var toDelete []string
	for tokenID, tok := range s.tokens {
		// 硬过期
		if tok.LastSeen > 0 && (now-tok.LastSeen) > hardExpire {
			toDelete = append(toDelete, tokenID)
			continue
		}
		// 撤销且超过审计期
		if tok.Revoked && tok.LastSeen > 0 && (now-tok.LastSeen) > revokedExpire {
			toDelete = append(toDelete, tokenID)
			continue
		}
	}
	for _, id := range toDelete {
		delete(s.tokens, id)
	}
	if len(toDelete) == 0 {
		return 0, nil
	}
	if err := s.saveAtomicLocked(); err != nil {
		// 注意: 这里内存已删,磁盘写失败,下次 SaveLoop 会重试 flush,
		// 最终一致。但日志应该记录。
		return len(toDelete), fmt.Errorf("prune saveAtomic: %w", err)
	}
	return len(toDelete), nil
}

// SaveLoop 周期把内存 last_seen 变化同步回磁盘。
// 每 30 秒 flush 一次,避免每请求都写盘(I/O 开销 + 跟 json_set.sh 冲突)。
// 设计文档 §3.2 注释: 冲突窗口从每请求缩到 30 秒。
// stop chan 用于 shutdown 通知。
func (s *TokensStore) SaveLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			// 最后一次 flush
			if err := s.Flush(); err != nil {
				// 不能 log.Fatal,进程正在退出
				fmt.Fprintf(os.Stderr, "final flush failed: %v\n", err)
			}
			return
		case <-ticker.C:
			if err := s.Flush(); err != nil {
				// 非致命,下轮重试
				fmt.Fprintf(os.Stderr, "periodic flush failed: %v\n", err)
			}
		}
	}
}

// Snapshot 返回当前内存中所有 token 的快照(副本).
// rc3.1.14 修 P2 (review §一致性): 之前 apiTokens 直接读磁盘 tokens.json,
// 而 UpdateLastSeen 只更内存 + saveLoop 30s 才同步, UI 看到的 last_seen
// 落后实际最多 30s. 改用 Snapshot 让 UI 拿到最新值.
func (s *TokensStore) Snapshot() map[string]Token {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]Token, len(s.tokens))
	for k, v := range s.tokens {
		out[k] = v
	}
	return out
}
