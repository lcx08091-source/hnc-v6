// audit.go — Patch 3.a · 审计日志
//
// 每个写操作都写一行到 logs/audit.log:
//   [2026-04-19 14:22:00] tid=xxxxxxxx action=rule_set mac=aa:... result=ok detail=
//
// 只追加不读,体积由 log_rotate.sh 管(跟其它 *.log 一起轮转)。
// 写失败只 stderr warn,不阻止 action 执行 — 审计日志挂不能让业务挂。

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var auditMu sync.Mutex

// auditLog 追加一条审计记录
// 字段:
//
//	tid       — TokenID 前 8 位(VerifyCookie 返回的完整 ID,这里截短)
//	             匿名请求(过渡期)为 "anon"
//	action    — action 名(白名单里的标识)
//	params    — map[string]string,会被展平成 k=v 追加,顺序按 key 字母表
//	result    — "ok" 或 "error"
//	detail    — 错误消息或成功细节,会做简单转义避免换行
func auditLog(hncDir, tid, action string, params map[string]string, result, detail string) {
	auditMu.Lock()
	defer auditMu.Unlock()

	logDir := filepath.Join(hncDir, "logs")
	_ = os.MkdirAll(logDir, 0755)
	path := filepath.Join(logDir, "audit.log")

	ts := time.Now().Format("2006-01-02 15:04:05")
	tidShort := tid
	if len(tidShort) > 8 {
		tidShort = tidShort[:8]
	}
	if tidShort == "" {
		tidShort = "anon"
	}

	// 按 key 排序参数,方便 grep
	paramStr := ""
	if len(params) > 0 {
		keys := make([]string, 0, len(params))
		for k := range params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var sb strings.Builder
		for _, k := range keys {
			sb.WriteString(" ")
			sb.WriteString(k)
			sb.WriteString("=")
			sb.WriteString(sanitizeField(params[k]))
		}
		paramStr = sb.String()
	}

	detailStr := ""
	if detail != "" {
		detailStr = " detail=" + sanitizeField(detail)
	}

	line := fmt.Sprintf("[%s] tid=%s action=%s%s result=%s%s\n",
		ts, tidShort, action, paramStr, result, detailStr)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: open %s: %v\n", path, err)
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
}

// sanitizeField 清理字段内容,防 log injection
// - 换行改成 \\n
// - 回车改成 \\r
// - tab 改空格
// - 长度截 256 (UTF-8 边界安全)
// rc3.1.34 修 #43: 之前 `s[:256]` 字节级硬切, 256 字节恰好把 UTF-8 多字节
// 字符切一半 → 日志查看器 (less / tail) 显示乱码 �. 中文 3 字节, emoji 4 字节,
// 概率 ~50%. 改成: 256 字节内找最后一个完整 UTF-8 字符边界.
func sanitizeField(s string) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > 256 {
		// 往左找合法 RuneStart, 至少能保证截断后是合法 UTF-8 序列
		cut := 256
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "..."
	}
	return s
}
