# A3 审查记录：hnc_httpd 网络 / DNS / 计费 / API

- 基线版本：v5.33.0-rc2
- 审查员：A3（子审查员）
- 范围：`daemon/hnc_httpd/` 下 dns_takeover.go、dns_forwarder.go、dns_wire.go、encdns.go、limit_policy.go、quota_global.go、conn_blocks.go、ct_events.go、ct_new_events.go、neigh_v6.go、ip_owner.go、mac_merge.go、mac_alias.go、api_conn.go、api_live.go、api_v5.go、api_self.go、api_alerts.go、api_events.go、api_sla.go、iface_patterns.go、hostname_junk.go、jsoncache.go、netstats_parse.go
- 原则：只记录真 bug，不改代码。

## 已审文件

## Bug

### A3-001 [P1][确认] DNS 缓存键用「规范化后的 QName 字符串」，标签内含 `.` 的线上名字与正常名字碰撞，热点客户端可给其他设备投毒 NXDOMAIN
- **位置**：`daemon/hnc_httpd/dns_wire.go:138-148`（dnsReadName 拼接标签）、`daemon/hnc_httpd/dns_forwarder.go:625-637`（dnsCacheKey）、`dns_forwarder.go:722-724`（命中时覆盖问题段）、`dns_wire.go:508-510`（dnsSameQuestion）
- **触发 / 现象**：DNS 接管开启后，恶意热点客户端发送 QNAME 为单个标签 `\x0ewww.google.com\x00`（标签内容本身含点）的 A 查询。上游把它当作一个不存在的 TLD，返回 NXDOMAIN 和根 SOA（TTL/MINIMUM 为 86400，会被封顶到 300 秒）。HNC 把这条应答按 `www.google.com|1|1` 存进缓存。之后任何设备正常查询 `www.google.com`，都会命中这条缓存：两种写法的线上长度相同（QEnd 都是 32），`get()` 会把受害者自己的问题段字节拷进去，并改写 ID，所以受害者收到的是一条格式完全合法的 NXDOMAIN。攻击者每 5 分钟重发一次，再把 EDNS、DO、CD 的 8 种组合各发一遍，就能让任意域名对其他热点设备长期解析失败。已在 scratchpad 用源码副本复现（`/tmp/claude-0/-home-user-hnc-v6/31404bef-78e5-5872-a677-b47d7e2efb42/scratchpad/A3/dnswire/wire_test.go` 中的 TestDotLabelCollision）：受害者拿到 rcode=3、id=自己的、问题段=自己的。另有一种不含点的变体：Kelvin 符号 U+212A 经 `strings.ToLower` 会变成 ASCII 的 `k`（例如 `\xe2\x84\xaaakao.com` 被解析成 `kakao.com`），同样会碰撞，只是 QEnd 不同，受害者收到问题段不匹配的应答，最终超时。
- **原因**：
  ```go
  sb.Write(b[off+1 : off+1+l])      // 标签原样拼接，不转义 '.'
  return strings.ToLower(sb.String()), next, nil
  k := q.QName + "|" + strconv.Itoa(int(q.QType)) + ...   // 缓存键只看规范化字符串
  ```
  `dnsSameQuestion` 比较的也是同一个规范化字符串，所以防串包校验同样会放行。
- **前提**：上游必须原样转发含点（或非 ASCII）的标签。配置自定义公共上游（如 223.5.5.5 / 1.1.1.1，它们把标签当不透明字节处理）时一定成立。默认的 tether 上游（系统 dnsmasq / netd 代理）会不会拒绝这类名字，未在真机验证。
- **建议修复**：`dnsReadName` 遇到标签内的 `.`、`\`、控制字符或非 ASCII 字节时，转义（如 `\046`）或直接判为畸形（回 FORMERR，不进缓存）。只对 ASCII 做小写化，不要用 `strings.ToLower`。另一个办法是把缓存键改成按 ASCII 小写化后的线上名字字节。

### A3-002 [P2][确认] 域名封锁展开 IP 时按 map 随机顺序截断 200 个，超过 200 个匹配 IP 时每 10 秒结果都不同，反复重跑 connblock_sync.sh，实际封锁集合随机抖动
- **位置**：`daemon/hnc_httpd/conn_blocks.go:120-134`（expandConnBlocks），`conn_blocks.go:146-167`（connBlockSyncLocked 的「内容没变就不跑」判断）
- **触发 / 现象**：给某台设备封锁一个大平台域名（如 `qq.com`、`douyin.com`、`googlevideo.com`，按后缀匹配子域名）。IP→域名表最多 4096 条（dpid）加 4096 条（DNS 接管），保留最长 24 小时，匹配 IP 很容易超过 200 个。`AppUsageLoop` 大约每 10 秒调一次 `connBlockRefresh`，而 Go 的 map 遍历顺序是随机的，所以每次挑出的 200 个 IP 都不一样。结果是 `string(old) == content` 几乎永远不成立，每圈都原子重写 `run/conn_blocks.flat` 并 fork `connblock_sync.sh` 重建 iptables，白白耗电、制造规则抖动。同时，上一圈封住的 IP 这一圈可能被放行，封锁时有时无。
- **原因**：
  ```go
  for ip, nm := range names {            // map 遍历顺序随机
      if h == d || strings.HasSuffix(h, "."+d) {
          set[it.MAC+" "+ip] = true
          if n++; n >= connBlockMaxIPsPerDomain { break }
  ```
- **建议修复**：先收集全部匹配 IP，再按确定性规则（如最近出现时间降序，或 IP 字典序）排序后取前 200 个；或者超限时保留上一轮已在 flat 里的 IP，保证结果稳定。

