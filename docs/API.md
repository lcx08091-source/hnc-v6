# HNC hnc_httpd HTTP API 参考

> 来源:逐行阅读 `daemon/hnc_httpd/*.go`(基线 HEAD `695a027`,另标注本轮 v5.11 审计修复带来的行为差异)。
> 目标读者:要给 HNC 写一个全新前端数据层的人。本文档力求"照着写就能跑",凡是代码里没有的行为一律不写。
>
> 约定:
> - 「`$HNC`」= httpd 的 `-hnc-dir`,默认 `/data/local/hnc`;「模块目录」= `/data/adb/modules/hotspot_network_control`。
> - 所有 `bin/*.sh` 都以 `sh $HNC/bin/<script> <argv...>` 形式调用(argv 数组,**不经过 shell 字符串拼接**),
>   环境变量只有 `HNC_DIR=$HNC`、`HNC=$HNC`、`PATH=/system/bin:/system/xbin:/vendor/bin:/usr/bin:/bin`。
> - 「字节/秒」字段虽然名字叫 `*_bps`,单位是 **Byte/s**,不是 bit/s(见 §3)。
> - 「Mbps」= 兆**比特**每秒(十进制,1 mbit = 1000 kbit);旧 UI 显示的 "MB/s" 是前端自己 ÷8 换算的,后端不认 MB/s。

---

## 0. 总览

### 0.1 监听端口

| 端口 | 协议 | 绑定 | 用途 | 开启条件 |
|---|---|---|---|---|
| 8444 | HTTP(明文) | `127.0.0.1` 固定 | 本机 KSU/SukiSU WebUI(通过 `ksu.exec` 跑 `curl`) | `-loopback-port`>0(默认 8444) |
| 8443 | HTTPS(自签 ECDSA P-256,10 年) | `-bind` 指定(热点 IP 或 `0.0.0.0`) | 热点内其它设备的浏览器远程访问 | 传了 `-bind`(`rules.json.remote_enabled=true` 时由 service/watchdog 拉起) |
| 8080 | HTTP | 同 `-bind` | 只做 `308` 跳转到 `https://<本机到达地址>:8443<原 URI>` | 传了 `-bind` 且 `-http-port`>0 且未 `-no-tls` |

- 8443 与 8444 **共用同一个 handler**,路由完全一致;区别只在鉴权分支(见 §1)。
- `-bind` 只允许 RFC1918 私网 / 127/8 / `0.0.0.0`(`validateBindAddress`)。注意 Go 在 `0.0.0.0` 上用 `tcp` 监听时是**双栈**,IPv6 客户端也能连。
- 证书:`$HNC/data/httpd_cert.pem`(0644)+ `httpd_key.pem`(0600);SAN = bind IP(非 0.0.0.0 时)+ `127.0.0.1` + `localhost`。
- 服务器超时:ReadHeader 10s / Read 30s / **Write 60s** / Idle 60s(8080 跳转服务 5/10/10s)。长耗时写操作会被 60s 写超时切断连接,但后台脚本继续跑完。

### 0.2 中间件链(外 → 内)

```
securityHeaders → accessLogMiddleware(含 panic recover)→ authMiddleware → ServeMux
```

- **securityHeaders**:所有响应(含 401/302)都带
  `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' http://127.0.0.1:8444; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`、
  `X-Frame-Options: DENY`、`X-Content-Type-Options: nosniff`。
  → 新前端若由 httpd 托管,不能引外部 CDN 脚本/样式;只能 `connect-src 'self'` 与 `http://127.0.0.1:8444`。
- **accessLog**:每请求写一行到 `$HNC/logs/httpd.log`(`ip method path status 耗时`);handler panic → 500 纯文本 `internal error`。
- **所有 `writeJSON` 响应**额外带 `Cache-Control: no-store, no-cache, must-revalidate, max-age=0`、`Pragma: no-cache`、`Expires: 0`、
  `Content-Type: application/json; charset=utf-8`。JSON 由 `json.Encoder` 输出,**末尾带一个 `\n`**。

### 0.3 路由总表(40 个 mux 路由注册 + `/api/action` 下 38 个 action)

| # | 方法 | 路径 | 鉴权 | 分组 |
|---|---|---|---|---|
| 1 | GET | `/` | 公开 | §13 |
| 2 | GET | `/static/app.js`、`/static/style.css` | 公开 | §13 |
| 3 | GET | `/pair` | 公开 + unauth 限流 | §10 |
| 4 | POST | `/api/pair/verify` | 公开 + unauth 限流 + PIN 限流 | §10 |
| 5 | POST | `/api/logout` | 公开(自行解析 cookie) | §10 |
| 6 | GET | `/api/health` | 公开 | §12 |
| 7 | GET | `/changelog.html` | 公开 | §13 |
| 8 | GET | `/json-health.html` | 公开 | §13 |
| 10 | GET | `/api/whoami` | 需鉴权(仅 cookie 身份有意义) | §10 |
| 11 | GET | `/api/tokens` | 需鉴权 | §10 |
| 12 | GET | `/api/devices` | 需鉴权 | §2 |
| 13 | GET | `/api/templates` | 需鉴权 | §2 |
| 14 | GET | `/api/live` | 需鉴权 | §3 |
| 15 | GET | `/api/events` | 需鉴权(SSE) | §3 |
| 16 | GET | `/api/stats` | 需鉴权 | §4 |
| 17 | GET | `/api/online_hours` | 需鉴权 | §4 |
| 18 | GET | `/api/dpi_history` | 需鉴权 | §4/§5 |
| 19 | GET | `/api/dpi_state` | 需鉴权 | §5 |
| 20 | GET | `/api/dpi_probe` | 需鉴权 | §5 |
| 21 | GET | `/api/app_limits` | 需鉴权 | §5 |
| 22 | GET | `/api/self` | 需鉴权 | §5 |
| 23 | GET | `/api/self/ifaces` | 需鉴权 | §5 |
| 24 | GET | `/api/self/attrib` | 需鉴权 | §5 |
| 25 | POST | `/api/self/toggle` | 需鉴权 + requireMutation | §5 |
| 26 | POST | `/api/self/auto_expand/toggle` | 需鉴权 + requireMutation | §5 |
| 27 | POST | `/api/self/auto_promote/toggle` | 需鉴权 + requireMutation | §5 |
| 28 | GET | `/api/alerts` | 需鉴权 | §6 |
| 29 | GET | `/api/alert_config` | 需鉴权 | §6 |
| 30 | GET | `/api/logs` | 需鉴权 | §7 |
| 31 | GET | `/api/config` | 需鉴权 | §8 |
| 32 | GET | `/api/iface_info` | 需鉴权 | §9 |
| 33 | GET | `/api/offload_status` | 需鉴权 | §11 |
| 34 | GET | `/api/sla` | 需鉴权 | §11 |
| 35 | POST | `/api/export` | 需鉴权 + requireMutation | §11 |
| 36 | GET | `/api/exports` | 需鉴权 | §11 |
| 37 | GET | `/api/exports/<name>.zip` | 需鉴权 | §11 |
| 38 | GET | `/api/capabilities` | 需鉴权 | §12 |
| 39 | GET | `/api/metrics` | 需鉴权 | §12 |
| 40 | POST | `/api/action` | 需鉴权 + CSRF + 写限流 + 全局串行 | §14 |

> v5.19 另注册了 `/api/sim`、`/api/phone_usage`、`/api/app_time`、`/api/dpi_unknown` 四个 GET 路由及一批新 action,见 §18。

(表中 40 行与 `server.go handler()` 里的 40 个 `mux.Handle/HandleFunc` 一一对应;`/static/` 前缀只认两个文件名,`/api/exports/` 前缀按文件名下载。
未注册的任何路径都会落到 `/` 的 handler:已鉴权 → `404 page not found`(纯文本);未鉴权 → 401/302,因为不在公开白名单。)

> **方法检查说明**:除明确写了"仅 POST/GET"的端点外,大多数 GET 端点**不校验方法**(POST/PUT 也会返回同样内容)。新前端请只用文档标注的方法。

---

## 1. 鉴权、限流与错误格式

### 1.1 三种身份

| 身份 | 如何获得 | 典型调用方 | 能力 |
|---|---|---|---|
| **本机 root(loopback secret)** | 连接来自 loopback(`127.0.0.1`/`::1`/`::ffff:127.0.0.1`)**且**请求**没有** `Origin` 与 `Referer` 头 **且** `X-HNC-Local-Admin: <64 位 hex>` 与 `$HNC/run/local_admin.secret` 内容常量时间比较相等 | KSU WebUI 通过 `ksu.exec("curl …")` | 全部接口,且是唯一能调用 loopback-only action(`pair_revoke`、`auth_required_set`、`remote_enabled_set`)的身份;写限流 key 固定为 `wr-loopback`(所有本机调用共享 60 次/分钟) |
| **远程 cookie** | `POST /api/pair/verify` 输入正确 PIN 后下发 `hnc_token` cookie | 热点内浏览器 | 除 loopback-only action 外全部;`/api/whoami` 只对它有意义 |
| **匿名** | — | — | 只能访问公开白名单 |

`local_admin.secret`:由 `service.sh` 启动时生成,`0600 root`,内容 32 字节随机数的 64 位 hex(大小写都认,首尾空白会被 trim)。磁盘文件不是合法 64 hex 时**拒绝所有** secret 请求。

### 1.2 authMiddleware 决策顺序(`middleware.go`)

1. 路径在公开白名单 → 直接放行。白名单:`/`、`/pair`、`/changelog.html`、`/json-health.html`、`/api/pair/verify`、`/api/pairing/status`(**未注册路由,实际 404**)、`/api/health`、`/api/logout`、以及前缀 `/static/`。
2. 连接来自 loopback:
   - 无 `Origin` 且无 `Referer`:
     - secret 校验通过 → 放行(context 里**没有** token);
     - `local_admin.secret` 文件不存在 → 仅 `/api/health` 放行,其余 401(fail-closed);
     - 文件存在但头缺失/错误 → 401。
   - 有 `Origin` 或 `Referer`(浏览器发起,防 DNS rebinding)→ 继续走下面的 cookie 流程,secret 头被忽略。
3. 消费 `$HNC/run/token_revoke.request`(shell CLI 撤销桥,见 §10.6),再按 mtime 同步 `remote_tokens.json`。
4. 读 cookie `hnc_token`:
   - 缺失/空 → 401(不下发清 cookie);
   - 格式 `<TokenID 11 字符>.<Secret 32 字符>`(base64url 无 padding),`VerifyCookie`:TokenID 不存在/已撤销/`last_seen` 超过 **14 天**/bcrypt 不匹配 → 401 **并下发清除 cookie**;
   - 通过 → 更新内存 `last_seen`(每 30s 落盘),把 TokenID 与 Token 放进 context,放行。

> `rules.json.auth_required` 字段**已不影响鉴权**(rc30.12.18 起默认拒绝),只在日志里提示;`auth_required_set` action 仍可写它。

### 1.3 Cookie 规格

```
Set-Cookie: hnc_token=<TokenID>.<Secret>; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Strict
清除:      hnc_token=; Path=/; Max-Age=0(-1); Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict
```

- 浏览器侧 30 天过期;服务端以 `last_seen` 滑动 14 天为准(14 天内有任意一次成功请求就续期)。
- 服务端存 `bcrypt(Secret, cost=10)`,每个带 cookie 的请求做一次 bcrypt(arm64 约 100–300ms CPU)。**新前端请避免高频并发请求**,轮询间隔建议 ≥2s。
- `Secure` 属性 → 只能在 HTTPS(8443)上被浏览器保存/回送。

### 1.4 未鉴权响应

| 情况 | 响应 |
|---|---|
| 路径以 `/api/` 开头 | `401`,`Content-Type: application/json`,body 恒为 `{"error":"auth required"}`(无换行)。cookie 无效时附带清除 cookie |
| 其它路径 | `302 Location: /pair` |

前端约定:收到任意 401 → 跳 `/pair`(远程)。本机 KSU WebUI 收到 401 说明 secret 没读到/不匹配,**不要**跳 `/pair`。

### 1.5 限流与写入限制一览

| 机制 | 作用范围 | 规则 | 超限响应 |
|---|---|---|---|
| unauth 令牌桶 | 仅 `/pair`、`/api/pair/verify` | 每源 IP 容量 20、每秒补 20;LRU 最多 512 个 IP,满且全在 PIN 锁定中时退化为全局桶 50/s | `429` + `Retry-After: 2`(全局桶为 1)+ `{"error":"rate limited"}` |
| PIN 尝试 | `/api/pair/verify` | 每源 IP 60s 窗口,第 5 次消费即锁 10 分钟(即每 IP 每轮最多 4 次真比对);格式错误也消费名额;无活动配对时不消费。**v5.11 起另加全局上限:所有来源合计每 60s 最多 20 次消费** | `429` + `Retry-After` + `{"error":"too many pin attempts","locked_for_sec":N}` |
| 写频率 | `/api/action`(**v5.11 起也含** `requireMutation` 包裹的 4 个 POST 端点) | 每身份 60 次 / 滑动 60s;key = `wr-<完整 TokenID>` 或 `wr-loopback` | action:`429 {"ok":false,"error":"write rate limited (60/min)"}`;其它:`429 {"error":"write rate limited (60/min)"}` |
| 写串行 | `/api/action` | 全局 `actionMu`,所有 action 严格排队执行(排队 >200ms 会记日志) | 不拒绝,只等待 |
| 导出串行 | `/api/export`(v5.11) | 同一时刻只允许一个导出 | `409 {"error":"export already in progress"}` |
| SSE 并发 | `/api/events` | 全进程最多 64 条 | `503` + `Retry-After: 10` + `{"error":"too many SSE connections"}` |
| body 上限 | `/api/action`、requireMutation 端点 16 KiB;`/api/pair/verify` 4 KiB | 超出 → 解码失败 | action:`400 bad json`;其它:`400` |

### 1.6 requireMutation(`/api/self/*/toggle`、`/api/export` 专用)

依次检查:方法必须 POST(否则 `405` + `Allow: POST` + `{"error":"POST only"}`)→ `Content-Type` 以 `application/json` 开头(否则 `415 {"error":"content-type must be application/json"}`)→ 头 `X-HNC-CSRF: 1`(否则 `400 {"error":"csrf header missing"}`)→(v5.11)写频率限制 → body 限 16 KiB。

### 1.7 错误响应格式汇总

后端没有统一错误信封,按端点分三类:

1. **普通 JSON 端点**:`{"error":"<英文短语>"}`,可能带额外字段(如 `max_range_secs`)。HTTP 状态码有意义。
2. **"可用性"类读端点**(`/api/dpi_state`、`/api/dpi_probe`、`/api/self`、`/api/capabilities`):**读失败仍返回 200**,body 为 `{"available":false,"error":"<Go 错误串,含文件路径>",...}`。前端要看 `available` 而不是状态码。
3. **`/api/action`**:恒为 `{"ok":bool,"error"?:string,"detail"?:string}`(`error`/`detail` 为空时省略)。状态码映射见 §14.1。
4. 少数端点返回**纯文本**:`405 method not allowed`(`/api/action`、`/pair`、`/api/pair/verify`、`/api/logout` 用 `http.Error`)、`400 invalid name` / `must end in .zip`(`/api/exports/<name>`)、`404 page not found`、panic 的 `500 internal error`。

---

## 2. 设备与规则

### 2.1 GET `/api/devices` — 设备列表(合并视图)

- 鉴权:需鉴权。无参数。永远 200。
- 数据来源(每次请求读,经 mtime+size 缓存):`$HNC/data/devices.json`(hotspotd 写,当前发现的客户端)、`$HNC/data/rules.json`(规则)、
  `$HNC/data/device_names.json`(手动命名)、`$HNC/run/dpi_state.json`(`clients[*].top_apps`)、内存中的 RateLoop 速率快照。
- 合并规则:
  1. devices.json 每台设备 → 复制其全部字段,再用 `rules.json.devices[mac]`(大小写不敏感)覆盖
     `mark_id, down_mbps, up_mbps, delay_ms, jitter_ms, loss_pct, limit_enabled, delay_enabled, sqm_enabled`;
  2. `device_names.json[mac]` 非空 → `hostname=<手动名>`、`hostname_src="manual"`;
  3. `status` 被**重写**为 `"blocked"`(MAC 在 `rules.json.blacklist`)或 `"allowed"`(devices.json 原 `status` 被覆盖);
  4. `online = last_seen>0 && now-last_seen < 90s`;
  5. `rx_bps/tx_bps` 来自后台 RateLoop(见 §3.1),单位 **Byte/s**;
  6. `dpi_apps`:该 MAC 在 dpi_state `clients` 中的 top_apps 前 5 项,仅非空时出现。
- **离线"虚行"**:`rules.json.devices` 里有规则、在黑名单里、或在 `device_names.json` 里有名字,但当前不在 devices.json 的 MAC,
  也会以离线行出现:`ip:"-"`(若规则里存了 `ip` 则为该值)、`online:false`、`rx_bps:0`、`tx_bps:0`、`last_seen` = 规则的
  `last_seen_persist`(无则 0),并复制 `ip, mark_id, down_mbps, up_mbps, delay_ms, jitter_ms, loss_pct, limit_enabled, delay_enabled`
  (**注意:虚行不带 `sqm_enabled`**)。虚行 MAC 为小写。
- 排序:按 IPv4 数值序(`-` 等非 IP 视为 0.0.0.0 排最前)。

响应:

```json
{
  "devices": [
    {
      "mac": "aa:bb:cc:dd:ee:01",          // string,devices.json 的 key(hotspotd 写小写)
      "ip": "192.168.43.23",                // string;虚行可能是 "-"
      "hostname": "Mi-10",                  // string
      "hostname_src": "manual",             // "manual" | "dhcp" | "oui" | "cache" | "mac" …(hotspotd 决定)
      "iface": "ap0",                       // string,真行才有
      "rx_bytes": 123456789,                // number,累计下载字节(iptables -d 规则计数),真行才有
      "tx_bytes": 2345678,                  // number,累计上传字节(iptables -s 规则计数),真行才有
      "status": "allowed",                  // "allowed" | "blocked"
      "last_seen": 1790000000,              // number,unix 秒
      "online": true,                       // bool
      "rx_bps": 524288,                     // number,下载速率 Byte/s
      "tx_bps": 20480,                      // number,上传速率 Byte/s
      "mark_id": 3,                         // 以下 9 个字段仅当 rules.json 有该设备规则时出现,类型照抄 rules.json
      "limit_enabled": true,
      "down_mbps": 10,                      // number,Mbps(可为小数,如 0.5)
      "up_mbps": 2,
      "delay_enabled": false,
      "delay_ms": 0,
      "jitter_ms": 0,
      "loss_pct": 0,
      "sqm_enabled": false,
      "dpi_apps": [                         // 可选,最多 5 项
        {"name": "抖音", "category": "video", "confidence": 0.92, "count": 17}
      ]
    }
  ],
  "whitelist_mode": false,                  // 原样透传 rules.json.whitelist_mode(可能为 null)
  "remote_enabled": true                    // 原样透传 rules.json.remote_enabled(可能为 null)
}
```

> 字段类型说明:rules.json 由 shell `json_set.sh` 写,数值通常是 JSON number、布尔是 JSON bool,但历史数据可能出现字符串,
> 前端解析请用 `Number()` / `=== true || === "true"` 兜底。

### 2.2 GET `/api/templates` — 限速模板

- 鉴权:需鉴权。无参数。
- 原样返回 `$HNC/data/templates.json`(文件不存在/损坏 → `{}`)。形状(由 `json_set.sh tpl_set` 写):

```json
{ "游戏": {"down_mbps": 20, "up_mbps": 5, "delay_ms": 0, "jitter_ms": 0, "loss_pct": 0} }
```

- 后端**没有**写模板的 HTTP 接口:旧 KSU 前端用 localStorage 存模板,并通过 `ksu.exec('sh $HNC/bin/json_set.sh tpl_set <name> …')` / `tpl_del <name>` 双写到 templates.json。
  浏览器前端只能读。"应用模板"= 前端把模板展开后调 `rule_set`(或 `template_apply`,二者等价)。

### 2.3 设备写操作(均经 `POST /api/action`,详细请求格式见 §14)

| action | params(全部是字符串) | 校验 | 后端执行 | 成功 detail |
|---|---|---|---|---|
| `rule_set` | `mac` 必填;`rate_down`、`rate_up` 至少一个 | `mac` 必须匹配 `^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`(**只收小写**);速率为 `"0"` 或 `^[0-9]+(kbit\|mbit)$`,换算后 64 kbit ≤ x ≤ 10 485 760 kbit(1 mbit=1000 kbit);MAC 不能是广播/全零/热点接口自身 MAC(否则 `protected mac`) | 速率先转成 Mbps 字符串(`"500kbit"`→`"0.5"`,`"10mbit"`→`"10"`,未填方向→`"0"`)。若 `run/capabilities.json` 明确 `tc_htb=false` 且有正速率 → `unsupported`;若 `uplink_supported=false` 则上行强制为 0(无下行时直接 OK 跳过)。然后 `sh bin/apply_device_rule.sh limit <mac> <down_mbps> <up_mbps>`(10s 超时),该脚本负责 iptables mark + tc class + rules.json | `"limit applied"`;上行被降级时 `"download limit applied; uplink unsupported/disabled on this ROM, kept up=0"` |
| `template_apply` | 同 `rule_set` | 同上 | 直接调用 `rule_set` 逻辑 | 同上 |
| `rule_clear` | `mac` | 小写 MAC | `apply_device_rule.sh clear <mac>` | `"limit cleared"` |
| `bl_add` | `mac` | 小写 MAC + 受保护 MAC 检查 | `apply_device_rule.sh bl_add <mac>` | `"blacklisted"` |
| `bl_del` | `mac` | 小写 MAC | `apply_device_rule.sh bl_del <mac>` | `"removed from blacklist"` |
| `delay_set` | `mac`、`delay_ms`、`jitter_ms`、`loss_pct` **全部必填** | `delay_ms`/`jitter_ms`:纯数字 0–5000(毫秒);`loss_pct`:`^[0-9]+(\.[0-9]+)?$` 且 0–100(百分比) | 有任一非零且 capabilities 明确 `tc_htb=false` 或 `tc_netem=false` → `unsupported`。流程:`device_detect.sh iface` → `json_set.sh device_get <mac> mark_id`(无则 `apply_device_rule.sh alloc_mid <mac>`)→ `tc_manager.sh set_delay <iface> <mid> <delay> <jitter> <loss> <当前ip>`(失败且是新分配的 mid 会回滚 `iptables_manager.sh unmark` + `json_set.sh device <mac> mark_id 0`)→ `hnc_ipc OFFLOAD_NOTIFY_LIMIT <mac> 1` → `json_set_batch.sh device <mac> delay_enabled true delay_ms … jitter_ms … loss_pct …` | `"delay injected"` |
| `delay_clear` | `mac` | 小写 MAC | 若设备还有正限速:`tc_manager.sh set_delay <iface> <mid> 0 0 0 <ip>`;否则 `tc_manager.sh remove` + `iptables_manager.sh unmark` + offload 通知 0。最后批量写 `delay_enabled=false, delay_ms=0, jitter_ms=0, loss_pct=0`。无 mark_id 时直接 OK | `"delay cleared"` 或 `"already cleared (no mid)"` |
| `rule_sqm` | `mac`、`enabled` | `enabled` 接受 `true/1/on/yes` 或 `false/0/off/no/""`(空=false) | 开启且 `tc_htb=false` → `unsupported`。`device_detect.sh iface` → 取/分配 mark_id(关闭且无 mid 时只写 flag)→ `tc_manager.sh set_sqm <iface> <mid> on\|off <ip>` → `json_set.sh device <mac> sqm_enabled true\|false` | `"sqm=true mac=…"` / `"sqm off (no class)"` |
| `device_rename` | `mac`,`name`(可空) | `mac` 接受 `aa:bb…` 或 `aa-bb-…`,大小写均可(保存为小写冒号);`name` trim 后 ≤32 **字节**、无控制字符;空串 = 删除手动名 | 进程内互斥 + 读改写 `$HNC/data/device_names.json`(紧凑 JSON,tmp+rename)。文件损坏 → `read failed` 且**不覆盖** | `"set aa:… -> \"名字\""` / `"cleared name for …"` / `"no manual name set; nothing to clear"` |
| `whitelist_set` | `enabled` | 仅 `"true"`/`"false"` | `json_set.sh top whitelist_mode <v>`(只写 JSON,生效依赖 watchdog/iptables 同步) | 无 detail |
| `refresh` | — | — | `device_detect.sh scan` | 脚本 stdout |
| `cleanup_rules` | — | — | `cleanup.sh rules`(60s 超时) | 无 detail |
| `cleanup_offline_devices` | `include_rules`(`"1"`/`"true"` 时连带有规则的离线设备一起清) | — | `cleanup_offline_devices.sh [--include-with-rules]` | 脚本 JSON 字符串:`{"ok":true,"removed":N,"kept_with_rules":N,"skipped_online":N}`(前端需 `JSON.parse(detail)`) |

**速率单位小抄**:前端若以 MB/s 显示,提交前 `Mbps = MB/s × 8`;`≥1` 的整数 Mbps 发 `"<n>mbit"`,其余发 `"<round(Mbps×1000)>kbit"`(与旧 UI 的 `fmtRate` 一致)。
两个方向都为 0 时请改调 `rule_clear`(`rule_set` 要求至少一个方向非空)。

## 3. 实时速率 / live / SSE

### 3.1 速率是怎么算的(RateLoop)

- 后台 goroutine 每 **2s** 读一次 `devices.json`,对每个 MAC 用"上次字节变化的那一帧"做差分:`rx_bps = Δrx_bytes / Δt`(Byte/s,整数)。
- hotspotd 最快 5s 才刷新一次计数器,所以字节没变化时沿用上次速率;连续 **10s** 无变化才归零;两帧间隔 >120s 视为计数中断,本轮 0。
- 首次见到的 MAC 速率为 0(需要第二帧)。计数器回退(规则重建)按 0 处理。
- `/api/devices` 与 `/api/live` 读同一份快照 → 两者永远一致。

### 3.2 GET `/api/live` — 状态条摘要(高频轮询用)

- 鉴权:需鉴权。无参数。内部就是 `buildDevicesPayload()` + 汇总,开销与 `/api/devices` 相同(都有缓存)。

```json
{
  "hotspot_active": true,              // bool,见下
  "iface": "ap0",                      // string,热点接口名,可能为 ""
  "hotspot_iface": "ap0",              // 同 iface(兼容字段)
  "hotspot_ip": "192.168.43.1",        // string,该接口的私网 IPv4,取不到为 ""
  "online": 3,                         // number,online=true 的设备数
  "total": 5,                          // number,devices 数组长度(含离线虚行)
  "rx_bps": 1048576,                   // number,全部设备下载速率之和,Byte/s
  "tx_bps": 65536,                     // number,上传速率之和,Byte/s
  "devices_sig": "3f0c…(40 位 hex)",   // string,设备关键字段的 SHA-1 指纹;变了才需要重拉 /api/devices
  "backend_version": "v5.10.0",        // string,编译时注入(module.prop version)
  "backend_version_code": "5100"       // string(注意是字符串),module.prop versionCode
}
```

- `iface` 来源优先级:`run/hnc_state` 为 `ACTIVE:<iface>` → `run/iface.cache` → `rules.json.hotspot_iface`。
- `hotspot_active`:`run/hnc_state` 以 `INACTIVE`/`OFF`/`DOWN` 开头 → false;以 `ACTIVE` 开头 → true;否则 iface 和 IP 都有 → true;否则 `online>0`。
- `devices_sig` 覆盖字段:`active`、`iface`,以及每台的 `mac|ip|online|status|limit_enabled|delay_enabled|down_mbps|up_mbps|delay_ms|jitter_ms|loss_pct`(**不含**速率、hostname、sqm_enabled、dpi_apps)。

推荐轮询:`/api/live` 每 2s;`devices_sig` 变化或用户操作后再拉 `/api/devices`。

### 3.3 GET `/api/events` — Server-Sent Events(仅浏览器直连可用)

- 鉴权:需鉴权(EventSource 同源自动带 cookie)。并发上限 64(超出 `503`)。
- 响应头:`Content-Type: text/event-stream; charset=utf-8`、`Cache-Control: no-cache`、`Connection: keep-alive`、`X-Accel-Buffering: no`;
  服务端清除写超时,连接可长期保持。
- 事件:
  - 连上立即:`event: changed` / `data: {"reason":"connect"}`
  - 每 1.5s stat 一次 `devices.json`,mtime 变化:`event: changed` / `data: {"reason":"devices"}`
  - 每 20s 心跳注释行 `: hb`
- 事件只是"该刷新了"的信号,不携带数据;收到后调 `/api/devices`(或 `/api/live`)。
- **基线 695a027 的已知缺陷**:访问日志中间件包装了 ResponseWriter 却没有 `Unwrap()`,`SetWriteDeadline` 失败 → 该端点恒返回
  `500 {"error":"sse unsupported"}`,远程 SPA 一直在走轮询兜底。v5.11 审计已修复(见 §17)。
- 本机 KSU WebUI(`ksu.exec` + curl)无法使用 SSE,只能轮询。

## 4. 统计

后端有**两条互不相同的流量统计链**,口径不同,前端必须明确选择:

| 链 | 写入方 | 文件 | 行语义 | 口径 |
|---|---|---|---|---|
| legacy | `bin/stats_sample.sh`(watchdog 每轮)+ `stats_rollup.sh` | `$HNC/data/stats_raw.jsonl` `{"ts":秒,"mac","rx","tx"}`(**累计计数器**);`$HNC/data/stats_daily.jsonl` `{"date":"YYYY-MM-DD","mac","rx","tx","name"}`(日汇总) | 计数器,需相邻差分 | iptables 全量 |
| dpi | dpid HistorySampler 每 15 分钟 | `$HNC/run/stats.YYYYMMDD.jsonl`(**文件名是 UTC 日期**)`{"t":秒,"mac","app","app_id","cat","tx","rx"}` | 每行即 15 分钟增量 | 只含被 DPI 归因的流量(略小于 iptables);默认只保留 7 天 |

所有 `rx` = 设备下载字节,`tx` = 设备上传字节,单位 **Byte**。

### 4.1 GET `/api/stats`

Query:

| 参数 | 类型 | 取值 | 默认 |
|---|---|---|---|
| `range` | string | `today` \| `week` \| `month` \| `all` | `today` |
| `mac` | string | 可选,`xx:xx:xx:xx:xx:xx`(大小写均可,内部转小写) | 空 = 全部设备合计 |
| `source` | string | `legacy` \| `dpi`(大小写不敏感;历史值 `shadow` 已移除,按 `legacy` 处理) | `legacy`(注意:旧 UI 默认传 `dpi`) |

错误:`400 {"error":"invalid range"}` / `{"error":"invalid mac"}` / `{"error":"invalid stats source"}`。

**legacy / shadow 响应**:

```json
{
  "range": "week",
  "mac": "",                 // 回显(小写),未传为 ""
  "source": "legacy",
  "buckets": [ {"label": "09-17", "rx": 123456, "tx": 7890}, … ]
}
```

- `today`:24 个桶,`label` = `"00:00"`…`"23:00"`(服务器本地时区);每个 MAC 按 ts 排序后相邻样本做差(负值按 0),归到后一个样本的小时。
- `week`/`month`:7/30 个桶,`label` = `"MM-DD"`,从旧到新,来自 daily;**今天**的桶用 raw 实时差分覆盖(若 >0)。
- `all`:从 daily 最早日期到今天,最多最近 90 个桶。
- 文件不存在 → 全 0 桶(不报错)。

**dpi 响应**(`source=dpi`):

```json
{
  "range": "week", "mac": "", "source": "dpi",
  "buckets": [ {"label": "09-17", "rx": 1, "tx": 2}, … ],         // today: 24 个 "HH:00" 桶;其余: days 个 "MM-DD" 桶(旧→新)
  "daily_buckets": [ {"label": "2026-09-17", "rx": 1, "tx": 2} ], // 仅有数据的日期,升序;range=today 时为 null
  "total_rx": 123, "total_tx": 45                                  // 仅 daily_buckets 非空时出现
}
```

- days:today=1、week=7、month=30、all=90(但 dpid 只保留 7 天文件)。
- **基线 695a027 缺陷**:时间窗下界写成了"now 往前 days-1 天的此刻"而不是那天零点 → `range=today` 恒全 0,week/month 的首日只剩部分;
  且按本地日期找 UTC 命名的文件,UTC+8 下凌晨 0–8 点的数据读不到。v5.11 已修为"本地零点起算 + 按覆盖窗口的 UTC 日期找文件 + 按行时间戳过滤"(§17)。

### 4.2 GET `/api/online_hours` — 设备在线小时数

- Query:`days` = `30` 时统计 30 天,其它任何值(含缺省)= 7 天。
- 数据:`$HNC/run/online_hours.jsonl`(watchdog 在热点 ACTIVE 时每 ≥55 分钟写一次,每台在线且未拉黑的设备一行 `{"t":秒,"day":"YYYYMMDD","mac":"…"}`)。
- 响应(`hours[mac][day]` = 当天被采样到的次数 ≈ 在线小时数):

```json
{ "days": 7, "hours": { "aa:bb:cc:dd:ee:01": { "20260922": 5, "20260923": 2 } } }
```

- 截止规则:`day >= (今天-days).Format("20060102")`(字符串比较)。
- **基线缺陷**:watchdog 写行时 `"t":` 值为空(shell 把变量当命令执行),整行不是合法 JSON,读侧全部丢弃 → `hours` 恒为 `{}`。
  v5.11 读侧已加正则兜底解析(§17);shell 侧仍需修 `bin/watchdog.sh`。

### 4.3 GET `/api/dpi_history` — 应用维度流量历史

- Query:

| 参数 | 类型 | 取值 | 默认 |
|---|---|---|---|
| `days` | int | 1–7(>7 截为 7,≤0 或非法 = 1) | 1 |
| `mac` | string | 可选,大小写不敏感,只统计该设备 | 全部 |
| `raw` | string | `1` 时附带原始行 | 不带 |

- 数据:`$HNC/run/stats.YYYYMMDD.jsonl`,每文件最多读前 10 MiB。
- 响应:

```json
{
  "ok": true,
  "generated_at": 1790000000,
  "days_requested": 1,
  "window_start": "2026-09-23",      // 基线实现为 UTC 日期;v5.11 起为本地日期
  "window_end": "2026-09-23",
  "sample_count": 96,                // 参与聚合的行数
  "total_tx": 123456, "total_rx": 9876543,
  "by_app": [ {"app_id": "douyin", "name": "抖音", "cat": "video", "tx": 1, "rx": 2} ],   // 按 tx+rx 降序;无 app_id 的行不进此表
  "by_hour": [ {"hour": 0, "tx": 0, "rx": 0}, … 共 24 项 ],                                // 本地时区小时,含所有行
  "by_client": [ {"mac": "aa:…", "total": 3, "apps": [ {"app_id": "…", "name": "…", "cat": "…", "tx": 1, "rx": 2} ]} ],  // 每设备最多 10 个 app,按 total 降序
  "raw": [ {"t": 1790000000, "mac": "aa:…", "app": "抖音", "app_id": "douyin", "cat": "video", "tx": 1, "rx": 2} ]       // 仅 raw=1;省略空字段
}
```

- **基线语义**:`days=1` 读的是"当前 UTC 日"的文件且不按时间戳过滤(UTC+8 下 = 本地 08:00 起)。v5.11 改为"本地今天/近 N 天"(按行 `t` 过滤),形状不变。

## 5. 应用 / DPI

### 5.1 GET `/api/dpi_state` — dpid 实时状态全量

- 读 `$HNC/run/dpi_state.json`(dpid 每 5s 刷新,开 self-capture 后可达数百 KB)。**不走缓存**,每次读盘。
- 成功:`{"available": true, "state": <dpi_state.json 原样>}`
- 失败(200):`{"available": false, "error": "<Go 错误串>", "hint": "hnc_dpid not running or no state yet; check $HNC_DIR/logs/dpid.log"}`
- `state` 的结构 = `src/dpid/output/state.go` 的 `State`,顶层字段:
  `schema_version, generated_at, version, mode, blind_reason?, interface?, tls_reassembly, ipv6_capture, offload_hint, uptime_s, stats{…},
  devices{key→Device}, clients{key→ClientProfile}?, client_count, top_hostnames?, top_sni?, top_apps?, top_categories?, top_ja4?, top_fingerprints?,
  unique_hostnames, unique_sni, unique_ja4, l3_enabled, l3_rule_version?, dfp_enabled, dfp_rule_version?, ndpi_available(已废弃: nDPI 实验已移除, 恒 false), ndpi_entries?,
  conntrack_available, conntrack_readable, conntrack_path?, conntrack_flows, total_tx_bytes?, total_rx_bytes?, self{SelfState}?, rebind_count,
  health?, stall_seconds?, unidentified_ratio{total_bytes, identified_bytes, …}?, evidence_summary{total, by_source, top_apps?}?,
  unmatched_snis_pending, unmatched_sni_samples?, byte_sampler_source?, app_label_source?, live_label_count?,
  candidate_pending?, candidate_high?, candidate_shared?, candidate_promoted?, entity_db_size?, auto_promote_on?, candidate_samples[{apex,tier,uid?,app?,hits,windows,promoted?}]?`
  (`?` = omitempty)。`clients[*]` 至少含 `client_mac` 与 `top_apps[{name, category, confidence, count}]`。
  该结构随 dpid 版本演进,新前端应做防御式读取。

### 5.2 GET `/api/dpi_probe` — dpid 启动时能力探测

- 读 `$HNC/run/dpid.probe.json`。成功 `{"available":true,"probe":<原样>}`;失败 `{"available":false,"error":"…","hint":"hnc_dpid not running or capability probe failed; …"}`(200)。

### 5.3 GET `/api/app_limits` — 按应用限速配置

- 读 `$HNC/data/app_limits.json`(缺失/损坏 → 空)。

```json
{ "ok": true, "items": [ {"mac": "aa:bb:cc:dd:ee:01", "app_id": "douyin", "down_mbps": 1.5} ] }
```

写操作(`/api/action`):

| action | params | 校验 | 执行 |
|---|---|---|---|
| `app_limit_set` | `mac`、`app_id`、`down_mbps` | `mac`:`aa:bb…`/`aa-bb-…` 大小写均可(存小写冒号);`app_id`:1–32 位 `[a-z0-9_-]`;`down_mbps`:浮点 0–10000(**Mbps**),`0` = 删除该条 | 进程内互斥读改写 `data/app_limits.json` + 伴生平面文件 `data/app_limits.flat`(每行 `<mac> <app_id> <down_mbps>`,只含 >0 项),两份 tmp 都写好再依次 rename;然后异步 touch `run/app_limit.dirty`,由 watchdog 调 `apply_app_limits.sh` 真正下发 tc/iptables。detail:`"set <mac>/<app> = 1.50 Mbps"` / `"cleared <mac>/<app>"` / `"no-op (rate=0 and no existing entry)"` |
| `app_limit_clear` | `mac`,`app_id` 可选 | 同上;`app_id` 为空 = 清该 MAC 全部 | 同上;detail `"cleared N entry(s)"` |

### 5.4 本机流量归因(self-capture)

| 方法 路径 | 说明 |
|---|---|
| GET `/api/self` | 从 dpi_state.json 取 `self` 块:`{"available":true,"self":<SelfState 或 null>,"auto_expand_enabled":bool,"auto_promote_enabled":bool}`;读失败 `{"available":false,"error":"…"}`(200)。`SelfState`:`enabled, reason?, interfaces[{name,started_at,restarts,last_error?,packets,tls_events,dns_events}]?, apps_by_uid{"<uid>"→{pkg?,display_name?,is_system?,flywheel_excluded?,uid,first_seen,last_seen,active_conns,total_conns,top_snis?,top_rules?,rule_hit_counts?,rx_bytes?,tx_bytes?,rx_bytes_delta?,tx_bytes_delta?,byte_sampler_updated_at?}}?, unknown_conns?, last_attrib_tick?, pkg_cache_size?`(见 `src/dpid/output/state.go`) |
| GET `/api/self/ifaces` | 枚举 `/sys/class/net`,按 self-capture 规则判定可用性:`{"enabled":bool,"ifaces":[{"name","oper_state","rx_bytes","eligible","reason"?}],"ap_iface":"<run/hotspot_iface 内容>","flag_path":"<绝对路径>"}`;可用的排前,组内按 rx_bytes 降序。`/sys/class/net` 读失败 → `{"error":"…"}`(200) |
| GET `/api/self/attrib?limit=N` | 读 `run/self_attrib.*.jsonl` 中文件名排序最大的那个(最新一天),返回最后 N 行(默认 200,1–2000,越界回默认):`{"file":"self_attrib.20260923.jsonl","observations":[<每行 JSON>],"shown":n,"total":<文件总行数>}`;无文件 → `{"observations":[],"note":"no self_attrib JSONL files yet (sampler may not have run)"}`;打开失败 `500 {"error":"…"}` |
| POST `/api/self/toggle` | requireMutation。body `{"enabled": true\|false}`(字段必填,`null`/缺失 → `400 {"error":"missing 'enabled' field"}`;JSON 错误 → `400 {"error":"<解码错误>"}`)。true = 写 `run/self_capture.enabled`,false = 删。响应 `{"status":"ok","enabled":bool,"note":"dpid will pick up the change within 5s on its next sampler tick"}`;IO 失败 `500 {"error":"…"}` |
| POST `/api/self/auto_expand/toggle` | 同上,flag 文件 `run/auto_expand.enabled`,note `"auto-expander goroutine will pick up the change within 60s on its next tick"` |
| POST `/api/self/auto_promote/toggle` | 同上,flag 文件 `run/auto_promote.enabled`,note `"candidate goroutine will pick up the change within 60s on its next tick"` |

相关 action:

| action | params | 执行 / 返回 |
|---|---|---|
| `self_attrib_purge` | — | 删除 `run/self_attrib.*.jsonl`,detail `"purged N file(s)"` |
| `candidate_promote` | `apex`(域名,trim+小写后 3–253 字符、含点、`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`、无 `..`) | 追加到 `$HNC/etc/candidate_decisions.json` 的 `promote[]`(tmp+rename;文件损坏 → `read failed` 不覆盖)。detail `"approved <apex> — dpid promotes within 60s"` / `"<apex> already approved"` |
| `candidate_reject` | `apex`(同上) | 追加到 `$HNC/etc/auto_expand_blocklist.json` 的 `blocked_apex[]`。detail `"blocklisted <apex> — …"` / `"<apex> already blocklisted"` |
| `flywheel_exclude_set` | `op`=`add`\|`remove`,`pkg`=Android 包名(`^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$`,3–255) | 读改写 `$HNC/etc/flywheel_exclude.json` 的 `exclude_pkgs[]`。detail `"excluded <pkg> — dpid applies within ~5 min"` / `"un-excluded …"` / `"… already excluded"` / `"… was not in the user list"`。当前用户列表可从 `/api/config.flywheel_exclude_user` 读 |
| `dpi_rebind` | `iface` 可选(`^[A-Za-z0-9_.:-]{1,32}$`) | `sh bin/dpi_rebind.sh [iface]`(30s 超时),detail = 脚本 stdout;失败 error `"dpi rebind failed"` |

`/api/dpi_history`(应用维度历史)见 §4.3。

## 6. 告警

告警由 dpid 的 `alert` 包(`src/dpid/alert`)检测并追加到 `$HNC/run/alerts.jsonl`;httpd 只做读取与"已读/已知"标记。

### 6.1 GET `/api/alerts`

- 读 `run/alerts.jsonl` 最后 4 MiB,最新在前,最多 100 条;已读集合来自 `run/alerts_seen.json`(`{"ids":[…]}`,最多 1000 个)。

```json
{
  "ok": true,
  "alerts": [
    {
      "id": "unknown_device_aabbccddee01_1789998400",     // string,<kind>_<去冒号 mac>_<整点 unix 秒>(同类同设备同小时同 ID)
      "ts": 1790000000,                                     // unix 秒
      "kind": "unknown_device",                             // "unknown_device" | "anomaly_traffic" | "monthly_quota" | v5.19: "device_quota" | "phone_quota" | "app_time_warn" | "app_time_exhausted"(§18.7)
      "mac": "aa:bb:cc:dd:ee:01",                           // 可选
      "ip": "192.168.43.50",                                // 可选
      "detail": "新设备接入: …",                             // 可选,人类可读
      "extra": { "hostname": "…" },                         // 可选,任意对象
      "seen": false                                         // bool,是否已读
    }
  ],
  "unread": 1,
  "total": 1
}
```

- 读文件出错(非"不存在")时:`{"ok":true,"alerts":[],"unread":0,"total":0,"error_hint":"<错误>"}`。

### 6.2 GET `/api/alert_config`

- 以 `alert.DefaultConfig()` 为底,`$HNC/data/alerts_config.json` 中同名 section **整体覆盖**(不做字段级合并):

```json
{
  "enabled": true,
  "unknown_device":  {"enabled": true,  "quiet_hour_start": 23, "quiet_hour_end": 7, "min_interval_sec": 1800},
  "anomaly_traffic": {"enabled": true,  "ratio_threshold": 3.0, "min_bytes": 54525952},
  "monthly_quota":   {"enabled": false, "limit_bytes": 0, "warn_at_pct": 80}
}
```

### 6.3 告警 action

| action | params | 说明 |
|---|---|---|
| `alert_mark_seen` | `ids`:逗号分隔的 ID 列表,或以 `[` 开头的 JSON 数组字符串;也接受备用键 `ids_json` | 写入 `run/alerts_seen.json`(本次标记的排最前,总数截断 1000)。detail `"marked N alert(s) as seen"`(英文复数) |
| `alert_mark_known` | `mac`(`aa:bb…`/`aa-bb…`,大小写均可;由 alert 包校验,非法 → `500 write failed / invalid mac`) | 写入 `data/known_devices.json`,此后不再对该 MAC 报 unknown_device。detail `"marked <mac> as known"` |
| `alert_dismiss_all` | — | 把最近 1000 条全部标记已读。detail `"dismissed N alerts"` / `"nothing to dismiss"` |
| `alert_config_set` | `section` + `enabled`(`"true"`/`"false"`,必填)+ 各 section 参数 | 读改写 `data/alerts_config.json`(tmp+rename;原文件损坏时当作空对象覆盖)。dpid 下一 tick 生效 |

`alert_config_set` 各 section:

| section | 额外参数 | 写入内容 |
|---|---|---|
| `master` | — | 顶层 `enabled`;若文件里没有 `monthly_quota` 会顺手补一个 `{enabled:false, limit_bytes:1073741824, warn_at_pct:80}` 哨兵 |
| `monthly_quota` | `limit_gb`:浮点 (0, 10240],**GiB**(×1073741824 存 `limit_bytes`);`warn_pct`:整数 1–99,缺省/非数字 = 80 | `{enabled, limit_bytes, warn_at_pct}` |
| `anomaly_traffic` | `ratio`:浮点 (0, 1000](必填);`min_mb`:整数 ≥0,**MiB**,缺省/非数字 = 50 | `{enabled, ratio_threshold, min_bytes}` |
| `unknown_device` | `quiet_start`/`quiet_end`:0–23(缺省 23/7);`min_interval_sec`:>0(缺省 1800) | `{enabled, quiet_hour_start, quiet_hour_end, min_interval_sec}` |

成功 detail:`"<section> → <enabled> · dpid 下一 tick 生效"`。未知 section → `400 bad params / unknown section: …`。

## 7. 日志

### 7.1 GET `/api/logs`

Query:

| 参数 | 取值 | 默认 |
|---|---|---|
| `file` | 白名单之一:`service.log` `watchdog.log` `detect.log` `iptables.log` `tc.log` `apply.log` `audit.log` `httpd.log` `hotspot.log` `stats.log` `hotspotd.log` `dpid.log` `dpid_guard.log`;或特殊值 `combined` | **必填**(不在白名单 → `400 {"error":"log file not in whitelist"}`) |
| `tail` | 整数 10–2000(越界或非数字按 300) | 300 |

- 实现:`tail -n <N> $HNC/logs/<file>`(3s 超时;失败/不存在 → 空串,不报错)。
- `combined` = `service.log`、`watchdog.log`、`detect.log` 各取 `N/3` 行,依次拼接,每段前加一行 `─── <name> ───`。

```json
{ "file": "watchdog.log", "content": "…多行文本…", "tail": 300 }
```

- `audit.log` 格式(每个 `/api/action` 一行,敏感参数 `password/pass/secret/token/pin` 已脱敏为 `<redacted>`):
  `[2026-09-23 12:00:00] tid=<TokenID 前 8 位|loopback> action=rule_set mac=aa:… rate_down=10mbit result=ok detail=limit applied`

## 8. 设置 / 偏好

### 8.1 GET `/api/config`

读 `$HNC/data/rules.json`(每次读盘,不缓存)+ `run/offload_guard.json` + `run/connblock_caps.json` + `etc/flywheel_exclude.json`:

```json
{
  "auth_required": true,             // bool,rules.json.auth_required(已不影响鉴权,见 §1.2)
  "whitelist_mode": false,           // bool
  "remote_enabled": true,            // bool,8443 远程访问总开关
  "hotspot_autostart": false,        // bool,读 hotspot_auto,回退 hotspot_autostart
  "hotspot_ssid": "MyAP",            // string,omitempty
  "hotspot_delay_sec": 60,           // number,omitempty(0 时省略);读 hotspot_delay,回退 hotspot_delay_sec
  "global_shaper_enabled": false,    // bool
  "global_shaper_down": "100mbit",   // string,omitempty,tc 速率串
  "global_shaper_up": "20mbit",      // string,omitempty
  "flywheel_exclude_user": ["com.v2ray.ang"],  // []string,omitempty,用户自加的飞轮排除包名
  "clsact_bpf_enabled": false,       // bool,v5.18 起只读兼容 = (clsact_bpf_mode == "on")
  "clsact_bpf_mode": "auto",         // string,"auto"|"on"|"off";缺失时旧键 clsact_bpf_enabled=true → "on",否则 "auto"
  "offload_guard": {                 // object|null,run/offload_guard.json 原样(守护每 60s 写);没有则 null
    "mode": "auto",                  //   生效模式
    "offload_state": "ACTIVE",       //   NOMAP|IDLE|CAPABLE|ACTIVE|NOHOTSPOT|UNKNOWN|SKIPPED(off 模式)
    "fallback_active": true,         //   是否正在强制 offload 走慢路径
    "since": 1790000000,             //   兜底启用时刻(unix 秒),未启用为 0
    "detail": "检测到 offload 正在旁路限速; 已强制 offload 走慢路径(limit_map=0, 每轮重申)",
    "last_check": 1790000060,        //   最近一轮时刻(unix 秒)
    "slowpath": "ok",                //   ok|empty|unavailable|error|n/a(未启用)
    "clsact": "skipped_pref1_mirred",//   installed|skipped_pref1_mirred|unavailable|failed|off
    "iface": "wlan2"
  },
  "conn_block_dns_layer": "available" // string,按设备域名封锁的 DNS 层:available|unavailable|unknown(尚未探测)
}
```

- 布尔字段兼容字符串 `"true"`;缺失 = false。**不返回热点密码**(`hotspot_pass` 只写不读)。

### 8.2 设置类 action

| action | params | 执行 | 备注 |
|---|---|---|---|
| `whitelist_set` | `enabled`=`true`\|`false` | `json_set.sh top whitelist_mode <v>` | 见 §2.3 |
| `auth_required_set` | `enabled`=`true`\|`false` | `json_set.sh top auth_required <v>` | **仅本机 loopback**;远程调用 → `500 {"ok":false,"error":"forbidden","detail":"this action is loopback-only (use the on-device KSU WebUI)"}` |
| `global_shaper_set` | `enabled`(宽松布尔,同 `rule_sqm`);开启时 `rate_down`/`rate_up`(`"0"` 或 `<n>kbit`/`<n>mbit`,≥64kbit,至少一个非 0) | 关:`device_detect.sh iface` → 有接口则 `tc_manager.sh global_shaper <iface> off 0 0` → `json_set.sh top global_shaper_enabled false`。开:`tc_htb=false` → `unsupported`;无热点接口 → `no hotspot iface`;`tc_manager.sh global_shaper <iface> on <down> <up>` → 依次写 `global_shaper_down`、`global_shaper_up`、`global_shaper_enabled=true`(任一失败回写 enabled=false) | detail `"global shaper on down=… up=…"` / `"global shaper off"` |
| `flywheel_exclude_set` | 见 §5.4 | | |
| `clsact_bpf_enabled_set` | `enabled`=`true`\|`false` | 见 §11.3(v5.18 起 = `clsact_mode_set` 别名) | |
| `clsact_mode_set` | `mode`=`auto`\|`on`\|`off` | 见 §11.3 | v5.18 |
| `alert_config_set` | 见 §6.3 | | |

## 9. 热点控制

### 9.1 GET `/api/iface_info` — 热点接口与本机地址

- 每次请求都执行 `sh bin/device_detect.sh iface`(10s 超时)取接口名;取不到则用 devices.json 里任一设备的 `iface`;
  再用 Go `net.InterfaceByName` 取该接口第一个 RFC1918 IPv4。

```json
{ "iface": "ap0", "ip": "192.168.43.1", "gateway": "192.168.43.1", "network": "192.168.43.1/24" }
```

- 所有字段 omitempty;`gateway` 恒等于 `ip`(AP 模式下本机即网关)。远程访问 URL = `https://<ip>:8443`。

### 9.2 热点 action

| action | params | 执行 | 返回 |
|---|---|---|---|
| `hotspot_start` | — | **异步**:`setsid sh bin/hotspot_autostart.sh start-now`,输出追加到 `$HNC/logs/cleanup_async.log`,立即返回 | detail `"已触发启动,正在后台拉起热点(请稍候)"`;真实结果请轮询 `/api/live.hotspot_active` |
| `hotspot_stop` | — | 同步 `hotspot_autostart.sh stop`(30s 超时) | detail `"hotspot stopped"`;失败 error `"hotspot stop failed"` |
| `hotspot_save` | 全部可选:`ssid`(1–32 **字节** UTF-8,无 <0x20 控制字符)、`password`(8–63 字节 UTF-8,无控制字符)、`delay_sec`(0–3600 整数)、`autostart`(`true`/`false`) | 对每个非空字段依次 `json_set.sh top hotspot_ssid\|hotspot_pass\|hotspot_delay\|hotspot_auto <v>`;**只写 rules.json,不重启热点** | detail `"config saved"`;任一写失败即返回 `save ssid/pass/delay/autostart failed`(之前的字段已写入,非事务) |
| `hotspot_iface_set` | `iface`:空或 `auto` = 自动;否则 ≤15 字符 `[A-Za-z0-9_.-]` | `json_set.sh top hotspot_iface <iface或空>` | detail `"hotspot iface set to auto"` / `"preferred hotspot iface set to <x>"` |

### 9.2a WebUI 访问白名单(v5.22)

| action | params | 执行 | 返回 |
|---|---|---|---|
| `webui_access_set` | `mode`:`all` \| `allowlist` \| `local_only`;`macs`(可选):逗号/空白分隔的 MAC 或 IP(v4/v6),≤32 条,MAC 统一小写冒号格式;省略 `macs` = 保留现有列表,传空串 = 清空 | 写 `data/webui_access.json`(单行 JSON, 0600)→ `bin/webui_guard.sh apply`(filter/INPUT 链 `HNC_WEBUI`,v4+v6,非放行客户端 TCP RST);httpd 同时按同一配置在 HTTP 层拒绝(403 + `Connection: close`) | 成功 detail `"webui access mode=<m> entries=<n>; WEBUI_GUARD=applied …"`;防火墙失败仍 `ok:true`,detail 含 `firewall apply failed, HTTP-level guard active`;非法 mode/条目 400 `bad params`;**远程请求**提交 `local_only`,或 `allowlist` 不含请求者自身 IP/MAC(邻居表反查)→ **409** `error:"self_lockout"`,detail 写明请求者 ip/mac(UI 可据此提示"把本机加入列表") |

- 请求源 IP 由服务端从连接注入(参数 `_client_ip` 由服务端覆盖,客户端传了也无效)。loopback(KSU WebUI / 本机浏览器)永远放行,也不受自锁检查限制。
- `/api/config` 新字段 `webui_access`:`{"mode":"all","macs":[],"port":8443,"firewall":"applied mode=all entries=0 v4=ok v6=ok ts=…"}`(`firewall` 为 `run/webui_guard.state` 首行,未跑过为空串)。
- 任何模式下,防火墙都拒绝来自蜂窝上行口(`rmnet+`/`ccmni+`/`wwan+`/`seth_+`/`sipa_eth+`)对 8443/8080/8444 的连接。
- 配置文件损坏 / mode 非法 → 两层都按 `local_only` 处理(fail-closed)。

- 热点状态本身没有单独的 GET 端点:用 `/api/live`(`hotspot_active/iface/hotspot_ip`)+ `/api/config`(`hotspot_*` 配置)。
- 空字符串参数一律视为"不修改";无法通过 `hotspot_save` 把 SSID/密码清空。

## 10. 远程访问 / 配对 / 授权设备

### 10.1 配对流程总览

```
本机 WebUI(loopback)                                   远程浏览器(https://<热点IP>:8443)
  │ POST /api/action {action:"pair_new"}                    │
  │   → sh bin/pair_gen.sh → 写 run/pair_pending            │
  │ ← detail = {"ok":true,"pin":"123456",…,"valid_sec":120} │
  │ 在屏幕上显示 PIN(及 /pair?prefill=PIN 快捷链接)       │ GET /  → 数据接口 401 → 跳 /pair
  │ 配对结果:设计上可 ksu.exec 读 run/pair_success.<sid>;  │ GET /pair(PIN 输入页)
  │   当前 index.html 未读取,靠刷新 /api/tokens 看到新设备 │
  │                                                          │ POST /api/pair/verify  pin=123456
  │                                                          │ ← 302 Location: /  + Set-Cookie: hnc_token=…
  │ 看到 pair_success.<sid>(token_id/label/时间)            │ 之后所有 /api/* 带 cookie
```

- `run/pair_pending`:三行 `PIN(6 位数字)` / `session_id(8–64 位 base64url)` / `过期 unix 秒`;PIN 有效期 120s,一次性(验证成功即删除)。
- `run/pair_success.<session_id>`:三行 `TokenID` / `label` / `unix 秒`(0600,60 分钟后被 GC)。

### 10.2 GET `/pair`

- 公开,unauth 限流(20 req/s/IP)。仅 GET(其它方法 `405` 纯文本)。返回内嵌的 `web/pair.html`(`Cache-Control: no-store`)。

### 10.3 POST `/api/pair/verify`

- 公开,unauth 限流 + PIN 限流(§1.5)。
- 请求:`Content-Type: application/x-www-form-urlencoded`,body `pin=123456`(≤4 KiB)。**不需要** CSRF 头。
- 成功:`302 Location: /` + `Set-Cookie: hnc_token=<TokenID>.<Secret>; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Strict`。
  用 `fetch(..., {redirect:'manual'})` 时表现为 `type==='opaqueredirect'`(status 0)。
- 失败(均为 JSON):

| 状态 | body | 场景 | 是否消耗名额 |
|---|---|---|---|
| 405 | 纯文本 `method not allowed` | 非 POST | 否 |
| 429 | `{"error":"too many pin attempts","locked_for_sec":N}` + `Retry-After` | 已锁定 / 本次消费触发锁定 / (v5.11)全局超额 | — |
| 400 | `{"error":"bad form"}` | 表单解析失败 | 否 |
| 400 | `{"error":"bad pin format","attempts_remaining":N}` | 不是 6 位数字 | 是 |
| 400 | `{"error":"no active pairing"}` | 没有 pair_pending | 否 |
| 400 | `{"error":"malformed pair_pending (…)"}` | pending 文件损坏 | 否 |
| 410 | `{"error":"pairing expired"}` | PIN 过期(顺手删除 pending) | 否 |
| 400 | `{"error":"wrong pin","attempts_remaining":N}` | PIN 错 | 是 |
| 500 | `{"error":"token issue failed"}` | 写 tokens 失败 | — |

  `attempts_remaining` = 本 60s 窗口内还能真比对的次数(每 IP 每窗口最多 4 次,第 5 次直接 429 锁 10 分钟)。

### 10.4 GET `/api/whoami` — 当前 cookie 身份

- 需鉴权。仅对 cookie 身份有效;本机 secret 调用没有 token → `401 {"error":"not authenticated"}`。

```json
{ "token_id": "Ab3dE_9x", "session_label": "Chrome on Android", "ip_hint": "192.168.43.23", "created": 1790000000, "last_seen": 1790003600 }
```

- `token_id` 只回前 8 位;`session_label` 由配对时 User-Agent 推断(`<Chrome|Edge|Firefox|Safari|Browser> on <iPhone|iPad|Android|Windows|Mac|Linux|Unknown>`)。

### 10.5 GET `/api/tokens` — 已授权远程设备列表

- 需鉴权。读内存快照(last_seen 实时)。只列未撤销的 token;顺序不固定(map 遍历)。

```json
{
  "version": 1,
  "tokens": [
    { "token_id": "Ab3dE_9xQ1w", "label": "Chrome on Android", "ip_hint": "192.168.43.23", "created": 1790000000, "last_seen": 1790003600 }
  ]
}
```

- 这里的 `token_id` 是**完整 11 位 TokenID**(撤销时要传它);`revoked` 字段恒省略。

### 10.6 撤销 / 登出

| 方式 | 说明 |
|---|---|
| action `pair_revoke`,params `token`=TokenID(`^[A-Za-z0-9_-]{8,256}$`) | **仅本机 loopback**。内存撤销 + 原子落盘,立即生效。TokenID 不存在也返回 `{"ok":true}` |
| POST `/api/logout` | 公开路径;仅 POST(否则 405 纯文本)。自己解析 cookie,有效就撤销该 token;无论如何都清 cookie 并返回 `200 {"ok":true}`。无需 CSRF 头 |
| shell CLI | `json_set.sh token_revoke <id>` / `token_revoke_all` 追加 `run/token_revoke.request`(每行一个 TokenID 或 `ALL`),httpd 在下一个请求鉴权前/60s 轮询/启动时消费 |
| 过期 | `last_seen` 超 14 天拒绝鉴权;超 30 天(或撤销后 16 天)被 prune 物理删除(每日 + `run/httpd_prune_request` 标记触发) |

### 10.7 远程访问开关与 PIN 生成(action)

| action | params | 说明 |
|---|---|---|
| `remote_enabled_set` | `enabled`=`true`\|`false` | **仅本机 loopback**。`json_set.sh top remote_enabled <v>`;watchdog 约 60s 内拉起/关闭 8443。detail `"remote access enabled · 约 1 分钟内远程 URL 可访问"` / `"remote access disabled · 约 1 分钟内 :8443 关闭"` |
| `pair_new` | — | `sh bin/pair_gen.sh`;detail 是 JSON **字符串**:`{"ok":true,"pin":"123456","session_id":"q1W2e3R4t5Y6","expiry":1790000120,"valid_sec":120}`(前端需 `JSON.parse(detail)`);脚本非 0 退出 → `500 {"ok":false,"error":"pair_gen failed","detail":"<脚本输出>"}` |
| `pair_revoke` | 见 10.6 | |

## 11. 诊断 / 维护 / 导出

### 11.1 GET `/api/offload_status` — 硬件 offload 是否在截胡限速

- 后台每 30s 跑一次 `sh bin/check_offload.sh`(脚本含 `sleep 5`),接口只读缓存。

```json
{ "active": false, "detail": "IDLE", "offload_guard": null }
```

- v5.18:offload guard 在 90s 内采样过则直接复用它的 `offload_state`,不再重复跑脚本;兜底生效时这里报的是被压下去之后的状态(横幅随之消失)。`offload_guard` 同 `/api/config`。

- `detail` = 脚本 stdout(trim,空则 `IDLE`),正常为 `NOMAP` / `IDLE` / `ACTIVE` 之一;`active` 仅当 detail(小写)**整词**等于 `active`/`warning`/`bpf_on`/`offload_on` 时为 true。
- httpd 启动后首轮检查完成前返回 `{"active":false,"detail":"PENDING"}`。

### 11.2 GET `/api/sla` — 运行健康计数器

全部读 `$HNC/run/` 下的文件,缺失/非数字的字段为 `null`(不编造):

```json
{
  "generated_at": 1790000000,
  "dpid_restart_count": 12,             // run/dpid.start_count
  "dpid_crash_recent": 0,               // run/dpid.crashflag 的非空行数
  "dpid_guard_heartbeat_age_s": 1,      // now - run/dpid_guard.heartbeat
  "watchdog_full_restore_count": 3,     // run/watchdog_full_restore.count
  "tc_repair_fail_count": 0,            // run/tc_repair_fail_count
  "uplink_fail_count": null,            // run/uplink_fail_count
  "json_legacy_fallback_count": null,   // run/json_legacy_fallback.count
  "qos_fallback_active": false,         // run/tc_qos_fallback 是否存在
  "uplink_unsupported": false           // run/uplink_unsupported 是否存在
}
```

### 11.3 clsact BPF(T1 限速层,opt-in)action

| action | params | 执行 | 返回 |
|---|---|---|---|
| `clsact_check` | — | 读 `run/hnc_state` 取 `ACTIVE:<iface>`(仅小写字母数字);`$HNC/bin/hnc_clsact_ctl check <iface>`(5s)+ `sh -c "pgrep -f hnc_clsact_watchdog"`(3s) | 热点未开 → `500 {"ok":false,"error":"hotspot not active"}`;否则 `{"ok":true,"detail":"{\"ok\":bool,\"clsact\":bool,\"bpf_filter\":bool,\"map\":bool,\"watchdog\":bool,\"iface\":\"ap0\"}"}`(detail 是 JSON 字符串) |
| `clsact_repair` | — | `sh bin/hnc_clsact_watchdog.sh repair <iface>` | `"clsact repaired"`;失败 `repair failed` |
| `clsact_mode_set` | `mode`=`auto`\|`on`\|`off`(大小写不敏感) | `json_set.sh top clsact_bpf_mode <mode>` + `json_set.sh top clsact_bpf_enabled <mode==on>`;再 `sh bin/hnc_offload_guard.sh apply`(25s 超时;auto 含 5s 采样) | 非法 → `bad params`;成功 `{"ok":true,"detail":"<offload_guard 状态 JSON 字符串>"}`;apply 失败仍 ok=true,detail=`"mode=<m> 已保存, 兜底将在 60 秒内按新模式执行"` |
| `clsact_bpf_enabled_set` | `enabled`=`true`\|`false` | v5.18 起为 `clsact_mode_set` 别名:true→on,false→off | 同 `clsact_mode_set` |

- v5.18 语义(详见 `bin/hnc_offload_guard.sh` 文件头):**auto**(默认)检测到 offload ACTIVE 时经 hotspotd `OFFLOAD_DISABLE_GLOBAL` 强制慢路径并每 60s 重申,热点关闭/tether map 消失连续 3 轮才撤销;**on** 热点在即始终强制 + 尝试 clsact 打标;**off** 不干预并撤销此前施加的一切。clsact 打标仅在 pref 1 未被 HNC 上行 mirred 占用时安装。

### 11.4 维护 action

| action | 执行 | 返回 |
|---|---|---|
| `cleanup_rules` | `sh bin/cleanup.sh rules`(同步,60s 超时) | `{"ok":true}` |
| `cleanup_all` | **异步** `setsid sh bin/cleanup.sh safe_release`(清 tc/iptables、停子进程后自动 fork service.sh 重启后端;**httpd 自己也会被重启**) | `"safe release scheduled · service will be restarted automatically"` |
| `restart_service` | **异步** `setsid sh bin/cleanup.sh restart` | `"restart scheduled · 30s 内 watchdog 重启所有服务"` |
| `refresh` | `device_detect.sh scan` | 脚本 stdout |
| `self_attrib_purge` | 见 §5.4 | |

`cleanup_all` / `restart_service` 之后前端应预期 8444/8443 短暂不可用(curl exit 7 / fetch 失败),轮询 `/api/health` 直到恢复。

### 11.5 POST `/api/export` — 打包诊断数据

- requireMutation(POST + JSON + `X-HNC-CSRF: 1` + 16 KiB)。body 全部可选:

```json
{ "from": 1789996400, "to": 1790000000, "notes": ["用户描述…"] }
```

  `to` 缺省/0 = 现在;`from` 缺省/0 = `to-3600`;from>to 会自动交换;跨度 >86400s → `400 {"error":"time range too large","max_range_secs":86400,"requested_secs":N}`。
  body 不是合法 JSON 时**不报错**,按全缺省处理。
- 生成 `$HNC/exports/hnc-export-YYYYMMDD-HHMMSS.zip`(tmp+rename),内容:`dpi_state.json`、`self_attrib/self_attrib.*.jsonl`、`stats/stats.*.jsonl`(按日期落在 [from,to] 的文件)、
  `ip_app_map.json`、`dpi_rules.d/*.json`、`manifest.json`(schema v3,含 getprop 机型信息、内核版本、HNC 版本、各 track 文件清单)。
- 响应:

```json
{
  "status": "ok",
  "name": "hnc-export-20260923-120000.zip",
  "size_bytes": 482133,
  "download_url": "/api/exports/hnc-export-20260923-120000.zip",
  "manifest": { "schema_version": "3", "generated_at": 1790000000, "generated_at_iso": "…", "hnc_version": "v5.10.0",
                "time_range": {"from":…,"to":…,"from_iso":"…","to_iso":"…"}, "device": {"arch":"arm64","model":"…",…},
                "tracks": {"dpi_state": {"included":true,"file_count":1,"bytes_total":1234,"files":["dpi_state.json"]}, "self_attrib": {…}, "stats": {…}, "ip_app_map": {…}, "dpi_rules": {…}},
                "notes": ["…"] }
}
```

- 错误:`500 {"error":"<IO 错误>"}`;(v5.11)已有导出在进行 → `409 {"error":"export already in progress"}`;写频率超限 → `429`。
- 旧导出**不会自动清理**。

### 11.6 GET `/api/exports` / GET `/api/exports/<name>.zip`

- 列表:`{"exports":[{"name":"hnc-export-….zip","size":482133,"modified":"2026-09-23T12:00:00+08:00","download_url":"/api/exports/…"}]}`,按文件名降序(新的在前);目录不存在 → `{"exports":[]}`。
- 下载:`name` 不能含 `/`、`\`、`..`,必须以 `.zip` 结尾(否则 `400` 纯文本 `invalid name` / `must end in .zip`);不存在 → `404`。
  成功:`Content-Type: application/zip`、`Content-Disposition: attachment; filename="<name>"`,由 `http.ServeFile` 发送(支持 Range)。
  本机 KSU WebUI 无法用浏览器下载二进制,只能让用户去 `$HNC/exports/` 取或远程浏览器下载。

## 12. 系统信息 / 能力 / 版本

### 12.1 GET `/api/health` — 探活(公开)

```json
{ "status": "ok", "version": "v5.10.0", "watchdog_passive": false }
```

- 公开;本机即使没有 secret 也可访问(watchdog 靠它判活)。`watchdog_passive` = `run/watchdog_passive.marker` 存在(watchdog 连续自检失败进入被动模式)。
- `version` 为编译时注入的 module.prop `version`(未注入时 `"dev"`)。`versionCode` 请从 `/api/live.backend_version_code` 取。

### 12.2 GET `/api/capabilities` — 内核/tc 能力探测结果

- 读 `$HNC/run/capabilities.json`(`bin/capability_probe.sh` 生成,经缓存)。
- 成功:`{"available":true,"capabilities":{…}}`;失败(200):`{"available":false,"error":"<Go 错误串>"}`。
- 常用字段(均为 bool,除注明外):`tc_htb`、`tc_netem`、`tc_fq_codel`、`tc_cake`、`sqm_supported`、`sqm_recommended_mode`(string)、`tc_ingress_supported`、`tc_clsact_supported`、
  `tc_u32_supported`、`tc_flower_supported`、`tc_matchall`、`tc_police_supported`、`tc_mirred`、`ifb_supported`、`uplink_supported`、`uplink_police_supported`、
  `downlink_mode`/`uplink_mode`/`delay_mode`/`tc_qos_mode`(string)、`qos_fallback_required`、`tc_binary`/`tc_binary_source`/`tc_version`(string)、`generated_at`(number)、
  各 `*_error`(string,失败原因),以及 fork/launcher 相关 `c_fork_supported`、`go_fork_supported`、`selected_launcher`、`dpid_version` 等。
- 后端写操作的门控只认 `tc_htb`、`tc_netem`、`uplink_supported` 三个键:**显式 false 才拒绝**,缺失/未知按支持处理。

### 12.3 GET `/api/metrics`

固定返回(本构建没有埋点计数器,诚实上报):

```json
{ "instrumented": false, "mode": "live-read", "backend_version": "v5.10.0", "compat": "hotfix16.8-live-api" }
```

## 13. 静态页面路由

| 路径 | 公开 | 内容 |
|---|---|---|
| `/` | 是 | 远程(非 loopback)或 loopback 但 UA 像完整浏览器 → 内嵌 `web/app.html`(远程 SPA);loopback 且 UA 为空/含 `wv)`/不像浏览器 → 磁盘 `模块目录/webroot/index.html`(KSU 版,首次读后缓存到进程退出),读不到回退 app.html。带与全局相同的 CSP。仅精确路径 `/`,其它未注册路径走 404/401 |
| `/static/app.js` | 是 | 内嵌 `web/app.js`(`application/javascript`) |
| `/static/style.css` | 是 | 内嵌 `web/style.css`(`text/css`);其它 `/static/*` → 404 |
| `/pair` | 是 | 内嵌 `web/pair.html`(见 §10.2) |
| `/changelog.html` | 是 | 磁盘 `模块目录/webroot/changelog.html`(每次读盘),缺失 404 |
| `/json-health.html` | 是 | 磁盘 `模块目录/webroot/json-health.html`,缺失 404 |

- 静态资源无 ETag/缓存头控制(内嵌文件随二进制更新)。新前端若想被 httpd 托管,需要改 `embed.go` 与 `serveStatic` 的白名单(当前只认两个文件名)。

## 14. /api/action 全部 action 一览

### 14.1 请求 / 响应格式

```
POST /api/action
Content-Type: application/json          ← 必须以 application/json 开头,否则 415
X-HNC-CSRF: 1                           ← 必须,否则 400
(本机)X-HNC-Local-Admin: <64 hex>      ← 或远程 cookie hnc_token

{"action":"rule_set","params":{"mac":"aa:bb:cc:dd:ee:01","rate_down":"10mbit","rate_up":"2mbit"}}
```

- body ≤16 KiB;**`DisallowUnknownFields`**:顶层只能有 `action` 和 `params`,多一个键就 `400 bad json`。
- `params` 是 `map[string]string`:**所有值必须是 JSON 字符串**(数字/布尔要先 `String()`),否则 `400 bad json`。`params` 可省略。
- 检查顺序:方法(非 POST → `405` 纯文本)→ Content-Type → CSRF 头 → 身份(context 无 token 且不是"无 Origin/Referer 的 loopback" → `401 {"ok":false,"error":"auth required for write"}`)→
  解码 → 写频率(60/分钟/身份)→ 获取全局 `actionMu`(串行)→ 分发 → 写 `logs/audit.log`。
- 响应恒为 `{"ok":true,"detail"?:"…"}` 或 `{"ok":false,"error":"…","detail"?:"…"}`。

HTTP 状态码映射(`ok:false` 时):

| error | 状态 |
|---|---|
| `unknown action`、`bad params`、`protected mac`、`invalid mac`、`invalid rate`、`bad json`、`csrf header missing` | 400 |
| `auth required for write` | 401 |
| `content-type must be application/json` | 415 |
| `write rate limited (60/min)` | 429 |
| **其它一切**(`forbidden`、`unsupported`、`apply failed`、`write failed`、`read failed`、`hotspot not active`、`no hotspot iface` …) | 500 |

> 客户端超时建议 ≥15s:串行锁 + 脚本最长 10s(cleanup 60s、hotspot/dpi_rebind 30s)。连接被 60s WriteTimeout 切断时,脚本仍在后台完成,前端应在失败后刷新状态收敛。

### 14.2 全表(38 个)

| # | action | 分组 | 关键 params | 仅本机 | 旧 KSU 前端 | 远程 SPA |
|---|---|---|---|---|---|---|
| 1 | `rule_set` | 设备 §2.3 | mac, rate_down?, rate_up? | | ✓ | ✓ |
| 2 | `rule_clear` | 设备 | mac | | ✓ | ✓ |
| 3 | `template_apply` | 设备 | 同 rule_set | | ✗ | ✗ |
| 4 | `bl_add` | 设备 | mac | | ✓ | ✓ |
| 5 | `bl_del` | 设备 | mac | | ✓ | ✓ |
| 6 | `delay_set` | 设备 | mac, delay_ms, jitter_ms, loss_pct | | ✓ | ✓ |
| 7 | `delay_clear` | 设备 | mac | | ✓ | ✓ |
| 8 | `rule_sqm` | 设备 | mac, enabled | | ✓ | ✓ |
| 9 | `device_rename` | 设备 | mac, name | | ✓ | ✓ |
| 10 | `whitelist_set` | 设备/设置 | enabled | | ✓ | |
| 11 | `refresh` | 设备 | — | | ✓ | |
| 12 | `cleanup_rules` | 维护 §11.4 | — | | ✓ | |
| 13 | `cleanup_offline_devices` | 设备 | include_rules? | | ✓ | |
| 14 | `cleanup_all` | 维护 | — | | ✓ | |
| 15 | `restart_service` | 维护 | — | | ✓ | |
| 16 | `app_limit_set` | 应用 §5.3 | mac, app_id, down_mbps | | ✓ | ✓ |
| 17 | `app_limit_clear` | 应用 | mac, app_id? | | ✓ | ✓ |
| 18 | `candidate_promote` | DPI §5.4 | apex | | ✓ | |
| 19 | `candidate_reject` | DPI | apex | | ✓ | |
| 20 | `flywheel_exclude_set` | DPI/设置 | op, pkg | | ✓ | |
| 21 | `dpi_rebind` | DPI | iface? | | ✓ | |
| 22 | `self_attrib_purge` | DPI | — | | ✓ | |
| 23 | `alert_mark_seen` | 告警 §6.3 | ids | | ✓ | |
| 24 | `alert_mark_known` | 告警 | mac | | ✓ | |
| 25 | `alert_dismiss_all` | 告警 | — | | ✓ | |
| 26 | `alert_config_set` | 告警/设置 | section, enabled, … | | ✓ | |
| 27 | `global_shaper_set` | 设置 §8.2 | enabled, rate_down?, rate_up? | | ✓ | |
| 28 | `auth_required_set` | 设置 | enabled | ✓ | ✓ | |
| 29 | `hotspot_start` | 热点 §9.2 | — | | ✓ | |
| 30 | `hotspot_stop` | 热点 | — | | ✓ | |
| 31 | `hotspot_save` | 热点 | ssid?, password?, delay_sec?, autostart? | | ✓ | |
| 32 | `hotspot_iface_set` | 热点 | iface | | ✓ | |
| 33 | `remote_enabled_set` | 远程 §10.7 | enabled | ✓ | ✓ | |
| 34 | `pair_new` | 远程 | — | | ✓ | |
| 35 | `pair_revoke` | 远程 | token | ✓ | ✓ | |
| 35a | `webui_access_set` | 远程 v5.22 | mode, macs? | | ✓ | 远程请求不得锁住自己(409 `self_lockout`) |
| 36 | `clsact_check` | 诊断 §11.3 | — | | ✓ | |
| 37 | `clsact_repair` | 诊断 | — | | ✓ | |
| 38 | `clsact_bpf_enabled_set` | 诊断/设置 | enabled | | ✓ | |
| 38a | `clsact_mode_set` | 设置 §11.3 | mode | | ✓ | |

布尔参数写法差异(照抄即可):`whitelist_set` / `auth_required_set` / `remote_enabled_set` / `clsact_bpf_enabled_set` / `alert_config_set.enabled` / `hotspot_save.autostart`
**只认** `"true"`/`"false"`;`rule_sqm` / `global_shaper_set` 认 `true/1/on/yes/false/0/off/no/""`;`cleanup_offline_devices.include_rules` 认 `"1"`/`"true"`。

MAC 参数写法差异:`rule_set/rule_clear/bl_add/bl_del/delay_set/delay_clear/rule_sqm/template_apply` **只收小写冒号**;
`device_rename/app_limit_*/alert_mark_known` 收大小写、冒号或短横线。新前端统一发**小写冒号**最省事。

## 15. 前端调用约定

后端对两类前端提供**同一套** API,区别只在传输通道与鉴权头:

| | 通道 A:本机 KSU/SukiSU WebView | 通道 B:浏览器直连 |
|---|---|---|
| 页面来源 | 模块 `webroot/index.html`,WebView 以 `file://`(或管理器自有域)加载 | httpd `/` 返回的 `web/app.html` + `/static/app.js` |
| 目标地址 | `http://127.0.0.1:8444`(常量 `API_BASE`) | 同源 `https://<热点IP>:8443`(相对路径 `/api/...`) |
| 传输 | `window.ksu.exec("curl …", cbName)` 在 root shell 里跑 curl,stdout 回传 JSON。WebView 直接 `fetch` 会带 `Origin` → 中间件改走 cookie → 401,所以 KSU 环境**跳过 fetch 直接走桥** | `fetch(url, {credentials:'same-origin'})`、`EventSource('/api/events')` |
| 鉴权 | 请求头 `X-HNC-Local-Admin: <secret>`;secret 用 `ksu.exec('cat /data/local/hnc/run/local_admin.secret')` 读一次、校验 `/^[0-9a-fA-F]{64}$/` 后缓存在内存 | HttpOnly cookie `hnc_token`(配对后浏览器自动带) |
| CSRF | 写请求也要带 `X-HNC-CSRF: 1`(由 `/api/action` 与 requireMutation 检查,与身份无关);**不能**带 `Origin`/`Referer`(curl 默认不带) | 写请求带 `X-HNC-CSRF: 1` |
| 401 处理 | 说明 secret 未就绪/错误 → 提示,不要跳 `/pair` | 跳 `/pair` 走 PIN 配对 |
| 超时 | curl `--connect-timeout 1 --max-time 6`,外层 JS `withTimeout` 8s(GET)/ 9s(POST);桥回调 30s 兜底 | `AbortController` 4–15s |
| 串行 | 旧 UI 把所有 action 串成一个 Promise 队列(ksu.exec 会阻塞 UI 线程,且后端本来就串行) | 同设备同 action 去重 |
| 能力 | 可用 loopback-only action;可直接 `ksu.exec` 读 `run/pair_success.*` 等无 HTTP 端点的文件;不能 SSE、不能下载 zip | 不能调用 loopback-only action;可 SSE、可下载导出 |

**curl 命令模板**(通道 A,参数必须单引号转义,见 `sq()`):

```sh
# GET
curl -sS --connect-timeout 1 --max-time 6 -H 'X-HNC-Local-Admin: <secret>' -H 'Cache-Control: no-cache' 'http://127.0.0.1:8444/api/live'
# POST /api/action
curl -sS --connect-timeout 1 --max-time 6 -X POST -H 'Content-Type: application/json' -H 'X-HNC-CSRF: 1' \
     -H 'X-HNC-Local-Admin: <secret>' --data '{"action":"rule_clear","params":{"mac":"aa:bb:cc:dd:ee:01"}}' 'http://127.0.0.1:8444/api/action'
```

curl 退出码约定(旧 UI 的友好化):`7` / "connection refused" = httpd 未监听 8444;`28` / "timed out" = 后端无响应。
注意 `curl -sS` 在 HTTP 4xx/5xx 时**退出码仍为 0**,错误要从 JSON body(`ok:false` 或 `error`)判断。

### 15.1 旧前端 `webroot/index.html` 关键源码原样摘录

**框架检测 detectKsuLike** — `webroot/index.html` 第 5654–5661 行:

```js
  const HNC = '/data/local/hnc';
  let __kcb = 0;
  let __ksuFramework = null;

  function detectKsuLike() {
    if (typeof window.ksu !== 'undefined' && typeof window.ksu.exec === 'function') return 'ksu';
    return null;
  }
```

**ksu.exec 唯一入口 __hncKsuExecRaw + kexec(退出码友好化)** — `webroot/index.html` 第 5663–5759 行:

```js
  /* rc30.12.29 (P1.8): __hncKsuExecRaw — 全 codebase 唯一直接 touch ksu.exec callback API 的地方.
   * 任何对 ksu.exec 调用风格的修改 (回调签名、Promise 化、SDK 升级等) 只改这一个函数.
   * hf2 修过的 callback signature bug 之所以发生, 就是因为 ksu.exec 调用散在 kexec()
   * 和 __hncLoadLocalAdminSecret() 两处, 同文件 200 行外有正确写法却没参照.
   *
   * 入参: cmd 是要执行的 shell 命令, timeoutMs 默认 30000ms (callback 不触发兜底).
   * 出参: Promise< { exitCode, stdout, stderr, syncMs } >
   *       - exitCode: 数字, 0 = 成功. -1 = bridge 缺失/timeout/异常.
   *       - stdout/stderr: 字符串 (永远不是 undefined).
   *       - syncMs: window.ksu.exec(...) 同步返回耗时, 用于 profiling.
   * 不 reject, 一律 resolve, 调用方根据 exitCode 判断.
   */
  let __hncKsuRawCb = 0;
  function __hncKsuExecRaw(cmd, timeoutMs) {
    return new Promise(function(resolve) {
      if (typeof window.ksu === 'undefined' || typeof window.ksu.exec !== 'function') {
        resolve({ exitCode: -1, stdout: '', stderr: 'no ksu bridge', syncMs: 0 });
        return;
      }
      var cbName = '__hnc_ksu_raw_cb_' + (++__hncKsuRawCb);
      var done = false;
      var tStart = performance.now();
      var syncMs = 0;

      window[cbName] = function(exitCode, stdout, stderr) {
        if (done) return;
        done = true;
        try { delete window[cbName]; } catch (e) {}
        resolve({
          exitCode: parseInt(String(exitCode), 10),
          stdout: typeof stdout === 'string' ? stdout : String(stdout || ''),
          stderr: typeof stderr === 'string' ? stderr : String(stderr || ''),
          syncMs: syncMs
        });
      };
      var tm = setTimeout(function() {
        if (done) return;
        done = true;
        try { delete window[cbName]; } catch (e) {}
        resolve({ exitCode: -1, stdout: '', stderr: 'timeout', syncMs: syncMs });
      }, timeoutMs || 30000);
      try {
        window.ksu.exec(cmd, cbName);
        syncMs = Math.round(performance.now() - tStart);
      } catch (e) {
        if (done) return;
        done = true;
        clearTimeout(tm);
        try { delete window[cbName]; } catch (e2) {}
        resolve({ exitCode: -1, stdout: '', stderr: String(e), syncMs: 0 });
      }
    });
  }

  function kexec(cmd) {
    return new Promise((resolve, reject) => {
      if (__ksuFramework === null) __ksuFramework = detectKsuLike();
      if (!__ksuFramework) { reject(new Error('No KSU/Magisk WebUI detected')); return; }
      // rc3.1.25 · profiling: 记录每次 kexec 的同步阻塞时长 + 回调总时长
      // rc30.12.29 (P1.8): 改走 __hncKsuExecRaw 统一入口, profiling 由 raw 提供 syncMs
      if (!window.__kexec_log) window.__kexec_log = [];
      const _tStart = performance.now();
      const _key = (function(){
        const m = /\/api\/[a-zA-Z_]+/.exec(cmd);
        return m ? m[0] : cmd.slice(0, 40);
      })();

      __hncKsuExecRaw(cmd, 30000).then(function(r) {
        // rc3.1.32: profiling push 只在 __HNC_DEBUG 下做, 避免长跑下 __kexec_log 涨到几 MB
        if (window.__HNC_DEBUG) {
          try {
            window.__kexec_log.push({
              k: _key,
              sync: r.syncMs,
              cb: Math.round(performance.now() - _tStart)
            });
          } catch(_){}
        }
        if (r.exitCode === 0) {
          resolve(r.stdout);
        } else {
          // rc3.1.4: 友好化常见错误. curl exit 7 = connection refused,
          // 意味着 hnc_httpd 未监听 127.0.0.1:8444
          const raw = r.stderr || '';
          let msg;
          if (r.exitCode === 7 || /failed to connect|connection refused|port \d+ after/i.test(raw)) {
            msg = '后端未就绪 · hnc_httpd 未运行, 等 10s 或检查模块是否启用';
          } else if (r.exitCode === 28 || /timed out|timeout/i.test(raw)) {
            msg = '后端无响应 · 超时';
          } else {
            msg = 'exit=' + r.exitCode + (raw ? ' ' + raw.slice(0, 80) : '');
          }
          reject(new Error(msg));
        }
      });
    });
  }
```

**JS 层硬超时 withTimeout** — `webroot/index.html` 第 5767–5787 行:

```js
  function withTimeout(promise, ms, label) {
    return new Promise(function(resolve, reject) {
      var done = false;
      var timer = setTimeout(function() {
        if (done) return;
        done = true;
        reject(new Error((label || 'request') + ' JS timeout ' + ms + 'ms'));
      }, ms);
      Promise.resolve(promise).then(function(v) {
        if (done) return;
        done = true;
        clearTimeout(timer);
        resolve(v);
      }, function(e) {
        if (done) return;
        done = true;
        clearTimeout(timer);
        reject(e);
      });
    });
  }
```

**API_BASE 与 local_admin.secret 读取** — `webroot/index.html` 第 5801–5832 行:

```js
  const API_BASE = 'http://127.0.0.1:8444';

  /* rc30.12.14 · loopback 鉴权加固
   * service.sh 启动时生成 /data/local/hnc/run/local_admin.secret (mode 0600, owner root).
   * 普通 App 没 root 读不到. WebUI 通过 kexec (有 root) 读出来缓存在内存里, 注入到每个 curl.
   * 启动时读一次, 失败 (老 service.sh 没生成) 则保持 '', 后端会 fallback 到老行为.
   *
   * rc30.12.28-hf2 修过 (GPT 三审): 之前 ksu.exec 回调签名写错 (function(out) 拿到 exitCode
   * 而非 stdout), secret 被设为字符串 "0". 同文件 kexec() 有正确签名却没参照.
   *
   * rc30.12.29 (P1.8): 不再直接调 ksu.exec, 改走 __hncKsuExecRaw 统一入口.
   * callback signature 集中在 raw 里, 这里只关心 stdout 内容 + 64 hex 校验.
   */
  let __hncLocalAdminSecret = '';
  let __hncLocalAdminSecretLoaded = false;
  function __hncLoadLocalAdminSecret() {
    if (__hncLocalAdminSecretLoaded) return Promise.resolve(__hncLocalAdminSecret);
    __hncLocalAdminSecretLoaded = true;
    return __hncKsuExecRaw(
      'cat /data/local/hnc/run/local_admin.secret 2>/dev/null',
      1500
    ).then(function(r) {
      var s = (r.stdout || '').trim();
      // 校验: 64 字符 hex (service.sh /dev/urandom 32 字节 hex)
      if (r.exitCode === 0 && /^[0-9a-fA-F]{64}$/.test(s)) {
        __hncLocalAdminSecret = s;
      }
      return __hncLocalAdminSecret;
    });
  }
  // 启动时异步加载, 不阻塞渲染
  try { __hncLoadLocalAdminSecret(); } catch (e) {}
```

**业务错误统一抛出 validateApiObject** — `webroot/index.html` 第 5874–5881 行:

```js
  function validateApiObject(obj) {
    if (obj && typeof obj === 'object' && obj.ok === false) {
      const err = new Error(obj.error || 'api error');
      err.detail = obj.detail;
      throw err;
    }
    return obj || {};
  }
```

**fetch 通道 fetchJsonWithTimeout(非 KSU 环境)** — `webroot/index.html` 第 5883–5967 行:

```js
  async function fetchJsonWithTimeout(url, ms, label) {
    if (typeof fetch !== 'function') throw new Error('fetch unavailable');
    let ctrl = null;
    // rc30.12.28 修 P0: fetch 路径也注入 X-HNC-Local-Admin secret. 之前只有 bridge 路径注入,
    // 导致 KSU WebUI 在 rc30.12.18 默认拒绝中间件下永远 401 (fetch 优先, fetch 401 后 bridge
    // 也没被启用). 现在不论 transport, 只要 secret 在就注入.
    // 注意: __hncLocalAdminSecret 可能是空 (首屏 paint 前 secret 还没加载完).
    //       但因为 __hncLoadLocalAdminSecret() 在脚本顶部启动时就 fire, 大部分情况下
    //       第一次 fetch 时它已经回调完了; 没回调完就空着, fetch 401 后 bridge 路径会再 await.
    let headers = { 'Cache-Control': 'no-cache' };
    if (typeof __hncLocalAdminSecret === 'string' && __hncLocalAdminSecret) {
      headers['X-HNC-Local-Admin'] = __hncLocalAdminSecret;
    }
    let opts = { cache: 'no-store', headers: headers };
    try {
      if (typeof AbortController !== 'undefined') {
        ctrl = new AbortController();
        opts.signal = ctrl.signal;
      }
    } catch (_) { ctrl = null; opts = { cache: 'no-store', headers: headers }; }

    return new Promise(function(resolve, reject) {
      let done = false;
      const timer = setTimeout(function() {
        if (done) return;
        done = true;
        try { if (ctrl) ctrl.abort(); } catch (_) {}
        reject(new Error((label || 'fetch') + ' timeout ' + ms + 'ms'));
      }, ms || 1800);

      try {
        fetch(url, opts).then(function(resp) {
          if (done) return;
          if (!resp || !resp.ok) {
            // rc30.12.28: 收到 401 立即引导到配对页, 跟远程 web/app.js (line 609) 行为一致.
            // 之前本机 KSU WebUI 401 时只显示 toast, 用户无路可走.
            // 注意 KSU WebUI 是 file:// 加载, 直接 window.location.href='/pair' 不行,
            // 必须用 API_BASE + '/pair' 跳到 httpd 服务的配对页.
            //
            // rc30.12.28-hf2 (GPT 三审): KSU/SukiSU 本地 WebUI 不应跳 /pair.
            // /pair 是远程浏览器的 cookie 配对流程, 本地 KSU WebUI 应该用 root
            // secret bridge curl. 跳 /pair 会把用户引到错误的流程.
            // 现在: 只有非 KSU 环境 (远程浏览器, fetch 失败 + 无 cookie) 才跳.
            // KSU WebUI 实际上 fetch 路径已经被 apiGet 的 __hncIsKsuWebUI 短路了,
            // 这里几乎不会被命中, 但保留作为防御.
            var isKsu = (typeof window !== 'undefined' && 
                         typeof window.ksu !== 'undefined' && 
                         typeof window.ksu.exec === 'function');
            if (resp && resp.status === 401 && !isKsu) {
              try {
                var pairUrl = API_BASE + '/pair';
                var here = String(window.location.href || '');
                if (here.indexOf(pairUrl) !== 0) {
                  setTimeout(function(){
                    try { window.location.href = pairUrl; } catch (_) {}
                  }, 800);
                }
              } catch (_) {}
            }
            throw new Error('HTTP ' + (resp ? resp.status : 'no response'));
          }
          return resp.text();
        }).then(function(txt) {
          if (done) return;
          done = true;
          clearTimeout(timer);
          let obj = {};
          try { obj = txt ? JSON.parse(txt) : {}; }
          catch (e) { throw new Error('invalid JSON: ' + String(txt || '').slice(0, 80)); }
          __hncTransportMode = 'fetch';
          resolve(validateApiObject(obj));
        }).catch(function(e) {
          if (done) return;
          done = true;
          clearTimeout(timer);
          reject(e);
        });
      } catch (e) {
        if (done) return;
        done = true;
        clearTimeout(timer);
        reject(e);
      }
    });
  }
```

**apiGet / apiGetSafe / apiAction(串行队列)/ apiActionOnce / apiPostJSON** — `webroot/index.html` 第 5971–6127 行:

```js
  async function apiGet(path, params) {
    let p = path.startsWith('/api') || path.startsWith('/') ? path : '/api/' + path;
    if (params && typeof params === 'object') {
      const qs = Object.keys(params).filter(k => params[k] !== undefined)
        .map(k => encodeURIComponent(k) + '=' + encodeURIComponent(params[k])).join('&');
      if (qs) p += '?' + qs;
    }
    const url = API_BASE + p;

    // rc30.12.28-hf2 (GPT 三审): KSU/SukiSU WebUI 强制 bridge-first, 跳过 fetch.
    // 理由:
    //   1. KSU WebView 加载源可能是 https://mui.kernelsu.org 之类的远程域,
    //      fetch 到 http://127.0.0.1:8444 会带 Origin header 触发 CORS preflight,
    //      或者至少让 authMiddleware 不再走 "无 Origin/Referer 的 loopback" 分支.
    //   2. authMiddleware 真正信任的是: isLoopbackRequest + Origin/Referer 为空 + 
    //      X-HNC-Local-Admin secret 校验通过. curl 命令没有浏览器 Origin,
    //      正好匹配这个安全模型.
    //   3. fetch 即使注入 secret, 浏览器自动加 Origin 后中间件不走 secret 分支,
    //      还是 cookie 鉴权失败 -> 401.
    // 所以 KSU 环境下: 跳过 fetch, 直接走 ksu.exec curl bridge.
    var __hncIsKsuWebUI = (typeof window !== 'undefined' && 
                          typeof window.ksu !== 'undefined' && 
                          typeof window.ksu.exec === 'function');

    // rc30.12.28: 在 fetch 之前先 await secret 加载完成. 之前只在 bridge 路径 await,
    // fetch 路径用空 secret 发请求 -> 401 (rc30.12.18 默认拒绝中间件下). 加载有缓存,
    // 第二次起立即返回, 不会变慢.
    try { await __hncLoadLocalAdminSecret(); } catch (e) {}

    // rc1.10 · first transport: browser fetch.
    // 这是异步 Web API，不会像 window.ksu.exec 那样同步卡死 UI 线程。
    // 一旦 bridge 已确认可用，后续请求直接走 bridge，避免每个接口先等 fetch 失败 1.8s。
    // rc30.12.28-hf2: KSU WebUI 直接跳过 fetch, 不浪费 1.8s 等超时.
    if (!__hncIsKsuWebUI && !__hncPreferBridgeTransport) {
      try {
        return await fetchJsonWithTimeout(url, 1800, 'FETCH ' + p);
      } catch (fetchErr) {
        try { window.__hnc_last_fetch_error = String((fetchErr && fetchErr.message) || fetchErr); } catch (_) {}
        if (!__hncAllowBridgeTransport) {
          throw new Error('HTTP fetch failed; KSU bridge auto disabled: ' + ((fetchErr && fetchErr.message) || fetchErr));
        }
      }
    }

    // rc1.10 · bridge transport is delayed/explicit.
    // 首屏 paint 后自动尝试一次；或者用户点击"强制桥接"后到这里。
    // rc30.12.14: 注入 X-HNC-Local-Admin header. 先 await 一次 secret 加载, 避免竞态.
    //            secret 没就绪 (老 service.sh 没生成) 时 adminH='', 后端 fallback 老 loopback bypass.
    // rc30.12.28: secret 现在已经在 apiGet 入口处 await 过, 这里调用是缓存命中, 立即返回.
    try { await __hncLoadLocalAdminSecret(); } catch (e) {}
    let adminH = '';
    if (__hncLocalAdminSecret) {
      adminH = "-H " + sq('X-HNC-Local-Admin: ' + __hncLocalAdminSecret) + " ";
    }
    const cmd = "curl -sS --connect-timeout 1 --max-time 6 " + adminH +
                "-H " + sq('Cache-Control: no-cache') + " " + sq(url);
    const raw = await withTimeout(kexec(cmd), 8000, 'GET ' + p);
    __hncTransportMode = 'bridge';
    if (!raw) return {};
    let obj;
    try { obj = JSON.parse(raw); }
    catch (e) { throw new Error('invalid JSON: ' + String(raw).slice(0, 80)); }
    return validateApiObject(obj);
  }

  function apiGetSafe(path, params, fallback, timeoutMs) {
    return withTimeout(apiGet(path, params), timeoutMs || 8000, 'GET ' + path)
      .catch(function(e) {
        try { dbg('apiGetSafe ' + path + ' failed: ' + (e && e.message || e), true); } catch (_) {}
        return fallback;
      });
  }

  const __apiActionInFlight = new Set();
  let __apiActionQueue = Promise.resolve();
  function apiActionKey(action, params) {
    params = params || {};
    return params.mac ? ('dev:' + String(params.mac)) : ('global:' + String(action || ''));
  }

  async function apiAction(action, params) {
    // KSU/SukiSU WebView 的 window.ksu.exec() 在部分环境会阻塞 UI 线程。
    // 写操作统一串行化，避免一次点击/批量操作同时堆多个 curl 导致卡顿和 tc/json 竞态。
    const run = () => apiActionOnce(action, params || {});
    const p = __apiActionQueue.catch(() => {}).then(run);
    __apiActionQueue = p.catch(() => {});
    return p;
  }

  async function apiActionOnce(action, params) {
    params = params || {};
    const actionKey = apiActionKey(action, params);
    if (__apiActionInFlight.has(actionKey)) {
      throw new Error('同一设备/操作正在执行,请稍后');
    }
    __apiActionInFlight.add(actionKey);
    try {
      // v5.1 修 P0-2: Go handleAction 期望 nested {action, params: {}}
      const body = { action: action, params: params };
      const json = JSON.stringify(body);
      // 不再做 1s/2s/4s 多次重试；后端未就绪时快速失败，避免点击限速卡住。
      // rc30.12.14: 注入 X-HNC-Local-Admin header. 先 await 一次 secret 加载 (内部有缓存,
      // 第二次起立即返回), 避免页面刚加载就调 apiAction 时 secret 还没读到导致 401.
      try { await __hncLoadLocalAdminSecret(); } catch (e) {}
      let adminH = '';
      if (__hncLocalAdminSecret) {
        adminH = "-H " + sq('X-HNC-Local-Admin: ' + __hncLocalAdminSecret) + " ";
      }
      const cmd = "curl -sS --connect-timeout 1 --max-time 6 -X POST " +
                  "-H " + sq('Content-Type: application/json') + " " +
                  "-H " + sq('X-HNC-CSRF: 1') + " " + adminH +
                  "--data " + sq(json) + " " +
                  sq(API_BASE + '/api/action');
      const raw = await withTimeout(kexec(cmd), 9000, 'ACTION ' + action);
      let obj;
      try { obj = JSON.parse(raw || '{}'); }
      catch (e) { throw new Error('invalid JSON response: ' + String(raw).slice(0, 80)); }
      if (!obj.ok) {
        const err = new Error(obj.error || 'action failed');
        err.detail = obj.detail;
        throw err;
      }
      try { if (typeof burstRefresh === 'function') burstRefresh(); } catch (e) {}
      return obj;
    } finally {
      __apiActionInFlight.delete(actionKey);
    }
  }

  // b-nav4 fix: 通用桥接 POST (给 /api/self/toggle、/api/export 等非 /api/action 端点).
  // 与 apiGet 同样 dual-mode: 非 KSU 走 fetch, KSU WebUI 走 ksu.exec curl 桥接.
  async function apiPostJSON(path, body) {
    const p = path.startsWith('/') ? path : '/api/' + path;
    const url = API_BASE + p;
    const json = JSON.stringify(body || {});
    try { await __hncLoadLocalAdminSecret(); } catch (e) {}
    const __isKsu = (typeof window !== 'undefined' && typeof window.ksu !== 'undefined' && typeof window.ksu.exec === 'function');
    if (!__isKsu) {
      const opts = {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-HNC-CSRF': '1' },
        body: json
      };
      if (__hncLocalAdminSecret) opts.headers['X-HNC-Local-Admin'] = __hncLocalAdminSecret;
      const resp = await fetch(url, opts);
      const raw = await resp.text();
      try { return JSON.parse(raw || '{}'); } catch (e) { throw new Error('invalid JSON: ' + String(raw).slice(0, 80)); }
    }
    let adminH = '';
    if (__hncLocalAdminSecret) adminH = "-H " + sq('X-HNC-Local-Admin: ' + __hncLocalAdminSecret) + " ";
    const cmd = "curl -sS --connect-timeout 1 --max-time 6 -X POST " +
                "-H " + sq('Content-Type: application/json') + " " +
                "-H " + sq('X-HNC-CSRF: 1') + " " + adminH +
                "--data " + sq(json) + " " + sq(url);
    const raw = await withTimeout(kexec(cmd), 9000, 'POST ' + p);
    try { return JSON.parse(raw || '{}'); } catch (e) { throw new Error('invalid JSON: ' + String(raw).slice(0, 80)); }
  }
```

**shell 单引号转义 sq** — `webroot/index.html` 第 6400–6400 行:

```js
  function sq(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }   // shell quote
```


### 15.2 远程 SPA `daemon/hnc_httpd/web/app.js` 关键源码原样摘录

**401 → /pair 跳转 + fetchWithTimeout** — `daemon/hnc_httpd/web/app.js` 第 58–97 行:

```js
function $(id) { return document.getElementById(id); }

// 远程面板未配对 / 登录过期 → 跳配对页。
// 后端把 "/" 作为公共 SPA 入口放行,但数据接口需要 hnc_token cookie,缺失即 401;
// SPA 必须据此自动跳到 /pair(见 hnc_httpd middleware.go 注释)。之前只有写路径
// (/api/action) 这么做,读/轮询路径把 401 当普通错误显示,导致未配对用户卡在
// "加载失败: HTTP 401" 永远到不了配对页。守卫防止多个并发 401 重复跳转 / 循环。
var __pairRedirecting = false;
function redirectToPair() {
  if (__pairRedirecting) return;
  __pairRedirecting = true;
  try { setStatus(false, '未配对 · 正在跳转配对页…'); } catch (_) {}
  setTimeout(function(){ try { window.location.href = '/pair'; } catch (_) {} }, 600);
}

// hotfix4: bounded async transport. fetch() can stay pending for a long time
// on unstable mobile links, keeping in-flight flags true and making the UI look
// frozen. AbortController is available on modern Android WebView; fallback keeps
// compatibility on older engines.
function fetchWithTimeout(url, opts, timeoutMs) {
  opts = opts || {};
  timeoutMs = timeoutMs || 10000;
  // 任一 API 拿到 401 (未配对/过期) → 统一跳配对页. 在中心助手里做, 所有读写
  // 端点都覆盖, 调用方各自的 r.ok / status 处理不受影响.
  function checkAuth(r) { if (r && r.status === 401) redirectToPair(); return r; }
  if (typeof AbortController === 'undefined') {
    return fetch(url, opts).then(checkAuth);
  }
  var ctrl = new AbortController();
  var t = setTimeout(function(){ try { ctrl.abort(); } catch (_) {} }, timeoutMs);
  var nextOpts = {};
  Object.keys(opts).forEach(function(k){ nextOpts[k] = opts[k]; });
  nextOpts.signal = ctrl.signal;
  return fetch(url, nextOpts).then(function(r){
    clearTimeout(t);
    return checkAuth(r);
  }, function(e){
    clearTimeout(t);
    throw e;
  });
```

**写操作 callAction(POST /api/action)** — `daemon/hnc_httpd/web/app.js` 第 596–639 行:

```js
// 所有写操作走 POST /api/action, 带 X-HNC-CSRF: 1 header
var actionInFlight = {};
function actionKey(action, params) {
  params = params || {};
  // rc39 (P2-12): include action in the per-device key so different ops on the
  // SAME device (e.g. limit then block) aren't falsely de-duped as "busy".
  return params.mac
    ? ('dev:' + String(params.mac) + ':' + String(action || ''))
    : ('global:' + String(action || ''));
}
async function callAction(action, params) {
  params = params || {};
  var key = actionKey(action, params);
  if (actionInFlight[key]) {
    return {status: 409, ok: false, error: 'busy', detail: 'same action is already running'};
  }
  actionInFlight[key] = true;
  try {
    var resp = await fetchWithTimeout('/api/action', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-HNC-CSRF': '1'
      },
      body: JSON.stringify({action: action, params: params})
    }, 15000);
    var data = {};
    try { data = await resp.json(); } catch(_) {}
    return {status: resp.status, ok: data.ok === true, error: data.error || '', detail: data.detail || ''};
  } catch (e) {
    var msg = String(e && e.message || e);
    if (e && e.name === 'AbortError') msg = 'request timeout';
    // The server-side shell action may still finish after a client timeout. Refresh
    // shortly so the UI converges instead of staying stale.
    setTimeout(function(){ loadDevices({force:true}); }, 1200);
    return {status: 0, ok: false, error: 'network', detail: msg};
  } finally {
    delete actionInFlight[key];
  }
}

// toast 显示短反馈
// kind: 'ok' (绿) / 'err' (红) / 'info' (蓝)
```

**SSE:EventSource('/api/events') 与轮询回退** — `daemon/hnc_httpd/web/app.js` 第 1038–1065 行:

```js
var __remoteSSE = null;
var __sseUp = false;
function stopRemoteSSE() {
  if (__remoteSSE) { try { __remoteSSE.close(); } catch (e) {} __remoteSSE = null; }
  __sseUp = false;
}
function startRemoteSSE() {
  if (typeof EventSource === 'undefined') return false; // 不支持 → 调用方走轮询
  if (__remoteSSE) return true;
  try {
    var es = new EventSource('/api/events'); // 同源, 自动带 auth cookie
    __remoteSSE = es;
    es.addEventListener('changed', function(){
      if (remotePollVisible && !document.hidden) remotePollOnce('force');
    });
    es.onopen = function(){ __sseUp = true; clearRemotePollTimer(); };
    es.onerror = function(){
      // EventSource 会自动重连;断开期间用轮询兜底,重连 onopen 后再停。
      __sseUp = false;
      if (remotePollVisible && !document.hidden) startRemotePolling();
    };
    return true;
  } catch (e) { __remoteSSE = null; return false; }
}
function startRemoteUpdates() {
  // 优先 SSE,不支持则轮询。SSE 连上后会经 'connect' 事件触发首次刷新。
  if (!startRemoteSSE()) startRemotePolling();
}
```

**身份 /api/whoami 与登出 /api/logout** — `daemon/hnc_httpd/web/app.js` 第 1117–1146 行:

```js
// v5.9.92: 走独立 /api/whoami 端点(鉴权) —— rc30.12.30 P0.4 把 session_label
// 从 /api/health 移除后(公共端点拿不到 token), 这里的 badge 和登出按钮
// 3 个版本恒隐藏, doLogout 白写。whoami 是 server.go 注释里规划的那个
// 端点, 现在落地。401 = 未鉴权/会话失效, 静默保持登出隐藏。
function loadSessionInfo() {
  fetch('/api/whoami', { credentials: 'same-origin' })
    .then(function(r) { return r.ok ? r.json() : null; })
    .then(function(d) {
      if (d && d.session_label) {
        var b = $('session-badge');
        if (b) {
          b.textContent = d.session_label;
          b.style.display = '';
        }
        var btn = $('logout-btn');
        if (btn) btn.style.display = '';
        var am = $('auth-mode');
        if (am) am.textContent = '已鉴权';
      }
    }).catch(function(){});
}
loadSessionInfo();

window.doLogout = function() {
  if (!confirm('登出并撤销本设备授权?\n\n下次访问需要重新配对。')) return;
  fetch('/api/logout', { method: 'POST', credentials: 'same-origin' })
    .then(function(){ window.location.href = '/pair'; })
    .catch(function(e){ alert('登出失败: ' + (e.message || e)); });
};

```


### 15.3 配对页 `web/pair.html` 提交逻辑原样摘录

**?prefill=XXXXXX 快捷链接自动提交** — `daemon/hnc_httpd/web/pair.html` 第 162–185 行:

```html
  /* v4.0 Patch 2.d: ?prefill=XXXXXX 自动填充 PIN + 自动提交
   * 主人本机点"复制快捷链接"→ 通过消息 app 发给远端 → 远端点开就自动登录
   * 格式校验: 必须 6 位数字,其它视为手输模式不自动填 */
  function getPrefillPin(){
    try {
      var m = window.location.search.match(/[?&]prefill=([0-9]{6})(?:&|$)/);
      return m ? m[1] : null;
    } catch(e){ return null; }
  }
  var prefillPin = getPrefillPin();
  if(prefillPin){
    pinInput.value = prefillPin;
    // 清 URL 里的 prefill (防止返回/刷新/分享时 PIN 暴露)
    try {
      var cleanUrl = window.location.pathname + window.location.hash;
      history.replaceState(null, '', cleanUrl);
    } catch(e){}
    // 自动提交(给用户 0.5 秒看一眼"正在自动登录")
    showMsg('info', '检测到配对链接,正在自动登录…');
    setTimeout(function(){
      // 触发 submit 走下面的 submit handler
      if(form.requestSubmit) form.requestSubmit();
      else form.dispatchEvent(new Event('submit', {cancelable:true, bubbles:true}));
    }, 500);
```

**PIN 提交与错误分支** — `daemon/hnc_httpd/web/pair.html` 第 187–256 行:

```html

  form.addEventListener('submit', async function(e) {
    e.preventDefault();
    var pin = pinInput.value.trim();
    if (pin.length !== 6) {
      showMsg('error', '请输入 6 位数字 PIN');
      return;
    }

    btn.disabled = true;
    btn.textContent = '验证中…';
    msg.className = 'msg';

    try {
      var body = new URLSearchParams();
      body.append('pin', pin);
      var resp = await fetch('/api/pair/verify', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: body.toString(),
        redirect: 'manual'
      });

      // 302: 配对成功
      if (resp.type === 'opaqueredirect' || (resp.status >= 300 && resp.status < 400)) {
        showMsg('info', '✓ 配对成功,正在跳转…');
        setTimeout(function(){ window.location.href = '/'; }, 400);
        return;
      }

      // 错误响应
      var data = {};
      try { data = await resp.json(); } catch(_) {}
      var errMsg = data.error || '未知错误 (HTTP ' + resp.status + ')';

      if (resp.status === 429) {
        var sec = data.locked_for_sec || parseInt(resp.headers.get('Retry-After')) || 600;
        var mins = Math.ceil(sec / 60);
        showMsg('error', '⛔ 尝试次数过多,请 ' + mins + ' 分钟后重试');
      } else if (resp.status === 410 || errMsg.indexOf('expired') >= 0) {
        showMsg('error', '⏱ 配对码已过期,请回本机重新生成');
      } else if (errMsg.indexOf('no active') >= 0) {
        showMsg('error', '当前没有活动配对请求,请先在本机点"生成配对码"');
      } else if (errMsg.indexOf('wrong pin') >= 0) {
        // v4.0 Patch 2.d: 显示剩余次数
        var rem = data.attempts_remaining;
        if (typeof rem === 'number' && rem >= 0) {
          if (rem === 0) {
            showMsg('error', 'PIN 错误,已达到尝试上限');
          } else if (rem === 1) {
            showMsg('error', '⚠ PIN 错误,<b>最后 1 次机会</b>,再错就锁 10 分钟');
          } else {
            showMsg('error', 'PIN 错误,还有 ' + rem + ' 次机会');
          }
        } else {
          showMsg('error', 'PIN 错误,请检查后重试');
        }
      } else if (errMsg.indexOf('bad pin format') >= 0) {
        showMsg('error', 'PIN 格式错误(应为 6 位数字)');
      } else {
        showMsg('error', errMsg);
      }
    } catch(err) {
      showMsg('error', '网络错误: ' + (err.message || err));
    } finally {
      btn.disabled = false;
      btn.textContent = '验证并登入';
      pinInput.focus();
      pinInput.select();
    }
```


### 15.4 给新前端数据层的建议骨架(非现有代码,仅示意)

```js
// transport: 'ksu' | 'browser'
const isKsu = typeof window.ksu?.exec === 'function';
async function request(method, path, body) {
  if (isKsu) {
    const secret = await loadSecretOnce();                  // cat run/local_admin.secret,校验 64 hex
    const args = ['curl -sS --connect-timeout 1 --max-time 6'];
    if (method === 'POST') args.push("-X POST -H 'Content-Type: application/json' -H 'X-HNC-CSRF: 1' --data " + sq(JSON.stringify(body || {})));
    if (secret) args.push('-H ' + sq('X-HNC-Local-Admin: ' + secret));
    args.push(sq('http://127.0.0.1:8444' + path));
    const r = await ksuExec(args.join(' '));                 // → {exitCode, stdout, stderr}
    if (r.exitCode !== 0) throw new Error('bridge ' + r.exitCode);
    return JSON.parse(r.stdout || '{}');
  }
  const res = await fetch(path, { method, credentials: 'same-origin',
    headers: method === 'POST' ? { 'Content-Type': 'application/json', 'X-HNC-CSRF': '1' } : {},
    body: method === 'POST' ? JSON.stringify(body || {}) : undefined });
  if (res.status === 401) { location.href = '/pair'; throw new Error('auth'); }
  return res.json();
}
const action = (name, params) => request('POST', '/api/action', { action: name, params: stringifyValues(params) });
```

## 16. 新旧前端覆盖差异

### 16.1 后端有、旧 KSU 前端(`webroot/index.html`)没用的

| 接口 | 谁在用 | 说明 |
|---|---|---|
| GET `/api/whoami` | 远程 SPA | 本机 secret 身份调用恒 401,KSU 前端用不上 |
| GET `/api/events` | 远程 SPA | ksu.exec 无法承载长连接;且基线恒 500(§3.3) |
| POST `/api/logout` | 远程 SPA | 本机无 cookie |
| GET `/pair`、POST `/api/pair/verify` | `pair.html` | 远程配对专用 |
| GET `/api/self/attrib` | **无人使用** | 两个前端都没调用,可作为新前端"本机 App 流量明细"数据源 |
| GET `/api/exports/<name>.zip` | 远程 SPA 列表里给下载链接 | KSU 前端只显示路径(file:// 下不能下载) |
| GET `/json-health.html`、`/changelog.html` | 浏览器直接打开 | KSU 前端用相对路径 `fetch('changelog.html')` 读模块目录文件,不经 httpd |
| action `template_apply` | **无人使用** | 前端都直接展开模板调 `rule_set` |

远程 SPA(`web/app.js`)只覆盖了子集:`/api/live`、`/api/capabilities`、`/api/iface_info`、`/api/devices`、`/api/stats`(不传 source → legacy)、`/api/events`、`/api/health`、
`/api/whoami`、`/api/logout`、`/api/dpi_state`、`/api/self/ifaces`、`/api/self/toggle`、`/api/exports`、`/api/export`,以及 10 个 action
(`rule_set rule_clear bl_add bl_del delay_set delay_clear rule_sqm device_rename app_limit_set app_limit_clear`)。

### 16.2 前端调了 / 读了,但后端没有的

路径层面:两个前端调用的所有 `/api/*` 路径**都已注册**,没有调用不存在的端点。字段/状态层面有以下"后端从不提供"的读取:

| 前端位置 | 读取 | 实际 |
|---|---|---|
| `web/app.js:957-958` `updateRemoteFreshness` | `/api/live.snapshot_age_ms`、`snapshot_stale`、`refresh_requested` | 后端没有这些字段 → 远程 SPA 的"数据新鲜度"恒显示"刚刚"(本机前端已改为按客户端最后成功轮询时间计算) |
| `web/app.js:170` 附近 `loadDevices` | `/api/devices` 返回 `503` 的分支 | 后端 `/api/devices` 永远 200 |
| `web/app.js:123/135` | `/api/live`、`/api/capabilities` 返回 404 时降级 | 两者均已注册,仅兼容极老后端 |
| `webroot/index.html:11498-11510` | `/api/metrics` 的 `snapshot_age_ms`、`json_cache_hits/misses`、`snapshot_refresh_count`、`shell_fallback_count`、`offload_check_count` | 后端恒返回 `instrumented:false`,这些字段不存在(前端走 `instrumented===false` 分支,属死代码) |
| `middleware.go` 公开白名单 | `/api/pairing/status` | 从未注册路由 → 404(没有前端调用,仅注释/白名单漂移) |
| 设计文档层面 | 配对状态查询、pair_success 读取、模板增删 | 无 HTTP 端点,旧 KSU 前端靠 `ksu.exec` 直接读写文件完成;浏览器前端无法实现这些功能 |

## 17. v5.11 审计修复导致的行为差异

正文中标注"v5.11"的行为来自紧随本文档之后的审计修复提交(`daemon/hnc_httpd`),汇总表在该提交中补全。

## 18. v5.19 新增接口与动作

> 来源:`daemon/hnc_httpd/sim.go`、`sim_merge.go`、`phone_usage.go`(+`phone_usage_sim.go`)、`limit_policy.go`、`app_time.go`。
> 新增 4 个 mux 路由(均需鉴权、只读、GET):`/api/sim`、`/api/phone_usage`、`/api/app_time`、`/api/dpi_unknown`;
> `/api/action` 新增 `sim_*`(6 个)、`phone_usage_set`、`quota_set/quota_clear/schedule_set/schedule_clear`、
> `app_time_limit_set/app_time_limit_del/category_block_set`。所有 params 仍是字符串。

### 18.1 模拟环境(调试用):GET `/api/sim` + `sim_*` 动作

- 状态文件 `$HNC/data/sim.json`(`{enabled, devices:[…], seed}`,tmp+rename)。模拟设备 MAC 一律是本地管理地址
  **`02:5e:00:xx:xx:xx`**(小写冒号),最多 32 台。今日累计(字节/小时、主应用活跃秒数)只在内存里按速率积分,不落盘;
  速率由 `(时间, seed, mac)` 决定(可复现),`blocked`/`offline` → 0,限速 → 封顶。
- **开启时(enabled 且至少一台)**,下列只读接口会把模拟设备合并进去,条目形状与真实条目一致并额外带 `"sim": true`:
  `/api/devices`、`/api/live`、`/api/events`、`/api/connections`、`/api/app_usage`、`/api/stats`(legacy)、`/api/usage_month`、
  `/api/online_hours`、`/api/dpi_history`、`/api/dpi_state`(`clients["sim-<mac>"]`)、`/api/app_limits`、
  `/api/app_time`(§18.5)、`/api/dpi_unknown`(§18.6)、`/api/phone_usage`(§18.2),以及 `/api/devices` 的 `quota/schedule/effective`(§18.3)。
  **关闭时所有接口输出与没有此功能时逐字节一致**。`/api/config.sim_enabled` 反映开关。
- **安全闸**:任何带 `mac` 的动作,只要 mac 是已登记的模拟设备(或模拟环境开启时任何 `02:5e:00` 前缀),在分发最前面被截走,
  只改 `sim.json` 里那台设备,**绝不调用脚本 / tc / iptables**。能改模拟状态的:`rule_set`、`template_apply`、`rule_clear`、`bl_add`、`bl_del`、
  `delay_set`、`delay_clear`、`rule_sqm`、`device_whitelist_set`、`device_rename`、`device_ident_set`、`conn_block_add/del`、`app_limit_set/clear`
  (校验规则与真实动作相同);其余带 mac 的动作对模拟设备是空操作(`ok:true`,detail「模拟设备: 该动作不影响模拟状态(未触达系统)」)。
  例外:纯配置类动作 `quota_set/quota_clear/schedule_set/schedule_clear/app_time_limit_set/app_time_limit_del/category_block_set`
  **放行**给原处理函数(只写策略文件),执行层对 `02:5e:00` 一律跳过,所以界面能看到模拟设备的配额/时段/时长上限视图,但什么都不下发。
  模拟环境开启时,未登记的 `02:5e:00` MAC → `ok:false, error:"not found"`。

GET `/api/sim`(仅 GET,其他方法 405):

```json
{
  "ok": true, "enabled": true, "count": 6, "seed": 123456789,
  "presets": ["busy", "home", "idle"],
  "types": ["tv", "phone", "laptop", "tablet", "game", "iot", "pc"],
  "mac_prefix": "02:5e:00:", "max": 32,
  "devices": [{
    "mac": "02:5e:00:1a:2b:3c", "ip": "192.168.43.120", "name": "模拟-客厅电视", "hostname": "MiTV-1A2B",
    "vendor": "Xiaomi", "type": "tv",
    "rx_bps": 3145728, "tx_bps": 92160,          // 基准速率 Byte/s(实际速率 = 基准 × (1 ± jitter·噪声))
    "jitter": 0.2, "app_id": "iqiyi", "app_name": "爱奇艺", "category": "video",
    "blocked": false, "limit_down_mbps": 0, "limit_up_mbps": 0, "delay_ms": 0, "created": 1790000000,
    // 以下仅在设置过时出现: jitter_ms, loss_pct, sqm, whitelist, offline, app_limits{app_id:down_mbps}, conn_blocks[], ident{}
    "cur_rx_bps": 3012345, "cur_tx_bps": 90000,  // 当前实际速率
    "online": true,
    "today_rx_bytes": 123456789, "today_tx_bytes": 3456789,
    "today_active_sec": 18000                    // 主应用今日活跃秒数(与 /api/app_time 同口径)
  }]
}
```

| action | params | 说明 / 成功 detail |
|---|---|---|
| `sim_set` | `enabled`(`true/1/on/yes` / `false/0/off/no`) | 开关。`"模拟环境已开启(N 台模拟设备)"` / `"模拟环境已关闭"` |
| `sim_device_add` | 全部可选:`name`(≤24 字)、`type`(tv\|phone\|laptop\|tablet\|game\|iot\|pc,空=随机)、`rx`/`tx`(Byte/s,可带 `k`=1024/`m`=1048576 后缀,≤1.25e9)、`app`(app_id,`[a-z0-9_-]{1,32}`,空=无应用)、`jitter`(0–1)、`ip`(私网 IPv4)、`vendor`(≤24)、`hostname`(≤32) | 未给的字段按类型模板随机。未知参数 → 400。detail 是 JSON 字符串 `{"mac":"02:5e:00:…","name":"…"}` |
| `sim_device_update` | `mac` 必填 + 上表字段 + `app_name`(≤32)、`category`(`[a-z0-9_-]{1,32}`)、`blocked`、`offline`、`limit_down_mbps`/`limit_up_mbps`(0–10000)、`delay_ms`(0–5000) | 全部先校验,任一失败整体不改。`"updated <mac>"` |
| `sim_device_del` | `mac` | `"deleted <mac>"`;不存在 → `not found` |
| `sim_clear` | — | 删除全部模拟设备(不改开关)。`"cleared N sim device(s)"` |
| `sim_preset` | `preset`:`home`(6 台晚间家庭)\|`busy`(8 台高负载,含已限速/已拉黑/加延迟各一台)\|`idle`(4 台心跳级,一台离线) | 替换全部模拟设备并**自动开启**。`"已载入预设 <name>(N 台), 模拟环境已开启"` |

### 18.2 本机 / 热点月流量:GET `/api/phone_usage` + `phone_usage_set`

- 数据源:`/proc/net/dev` 每 60 秒差分(整机网卡计数,最接近运营商计费口径)。接口分类:`cell`(`rmnet_data*`/`rmnetN`/`ccmni*`/`seth_lte*`/`wwan*`;
  不计 `v4-rmnet*`、`r_rmnet*`、`rmnet_ipa*` 等防重复)、`wifi`(`wlan0` 且不是热点口)、`hotspot`(当前热点口,取不到按 `ap*`/`softap*`/`swlan*`)。
- 本机 ≈ 上游 − 热点(逐方向截 0);上游 = `ip route get 1.1.1.1` 出口,再用增量交叉校验。蜂窝增量记给当前默认数据卡(5 分钟刷新一次;识别不到记 slot 0「蜂窝(未知卡)」)。
- 存储:`run/phone_usage.YYYYMMDD.json`(保留 400 天)、`run/phone_usage_state.json`、配置 `data/phone_usage_config.json`。
- Query:`period=cycle|month|today|7d|30d`(默认 `cycle` = 当前计费周期;其它值 → 400 `{"error":"period must be cycle|month|today|7d|30d"}`)。

```json
{
  "period": "cycle", "since": 1788192000, "until": 1790000000,
  "billing_day": 1, "cycle_start": 1788192000, "cycle_end": 1790784000,
  "config": {"billing_day": 1, "warn_percent": 80, "plan_sim1_gb": 30, "plan_sim2_gb": 0},
  "totals": {                                   // 全部 {rx, tx, total} 字节; hotspot 是客户端视角 rx=下载 tx=上传
    "cellular": {"rx": 0, "tx": 0, "total": 0}, "wifi": {…}, "hotspot": {…}, "local": {…}
  },
  "hotspot_via": {"cell": {"rx":…,"tx":…,"total":…}, "wifi": {…}, "unknown": {…}},   // 热点流量走的上游
  "by_sim": [{
    "slot": 1, "carrier": "中国移动", "carriers": ["中国移动"],
    "rx": 0, "tx": 0, "total": 0, "local_rx": 0, "local_tx": 0,
    "hotspot_total": 0,                          // total − local
    "cycle_used": 0,                             // 本计费周期用量(不论 period)
    "plan_bytes": 32212254720, "used_pct": 12.3, // 无套餐时 plan_bytes=0, used_pct=null
    "is_default_data": true
  }],
  "by_day": [{"date": "2026-09-30", "cell": 0, "wifi": 0, "hotspot": 0, "local": 0}],
  "by_hour": [{"h": 0, "cell": 0, "wifi": 0, "hotspot": 0, "local": 0}],   // 仅 period=today,24 项
  "default_sim": {"slot": 1, "carrier": "中国移动", "sub_id": 1},            // 未探测过为 null
  "hotspot_by_device": {"endpoint": "/api/usage_month", "note": "…"},
  "sources": {"sim_detect": "ok|unknown", "sim_source": "settings|isub|getprop|", "ifaces": [{"name":"rmnet_data0","class":"cell"}],
              "hotspot_iface": "wlan2", "upstream": "cell", "counters": "/proc/net/dev", "last_sample": 1790000000, "error": "…(可选)"},
  "sim_included": true,                          // 仅模拟环境开启时出现
  "sim_hotspot": {"rx": 0, "tx": 0, "total": 0}  // 仅模拟环境开启时: 叠加进来的模拟热点字节
}
```

- **模拟环境**:模拟设备今天的字节(客户端视角 [下载, 上传])叠加到**今天那天的内存副本**:`totals.hotspot` 与 `totals.cellular` 各加同样字节
  (上游按蜂窝算,记给当前默认数据卡 → `by_sim[].total/cycle_used/hotspot_total/used_pct` 随之变化)、`hotspot_via.cell`、`by_day` 今天那行、
  `by_hour`;`local`/`wifi` 不变。**不写入日文件、不参与 `phone_quota` 告警**。关闭时没有 `sim_included`/`sim_hotspot`。

`phone_usage_set`(全部可选,只改传了的;任一非法整体拒绝;一个都没传 → 400):

| param | 取值 |
|---|---|
| `billing_day` | 1–28(计费日;设备配额的月周期也用它) |
| `plan_sim1_gb` / `plan_sim2_gb` | 0–100000(GiB,0 = 无套餐) |
| `warn_percent` | 1–100(默认 80) |

成功 detail:`"billing_day=1 sim1=30GB sim2=0GB warn=80%"`。

### 18.3 设备流量配额 / 分时段限速:`quota_set` `quota_clear` `schedule_set` `schedule_clear` + `/api/devices` 字段

- 配置 `data/limit_policies.json`,运行状态 `data/limit_ctl_state.json`。控制器每分钟(动作成功后立即 poke)一轮:用量累加 → 配额判定 → 期望规则 →
  与上次不同才经 `rule_set/rule_clear/bl_add/bl_del` 同一条链路落地。优先级 **block(手动黑名单)> quota > schedule > manual**;
  配额 throttle 在下层结果上取更严;时段窗口替换手动限速(`down/up=0` = 该时段不限速);覆盖结束恢复到用户的手动基线。
- 用量 = `devices.json` 计数器差分累加与 `run/stats.YYYYMMDD.jsonl` 同窗口合计取 max;日 = 本地零点,月 = 计费日(§18.2 `billing_day`)起。
- MAC 必须小写冒号(`quota_set`/`schedule_set` 还拒绝受保护 MAC)。

| action | params | 说明 |
|---|---|---|
| `quota_set` | `mac`;`daily_gb`(0–1e6)、`monthly_gb`(0–1e7)至少一个 >0(GiB = 1073741824 字节);`action`=`throttle`(默认)\|`block`;`throttle_mbps`、`throttle_up_mbps`(0 或 0.064–10000) | throttle 缺省 1 / 0.5 Mbps;只给下行时上行 = 下行/2。detail `"quota saved"` |
| `quota_clear` | `mac` | detail `"cleared"` / `"nothing to clear"` |
| `schedule_set` | `mac`;`windows` = JSON 数组字符串,1–16 项,每项 `{"days":[0-6…](空=每天, 0=周日),"start":"HH:MM","end":"HH:MM","down_mbps":0,"up_mbps":0,"block":false}` | 未知字段拒绝。`start==end` = 全天;`start>end` = 跨零点(属于开始那天);多窗口取第一个命中的。detail `"schedule saved"` |
| `schedule_clear` | `mac` | 同 `quota_clear` |

`/api/devices` 每行都新增(`limitCtl.annotateDevices`):

```json
"quota": {                          // 无配额 → null
  "daily_gb": 5, "monthly_gb": 0, "action": "throttle", "throttle_mbps": 1, "throttle_up_mbps": 0.5,
  "used_today": 1234567, "used_month": 98765432,      // 字节(tx+rx)
  "state": "ok|warn|exceeded", "exceeded_period": "daily|monthly|",
  "applied": true,                  // 已超限且当前生效原因就是 quota
  "billing_day": 1, "month_start": 1788192000,
  "sim": true, "enforced": false    // 仅模拟设备
},
"schedule": {                       // 无时段 → null
  "windows": [ … ], "active_window_index": 0,         // -1 = 当前不在任何窗口
  "sim": true                       // 仅模拟设备
},
"effective": {                      // 每行都有
  "down_mbps": 1, "up_mbps": 0.5, "blocked": false,
  "reason": "manual|schedule|quota|block",
  "apply_error": "…",               // 可选: 上次落地失败
  "sim": true, "enforced": false    // 仅模拟设备
}
```

- 没有策略的设备:`quota=null, schedule=null`,`effective` 由行内 `status/limit_enabled/down_mbps/up_mbps` 给出(reason `manual`/`block`)。
- **模拟设备**:策略照常保存,控制器只算视图、**永不 apply、不落状态、不发告警**。基线 = 模拟设备自己的限速/拉黑状态;
  `used_today` = 模拟今日积分字节,`used_month` = 今日 + 本计费周期此前每天的估算(与 `/api/usage_month` 同一估算),
  所以可以把配额设小来看 `warn/exceeded` 与 `reason:"quota"`;`applied/reason` 表示「真机上会怎样」,`enforced:false` 表示实际什么都没下发。
- 超限告警 `device_quota` 见 §18.7。

### 18.4 应用时长上限 / 类别封锁动作

配置 `data/app_controls.json`(`{time_limits:[{mac,app_id,minutes,ts}], category_blocks:[{mac,category,ts}]}`)。
时长用完 / 类别封锁不写 `conn_blocks.json`,而是展开时现算「派生封锁项」(`source:"app_time"`,`until`=本地次日 0 点;`source:"category"`),
由现有 conn_blocks 机制(IP 层 + DNS 层)落地,过 0 点自动解封。

| action | params | 说明 |
|---|---|---|
| `app_time_limit_set` | `mac`(`aa:bb…`/`aa-bb…`)、`app_id`(`[A-Za-z0-9_.-]{1,64}`)、`minutes`(0–1440;**0 = 删除**) | app_id 必须是「真应用」(规则库里有且类别不属系统/SDK,或今天见过);模拟设备另接受模拟应用库里的应用。上限 200 条。成功后重算封锁(结果不变不跑脚本) |
| `app_time_limit_del` | `mac`、`app_id` | 不存在 → `not found` |
| `category_block_set` | `mac`、`category`、`enabled`(`true/1/on/yes`/`false/0/off/no`) | 开启时类别必须是规则库里可封锁的「真应用」类别(模拟设备另接受模拟应用库的类别);已是目标状态 → detail `"no change"`。上限 100 条 |

模拟设备(`02:5e:00`):三个动作只写配置,不重跑同步(detail `"模拟设备: 已保存(只显示, 不下发)"`),派生项在生效集合里被滤掉。
`/api/devices` 有配置的设备行额外带:

```json
"app_time_limits": [{"app_id": "douyin", "name": "抖音", "category": "video", "minutes": 60,
                     "used_sec": 3700, "used_min": 61, "exhausted": true, "enforced": true,
                     "until": 1790006400,          // 仅 exhausted
                     "sim": true}],                // 仅模拟设备(此时 enforced 恒 false)
"category_blocks": [{"category": "game", "app_count": 12, "ts": 1790000000, "enforced": true}]
```

### 18.5 GET `/api/app_time` — 应用使用时长

- 记账(`app_usage.go` 每 10 秒一轮):某 (设备, 应用) 本轮字节 ≥ 8 KB/10 s(按实际间隔折算)且应用属「真应用」档 → 这一轮记为活跃,
  按 (mac, app, 小时) 累加进 `run/app_usage.YYYYMMDD.json` 的 `active`/`seen`。
- Query:`mac`(可选,小写冒号;非法 → 400 `{"error":"invalid mac"}`)、`days` 1–31(默认 1,含今天)。

```json
{
  "ok": true, "days": 1, "mac": "", "since": "20260930",
  "total_active_sec": 7200,
  "apps": [{
    "id": "douyin", "name": "抖音", "category": "video",
    "active_sec": 3600, "first_seen": 1789970000, "last_seen": 1790000000,
    "by_hour": [0, 0, …, 600],            // 24 个数, 秒
    "sim_active_sec": 3600,               // 仅当含模拟设备的时长
    "sim": true                           // 仅当全部来自模拟设备
  }],
  "by_hour": [{"h": 0, "active_sec": 0}, …],                     // 24 项
  "categories": [{"id": "video", "apps": [{"id": "douyin", "name": "抖音"}]}],   // 可封锁类别
  "threshold_bytes": 8192, "tick_sec": 10,
  "app_time_limits": [ … ], "category_blocks": [ … ],            // 仅传了 mac 时, 形状同 §18.4
  "sim_included": true                                           // 仅当结果含模拟设备的活跃时长
}
```

- **模拟环境**:模拟设备的主应用(属「真应用」档时)按同一阈值积分活跃秒数(实时段按当前速率;首次回填零点至今那段按作息曲线概率决定每 10 分钟是否在用),
  合并进今天的 `apps/by_hour/total_active_sec`;`app_time_limits` 对模拟设备显示真实的 `used_sec/exhausted`,但 `enforced:false`、不封锁、不发告警。

### 18.6 GET `/api/dpi_unknown` — 未识别流量 Top

- app 归不上的连接按目的聚合(有反查名 → 基础域名,否则 IP),每天最多 300 个目的,每个目的最多记 8 台设备。Query:`days` 1–31(默认 1)。

```json
{
  "ok": true, "days": 1, "cap_per_day": 300,
  "total_unknown_bytes": 123456789,        // 按字节账(含被裁掉的尾部)
  "items": [{                              // 按 bytes 降序, 最多 100
    "name_or_ip": "example-cdn.com", "kind": "domain|ip", "sample": "img3.example-cdn.com",
    "bytes": 12345678, "devices": 2, "macs": ["aa:bb:cc:dd:ee:01"],
    "sim": true                            // 仅当该目的只来自模拟设备
  }],
  "sim_included": true                     // 仅当合并了模拟设备
}
```

- **模拟环境**:有主应用的模拟设备把今天 2%–5% 的字节记为未识别(无主应用的设备全部),按 (seed, mac) 确定拆成一个域名(约 70%)+ 一个裸 IP;
  同样的字节也出现在 `/api/app_usage` 的 `_unknown`(未识别)条目里,所以 `total_unknown_bytes` 与 items 对得上。

### 18.7 新告警 kind(均追加到 `run/alerts.jsonl`,经 §6.1 读取)

| kind | 由谁发 | 去重 | id | extra |
|---|---|---|---|---|
| `device_quota` | limit_policy 控制器,设备超出日/月配额时 | 每设备每周期一次 | `device_quota_<去冒号mac>_<daily\|monthly>_<周期键>` | `period`、`period_key`、`used_bytes`、`quota_bytes`、`action` |
| `phone_quota` | phone_usage,某卡本计费周期用量跨过 `warn_percent` 或 100% 套餐(每 5 分钟检查) | 每卡每档每周期一次(直接越过 100% 时不再补发 warn) | `phone_quota_<warn\|over>_sim<slot>_<周期起 YYYYMMDD>` | `slot`、`carrier`、`level`(warn\|over)、`used_bytes`、`plan_bytes`、`cycle_start`、`warn_percent`(无 `mac`) |
| `app_time_warn` | app_time,距上限 ≤5 分钟(上限 >5 分钟时) | 每 (设备, 应用, 天) 一次;已用完时不补发 | `app_time_warn_<去冒号mac>_<app_id>_<YYYYMMDD>` | `app_id`、`app_name`、`minutes`、`used_sec`、`until` |
| `app_time_exhausted` | app_time,今日活跃秒数达到上限(同时开始封锁到次日 0 点) | 同上 | `app_time_exhausted_<去冒号mac>_<app_id>_<YYYYMMDD>` | 同上 |

- 四种都只在告警总开关(`alerts_config.json.enabled`)开启时写入;模拟设备、模拟热点流量都不会触发。

## 19. v5.21 识别准确度:加密 DNS 策略 / VPN·代理检测 / 共现推断

> 来源:`daemon/hnc_httpd/encdns.go`、`traffic_ident.go`、`ct_new_events.go`、`bin/encdns_sync.sh`、`data/encdns_resolvers.txt`、
> `src/dpid/output/encdns.go`。新增路由 GET `/api/encdns`(鉴权、敏感只读);新增动作 `encdns_set`。

### 19.1 加密 DNS 策略:GET `/api/encdns` + `encdns_set`

配置 `data/encdns.json`:`{"policy":"off|dot|strict","devices":{"<mac>":"off|dot|strict"},"ts":N}`(httpd 写,脚本读)。

| 档位 | 效果 |
|---|---|
| `off`(默认) | 不干预 |
| `dot` | 拒绝 tcp/853(DoT,tcp-reset)与 udp/853(DoQ,端口不可达)→ 私人 DNS「自动」回落明文 53 |
| `strict` | dot + 公共 DoH:解析器 IP 的 tcp/udp 443 REJECT;解析器主机名的明文 DNS 查询 DROP、TLS SNI 命中的 443 连接 tcp-reset(后两者需 xt_string) |

- 范围:`policy` 作用于热点口上的全部设备;`devices` 按 MAC 覆盖(`off` = 该设备豁免全局)。热点未开时全局部分 `pending`,按 MAC 覆盖照常生效。
- **取舍**:「私人 DNS = 指定主机名」(严格模式)的设备在 dot/strict 下不会回落,会**整体无法解析(断网)**。响应里的 `tradeoff` 是给界面直接展示的中文说明。
- 名单:`data/encdns_resolvers.txt`(一行一个主机名 / IP / CIDR;`/data/local/hnc/etc/encdns_resolvers.txt` 优先),dpid 内置同一份(有测试对齐)。

动作 `encdns_set`:

| params | 说明 |
|---|---|
| `policy` | 全局:`off\|dot\|strict`;按设备另可 `inherit`(删除覆盖,跟随全局) |
| `scope` | `global`(默认)\|`device`;带 `mac` 时默认 `device` |
| `mac` | scope=device 必填;模拟设备(`02:5e:00`)拒绝;覆盖最多 64 台 |

返回 `detail`:脚本最后一行 `ENCDNS=off` 或 `ENCDNS=on global=<off|dot|strict|pending> devices=<n> rules=<n> string_layer=<1|0>`;已是目标状态 → `"no change"`。

GET `/api/encdns`:

```json
{
  "ok": true, "policy": "dot", "devices": {"aa:bb:cc:00:00:02": "strict"},
  "device_list": [{"mac": "aa:bb:cc:00:00:02", "policy": "strict"}],
  "policies": ["off", "dot", "strict"],
  "string_layer": "available",            // available|unavailable|unknown(strict 的 SNI/DNS 名字层)
  "counters": {                            // iptables -nvxL 计数, 每次重同步清零; null = 读取失败(见 counters_error)
    "chain": true, "v6": true,
    "dot": {"pkts": 20, "bytes": 1300}, "doh_ip": {"pkts": 11, "bytes": 700},
    "doh_sni": {"pkts": 1, "bytes": 517}, "doh_dns": {"pkts": 4, "bytes": 300},
    "total_pkts": 36, "total_bytes": 2817, "v4_pkts": 29, "v6_pkts": 7
  },
  "dpid": {"dns_seen": 120, "dot_attempts": 3, "dot_flows": 0, "doh_suspect": 2,
           "recent_doh": [{"client_mac": "…", "name": "dns.google", "ts": 0}], "since": 0},  // dpi_state.json 的 encdns 块, 可能为 null
  "tradeoff": "…", "updated_at": 1790000000
}
```

`counters.*.pkts` ≈ 被挡下的加密 DNS 尝试次数(tcp-reset 后客户端的重试也计入)。

### 19.2 客户端 VPN / 代理检测:`/api/devices[].vpn`

每台设备最近 5 分钟(按 app_usage 10 秒一轮的连接表差分):

```json
"vpn": {"level": "none|likely|certain", "reason": "WireGuard(udp 51820)", "share": 0.93, "bytes": 5242880,
        "dst": "8.8.9.9", "window_sec": 300}
```

- `certain`:协议特征流(WireGuard 51820 / OpenVPN 1194 / IPsec 500·4500·ESP / L2TP 1701 / PPTP 1723·GRE / WARP 2408 / VPN 服务商域名 / 规则库 vpn·proxy 类)字节占比 ≥ 50%。
- `likely`:特征流占比 ≥ 20%;或 单个「可疑目的」(无域名且归不上应用的 TLS 443 / QUIC 443 / 非标准端口 TCP / 其它 UDP)占比 ≥ 70%、窗口 ≥ 2 MB、持续 ≥ 2 分钟、其余 ≥ 64 KB 的目的 ≤ 3 个(此时 `dst` = 隧道对端)。
- 窗口内总字节 < 256 KB 不判(`none`)。

应用归属:特征流、以及判为 likely 的那个对端 IP 上本来记「未识别」的字节,记到伪应用 **`_tunnel`**(name「VPN/代理隧道」, category `tunnel`),
出现在 `/api/app_usage.by_app`,**不计入应用使用时长**(`/api/app_time` 里没有它)。

### 19.3 共现推断:`inferred_bytes`

目的 IP 无反查名、不在 ip_app_map 的新连接,若同一设备 ±5 秒内新建了某个真应用的连接且只有这一个应用(或它建连数 ≥2 且 ≥ 第二名 2 倍),推测为该应用;
建连时间来自 conntrack NEW 事件,订阅不上时退回 10 秒轮询粒度(此时要求同一轮唯一应用且 ≥2 条建连)。推测按 (设备, IP) 缓存 10 分钟。
为了看到建连后 5 秒内的连接,新出现的无名连接字节会**延后一轮(10 秒)**记账。

- `/api/app_usage`:顶层 `inferred_bytes`;`by_app[].inferred_bytes`(该应用字节中推测来的部分,界面可标「推测」)。
- `/api/dpi_unknown`:新增 `tunnel_bytes`、`inferred_bytes`(已从「未识别」里分出去的两块)。
- 日文件 `run/app_usage.YYYYMMDD.json` 新增可选字段 `inferred: {"mac|app": [up, down]}`(旧文件兼容)。

## 20. v5.22 功耗:GET `/api/power` + `run/activity.json`

> 来源:`daemon/hnc_httpd/power_activity.go`(活动状态)、`power_sched.go`(间隔策略表)、`power_stats.go`(自测采样);
> shell 侧 `bin/hnc_activity.sh`;dpid 侧 `src/dpid/activity`。鉴权、只读、GET。

- `GET /api/power[?refresh=1]`(`refresh=1` 立即补采一次,距上次 <10s 时忽略):
  - `activity`:`{ts, level, screen_on, screen_known, screen_source(backlight|power|display|none), hotspot_active, hotspot_iface, clients_online, webui_active, sse_clients, last_api_ago_s, ct_precise, known}`
  - `level` / `level_label`:`active` 活跃 | `background` 后台(熄屏且无界面)| `no_clients` 热点开着无在线设备 | `hotspot_off` 热点未开 | `unknown`
  - `processes[]`:`{name, label, pid, alive, cpu_pct_5m, cpu_pct_1h, cpu_pct_since_start, cpu_sec_per_hour, basis(1h|5m|since_start|none), wakeups_per_min, rss_kb, window_5m_s, window_1h_s}`;
    name ∈ `hnc_httpd`(含它拉起的脚本)、`hotspotd`、`hnc_dpid`、`dpid_guard`、`watchdog`、`offload_guard`、`clsact_wd`。CPU 含已回收子进程与存活后代;`cpu_pct_*` 为单核百分比。
  - `total`:`{cpu_pct_5m, cpu_pct_1h, cpu_sec_per_hour, wakeups_per_min, rss_kb}`
  - `by_level[]`:`{level, label, seconds, cpu_sec, cpu_sec_per_hour}`(httpd 启动以来各档位下的合计 CPU,对比亮屏/熄屏用)
  - `loops[]`:`{name, label, owner(httpd|watchdog|offload_guard|dpid|dpid_guard), base_interval_s, current_interval_s, multiplier, reason, critical, mirror, last_run_ago_s}`
  - `tips[]`:中文建议;`ts`、`sampled_at`、`sample_every_s`(300)、`samples`
- 同内容每次采样写 `run/power_stats.json`;自检「进程与资源」新增 `power`(功耗)项。
- `run/activity.json`:httpd 每 15s 探测,变化或每 60s 写一次;单行 JSON,字段顺序固定(shell 用模式匹配读,勿重排)。
  超过 180s(shell)/120s(dpid)未更新视为不可信,全部回到基准间隔。

## 21. v5.23 DPI 二代

### 21.1 TLS 指纹学习 + 纠正识别

- GET `/api/dpi_fp[?all=1]` → `{ok, learned:[{ja4, alpn, port_class, app_id, name, category, purity, support, devices, usable, generic, conf, first_seen, last_seen, top:[{id,name,share}]}], stats:{flows_seen, flows_learned, flows_attributed_by_fp, generic_skipped, entries, usable, binds, seed}, thresholds:{min_support, min_support_multi_device, min_devices, min_purity, half_life_days, user_ip_ttl_days}, user_rules:[…]}`。默认只返回前若干条,`all=1` 全量。学习表存 `data/fp_learned.json`。
- 动作 `dpi_correct {mac?, dst_ip?, dst_port?, name?, ja4?, app_id, app_name?, category?, kinds?}`:按 `kinds`(默认 `domain,ip,ja4`)各写一条用户规则到 `data/dpi_user_rules.json`;IP 规则 7 天过期;`app_id` 不在规则库时必须带 `app_name`;不能纠正为广告 / 统计 / CDN 类;模拟设备拒绝。没给 `ja4` 时按 `mac + dst_ip + dst_port` 在近期流里查。
- 动作 `dpi_correct_list` → detail 为 JSON 数组 `[{id, kind(domain|ip|ja4), value, port?, app_id, app_name, category, created, expires?, mac?}]`;`dpi_correct_del {id | all=true}`。
- `/api/connections?mac=` 每行新增:`app_src`(`user` 你纠正的 / `rule` 规则库 / `name` 域名推断 / `fp` 指纹学习 / `seed` 内置指纹)、`app_conf`(0–1,fp/seed/user)、`ja4`、`owner {key, name, kind}`(IP 归属,见 21.2)、`traffic_type`、`traffic_conf`。
- `/api/app_usage` 新增 `fp_bytes`、`fp_conf`、`user_bytes`。

### 21.2 IP 归属库

`data/ip_owner.bin`(`tools/build_ip_owner.py` 生成)。`owner.kind`:`app`(应用公司,未识别流量在统计里归到 `_org:<key>`,显示「XX系(未细分)」)/ `cloud` / `cdn` / `carrier`(只标归属,不归类)。`/api/dpi_unknown` 的条目带 `owner`,汇总带 `org_bytes`。

### 21.3 流量形态 + 前台应用

- `/api/devices[].traffic_type {type, label, confidence(0–1), since}`,`type` ∈ `video_stream | live_stream | video_call | voice_call | gaming | download | upload | browsing | background | unknown`。
- `/api/devices[].fg {state(active|paused|idle|stale|unknown), app_id, name, category, confidence(0–100), since, reasons[], background:[{app_id,name,category,label}], label("正在用：X"), bg_label("后台：A、B"), score, tick_sec, coarse?, stale?, updated}`。
- GET `/api/fg_timeline?mac=&days=1..8` → `{ok, mac, days, sessions:[{mac, app_id, name, category, start, end, sec, confidence, open}], by_app:[{app_id, name, category, fg_sec, fg_min, sessions, active_sec}], current}`。时间线按天存 `run/fg_timeline.YYYYMMDD.json`。`active_sec` 为按字节阈值算的时长(应用限时用的口径),仅作对照。

### 21.4 DNS 接管(可选,默认关)

- 配置 `data/dns_takeover.json`:`{enabled, block_mode("nxdomain"|"zero"), log_queries, log_redact, upstream("" = 自动), ts}`。
- 动作 `dns_takeover_set {enabled?, block_mode?, log_queries?, log_redact?, upstream?}`(至少一个),写入后立即同步一次。
- GET `/api/dns` → `{ok, enabled, active, healthy, state, iface, listen[], port, upstream, upstream_kind, v6:{status,reason}, block_mode, log_queries, log_redact, upstream_config, stats:{queries, cached, blocked, errors, ratelimited, dropped, upstream, upstream_errs, upstream_tcp, servfail, p50_ms, p95_ms, cache_entries}, top_domains_today:[{name,count}], recent?, blocklist:{devices, global}, failopen:{count, last_ts, reason, retry_at}, last_error, last_check, selftest_ms, ip_names}`。
- GET `/api/dns/log?mac=&limit=` → `{ok, log_queries, log_redact, mac, entries:[…]}`(新→旧,仅开启查询日志时有内容)。两个接口都属于敏感读路径。
- 实现:转发器监听热点 IP:15353,只对「热点接口 → 网关:53」做 DNAT(`bin/dns_takeover.sh`);上游依次为自定义 / 热点网关 53 / 系统;每 10 秒健康检查,自检失败、上游连续出错、DNAT 不生效或无上游时撤掉 DNAT 放行直连(fail-open)并按退避重试。

## 22. v5.24 本机带标签样本(DPI 3.0 地基)

由 dpid 在「追踪本机应用流量」(`run/self_capture.enabled`)开启时写入,只含本机流量:

- `run/label_samples.YYYYMMDD.jsonl`(本地日期,保留 7 天),每行:`{ts, pkg, uid, sni, ja4, alpn?, dport, quic, ech, partial, rip, rule_id?, rule_name?}`;`rule_*` 为写入时规则库按 SNI 的命中结果。
- `run/label_samples.YYYYMMDD.capped`:当天超过 20 MB 后出现,此后当天不再写。
- `run/label_samples.stats.json`:`{ts, since, day, written, deduped, dropped, skipped_system, skipped_empty, capped}`,每分钟更新,计数自写入器启动起累计。

- `run/self_fg.YYYYMMDD.jsonl`(v5.24.0-rc2):本机前台变化记录 `{ts, pkg, source(activities|window)}`,亮屏且开关开启时每 10 秒探测一次,只记变化,保留 7 天。
- `GET /api/dpi_eval?days=1|7[&refresh=1]`(v5.24.0-rc2,敏感只读):`{ok, generated_at, days, enabled, samples, apps, capped, skipped_system, sdk_samples, methods:{rule,fp,owner,combined:{samples,predicted,correct,coverage,accuracy,accuracy_na?}}, by_app:[{truth,name,samples,coverage,accuracy}], top_wrong:[{truth,name,pred,pred_name,n}], top_unknown:[{truth,name,n,snis}], fg_truth:{switches_24h,last_pkg,last_ts,source}, note}`。真值 = `data/pkg_app_map.json[pkg]`,不在表里为 `pkg:<包名>`;规则库命中广告 / SDK / CDN 类不计入预测(`sdk_samples`);owner 只算覆盖率。结果缓存 10 分钟并写 `run/dpi_eval.json`。
- 动作 `dpi_eval_clear`:删除 `label_samples.*`、`self_fg.*`、`dpi_eval.json`。

## 23. v5.25 变更

- `GET /api/dpi_eval`:`methods.*` 增加 `judged`(有标准答案且有预测的样本数,准确率的分母);顶层增加 `unlabeled`(包名不在对照表的样本数,只算覆盖率);`by_app[].accuracy_na` 表示该应用没有标准答案。规则库改从 `etc/dpi_rules.d`、`etc/dpi_rules.json` 读取(回退 `data/`)。
- `run/clock_state.json` 增加 `hwm_reset`(`auto_time` | `behind_6h`)、`hwm_reset_at`、`hwm_reset_from`。
- `GET /api/power`:`watchdog_pending` 在 `hotspot_off` 档为 120 秒(Go 版 watchdog 由网卡事件即时唤醒,轮询仅兜底)。
- `GET /api/run_status`(v5.25.0-rc2):`watchdog` 改为 0/1(按 pidfile + cmdline 判断),新增 `watchdog_kind`(go | shell)、`watchdog_pid`、`watchdog_hb_age`(Go 版心跳秒数,-1 = 不适用)。
