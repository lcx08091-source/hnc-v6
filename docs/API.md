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
| 9 | GET | `/ndpi-lab.html` | 公开 | §13 |
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

1. 路径在公开白名单 → 直接放行。白名单:`/`、`/pair`、`/changelog.html`、`/json-health.html`、`/ndpi-lab.html`、`/api/pair/verify`、`/api/pairing/status`(**未注册路由,实际 404**)、`/api/health`、`/api/logout`、以及前缀 `/static/`。
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
| shadow | v5.2 灰度采样(需 `run/stats_shadow.enabled` 存在) | `data/stats_shadow_raw.jsonl` / `stats_shadow_daily.jsonl` | 同 legacy | 同 legacy |
| dpi | dpid HistorySampler 每 15 分钟 | `$HNC/run/stats.YYYYMMDD.jsonl`(**文件名是 UTC 日期**)`{"t":秒,"mac","app","app_id","cat","tx","rx"}` | 每行即 15 分钟增量 | 只含被 DPI 归因的流量(略小于 iptables);默认只保留 7 天 |

所有 `rx` = 设备下载字节,`tx` = 设备上传字节,单位 **Byte**。

### 4.1 GET `/api/stats`

Query:

| 参数 | 类型 | 取值 | 默认 |
|---|---|---|---|
| `range` | string | `today` \| `week` \| `month` \| `all` | `today` |
| `mac` | string | 可选,`xx:xx:xx:xx:xx:xx`(大小写均可,内部转小写) | 空 = 全部设备合计 |
| `source` | string | `legacy` \| `shadow` \| `dpi`(大小写不敏感) | `legacy`(注意:旧 UI 默认传 `dpi`) |

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
  unique_hostnames, unique_sni, unique_ja4, l3_enabled, l3_rule_version?, dfp_enabled, dfp_rule_version?, ndpi_available, ndpi_entries?,
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
      "kind": "unknown_device",                             // "unknown_device" | "anomaly_traffic" | "monthly_quota"
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

读 `$HNC/data/rules.json`(每次读盘,不缓存)+ `run/stats_shadow.enabled` + `etc/flywheel_exclude.json`:

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
  "clsact_bpf_enabled": false,       // bool
  "stats_shadow_enabled": false      // bool,run/stats_shadow.enabled 是否存在
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
| `clsact_bpf_enabled_set` | `enabled`=`true`\|`false` | 见 §11.3 | |
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
{ "active": false, "detail": "IDLE" }
```

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
| `clsact_bpf_enabled_set` | `enabled`=`true`\|`false` | `json_set.sh top clsact_bpf_enabled <v>`;开:热点在则 `hnc_clsact_watchdog.sh repair <iface>`;关:`hnc_clsact_ctl uninstall <iface>` | 开 `"clsact BPF enabled · watchdog 会在 10s 内完成安装"`(repair 失败也 ok=true,detail 带原因);关 `"clsact BPF disabled · filter 已卸载"` |

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
| `/ndpi-lab.html` | 是 | 磁盘 `模块目录/webroot/ndpi-lab.html`,缺失 404(页面本身依赖 `ksu.exec`,远程打开只能看) |

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
| 36 | `clsact_check` | 诊断 §11.3 | — | | ✓ | |
| 37 | `clsact_repair` | 诊断 | — | | ✓ | |
| 38 | `clsact_bpf_enabled_set` | 诊断/设置 | enabled | | ✓ | |

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
| GET `/json-health.html`、`/ndpi-lab.html`、`/changelog.html` | 浏览器直接打开 | KSU 前端用相对路径 `fetch('changelog.html')` 读模块目录文件,不经 httpd |
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
