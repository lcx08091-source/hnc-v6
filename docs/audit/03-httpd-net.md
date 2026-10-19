# A3 审查记录：hnc_httpd 网络 / DNS / 计费 / API

- 基线版本：v5.33.0-rc2
- 审查员：A3（子审查员）
- 范围：`daemon/hnc_httpd/` 下 dns_takeover.go、dns_forwarder.go、dns_wire.go、encdns.go、limit_policy.go、quota_global.go、conn_blocks.go、ct_events.go、ct_new_events.go、neigh_v6.go、ip_owner.go、mac_merge.go、mac_alias.go、api_conn.go、api_live.go、api_v5.go、api_self.go、api_alerts.go、api_events.go、api_sla.go、iface_patterns.go、hostname_junk.go、jsoncache.go、netstats_parse.go
- 原则：只记录真 bug，不改代码。

## 已审文件

## Bug

