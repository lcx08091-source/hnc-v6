# A1 审查记录：hnc_httpd 安全面

- 基线版本：v5.33.0-rc2
- 审查员前缀：A1
- 范围：`daemon/hnc_httpd/` 下 main.go、server.go（路由与鉴权接线）、middleware.go、auth.go、tokens.go、security_headers.go、webui_access.go、pair.go、pair_guard.go、web/pair.html、remote_listener.go、tls.go、ratelimit.go、writelimit.go、audit.go、embed.go、capability.go、detached_linux.go、hnc_paths.go
- 重点：路由鉴权、本机/远程区分能否伪造、token/配对码、CSRF/Origin/CORS/Cookie、写接口限流、路径穿越、TLS 证书、错误信息泄露、并发 map
- 只记录、不改代码

## 已审文件

## Bug

