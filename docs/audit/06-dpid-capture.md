# A6 审查记录：dpid 抓包 / 解析（src/dpid/capture 等）

- 基线版本：v5.33.0-rc2
- 审查员：A6 子审查员
- 范围：
  - `src/dpid/capture/` 全部非测试文件（bpf.go、devhint.go、http.go、iface.go、ja4.go、parse.go、quic.go、rawsocket.go、recorder.go、replay.go、self_iface.go、tls_reasm.go）
  - `src/dpid/cmd/dpid/`（main.go、self_capture.go、flowfp.go）
  - `src/dpid/cmd/dpid_replay/main.go`
  - `src/dpid/bytestats/`
  - `src/dpid/probe/capability.go`
  - `src/dpid/bpf/hnc_clsact.bpf.c`
- 原则：只记真 bug，只记录不改代码。严重度 P0–P3，状态「确认 / 疑似」。

## 已审文件

## Bug

