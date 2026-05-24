# CLAUDE.md — 项目记忆 / 约定

## 沟通语言(用户长期偏好)
- **每次回复都必须用中文**(用户明确要求)。技术名词/命令/代码可保留英文,但解释和对话一律中文。

## 版本与日志纪律
- 每次改动都要:bump `module.prop` 的 `version` + `versionCode` → 写 `CHANGELOG.md` → 同步写应用内 `webroot/changelog.html`。
- 改完跑静态校验:`sh -n`(改过的脚本)、`node --check`(抽取 index.html 内联 JS)、`go vet` + `CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build`(改过 Go 时)、`sh bin/version_consistency_check.sh`。

## 构建 / 分支
- 开发在分支 `claude/webui-fake-code-audit-RJjFZ`;验证通过后 fast-forward 合并到 `main` 触发 CI(`.github/workflows/build.yml` 只在 push main / tag v* / 手动时构建)。
- 改了 Go(`daemon/hnc_httpd`、`src/dpid`)或 C(`src/launcher`)需要 CI 重编对应二进制;纯 shell/前端不用重编。

## 设备环境(真机)
- realme RMX5010 / ColorOS Android 16 / 内核 6.6 GKI / SukiSU(Magic Mount 元模块 `magic_mount_rs`,`umount=false`)+ SuSFS。
- 已知:运行期 `/system/bin` 可能被卸(已加 `/data` 兜底);该内核疑似无 `sch_cake`/`sch_fq_codel`(低延迟退 `sfq`);ColorOS 是否放行 `cmd wifi start-softap` 等需真机验证。
