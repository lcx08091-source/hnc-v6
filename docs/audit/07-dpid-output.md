# A7 审查记录：dpid output / alert / apkscan / appmeta

- 基线版本：v5.33.0-rc2
- 审查员前缀：A7
- 范围：
  - `src/dpid/output/` 下全部非测试文件（auto_expand、candidate、classify、cluster、conntrack、devid、dfp、discover、encdns、entity、evidence_ledger、flow、flowlog、flywheel_exclude、history、ip_app_map、ipname、ja4family、label_samples、qtp、rule、self_attrib、shared_infra、state）
  - `src/dpid/alert/`
  - `src/dpid/apkscan/`（解析 APK / 文件，属于不可信输入）
  - `src/dpid/appmeta/`
- 原则：只记真 bug，只记录不改代码。

## 已审文件

## Bug

