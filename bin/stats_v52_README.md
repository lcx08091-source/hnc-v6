# `bin/stats_v52_*.sh` 前缀历史说明

<!-- rc30.12.35 (TASK-c Stage 2): GPT 一审 P2.13 收口 -->

## 为什么这些脚本都有 `stats_v52_` 前缀?

历史包袱.

v5.2 时期(rc 编号 v5.2-rc1.0 起)项目从老的 stats 子系统迁移到新的
DPI-based stats. 当时为了**灰度发布安全**(不一次性切换破坏所有用户),
做了一整套带 v5.2 命名的工具:

- 灰度切换器(`stats_v52_rc1_switch.sh`)
- 自检脚本(`stats_v52_install_selfcheck.sh`)
- 诊断打包器(`stats_v52_diag_bundle.sh`)
- 灰度观测/报告(`stats_v52_gray_observe.sh`, `stats_v52_gray_report.sh`)
- 真机预检/冒烟测试(`stats_v52_device_check.sh`, `stats_v52_rc_smoke.sh`)
- WebUI 状态卡(`stats_v52_web_status.sh`)
- ...

v5.3 进入 stable 后, 老的 stats 子系统已经替换完成. 但这些 v5.2 helper
仍在 hot path:

- `bin/json_diag_bundle.sh` 调 `stats_v52_diag_bundle.sh`
- `bin/ci_preflight.sh` 调多个做发布前自检
- `bin/json_health_panel.sh` 调 `stats_v52_web_status.sh` 做 WebUI 状态卡
- `bin/stats_health_summary.sh` 聚合多个
- `webroot/changelog.html` 文档引用 v5.2 stats RC 历史

## 为什么不重命名?

5 个调用方任一漏改就 break. 调用方都是 hardcode 文件名 grep / cat / source,
不像 Go import 有编译器 catch.

GPT 一审 P2.13 建议"至少把 rc1_13/rc1_14 拿掉", 但实测仓库现状:
- 没有 `rc1_13` / `rc1_14` 这种命名 (报告作者按"假想可能存在"写的)
- 真实存在的脚本前缀都是 `stats_v52_<功能名>` 形式, 不含历史 rc 编号

唯一**真的暴露历史 rc 编号**的位置是脚本顶部注释 (`# HNC hotfix22.x v5.2 stats ...`),
rc30.12.35 (TASK-c Stage 2) 已经清理: 改成 `since v5.2-hotfix22.x` 风格,
功能描述放前面, 历史 rc 标在 since 字段, 让代码读起来不像考古.

## 未来什么时候才能改文件名

v6.0 stats 子系统大重构时. 那时候会:

1. Stage 1: 加 symlink (旧名 → 新名), 调用方先逐个迁移到新名
2. Stage 2: 装机稳定 N 个 rc 后删 symlink
3. Stage 3: 删旧名引用

跟 dpi_rules.d/ 三阶段切换 (TASK-a) 同样的安全模式. v5.3.x 周期不动.

## 命名反模式提醒

**新功能不要再用 `v<N>_` 前缀命名**. 文件名应反映**功能**, 而不是**当时
是哪个 rc**. 反例: `dpi_v53_split.py`. 正例: `dpi_rules_split.py`.

历史 rc 编号属于 git log / CHANGELOG, 不属于文件名.

---

参见:
- `docs/TASK-c-stats-v52-rename-plan.md` — TASK-c v1 设计稿 (rc30.12.34)
- ARCHITECTURE.md "命名反模式" 段 (待加, rc30.12.35 中)
