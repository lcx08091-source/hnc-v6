# TASK-c: `stats_v52_*` 老 rc 脚本重命名清单 (设计稿)

<!-- rc30.12.34 (TASK-c): GPT 一审 P2.13 收口 -->

**类型**: 设计稿(Stage 1, 0 代码改动)
**基线**: HNC v5.3.0-rc30.12.33
**生效状态**: **本文档仅为设计稿**. 实际重命名要等 Stage 2 真做时执行.

---

## 背景

GPT 一审报告 P2.13 点名:

> `bin/stats_v52_rc1_13_report_direct_helper.sh` /
> `bin/stats_v52_rc1_14_fast_report_cache.sh` /
> `bin/stats_v52_gray_observe.sh` / ... 十几个。v5.2 已经发布稳定,
> 进入 v5.3 这些脚本还在不在 hot path?
>
> 如果还在用,至少把 `rc1_13` / `rc1_14` 这种历史 rc 编号从文件名拿掉。
> 如果不用,删。

实际现状(rc30.12.33 baseline):

- 仓库里有 **10 个** `stats_v52_*.sh` 脚本,共 **2260 行**
- 报告写的是 rc28 时点的猜测,实际 `rc1_13` / `rc1_14` 这些扩展名形式
  在 rc28 之后已经被简化过,但 **`stats_v52_` 前缀和 v5.2 rc 编号
  内嵌在脚本注释/版本号里**

## 当前 10 个脚本的功能分类

| 文件 | 行数 | 功能 | 历史 rc 编号 (脚本头注释) |
|---|---:|---|---|
| `stats_v52_device_check.sh` | 317 | v5.2 stats 真机 RC 预检 | hotfix22.4 |
| `stats_v52_diag_bundle.sh` | 182 | v5.2 stats 诊断聚合 | hotfix22.3 |
| `stats_v52_gray_observe.sh` | 294 | 灰度观测助手 | v5.2-rc1.21 |
| `stats_v52_gray_report.sh` | 400 | shadow-aware 灰度报告导出 | v5.2-rc1.16 |
| `stats_v52_install_selfcheck.sh` | 206 | 首启安装自检 | v5.2-rc1.14 |
| `stats_v52_rc1_switch.sh` | 134 | v5.2-rc1 灰度切换 | v5.2-rc1 |
| `stats_v52_rc_control.sh` | 152 | v5.2 stats RC 控制 | hotfix22.0 |
| `stats_v52_rc_smoke.sh` | 174 | v5.2 stats RC 冒烟测试 | hotfix22.2 |
| `stats_v52_review_bundle.sh` | 278 | 审阅打包 (脱敏) | v5.2-rc1.16 |
| `stats_v52_web_status.sh` | 123 | WebUI 状态卡 (JSON/TXT) | (无版本号) |

**关键发现**: 没有 `rc1_13` / `rc1_14` 这种 GPT 报告写的命名形式. 报告
作者是按"假想这种文件可能存在"写的, 实际不存在.

## 调用关系(谁还在用)

`grep -rln "stats_v52_" bin/ daemon/ service.sh post-fs-data.sh webroot/ src/`:

```
bin/json_diag_bundle.sh       ← 调 stats_v52_diag_bundle.sh
bin/ci_preflight.sh           ← 调 stats_v52_* 做发布前自检 (具体哪几个待查)
bin/json_health_panel.sh      ← 调 stats_v52_web_status.sh 做 WebUI 状态
bin/stats_health_summary.sh   ← 调 stats_v52_* 多个 (聚合)
webroot/changelog.html        ← 文档引用, 提及 v5.2 stats RC
```

5 个调用方, 都在 hot path. **不能直接删, 也不能简单 rename 单个文件**
(会破坏调用方 grep / cat / source).

## 选项分析

### 选项 A: 全部 rename, 去掉 v52 前缀

```
stats_v52_device_check.sh        → stats_device_check.sh
stats_v52_diag_bundle.sh         → stats_diag_bundle.sh
stats_v52_gray_observe.sh        → stats_gray_observe.sh
stats_v52_gray_report.sh         → stats_gray_report.sh
stats_v52_install_selfcheck.sh   → stats_install_selfcheck.sh
stats_v52_rc1_switch.sh          → stats_switch.sh       (砍掉 rc1)
stats_v52_rc_control.sh          → stats_control.sh      (砍掉 rc)
stats_v52_rc_smoke.sh            → stats_smoke.sh        (砍掉 rc)
stats_v52_review_bundle.sh       → stats_review_bundle.sh
stats_v52_web_status.sh          → stats_web_status.sh
```

**优点**: 摆脱 v5.2 历史包袱, 名字反映功能不是 rc 历史.
**缺点**: 10 个文件 rename + 5 个调用方 grep-replace, **`ci_preflight`
的 sanity gate 引用可能写死了文件名 — 漏改一处装机就出问题**.
**风险**: 高 (调用方改动面太大, 容易漏一个).

### 选项 B: 保留前缀, 只删 rc 数字

```
stats_v52_rc1_switch.sh   → stats_v52_switch.sh
stats_v52_rc_control.sh   → stats_v52_control.sh
stats_v52_rc_smoke.sh     → stats_v52_smoke.sh
其他 7 个不动
```

**优点**: 改动面小(3 个文件 rename + 3 处 grep-replace).
**缺点**: 仍然保留 `v52` 前缀, GPT 报告的核心抱怨没解决.
**风险**: 中.

### 选项 C: ★ 一动不如一静(推荐)

**不重命名任何文件**. 只做以下:

1. **加 `bin/stats_v52_README.md`** 解释"为什么名字里有 v52 历史包袱":
   ```
   这些脚本前缀 stats_v52_ 是 v5.2 时期引入的 stats migration
   helper. v5.3 起 stats migration 已完成, 但脚本仍在 hot path
   (健康面板/CI 自检/诊断打包). 删除前缀的代价是 5 个调用方都要
   grep-replace, 漏改即破环. v5.3.x 不重命名, v6.0 重构 stats 子
   系统时一并处理.
   ```

2. **审阅每个脚本顶部注释**, 把 `hotfix22.x` / `v5.2-rc1.21` 这种历史
   rc 编号统一改成 `since v5.2`:
   ```sh
   # 之前: # stats_v52_diag_bundle.sh — HNC hotfix22.3 v5.2 stats diagnostic aggregator
   # 之后: # stats_v52_diag_bundle.sh — v5.2 stats diagnostic aggregator (since v5.2-hotfix22.3)
   ```

3. **加 `_v52_` 反模式注释到 CONTRIBUTING / 架构文档**:
   "新功能不要再用 v\<N\> 前缀命名. 它是历史 stats migration 遗留.
   新代码用功能名命名, 例: `dpi_rules_split.py` 而不是 `dpi_v53_split.py`."

**优点**:
- 零调用方影响 (不 rename)
- 解决了 GPT 报告核心抱怨的"文件名暴露历史 rc"问题 (改注释)
- 给未来正确命名立规矩

**缺点**:
- 文件名上 `_v52_` 仍在, 报告作者会说"不够彻底"
- 但 GPT 报告作者不承担装机调试责任 — 5 个调用方漏改一处就 break

**风险**: 极低 (纯文档改动).

## 推荐 (TASK-c v1)

**选项 C (一动不如一静 + 文档收口)**.

理由:
1. GPT 报告 P2.13 写的 "如果还在用,至少把 rc1_13/rc1_14 拿掉" — 实际
   不存在这种命名, 报告对仓库现状的描述有偏差
2. 真正存在的 10 个脚本都在 hot path, rename 高风险低收益
3. 历史包袱在文件名里没坏处, 在调用方 hardcode 文件名时拆开才坏
4. v5.3 收尾期不动调用图, 留 v6.0 大重构

## 验收

1. `bin/stats_v52_README.md` 存在并解释了前缀历史
2. 10 个脚本顶部注释里 `hotfix22.x` / `v5.2-rcN.M` 改成 `since v5.2-xxx` 风格
3. ARCHITECTURE.md 或 CONTRIBUTING.md 加 "命名反模式" 段
4. **不动文件名, 不动调用方** — 装机零回归

## 未来 v6.0 真重命名时的迁移路径

1. Stage 1: 加 symlink (旧名 → 新名), 调用方先逐个迁移到新名
2. Stage 2: 装机稳定 N 个 rc 后删 symlink
3. Stage 3: 删旧名引用

跟 dpi_rules.d/ 三阶段切换 (TASK-a) 同样的安全模式.

---

**End of TASK-c v1 设计稿**. Ling 看完点头 → 实施 (5 分钟改注释 + 加 README).
