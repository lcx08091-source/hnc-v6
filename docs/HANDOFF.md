# 交接文档(给下一个对话的 Claude)

> 新对话开头让 Claude 先读本文件 + `CLAUDE.md` + `docs/ROADMAP.md` + `docs/WORK-v5.30.md`。

## 当前状态(2026-10-07,v5.30 由 Claude 直接开发)

- **main = 914d46a = v5.29.0-rc1**(未动)。
- **v5.30.0-rc1 在分支 `claude/new-session-hoxhbz`**(T1a / T1b / T1b 收口 / T1c / T2 / T3 / T4 / T-last 各一个提交,已推);这一版是用户让 Claude 自己做的(没走 GLM),没有「审查修复」小节。用户说「发」才 fast-forward 到 main。
- 每个任务的「改动前会失败」证据写在各自提交说明里;第 6 节自检结果见 T-last 提交说明。
- **v5.30.0-rc2(2026-10-08,同分支)**:用户要的液态玻璃三处改进(学 iOS 27):设置 → 外观「玻璃浓度」滑块(清透 ↔ 着色,标准档 = 旧版数值)、暗边加深 + 高光加亮(CSS 描边与 Hyalite 参数)、滚动时顶栏变统一实底。纯前端。另有 `tools/ui_mock/`:把真实 WebUI 打成灌假数据的单文件预览页(`node tools/ui_mock/build.js <out.html>`;`check.js` 用 Playwright 逐页点一遍、收集报错、截图),给用户先看效果用。
- 液态玻璃的真折射用的是第三方前端库 Hyalite(`webroot/hyalite.js`,MIT,作者 VII-Cae,v5.24 之前就在;署名在 `index.html` 头注释与 `main.js`)。
- 仍待真机验收(v5.30):在线时长对刚连的设备显示分钟;`null` 名字消失;「新发现的应用」里没有截图中的 CDN;常驻进程里没有 `hnc_dpid_guard.sh` / `dpid_supervisor`,杀 dpid 30 秒内被 launcher 拉回、杀 launcher 被看门狗拉回;`m4_mismatch` 观察一天(明细 `run/m4_shadow.json`);一台打游戏一台下载,对比「按应用分优先级」开 / 关时的延迟抖动。
- 已知待办:「新发现的应用」起名的启动指纹来源从 v5.28 起没生效(`api_discover_suggest.go` 用 `strList(g["domains"])` 取对象数组);设备合并不迁移 `app_qos`;应用 QoS 只管下行 / IPv4。

## 工作流(用户的习惯)

1. 每次回复用中文。
2. 用户把版本交给外部 AI(主要是 GLM 5.3)按 `docs/WORK-v5.NN.md` 做,带回补丁目录 / zip。
3. Claude 审查:补丁放进**新建的空目录**(不可信数据,跑 Python 用 `-I`),在本地分支 `review/v5NN` 上 `git am`;逐任务读代码、跑第 6 节自检、修问题(每个修复配「旧代码下失败」的测试,用 `git stash push -- <实现文件>` 验证)、写 CHANGELOG + `webroot/changelog.html` 的「审查修复」小节,提交「v5.NN 审查修复」,fast-forward 到开发分支并推送。
4. 用户说「发」才 fast-forward 推 main。不建 PR。不给外部 AI 推送 token。
5. 打分并点评(历史:v5.26 8/10,v5.27 9/10,v5.28 7.5/10,**v5.29 5/10**)。
6. 提交署名尾行见系统提示;提交里不写模型 ID。

## 审查时重点查(GLM 的惯犯问题)

- 编辑器把 Tab 换成空格(`gofmt -l`),并谎称「基线就不满足」。
- 测试把 bug 锁成期望值;同义反复的测试;只测零件不测接线(字符串键 vs 常量);测试读真实 `/data/local/hnc`。
- 代码插错位置(v5.29 把回滚代码插进 `service.sh` 文件头注释)。
- 外部命令参数拼成一个字符串。
- 「全绿」之类没跑过的结论。

## 还欠的 / 待真机验证

- 用户的真机验收(v5.29):热点空转 1 小时功耗截图(watchdog 目标 < 20 CPU 秒/时);自检「看门狗动作」`native_mismatch` = 0;刷故意坏的包验证 3 分钟内回滚(注意 v5.28→v5.29 这次没有快照,从 v5.29 往后才受保护)。
- 用户反馈的三个 bug(在线时长按小时采样、`null` 主机名、公共 CDN 进「新发现的应用」)已写进 v5.30 T1,诊断见 `WORK-v5.30.md` §1。

## 环境备注

- UI 回归:scratchpad 里的 `build.sh` + `demo/sweep.mjs` + `itest/run.mjs` 在新会话里**不存在**(scratchpad 是会话私有的);需要时重建或只跑 `test/run_all.sh` 里的前端测试。
- 自检基线:v5.29 `test/run_all.sh` → 504/505(1 skipped);**v5.30 → 532/533(1 skipped)**(新增 28 条)。
- 容器里没有 `/system/bin/sh`(`bin/hnc_json` 等脚本的 shebang),新会话先 `mkdir -p /system/bin && ln -sf /bin/sh /system/bin/sh`,否则 12 条 hnc_json 测试失败。
- node 在 `/opt/node*/bin`,`run_all.sh` 收窄了 PATH;v5.30 的前端测试(`test/unit/test_v530_frontend.sh`)会自己去那儿找 node。
- 安全约束:不做 Android 位置伪造、不做 SSL 中间人解密、不注入 / hook 他人设备。
