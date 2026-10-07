# 交接文档(给下一个对话的 Claude)

> 新对话开头让 Claude 先读本文件 + `CLAUDE.md` + `docs/ROADMAP.md` + `docs/WORK-v5.30.md`。

## 当前状态(2026-10-07)

- **main = 914d46a = v5.29.0-rc1**(含 v5.28 + 两版的审查修复),已推,CI 会出 `-rc` 预发布包。
- 开发分支 `claude/environment-config-ydr2ow` 与 main 相同,另加本文件和 `docs/WORK-v5.30.md`。
- 下一版:**v5.30**,工作文档 `docs/WORK-v5.30.md`(T1 三个用户 bug → T2 迁移 M5 → T3 M4 影子 → T4 应用感知 QoS 初版)。

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
- 自检基线:`test/run_all.sh` → 504/505(1 skipped)。
- 安全约束:不做 Android 位置伪造、不做 SSL 中间人解密、不注入 / hook 他人设备。
