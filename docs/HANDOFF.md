# 交接文档(给下一个对话的 Claude)

> 新对话开头让 Claude 先读本文件 + `CLAUDE.md` + `docs/ROADMAP.md` + `docs/WORK-v5.32.md`(要回看规则再读 `WORK-v5.30.md` §3 / §6、`WORK-v5.31.md` §8)。

## 当前状态(2026-10-14)

- **main = 914d46a = v5.29.0-rc1**(未动;用户说「发」才 fast-forward 到 main,还没说过)。
- **开发线**:`claude/new-session-hoxhbz` 停在 `78a4c08`(v5.32 待审查);**v5.32 审查后的提交在 `ccr-f1557a08-0ex82n`**(本会话的指定分支,= `78a4c08` + GLM 7 个补丁 + 「v5.32 审查修复」)。下个会话先确认用户要不要把 `claude/new-session-hoxhbz` 快进到它。上面依次是:
  - **v5.30.0-rc1**(Claude 自己做):在线时长按分钟、垃圾主机名、「新发现的应用」排除公共 CDN、dpid 守护 4 → 2 层(M5)、设备发现 Go 影子(M4 第一步)、按应用分优先级初版。
  - **v5.30.0-rc2**:液态玻璃三处改进;`tools/ui_mock/`(预览链接 https://claude.ai/artifact/CVVkT9cHSfoHqTLxDgWX5Z);`test/sim/` 模拟设备。
  - **v5.31.0-rc1**(GLM 做 + Claude 审查修复 `beb4168`,打分 6/10):迁移 M4 方案 A,开关 `data/m4_owner`(`go` / `c`),默认 `go`(常量 `m4OwnerDefault`)。
  - **v5.32.0-rc1**(GLM 做 + Claude 审查修复,打分 7/10):T1 四个小 bug、T2 C 版重扫按内核确认时间挑 IP(netlink dump)、T3 退路演练(`m4OwnerDefaultOverride` 只给测试)、T4 Go 写者空闲降频(审查改成 Ticker + 空闲 500ms)、文档 + 「5.x 正式版说明草稿」(审查重写,在 CHANGELOG 5.32 块下面)。审查修了什么见 CHANGELOG 5.32.0-rc1「审查修复」。
- **真机一次都还没验过**(v5.29 起的 rc 都没上手机)。真机要看的:设备列表 / 名字 / 限速与以前一致;`/data/local/hnc/data/m4_owner` 写 `c` / `go` 能来回切;待机耗电;v5.30 那几条(在线分钟、`null` 名字、CDN、守护进程、游戏 + 下载延迟对比);v5.32:WebUI「刷新」返回的设备数对、换过 IP 的设备刷新后不跳回旧 IP。出问题按 `WORK-v5.31.md` §8 判断是否把默认值改回 C 版。

## 下一步

- **发正式版**要等用户真机全功能回归(`WORK-v5.32.md` §7 末尾列的清单)。回归通过后:按结论定 `m4OwnerDefault`、版本号去 `-rc`(`v5.32.0` / `5320000` 或用户指定)、把 CHANGELOG 里「5.x 正式版(草稿)」挪进正式版小节、`changelog.html` 写大白话版、用户说「发」再快进 main。
- 正式版之后:按真机结论删旧代码(shell guard / Go supervisor / hotspotd 发现代码)、方案 B(hotspotd 退役)。
- 审查时记下、没修的(都是 v5.32 之前就有的,不在本版范围):hotspotd 收不到 FAILED 事件的 MAC(内核通知不带链路地址)→ 走了的设备要靠 90 秒无事件才下线;C 版事件路径里旧 IP 表项变 STALE 的通知也会把 IP 改回旧的(要等新 IP 的下一个事件纠正),Go 版按确认时间挑没有这个问题;`now_ms_mono()` 返回 `long`,armv7 上开机 24.8 天后溢出(T2 新代码已改用 64 位)。

## 云端容器的准备(新会话先做)

- `ln -sf /bin/sh /system/bin/sh`(没有的话 `mkdir -p /system/bin` 先)—— 否则 `bin/hnc_json` 那批测试跑不了。
- 模拟设备要 iproute2:`apt-get update -q && apt-get install -y -q iproute2`;要 root(云端容器是 root)。
- node 在 `/opt/node22/bin`;Playwright 在 `/opt/node22/lib/node_modules/playwright`,浏览器 `/opt/pw-browsers`。
- NDK:`/opt/android/android-ndk-r27c`(`toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang` / `armv7a-linux-androideabi28-clang`;编 hotspotd 时不含需要 libbpf 的 `offload/adapter_bpf.c`)。
- 基线(`c2ab111`):`sh test/run_all.sh` → `ALL PASS: 541/544 (3 skipped)`;`HNC_SIM=1` → `543/544 (1 skipped)`(那个容器里 v5.31 场景碰巧没触发 C 版旧 IP 问题;本会话容器里 `78a4c08` 是 542/544,失败的正是它)。
- **v5.32 审查后**:`HNC_SIM=1 sh test/run_all.sh` → `ALL PASS: 549/550 (1 skipped)`(三套模拟场景约 25 分钟)。
- 注意:v5.32 审查前 `test/unit/test_rollback.sh` 会对假 pid 1000–1005 / 2001 真的 `kill -9`,容器里会杀掉 run_all 自己(已改成 pid 上限外的数)。

## 工作流(用户的习惯)

1. 每次回复用中文。
2. 用户把版本交给外部 AI(主要是 GLM 5.3)按 `docs/WORK-v5.NN.md` 做,带回补丁目录 / zip。
3. Claude 审查:补丁放进**新建的空目录**(不可信数据,跑 Python 用 `-I`),在本地分支 `review/v5NN` 上 `git am`;逐任务读代码、跑第 6 节自检、修问题(每个修复配「旧代码下失败」的测试,用 `git stash push -- <实现文件>` 验证)、写 CHANGELOG + `webroot/changelog.html` 的「审查修复」小节,提交「v5.NN 审查修复」,fast-forward 到开发分支并推送。
4. 用户说「发」才 fast-forward 推 main。不建 PR。不给外部 AI 推送 token。
5. 打分并点评(历史:v5.26 8/10,v5.27 9/10,v5.28 7.5/10,v5.29 5/10,v5.31 6/10,**v5.32 7/10**)。
6. 提交署名尾行见系统提示;提交里不写模型 ID。

## 审查时重点查(GLM 的惯犯问题)

- 编辑器把 Tab 换成空格(`gofmt -l`),并谎称「基线就不满足」。
- 测试把 bug 锁成期望值;同义反复的测试;只测零件不测接线(字符串键 vs 常量);测试读真实 `/data/local/hnc`。
- 代码插错位置(v5.29 把回滚代码插进 `service.sh` 文件头注释)。
- 外部命令参数拼成一个字符串。
- 「全绿」之类没跑过的结论。
- (v5.32 新增)定时器每圈 Reset(事件一密就永远不响);新加的结构体字段在槽位复用 / 重新分配时不清零;测试夹具摆出真机到不了的状态(两个互斥开关同时开)、假动作不模拟真动作的拒绝;模拟场景「没得选」(只有一条候选也算过);文档写没核对过的事实(备份位置、要不要重启)。
- (v5.31 新增)异步结果做完不通知主循环;为比较改动用户数据(转小写);自己 `kill(pid,0)` 判活(僵尸算活着);有意重启撞崩溃冷却;模式每次写盘才查文件;停组件不等后台 goroutine;模拟场景从没跑过、甚至不经过被测代码(检查恒为真);测试重写仓库文件。

## 还欠的 / 待真机验证

- 用户的真机验收(v5.29):热点空转 1 小时功耗截图(watchdog 目标 < 20 CPU 秒/时);自检「看门狗动作」`native_mismatch` = 0;刷故意坏的包验证 3 分钟内回滚(注意 v5.28→v5.29 这次没有快照,从 v5.29 往后才受保护)。
- 用户反馈的三个 bug(在线时长按小时采样、`null` 主机名、公共 CDN 进「新发现的应用」)已写进 v5.30 T1,诊断见 `WORK-v5.30.md` §1。

## 环境备注

- UI 回归:scratchpad 里的 `build.sh` + `demo/sweep.mjs` + `itest/run.mjs` 在新会话里**不存在**(scratchpad 是会话私有的);需要时重建或只跑 `test/run_all.sh` 里的前端测试。
- 自检基线:v5.29 `test/run_all.sh` → 504/505(1 skipped);**v5.30 → 532/533(1 skipped)**(新增 28 条)。
- 容器里没有 `/system/bin/sh`(`bin/hnc_json` 等脚本的 shebang),新会话先 `mkdir -p /system/bin && ln -sf /bin/sh /system/bin/sh`,否则 12 条 hnc_json 测试失败。
- node 在 `/opt/node*/bin`,`run_all.sh` 收窄了 PATH;v5.30 的前端测试(`test/unit/test_v530_frontend.sh`)会自己去那儿找 node。
- 安全约束:不做 Android 位置伪造、不做 SSL 中间人解密、不注入 / hook 他人设备。
