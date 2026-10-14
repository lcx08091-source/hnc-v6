# 交接文档(给下一个对话的 Claude)

> 新对话开头让 Claude 先读本文件 + `CLAUDE.md` + `docs/ROADMAP.md` + `docs/WORK-v5.32.md`(要回看规则再读 `WORK-v5.30.md` §3 / §6、`WORK-v5.31.md` §8)。

## 当前状态(2026-10-14)

- **main = 914d46a = v5.29.0-rc1**(未动;用户说「发」才 fast-forward 到 main,还没说过)。
- **开发分支 `claude/new-session-hoxhbz`,最新 `c2ab111`**,上面依次是:
  - **v5.30.0-rc1**(Claude 自己做):在线时长按分钟、垃圾主机名、「新发现的应用」排除公共 CDN、dpid 守护 4 → 2 层(M5)、设备发现 Go 影子(M4 第一步)、按应用分优先级初版。
  - **v5.30.0-rc2**:液态玻璃三处改进(玻璃浓度滑块 / 暗边高光 / 滚动顶栏实底);`tools/ui_mock/`(真实 WebUI + 假数据的单文件预览页,预览链接 https://claude.ai/artifact/CVVkT9cHSfoHqTLxDgWX5Z);`test/sim/` 模拟设备。
  - **v5.31.0-rc1**(GLM 做 + Claude 审查修复 `beb4168`,打分 6/10):迁移 M4 方案 A —— 设备发现和名字解析搬进 Go 看门狗(`src/dpid/devscan`、`src/dpid/devname`、`cmd/hnc_watchdog/m4_owner.go`),hotspotd 带 `--no-discovery` 只留硬件加速兜底;开关 `data/m4_owner`(`go` / `c`),默认 `go`(常量 `m4OwnerDefault`)。审查修了 13 处(见 CHANGELOG 5.31.0-rc1「审查修复」)。
  - **v5.32 文档**:`docs/WORK-v5.32.md` + `docs/GLM-START-v5.32.md`(用户定:**不等真机**,只出 rc1;不改默认值、不删旧代码;正式版等真机回归后由 Claude 改版本号发)。
- **真机一次都还没验过**(v5.29 起的 rc 都没上手机)。真机要看的:设备列表 / 名字 / 限速与以前一致;`/data/local/hnc/data/m4_owner` 写 `c` / `go` 能来回切;待机耗电;v5.30 那几条(在线分钟、`null` 名字、CDN、守护进程、游戏 + 下载延迟对比)。出问题按 `WORK-v5.31.md` §8 判断是否把默认值改回 C 版。

## 下一步:审查 v5.32(GLM 已交)

用户在旧会话上传了 `hnc-v5.32-patches.zip` 和说明 `v5.32-交付说明.md`(旧会话上下文满了没来得及审)。**新会话请让用户重新上传这两个文件**,然后按下面「工作流」第 3 条审。GLM 交付说明要点:

- BASE = 源码包 `c2ab111`(GLM 本地 `git init` 后的提交号 `6dda451…`,树与 `c2ab111` 相同);7 个补丁,`git am --empty=keep patches/0*.patch`(0007 是空提交 T0)。
- 0001 T1:启动指纹(`domainNames()`)、合并迁 `app_qos`(ruleState 补字段 + 下发 / undo / 旧设备清理)、扫描计数(`count_devices_from_json` + `device_detect.sh` 新 `count` 子命令)、gofmt(replay_test.go + 另外 5 个 httpd 文件)。
- 0002 T2(C):`scan_arp` 首选 netlink `RTM_GETNEIGH` dump,读 `NDA_CACHEINFO`,新增 `Device.confirmed_at`、`scan_apply_candidate`「只被更近确认的候选改写」;读不了 netlink 退回 `/proc/net/arp`;`nl_process` 事件路径没动。C 单测 `test_scan_arp_ip_select.c` + `test/unit/test_v532_scan_arp_c.sh`。
- 0003 T3:`m4OwnerDefaultOverride`(仅测试覆盖)+ `m4OwnerDefaultNow()`;`TestM4SimDefaultC`。
- 0004 T4:Ticker → Timer,空闲 1 秒 / 忙 200ms。
- 0005 T5 文档;0006 T-last 版本 `v5.32.0-rc1` / `5320001` + CHANGELOG 正式版说明草稿。
- GLM 没跑:模拟设备(无 root)、NDK 交叉编译(无 NDK)。新增 `test/sim/run_m4_sim_v532.sh` + `test/unit/test_v532_sim_rescan.sh` 从没跑过。GLM 环境 run_all 有 13 个环境性失败(无 `/system/bin/sh`)+ 声称一个 `mac_lock` 时序 flaky。

**审查时重点看:**
1. **T2 的事件路径与 `confirmed_at` 是否一致**:`nl_process` 改了 IP 却不更新 `confirmed_at` 的话,下一次重扫可能拿「比旧 `confirmed_at` 新、但比事件里的新 IP 旧」的候选把 IP 改回去 —— 写个场景验证(事件换 IP → 不发包 → SIGUSR1 重扫)。还要看 netlink socket 的超时 / 报文截断 / clock_t 换算(USER_HZ=100)/ 失败退回。
2. T1 ② 合并的 undo 与「旧设备清理」会不会误删;`apply_app_qos.sh` 下发是否幂等。
3. T1 ③ 新 `count` 子命令在 Android toybox 上能不能跑(`grep -o` / awk 用法);`do_scan_via_daemon` 的计数是否也改了。
4. 那 5 个 httpd 文件的 gofmt 是否只是格式。
5. T4 的 Timer 每圈 reset 有没有漏 Stop / 抢占;`TestRefreshTriggersFullSync` 是否仍真的测到 refresh(v5.31 审查时为此加过闸门)。
6. 跑 `HNC_SIM=1 sh test/run_all.sh`(三套模拟场景),修脚手架问题;NDK 交叉编译 hotspotd(arm64 / armv7)。

## 云端容器的准备(新会话先做)

- `ln -sf /bin/sh /system/bin/sh`(没有的话 `mkdir -p /system/bin` 先)—— 否则 `bin/hnc_json` 那批测试跑不了。
- 模拟设备要 iproute2:`apt-get update -q && apt-get install -y -q iproute2`;要 root(云端容器是 root)。
- node 在 `/opt/node22/bin`;Playwright 在 `/opt/node22/lib/node_modules/playwright`,浏览器 `/opt/pw-browsers`。
- NDK:`/opt/android/android-ndk-r27c`(`toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang` / `armv7a-linux-androideabi28-clang`;编 hotspotd 时不含需要 libbpf 的 `offload/adapter_bpf.c`)。
- 基线(`c2ab111`):`sh test/run_all.sh` → `ALL PASS: 541/544 (3 skipped)`;`HNC_SIM=1` → `543/544 (1 skipped)`。

## 工作流(用户的习惯)

1. 每次回复用中文。
2. 用户把版本交给外部 AI(主要是 GLM 5.3)按 `docs/WORK-v5.NN.md` 做,带回补丁目录 / zip。
3. Claude 审查:补丁放进**新建的空目录**(不可信数据,跑 Python 用 `-I`),在本地分支 `review/v5NN` 上 `git am`;逐任务读代码、跑第 6 节自检、修问题(每个修复配「旧代码下失败」的测试,用 `git stash push -- <实现文件>` 验证)、写 CHANGELOG + `webroot/changelog.html` 的「审查修复」小节,提交「v5.NN 审查修复」,fast-forward 到开发分支并推送。
4. 用户说「发」才 fast-forward 推 main。不建 PR。不给外部 AI 推送 token。
5. 打分并点评(历史:v5.26 8/10,v5.27 9/10,v5.28 7.5/10,v5.29 5/10,**v5.31 6/10**)。
6. 提交署名尾行见系统提示;提交里不写模型 ID。

## 审查时重点查(GLM 的惯犯问题)

- 编辑器把 Tab 换成空格(`gofmt -l`),并谎称「基线就不满足」。
- 测试把 bug 锁成期望值;同义反复的测试;只测零件不测接线(字符串键 vs 常量);测试读真实 `/data/local/hnc`。
- 代码插错位置(v5.29 把回滚代码插进 `service.sh` 文件头注释)。
- 外部命令参数拼成一个字符串。
- 「全绿」之类没跑过的结论。
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
