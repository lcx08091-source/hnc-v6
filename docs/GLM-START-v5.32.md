# 给 GLM 的开工说明:HNC v5.32.0-rc1(收尾 + 正式版候选)

> 这份只讲「怎么拿代码、先读什么、怎么交活」。**要做什么、硬约束、测试纪律全在 `docs/WORK-v5.32.md`,两份冲突时以 WORK 为准。**

---

## 0. 粘贴给 GLM 的开场白(维护者直接复制这一段)

```
你是接手 HNC(Android 热点网络控制模块)v5.32 开发的 AI 编程助手。
代码:https://github.com/lcx08091-source/hnc-v6 ,分支 claude/new-session-hoxhbz
(拉不了 GitHub 就用我给你的源码包)。

请先完整读完 docs/GLM-START-v5.32.md 和 docs/WORK-v5.32.md 再动手,
严格按 WORK 文档的任务优先级、第 2 节边界、第 3 节测试纪律执行。
特别注意 WORK 第 1.3 节「v5.31 审查里出过的错」—— 上一版这些错一共 13 处, 本版不许再犯。
全程用中文(回复、提交说明、注释)。
每个任务一个提交;每个修复都要有「改动前会失败」的测试,并在提交说明里写清怎么验证的;
提交说明里贴命令的实际输出,不要写没跑过的结论。
本版不改设备发现的默认值、不删旧代码、不发正式版。
文档和代码对不上时以代码为准,在提交说明里写明;必须越过边界才能做的任务停下来说明,其余照做。
做完按 docs/GLM-START-v5.32.md 第 5 节打包交回,不要推 main。
```

---

## 1. 拿代码

```sh
git clone https://github.com/lcx08091-source/hnc-v6.git
cd hnc-v6
git checkout claude/new-session-hoxhbz     # v5.31.0-rc1 + 审查修复 + 本文件;main 还停在 v5.29,不要从 main 开工
git log --oneline -1                        # 应包含本文件(docs/GLM-START-v5.32.md)
git checkout -b ai/v5.32
BASE=$(git rev-parse HEAD); echo "$BASE"    # 记下来,交活时要写
```

**拉不了 GitHub**:用维护者给的源码包(GitHub 按提交打的 zip,不带 `.git`):

```sh
unzip hnc-v6-<提交号>.zip && cd hnc-v6-<提交号>
git init -q && git add -A && git commit -qm "base: v5.31.0-rc1 + 审查修复" && git checkout -b ai/v5.32
BASE=$(git rev-parse HEAD)
```
交活时 README 里写明「基于源码包 <提交号>」。

---

## 2. 先读什么(按顺序)

1. `docs/WORK-v5.32.md` 全文 —— 任务、§1.3「v5.31 审查里出过的错」、§2 边界、§3 测试纪律。
2. `docs/WORK-v5.30.md` §3(测试纪律 9 条)与 §6(自检命令);`docs/WORK-v5.31.md` §3(第 10、11 条)、§6、§8(「有问题」的定义)。
3. `CHANGELOG.md` 的 5.31.0-rc1 一节,尤其「审查修复」—— 每一条都是上一版真实出过的错。
4. 按任务读代码:
   - T1:`daemon/hnc_httpd/api_discover_suggest.go`(约 244 行)、`api_discover.go`(`strList` / `firstHost`)、`mac_merge_action.go`(`deviceMerge`)、`bin/device_detect.sh`(约 166 行)。
   - T2:`daemon/hotspotd/hotspotd.c`(`scan_arp`、`nl_process`)、`src/dpid/neigh/neigh.go`(netlink 邻居表与 `NDA_CACHEINFO` 的解析,可参照)、`daemon/hotspotd/test/test_no_discovery.c` + `test/unit/test_v531_no_discovery_c.sh`(C 单测怎么写、怎么接进 `run_all`)。
   - T3:`src/dpid/cmd/hnc_watchdog/m4_owner.go`(`m4OwnerDefault`、`tick`、`reconcileLocked`)、`m4_owner_review_test.go`、`m4_sim_v531_test.go`(`TestM4SimOwner`)、`test/sim/run_m4_sim_v531.sh`。
   - T4:`m4_owner.go` 的 `run()` 主循环。

`CLAUDE.md` 是写给 Claude 会话的:里面的分支名不适用于你;「用中文」「每次改动 bump 版本 + 写 CHANGELOG / changelog.html」「改完跑静态校验」适用。**不要改 `CLAUDE.md`。**

---

## 3. 环境

- 需要:Go(版本见 `src/dpid/go.mod`、`daemon/hnc_httpd/go.mod`,**不要改这两个文件的 `go` 版本**)、gcc、python3、POSIX sh;改了 `webroot/` 才需要 node。
- **模拟设备**需要 Linux + root + iproute2 + 网络 / 挂载命名空间:
  ```sh
  sudo HNC_SIM=1 sh test/run_all.sh          # 或单跑 sudo bash test/sim/run_m4_sim_v531.sh
  ```
  跑不了:场景照写、单测照写,提交说明写明「test/sim 未在本地跑」,审查时 Claude 在云端容器里跑。
- 有 NDK 就按 `.github/workflows/build.yml` 交叉编译 hotspotd;没有就写明(审查时 Claude 用 NDK 编)。
- 维护者环境基线:`sh test/run_all.sh` → `ALL PASS: 541/544 (3 skipped)`;`HNC_SIM=1` → `543/544 (1 skipped)`。你的环境不同的话(比如没有 `/system/bin/sh` 导致 `bin/hnc_json` 那批测试跑不了),T0 记下你自己的,并说明原因。

---

## 4. 最容易做错的几条(WORK 里都有,这里再点一次)

1. **不改 `m4OwnerDefault` 的值、不删任何旧代码**(shell guard / Go supervisor / hotspotd 的发现代码)。T3 只是让默认值「在测试里可替换」,生产代码里默认值仍只写在一处、仍是 `go`。
2. **异步结果要通知主循环**,停组件要等它的后台 goroutine 结束(v5.31 的两处严重错误)。
3. **不改用户数据**:比较时折叠大小写,取值用原文。
4. **判断进程活着用 `processAlive` / `findLiveByName`**,不要自己 `kill(pid, 0)`(僵尸会被当成活着)。
5. **模拟设备场景必须真的经过被测代码**(v5.31 的切换场景是脚本自己停起 hotspotd,检查恒为真)。每个新场景写一条「还原实现后它失败」的证据。
6. **测试不改仓库文件、不碰真实的 `/data/local/hnc`**,路径变量测试结束要恢复。
7. C 改动只在 T2 范围(`scan_arp` 及其直接调用的函数),硬件加速兜底不动;外部命令参数分开传、带超时。
8. 所有改动的 Go 文件 `gofmt -l` 为空;编辑器不许把 Tab 换成空格。

---

## 5. 交活

```sh
git format-patch "$BASE"..ai/v5.32 -o patches/
# 写 patches/README.md,内容见下
zip -r hnc-v5.32-patches.zip patches/
```

`patches/README.md` 必须有:

1. `BASE` 的提交号(从源码包开工的写「源码包 <提交号>」);
2. 每个任务(T0–T5、T-last):做了什么、没做什么、为什么;
3. 每个任务「改动前会失败」的证据(哪个测试、怎么验证的);模拟设备场景另写「还原实现后场景失败」的证据(或写明没跑);
4. `docs/WORK-v5.32.md` §6 自检命令的**实际输出**(原样贴,不要改写成「全部通过」);
5. `test/sim` 跑没跑;跑了贴报告;
6. C 改动有没有交叉编译。

**不要推 main**;没有推送权限就只交 zip。把 `hnc-v5.32-patches.zip` 交给维护者,由 Claude 审查、修正后合入。
