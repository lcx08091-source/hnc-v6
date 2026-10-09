# 给 GLM 的开工说明:HNC v5.31.0-rc1(迁移 M4 方案 A)

> 这份只讲「怎么拿代码、先读什么、怎么交活」。**要做什么、硬约束、测试纪律全在 `docs/WORK-v5.31.md`,两份冲突时以 WORK 为准。**

---

## 0. 粘贴给 GLM 的开场白(维护者直接复制这一段)

```
你是接手 HNC(Android 热点网络控制模块)v5.31 开发的 AI 编程助手。
代码:https://github.com/lcx08091-source/hnc-v6 ,分支 claude/new-session-hoxhbz
(拉不了 GitHub 就用我给你的源码包 hnc-v6-v5.30.0-rc2-src.zip)。

请先完整读完 docs/GLM-START-v5.31.md 和 docs/WORK-v5.31.md 再动手,
严格按 WORK 文档的任务优先级、第 2 节边界、第 3 节测试纪律执行。
全程用中文(回复、提交说明、注释)。
每个任务一个提交;每个修复都要有「改动前会失败」的测试,并在提交说明里写清怎么验证的;
提交说明里贴命令的实际输出,不要写没跑过的结论。
文档和代码对不上时以代码为准,在提交说明里写明;必须越过边界才能做的任务停下来说明,其余照做。
做完按 docs/GLM-START-v5.31.md 第 5 节打包交回,不要推 main。
```

---

## 1. 拿代码

```sh
git clone https://github.com/lcx08091-source/hnc-v6.git
cd hnc-v6
git checkout claude/new-session-hoxhbz     # v5.30.0-rc2 + 工作文档;main 还停在 v5.29,不要从 main 开工
git log --oneline -1                        # 应包含本文件(docs/GLM-START-v5.31.md)
git checkout -b ai/v5.31
BASE=$(git rev-parse HEAD); echo "$BASE"    # 记下来,交活时要写
```

**拉不了 GitHub**:用维护者给的 `hnc-v6-v5.30.0-rc2-src.zip`(`git archive` 打的,不带 `.git`):

```sh
mkdir hnc-v6 && cd hnc-v6 && unzip ../hnc-v6-v5.30.0-rc2-src.zip
git init -q && git add -A && git commit -qm "base: v5.30.0-rc2" && git checkout -b ai/v5.31
BASE=$(git rev-parse HEAD)
```

---

## 2. 先读什么(按顺序)

1. `docs/WORK-v5.31.md` 全文 —— 任务、§2 边界、§3 测试纪律、§8「有问题」的定义。
2. `docs/WORK-v5.30.md` §3(测试纪律 9 条)和 §6(自检命令)—— v5.31 原样沿用。
3. `docs/CODEMAP.md` 里设备发现 / hotspotd / 看门狗相关各节。
4. 模拟设备:`test/sim/simnet.sh`、`test/sim/run_m4_sim.sh` 的头注释,`src/dpid/cmd/hnc_watchdog/m4_sim_test.go`。
5. 现有 Go 侧:`src/dpid/neigh/neigh.go`、`src/dpid/cmd/hnc_watchdog/m4_shadow.go`、`main.go`(`hotspotdDaemon`)、`src/dpid/hostname/`。
6. 要搬的 C 侧:`daemon/hotspotd/hotspotd.c`(找设备、离线、写 `devices.json`、名字、控制接口)、`hnc_helpers.c`(DHCP 解析、厂商表、MAC 兜底)、`hostname_cache.c`;调用方 `bin/device_detect.sh`。

`CLAUDE.md` 是写给 Claude 会话的:里面的分支名不适用于你;「用中文」「每次改动 bump 版本 + 写 CHANGELOG / changelog.html」「改完跑静态校验」适用。**不要改 `CLAUDE.md`。**

---

## 3. 环境

- 需要:Go(版本见 `src/dpid/go.mod`、`daemon/hnc_httpd/go.mod`,**不要改这两个文件的 `go` 版本**)、gcc、python3、POSIX sh;改了 `webroot/` 才需要 node。
- **模拟设备**(本版主要验收手段)需要 Linux + root + iproute2 + 网络命名空间:
  ```sh
  sudo HNC_SIM=1 sh test/run_all.sh          # 或单跑:sudo bash test/sim/run_m4_sim.sh
  ```
  你的环境跑不了也没关系:场景照写、单测照写,提交说明写明「test/sim 未在本地跑」,审查时维护者在云端容器里跑。
- 维护者环境的基线:`sh test/run_all.sh` → `ALL PASS: 538/540 (2 skipped)`;`HNC_SIM=1` → `539/540 (1 skipped)`。你的环境可能不同,T0 记下你自己的。

---

## 4. 最容易做错的几条(WORK 里都有,这里再点一次)

1. **只能一个写者**:`devices.json` / `hostname_cache.json` 任何时刻只有 hotspotd、Go、`device_detect.sh` 的 shell 兜底三者之一在写;切换「先停后起」。
2. **默认值只写在一处、开关双向**(`data/m4_owner` 写 `go` / `c`);**名字解析(T2)没做完,默认值必须是 `c`**。
3. **不删 hotspotd 的发现代码,不动硬件加速兜底**(`scheduler.c` / `upstream.c` / `adapter_bpf.c` / `OFFLOAD_*`),只给 hotspotd 加 `--no-discovery`。
4. **在线语义不改**:离开后仍保留 90 秒再移出,和 hotspotd 一样。
5. **同一个 MAC 有两个 IP**(换 IP 后旧表项还在)要挑对:REACHABLE > DELAY > PROBE > STALE。
6. **与 C 版对照的测试比的是同一输入下两边的输出**,不是各自和一份手写期望比;场景期望来自场景本身,不许从被测程序的输出里抄。
7. 外部命令(`dumpsys`、`iptables_manager.sh`、`mdns_resolve`)参数分开传、带超时,不经 shell。
8. 所有改动的 Go 文件 `gofmt -l` 为空;编辑器不许把 Tab 换成空格。

---

## 5. 交活

```sh
git format-patch "$BASE"..ai/v5.31 -o patches/
# 写 patches/README.md,内容见下
zip -r hnc-v5.31-patches.zip patches/
```

`patches/README.md` 必须有:

1. `BASE` 的提交号(从源码包开工的写「源码包 v5.30.0-rc2」);
2. 每个任务(T0–T5、T-last):做了什么、没做什么、为什么;
3. 每个任务「改动前会失败」的证据(哪个测试、怎么验证的);
4. `docs/WORK-v5.31.md` §6 自检命令的**实际输出**(原样贴,不要改写成「全部通过」);
5. `test/sim` 跑没跑;跑了贴 `m4_sim_report.txt` 和新增场景的报告;
6. 默认值最后是 `go` 还是 `c`,为什么。

**不要推 main**;没有推送权限就只交 zip。把 `hnc-v5.31-patches.zip` 交给维护者,由 Claude 审查、修正后合入。

---

## 6. 之后

v5.31 审查合入、维护者真机装过之后,才轮到 `docs/WORK-v5.32.md`(收尾 + 正式版)。那份里有几处要维护者先填(真机反馈清单、退路结论),**现在不要开始做 v5.32**。
