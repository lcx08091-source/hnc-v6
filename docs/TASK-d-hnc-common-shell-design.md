# TASK-d: `bin/hnc_common.sh` 公共 shell 库设计稿

<!-- rc30.12.34 (TASK-d): GPT 一审 P2.14 收口 -->

**类型**: 设计稿(Stage 1, 0 代码改动)
**基线**: HNC v5.3.0-rc30.12.33
**生效状态**: **本文档仅为设计稿**. 实际抽公共库要等 Stage 2 真做时.

---

## 背景

GPT 一审报告 P2.14:

> 每个 shell 自己写 `log()`,格式不统一. 抽 `bin/hnc_common.sh` 提供
> `log`、`log_error`、`sq`(shell quote)、`json_get_top` 等基础函数,
> 所有脚本 `. /data/local/hnc/bin/hnc_common.sh`。能省好几千行重复代码。

## 当前现状(rc30.12.33)

**22 个脚本**各自实现 `log()`. 抽样对比 8 个:

| 脚本 | log() 实现 | 时间戳格式 | 自带前缀 | mkdir | err 静默 |
|---|---|---|---|---|---|
| apply_app_limits | `echo "[time] $*" >> $LOG` | `%Y-%m-%d %H:%M:%S` | 无 | 无 | 无 |
| apply_device_rule | `mkdir -p + echo` | `%H:%M:%S` | `[APPLY]` | 是 | `\|\| true` |
| capability_probe | `echo` (无重定向 → stdout) | `%Y-%m-%d %H:%M:%S` | `[CAP]` | 无 | 无 |
| cleanup | `echo >> $LOG` | `TZ=Asia/Shanghai %H:%M:%S` | `[CLEANUP]` | 无 | 无 |
| cleanup_offline_devices | `mkdir -p + echo` | `%Y-%m-%d %H:%M:%S` | 无 | 是 | `\|\| true` |
| cleanup_stale_rules | 同上 | 同上 | 无 | 是 | `\|\| true` |
| device_detect | 同 apply_device_rule | `TZ=... %H:%M:%S` | `[DETECT]` | 是 | `\|\| true` |
| dpi_rebind | `echo >> $LOG \|\| true` | `%Y-%m-%d %H:%M:%S` | `[DPI-REBIND]` | 无 | `\|\| true` |

**离散度**:
- **时间戳格式 4 种**:有/无 TZ,有/无年月日
- **前缀 6 种**:无 / `[APPLY]` / `[CAP]` / `[CLEANUP]` / `[DETECT]` / `[DPI-REBIND]`
- **mkdir 行为 2 种**:做/不做
- **错误处理 2 种**:静默 / 不静默
- **输出目标 2 种**:stdout / 文件

**实际重复行数估算**: 每个脚本 1-5 行 log() impl, 22 个脚本 = **~60 行重复**.
不算 "几千行" (GPT 报告里数字偏激), 但仍值得收口.

## 设计目标

抽出 `bin/hnc_common.sh` 提供:

1. `hnc_log <msg>` — 标准 log, 时间戳 + 前缀(从 `HNC_LOG_TAG` 环境变量取)
2. `hnc_log_error <msg>` — 同上但写 stderr 且加 `[ERROR]` 标
3. `hnc_log_init <path>` — 初始化 LOG 路径, 自动 mkdir, 自动 rotate >256KB
4. `hnc_sq <str>` — shell quote 安全拼接 (防 shell injection)
5. `hnc_json_get_top <file> <key>` — 顶层 JSON key 读取(替代多处独立 sed)
6. `hnc_run_dir`, `hnc_etc_dir`, `hnc_logs_dir` — 路径常量 helper

**关键约束**: 必须在 `mksh` (Android `/system/bin/sh`) 上跑, 不能用
bash-only 特性 (`[[ ]]` / array / process substitution).

## 推荐 API

### `hnc_common.sh` 接口草案

```sh
#!/system/bin/sh
# bin/hnc_common.sh — HNC 公共 shell 函数库 (since v5.3.x)
#
# 用法: 在脚本顶部加:
#   . /data/local/hnc/bin/hnc_common.sh
#   hnc_log_init "/data/local/hnc/logs/myscript.log" "MYSCRIPT"
#   hnc_log "started"
#
# 兼容: Android /system/bin/sh (mksh) + BusyBox sh. 不依赖 bash.

# ─── 路径常量 ─────────────────────────────────────────────
HNC_DIR="${HNC_DIR:-/data/local/hnc}"
HNC_BIN="$HNC_DIR/bin"
HNC_ETC="$HNC_DIR/etc"
HNC_RUN="$HNC_DIR/run"
HNC_LOGS="$HNC_DIR/logs"
HNC_DATA="$HNC_DIR/data"

# ─── 日志 ────────────────────────────────────────────────
# 内部状态 (调用 hnc_log_init 后设置)
_HNC_LOG_PATH=""
_HNC_LOG_TAG=""
_HNC_LOG_ROTATE_BYTES=262144  # 256 KB

hnc_log_init() {
    # $1 = 日志路径; $2 = 可选 tag 前缀 (例: "APPLY")
    _HNC_LOG_PATH="$1"
    _HNC_LOG_TAG="${2:-}"
    mkdir -p "$(dirname "$_HNC_LOG_PATH")" 2>/dev/null

    # rotate 大文件 (>256 KB)
    if [ -f "$_HNC_LOG_PATH" ]; then
        sz=$(stat -c %s "$_HNC_LOG_PATH" 2>/dev/null || echo 0)
        if [ "$sz" -gt "$_HNC_LOG_ROTATE_BYTES" ]; then
            mv "$_HNC_LOG_PATH" "${_HNC_LOG_PATH}.1" 2>/dev/null
        fi
    fi
}

hnc_log() {
    if [ -z "$_HNC_LOG_PATH" ]; then
        # 没 init, 走 stdout (兼容 capability_probe 这种探针用例)
        echo "[$(date '+%Y-%m-%d %H:%M:%S')]${_HNC_LOG_TAG:+ [$_HNC_LOG_TAG]} $*"
        return
    fi
    if [ -n "$_HNC_LOG_TAG" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$_HNC_LOG_TAG] $*" >> "$_HNC_LOG_PATH" 2>/dev/null || true
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$_HNC_LOG_PATH" 2>/dev/null || true
    fi
}

hnc_log_error() {
    if [ -n "$_HNC_LOG_TAG" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$_HNC_LOG_TAG] [ERROR] $*" | tee -a "$_HNC_LOG_PATH" >&2
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" | tee -a "$_HNC_LOG_PATH" >&2
    fi
}

# ─── shell quote ─────────────────────────────────────────
# 用于安全拼接 sh -c "$(...)" 之类的命令字符串. 把单引号转义.
hnc_sq() {
    # 替换 ' → '\'' (mksh 兼容)
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

# ─── JSON 顶层 key 读取 ─────────────────────────────────
# 用法: hnc_json_get_top devices.json hotspot_iface
# 局限: 只读顶层 key, 不支持嵌套. 嵌套用 jq (如果有).
hnc_json_get_top() {
    file="$1"; key="$2"
    [ -r "$file" ] || return 1
    sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$file" 2>/dev/null | head -1
}

# ─── 锁文件 (singleton 模式) ──────────────────────────────
# 简单锁, 不防止 TOCTOU. 适合 cron-like 防重入. 不适合互斥共享资源.
hnc_lock_acquire() {
    lockfile="$1"
    if [ -f "$lockfile" ]; then
        old_pid=$(cat "$lockfile" 2>/dev/null)
        if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
            return 1  # 已有活跃进程
        fi
    fi
    echo $$ > "$lockfile"
    return 0
}

hnc_lock_release() {
    rm -f "$1" 2>/dev/null
}
```

## 迁移路径(分阶段)

跟 TASK-a 一样用三阶段安全切换, 不要一次性改 22 个脚本.

### Stage 1 (本设计稿): 文档 + API 评审

仅设计稿, 0 代码改动. Ling 看完点头才进 Stage 2.

### Stage 2: 添加 hnc_common.sh 文件

- 新建 `bin/hnc_common.sh` (上面草案的实现)
- 加 unit test: `test/unit/test_hnc_common.sh` 覆盖 5 个函数行为
- **不动任何现有脚本**. 22 个脚本各自 log() 不变.
- 风险: 极低 (只是加文件)
- 装机验证: `ls /data/local/hnc/bin/hnc_common.sh` 存在 + service.sh 启动正常

### Stage 3: 逐个脚本迁移 (每脚本独立 commit)

- 优先级 1 (最简单): `cleanup_offline_devices.sh` / `cleanup_stale_rules.sh`
  这两个 log() 实现完全一致, 改动最稳
- 优先级 2: `apply_app_limits.sh`, `dpi_rebind.sh`, `dpi_rules_import.sh`
- 优先级 3 (大脚本): `apply_device_rule.sh` (472 行)
- 优先级 4 (探针脚本): `capability_probe.sh` (输出 stdout 用例特殊)

每个脚本迁移:
```sh
# rc30.12.X (TASK-d Stage 3): 改用 hnc_common.sh
. "$(dirname "$0")/hnc_common.sh"
hnc_log_init "$HNC_LOGS/myscript.log" "MYTAG"
# 删除本地 log() 函数定义
# 调用方 log "msg" → 改成 hnc_log "msg"
```

风险: 中. 每个脚本独立 commit + 装机验证. 一次最多迁 3 个脚本.

### Stage 4: 永不删

`hnc_common.sh` 永远是核心, 不删. 跟 dpi_rules.json 派生产物模式一样
(TASK-a v2 锁定).

## 不在本任务范围

- **shell-> Go/C 重写** (GPT 一审 P2.15): 是更大的话题, 跟本任务无关
- **替换 jq / sed 等外部命令**: hnc_common 提供 thin wrapper 即可, 不重写 jq
- **加 i18n 支持**: 现在所有日志中英文混杂, 不在收口范围

## 风险评估

| 风险点 | 严重度 | 缓解 |
|---|---|---|
| `mksh` 兼容性: `printf` / `sed` 行为差异 | 低 | 草案用最保守 POSIX 子集. 测试 fixture 用 `/system/bin/sh` 跑 |
| `. hnc_common.sh` 在 PATH 不存在时静默失败 | 中 | 加 sourceguard: `[ -r "$_HNC_COMMON" ] || { echo "FATAL: hnc_common.sh missing"; exit 1; }` |
| 迁移期间新旧两套 log() 并存 | 低 | 三阶段切换, 每脚本独立验证 |
| service.sh 启动顺序: `.` source 必须在所有调用前 | 低 | 在每个脚本第一行 source, 跟现有 `set -e` 风格一致 |

## 验收

1. `bin/hnc_common.sh` 存在并 `sh -n` 通过
2. 5 个 API 函数 unit test 覆盖率 100%
3. 装机后 `. /data/local/hnc/bin/hnc_common.sh && hnc_log "test"` 写日志到默认路径
4. **Stage 2 不动任何现有脚本** — 这是设计稿验收的硬要求

---

**End of TASK-d v1 设计稿**. Ling 看完点头 → Stage 2 添加 hnc_common.sh
(单文件 commit, 大概 80 行 shell + 一份 unit test).
