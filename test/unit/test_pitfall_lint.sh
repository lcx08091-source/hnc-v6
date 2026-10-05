#!/system/bin/sh
# test_pitfall_lint.sh — v5.28 A4: 老坑 lint 每条规则都能报出、白名单生效、
# 当前仓库 0 新增违规。测的是行为: 在临时目录造违规文件, 真跑 bin/pitfall_lint.sh。

HNC_REPO_ROOT="${HNC_REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
LINT="$HNC_REPO_ROOT/bin/pitfall_lint.sh"

# test_start 会 rm -rf $HNC_TEST_DIR, 假仓库放旁边
FAKE="${HNC_TEST_DIR}-lint"

# mkfake <name>: 建一个干净的假仓库骨架(lint 认根 = 有 service.sh)
mkfake() {
    rm -rf "$FAKE"
    mkdir -p "$FAKE/bin" "$FAKE/src/dpid/cmd/dpid" "$FAKE/src/dpid/cmd/hnc_watchdog" \
             "$FAKE/src/dpid/alert" "$FAKE/daemon/hnc_httpd"
    : > "$FAKE/service.sh"
}
# run_lint: 对假仓库跑 lint, 返回退出码; 输出留在 $FAKE.out
run_lint() {
    sh "$LINT" "$FAKE" > "$FAKE.out" 2>&1
    return $?
}

test_start "P1: main 包用 time.Now 而无 tzlocal.Location → 报违规"
mkfake
cat > "$FAKE/src/dpid/cmd/dpid/main.go" <<'EOF'
package main

import "time"

func main() { _ = time.Now() }
EOF
run_lint
rc=$?
[ "$rc" -eq 1 ] && grep -q 'dpid/main.go:P1' "$FAKE.out" && test_pass || test_fail "rc=$rc, out=$(cat "$FAKE.out")"

test_start "P1: 有 tzlocal.Location → 干净"
mkfake
cat > "$FAKE/src/dpid/cmd/dpid/main.go" <<'EOF'
package main

import (
    "time"

    "hnc.io/dpid/tzlocal"
)

func main() { time.Local = tzlocal.Location(); _ = time.Now() }
EOF
run_lint
rc=$?
[ "$rc" -eq 0 ] && test_pass || test_fail "rc=$rc, out=$(cat "$FAKE.out")"

test_start "P2: bin/*.sh 里 BRE \\| → 报违规"
mkfake
printf 'if grep -q "a\\|b" f; then :; fi\n' > "$FAKE/bin/new_thing.sh"
run_lint
rc=$?
[ "$rc" -eq 1 ] && grep -q 'new_thing.sh:P2' "$FAKE.out" && test_pass || test_fail "rc=$rc, out=$(cat "$FAKE.out")"

test_start "P3: Go 里 exec.Command(\"ps\") → 报违规"
mkfake
cat > "$FAKE/src/dpid/cmd/dpid/probe.go" <<'EOF'
package main

import "os/exec"

func bad() { _ = exec.Command("ps") }
EOF
run_lint
rc=$?
[ "$rc" -eq 1 ] && grep -q 'probe.go:P3' "$FAKE.out" && test_pass || test_fail "rc=$rc, out=$(cat "$FAKE.out")"

test_start "P3: shell 里 ps -ef | grep → 报违规"
mkfake
printf 'ps -ef 2>/dev/null | grep hnc_watchdog\n' > "$FAKE/bin/new_thing.sh"
run_lint
rc=$?
[ "$rc" -eq 1 ] && grep -q 'new_thing.sh:P3' "$FAKE.out" && test_pass || test_fail "rc=$rc, out=$(cat "$FAKE.out")"

test_start "P3: ps -ef | awk 兜底不算违规(A3 保留的兜底形态)"
mkfake
printf 'ps -ef 2>/dev/null | awk \x27{print $2}\x27\n' > "$FAKE/bin/new_thing.sh"
run_lint
rc=$?
[ "$rc" -eq 0 ] && test_pass || test_fail "rc=$rc, out=$(cat "$FAKE.out")"

test_start "P4: alert 包之外直接写 alerts.jsonl → 报违规"
mkfake
cat > "$FAKE/daemon/hnc_httpd/bad_alert.go" <<'EOF'
package main

import "os"

func bad() {
    f, _ := os.OpenFile("run/alerts.jsonl", os.O_APPEND, 0o644)
    _ = f
}
EOF
run_lint
rc=$?
[ "$rc" -eq 1 ] && grep -q 'bad_alert.go:P4' "$FAKE.out" && test_pass || test_fail "rc=$rc, out=$(cat "$FAKE.out")"

test_start "P4: alert 包内部的 alerts.jsonl → 干净"
mkfake
cat > "$FAKE/src/dpid/alert/append.go" <<'EOF'
package alert

import "os"

func Append() {
    f, _ := os.OpenFile("run/alerts.jsonl", os.O_APPEND, 0o644)
    _ = f
}
EOF
run_lint
rc=$?
[ "$rc" -eq 0 ] && test_pass || test_fail "rc=$rc, out=$(cat "$FAKE.out")"

test_start "P5: json_escape 的 sed 用 \\t 转义而非字面 Tab → 报违规"
mkfake
cat > "$FAKE/bin/new_json.sh" <<'EOF'
json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r/ /g; s/\n/ /g; s/\t/ /g'
}
EOF
run_lint
rc=$?
[ "$rc" -eq 1 ] && grep -q 'new_json.sh:P5' "$FAKE.out" && test_pass || test_fail "rc=$rc, out=$(cat "$FAKE.out")"

test_start "P5: sed 用真 Tab → 干净"
mkfake
printf 'json_escape() {\n  printf \x27%%s\x27 "$1" | sed \x27s/\\\\/\\\\\\\\/g; s/\t/ /g\x27\n}\n' > "$FAKE/bin/new_json.sh"
run_lint
rc=$?
[ "$rc" -eq 0 ] && test_pass || test_fail "rc=$rc, out=$(cat "$FAKE.out")"

test_start "白名单: 命中 bin/pitfall_lint.allow 的存量 → 放行"
mkfake
printf 'if grep -q "a\\|b" f; then :; fi\n' > "$FAKE/bin/legacy.sh"
printf 'bin/legacy.sh:P2:存量: 真机已验证, 修它要单独回归\n' > "$FAKE/bin/pitfall_lint.allow"
run_lint
rc=$?
[ "$rc" -eq 0 ] && test_pass || test_fail "rc=$rc, out=$(cat "$FAKE.out")"

test_start "白名单只放行存量: 同文件新增另一条规则(P3)照样失败"
printf 'ps -ef 2>/dev/null | grep hnc\n' >> "$FAKE/bin/legacy.sh"
run_lint
rc=$?
[ "$rc" -eq 1 ] && grep -q 'legacy.sh:P3' "$FAKE.out" && test_pass || test_fail "rc=$rc, out=$(cat "$FAKE.out")"

test_start "当前仓库: 0 新增违规(exit 0)"
sh "$LINT" > "${FAKE}.repo.out" 2>&1
rc=$?
[ "$rc" -eq 0 ] && test_pass || test_fail "rc=$rc, out=$(cat "${FAKE}.repo.out")"

rm -rf "$FAKE" "${FAKE}.out" "${FAKE}.repo.out"
