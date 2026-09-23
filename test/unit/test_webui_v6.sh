#!/bin/sh
# v5.11: 新版 WebUI (webroot/index.html, "HNC WebUI v6") 的静态回归测试。
#   - 内联 JS 能被 node 解析
#   - 前端用到的每个 /api/action 动作名, 后端 dispatchAction 都有对应 case
#   - 前端请求的每个 /api/* 路径, 后端 server.go 都注册了路由
#   - 旧版已知 bug 不回归: 保存热点配置带 autostart / 配对链接用 ?prefill= /
#     curl 取 HTTP 状态码 / 告警拉黑走网关保护
set -u
ROOT="${HNC_TEST_ROOT:-$(cd "$(dirname "${HNC_TEST_FILE:-$0}")/../.." && pwd)}"
HTML="$ROOT/webroot/index.html"
ACTION_GO="$ROOT/daemon/hnc_httpd/action.go"
SERVER_GO="$ROOT/daemon/hnc_httpd/server.go"
fail=0
ok() { echo "[OK] $1"; }
bad() { echo "[FAIL] $1"; fail=1; }

[ -f "$HTML" ] || { echo "[FAIL] missing webroot/index.html"; exit 1; }
grep -q 'HNC WebUI v6' "$HTML" && ok "v6 marker present (httpd serves it to remote browsers)" || bad "v6 marker missing"
[ -f "$ROOT/webroot/hyalite.js" ] && ok "hyalite.js shipped" || bad "webroot/hyalite.js missing"
[ -f "$ROOT/webroot/LICENSE-hyalite" ] && ok "Hyalite license shipped" || bad "webroot/LICENSE-hyalite missing"
[ -f "$ROOT/webroot/classic.html" ] && ok "classic UI kept" || bad "webroot/classic.html missing"

if command -v node >/dev/null 2>&1; then
  TMP="${TMPDIR:-/tmp}/hnc_v6_inline.$$.js"
  node -e "
    const s=require('fs').readFileSync(process.argv[1],'utf8');
    const m=[...s.matchAll(/<script>([\s\S]*?)<\/script>/g)];
    require('fs').writeFileSync(process.argv[2], m.map(x=>x[1]).join('\n;\n'));
  " "$HTML" "$TMP"
  node --check "$TMP" 2>/dev/null && ok "inline JS parses" || bad "inline JS syntax error"
  rm -f "$TMP"
else
  echo "[SKIP] node not found"
fi

# 动作名对齐
missing=""
for a in $(grep -oE "api\.action\('[a-z_]+'" "$HTML" | sed "s/.*('//; s/'//" | sort -u) \
         $(grep -oE "\? '(candidate_promote|candidate_reject)'" "$HTML" | grep -oE "[a-z_]+" | sort -u); do
  grep -q "case \"$a\"" "$ACTION_GO" || grep -qE "case .*\"$a\"" "$ACTION_GO" || missing="$missing $a"
done
[ -z "$missing" ] && ok "all frontend actions exist in dispatchAction" || bad "actions missing in backend:$missing"

# 路由对齐
missing=""
for p in $(grep -oE "api\.(get|getSafe|post)\(./api/[a-z_/]+" "$HTML" | sed "s/.*(.//" | grep -v "/$" | sort -u); do
  grep -q "\"$p\"" "$SERVER_GO" || missing="$missing $p"
done
for p in $(grep -oE "api\.post\('/api/self/' \+ path" "$HTML" >/dev/null && echo /api/self/toggle /api/self/auto_expand/toggle /api/self/auto_promote/toggle); do
  grep -q "\"$p\"" "$SERVER_GO" || missing="$missing $p"
done
[ -z "$missing" ] && ok "all frontend API paths are registered" || bad "routes missing in backend:$missing"

# 旧版 bug 不回归
grep -q "autostart: S.cfg.hotspot_autostart === true" "$HTML" && ok "hotspot_save keeps autostart" || bad "hotspot_save may drop autostart"
grep -q "/pair?prefill=" "$HTML" && ok "pair link uses ?prefill=" || bad "pair link not using ?prefill="
grep -q "__HNC_HTTP__%{http_code}" "$HTML" && ok "bridge curl reads HTTP status" || bad "bridge curl ignores HTTP status"
grep -q "return blockDevice(d)" "$HTML" && ok "alert block goes through gateway guard" || bad "alert block bypasses gateway guard"
grep -q "paintOnlineHours()" "$HTML" && ok "online hours painted after render" || bad "online hours never painted"

exit $fail
