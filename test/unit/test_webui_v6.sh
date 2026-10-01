#!/bin/sh
# v5.11: 新版 WebUI (webroot/index.html, "HNC WebUI v6") 的静态回归测试。
#   - 内联 JS 与 webroot/js/*.js 都能被 node 解析
#   - 前端用到的每个 /api/action 动作名, 后端 dispatchAction 都有对应 case
#   - 前端请求的每个 /api/* 路径, 后端 server.go 都注册了路由
#   - 旧版已知 bug 不回归: 保存热点配置带 autostart / 配对链接用 ?prefill= /
#     curl 取 HTTP 状态码 / 告警拉黑走网关保护
# v5.22: 页面拆成 index.html + css/*.css + js/*.js —— 内容类检查对三者拼接后的
#   $SRC 做(webui_src 按 index.html 的引用顺序拼); 另查每个引用文件存在、
#   httpd 登记了路由、CI 必需文件清单里有它。
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
[ ! -e "$ROOT/webroot/classic.html" ] && ok "classic UI removed" || bad "webroot/classic.html should be gone"

# index.html 引用的样式/脚本(相对路径, 按出现顺序; 不含 hyalite.js)
ASSETS=$(grep -oE '<(link rel="stylesheet" href|script src)="(css|js)/[^"]+"' "$HTML" | sed 's/.*="//; s/"$//')
[ -n "$ASSETS" ] && ok "index.html references split css/js" || bad "index.html references no css/js assets"
SRC="${TMPDIR:-/tmp}/hnc_v6_src.$$.txt"
trap 'rm -f "$SRC"' EXIT
cat "$HTML" > "$SRC"
missing=""; unrouted=""; unlisted=""
for a in $ASSETS; do
  case "$a" in /*|*..*|*://*) bad "asset path must be relative: $a"; continue ;; esac
  if [ -f "$ROOT/webroot/$a" ]; then cat "$ROOT/webroot/$a" >> "$SRC"; else missing="$missing $a"; fi
  grep -q "\"$a\"" "$SERVER_GO" || unrouted="$unrouted $a"
  for gate in bin/artifact_sanity_check.sh bin/ci_preflight.sh; do
    grep -q "webroot/$a" "$ROOT/$gate" || unlisted="$unlisted $gate:$a"
  done
done
[ -z "$missing" ] && ok "all referenced css/js exist" || bad "referenced but missing:$missing"
[ -z "$unrouted" ] && ok "httpd webuiAssets lists every css/js" || bad "not in server.go webuiAssets:$unrouted"
[ -z "$unlisted" ] && ok "CI required-file lists include every css/js" || bad "missing from CI lists:$unlisted"
extra=""
for f in "$ROOT"/webroot/css/*.css "$ROOT"/webroot/js/*.js; do
  [ -f "$f" ] || continue
  rel="${f#"$ROOT"/webroot/}"
  echo "$ASSETS" | grep -qx "$rel" || extra="$extra $rel"
done
[ -z "$extra" ] && ok "no orphan css/js under webroot" || bad "css/js not referenced by index.html:$extra"

if command -v node >/dev/null 2>&1; then
  TMP="${TMPDIR:-/tmp}/hnc_v6_inline.$$.js"
  node -e "
    const s=require('fs').readFileSync(process.argv[1],'utf8');
    const m=[...s.matchAll(/<script>([\s\S]*?)<\/script>/g)];
    require('fs').writeFileSync(process.argv[2], m.map(x=>x[1]).join('\n;\n'));
  " "$HTML" "$TMP"
  node --check "$TMP" 2>/dev/null && ok "inline JS parses" || bad "inline JS syntax error"
  rm -f "$TMP"
  perr=""
  for a in $ASSETS; do
    case "$a" in *.js) node --check "$ROOT/webroot/$a" 2>/dev/null || perr="$perr $a" ;; esac
  done
  [ -z "$perr" ] && ok "webroot/js/*.js parse" || bad "JS syntax error:$perr"
else
  echo "[SKIP] node not found"
fi

# 动作名对齐
missing=""
for a in $(grep -oE "api\.action\('[a-z_]+'" "$SRC" | sed "s/.*('//; s/'//" | sort -u) \
         $(grep -oE "\? '(candidate_promote|candidate_reject)'" "$SRC" | grep -oE "[a-z_]+" | sort -u); do
  grep -q "case \"$a\"" "$ACTION_GO" || grep -qE "case .*\"$a\"" "$ACTION_GO" || missing="$missing $a"
done
[ -z "$missing" ] && ok "all frontend actions exist in dispatchAction" || bad "actions missing in backend:$missing"

# 路由对齐
missing=""
for p in $(grep -oE "api\.(get|getSafe|post)\(./api/[a-z_/]+" "$SRC" | sed "s/.*(.//" | grep -v "/$" | sort -u); do
  grep -q "\"$p\"" "$SERVER_GO" || missing="$missing $p"
done
for p in $(grep -oE "api\.post\('/api/self/' \+ path" "$SRC" >/dev/null && echo /api/self/toggle /api/self/auto_expand/toggle /api/self/auto_promote/toggle); do
  grep -q "\"$p\"" "$SERVER_GO" || missing="$missing $p"
done
[ -z "$missing" ] && ok "all frontend API paths are registered" || bad "routes missing in backend:$missing"

# 旧版 bug 不回归
grep -q "autostart: S.cfg.hotspot_autostart === true" "$SRC" && ok "hotspot_save keeps autostart" || bad "hotspot_save may drop autostart"
grep -q "/pair?prefill=" "$SRC" && ok "pair link uses ?prefill=" || bad "pair link not using ?prefill="
grep -q "__HNC_HTTP__%{http_code}" "$SRC" && ok "bridge curl reads HTTP status" || bad "bridge curl ignores HTTP status"
grep -q "return blockDevice(d)" "$SRC" && ok "alert block goes through gateway guard" || bad "alert block bypasses gateway guard"
grep -q "paintOnlineHours()" "$SRC" && ok "online hours painted after render" || bad "online hours never painted"

exit $fail
