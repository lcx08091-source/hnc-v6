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
[ -f "$ROOT/webroot/hyalite.js" ] || [ -f "$ROOT/webroot/js/vendor/hyalite.js" ] && ok "hyalite.js shipped" || bad "hyalite.js missing"
[ -f "$ROOT/webroot/LICENSE-hyalite" ] && ok "Hyalite license shipped" || bad "webroot/LICENSE-hyalite missing"
[ ! -e "$ROOT/webroot/classic.html" ] && ok "classic UI removed" || bad "webroot/classic.html should be gone"

# index.html 引用的样式/脚本(相对路径, 按出现顺序; 不含顶层 hyalite.js)
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
  # 1. 全量独立 .js 语法校验: 含 webroot/js/*.js、webroot/hyalite.js、webroot/js/vendor/hyalite.js 及 tools/ui_mock/fake_api.js
  js_err=""
  js_cnt=0
  for jsf in $(find "$ROOT/webroot" "$ROOT/tools/ui_mock" -type f -name '*.js' 2>/dev/null | sort); do
    [ -f "$jsf" ] || continue
    js_cnt=$((js_cnt + 1))
    rel_js="${jsf#"$ROOT"/}"
    node --check "$jsf" 2>/dev/null || js_err="$js_err $rel_js"
  done
  if [ "$js_cnt" -gt 0 ] && [ -z "$js_err" ]; then
    ok "all $js_cnt standalone .js files parse (webroot + vendor/hyalite + tools/ui_mock)"
  else
    bad "standalone .js syntax error (checked=$js_cnt):${js_err:- none found}"
  fi

  # 2. 全量 HTML 内联 <script> 逐块语法校验 (覆盖 webroot/*.html 与嵌入页 daemon/hnc_httpd/web/*.html, 排除 type=application/json 等非 JS 块)
  [ -f "$ROOT/webroot/json-health.html" ] || bad "webroot/json-health.html missing"
  [ -f "$ROOT/webroot/pair.html" ] || [ -f "$ROOT/daemon/hnc_httpd/web/pair.html" ] || bad "pair.html missing"
  TMP_INL_DIR="${TMPDIR:-/tmp}/hnc_v6_inline_blocks.$$"
  rm -rf "$TMP_INL_DIR" 2>/dev/null || true
  mkdir -p "$TMP_INL_DIR"
  html_err=""
  inline_total=0
  for hf in "$ROOT"/webroot/*.html "$ROOT"/daemon/hnc_httpd/web/*.html; do
    [ -f "$hf" ] || continue
    rel_hf="${hf#"$ROOT"/}"
    _blk_list=$(node -e '
      const fs = require("fs");
      const path = require("path");
      const htmlPath = process.argv[1];
      const outDir = process.argv[2];
      const tagPrefix = process.argv[3];
      const s = fs.readFileSync(htmlPath, "utf8");
      const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
      let m, idx = 0;
      while ((m = re.exec(s)) !== null) {
        const attrs = m[1] || "";
        if (/\bsrc\s*=/i.test(attrs)) continue;
        const tm = attrs.match(/\btype\s*=\s*(?:"([^"]*)"|\x27([^\x27]*)\x27|([^\s>]+))/i);
        const rawType = (tm ? (tm[1] || tm[2] || tm[3] || "") : "").trim().toLowerCase();
        const mimeType = rawType.split(";")[0].trim();
        if (mimeType && mimeType !== "text/javascript" && mimeType !== "application/javascript" && mimeType !== "text/ecmascript" && mimeType !== "application/ecmascript" && mimeType !== "module") {
          continue;
        }
        const body = m[2] || "";
        if (!body.trim()) continue;
        idx++;
        const ext = (mimeType === "module") ? ".mjs" : ".js";
        const outFile = path.join(outDir, tagPrefix + "_block" + idx + ext);
        fs.writeFileSync(outFile, body, "utf8");
        console.log(idx + "\t" + outFile);
      }
    ' "$hf" "$TMP_INL_DIR" "$(printf '%s' "$rel_hf" | tr '/.' '__')")
    if [ $? -ne 0 ]; then
      html_err="$html_err ${rel_hf}(extract_failed)"
      continue
    fi
    if [ -n "$_blk_list" ]; then
      while IFS="$(printf '\t')" read -r _bidx _bfile; do
        [ -n "$_bfile" ] && [ -f "$_bfile" ] || continue
        inline_total=$((inline_total + 1))
        if ! node --check "$_bfile" 2>/dev/null; then
          html_err="$html_err ${rel_hf}#script${_bidx}"
        fi
      done <<EOF_BLKS
$_blk_list
EOF_BLKS
    fi
  done
  rm -rf "$TMP_INL_DIR" 2>/dev/null || true
  if [ "$inline_total" -gt 0 ] && [ -z "$html_err" ]; then
    ok "all $inline_total inline <script> blocks across HTML pages parse via node --check"
  else
    bad "inline <script> syntax error (checked=$inline_total):${html_err:- zero inline scripts found}"
  fi
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

# v6.1.0-rc.1: 静态零拖动滑条门禁 (全站禁止 <input type=range> 与 .gx-range)
if grep -qiE '<input[^>]*type=["'"'"']?range' "$SRC"; then
  bad "WebUI still contains forbidden <input type=range> slider"
else
  ok "zero <input type=range> sliders in WebUI"
fi
if grep -qF 'gx-range' "$SRC"; then
  bad "WebUI still contains forbidden .gx-range slider class/selector"
else
  ok "zero .gx-range references in WebUI"
fi

exit $fail
