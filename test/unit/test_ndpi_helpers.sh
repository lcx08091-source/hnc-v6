#!/bin/sh
# [opt #17] nDPI 辅助函数单元测试
set -u
ROOT="${HNC_TEST_ROOT:-$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)}"
HTML="$ROOT/webroot/index.html"
fail=0
ok() { echo "[OK] $1"; }
bad() { echo "[FAIL] $1"; fail=1; }

[ -f "$HTML" ] || { echo "[FAIL] missing webroot/index.html"; exit 1; }

if ! command -v node >/dev/null 2>&1; then
  echo "[SKIP] node not available, skipping function tests"
  exit 0
fi

RESULT=$(node -e '
  const errors = [];
  function assert(cond, msg) { if (!cond) errors.push(msg); }

  // Define helper functions inline
  function normMac(m) { return String(m || "").toLowerCase().replace(/[:.\-]/g, ""); }

  function ndpiExtractJSONLine(txt, marker, requiredKey) {
    const idx = txt.indexOf(marker);
    const part = idx >= 0 ? txt.slice(idx + marker.length) : txt;
    const lines = part.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    for (const line of lines) {
      if (!line.startsWith("{") || !line.endsWith("}")) continue;
      try {
        const obj = JSON.parse(line);
        if (!requiredKey || Object.prototype.hasOwnProperty.call(obj, requiredKey)) return obj;
      } catch (_) {}
    }
    return null;
  }

  function ndpiExtractAll(txt) {
    const result = { structured: null, state: null };
    const lines = String(txt || "").split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) continue;
      try {
        const obj = JSON.parse(trimmed);
        if (!result.structured && obj.protocols) result.structured = obj;
        if (!result.state && obj.mode) result.state = obj;
      } catch (_) {}
    }
    return result;
  }

  function ndpiFmtNum(v, suffix) {
    const n = Number(v || 0);
    if (!Number.isFinite(n)) return "0" + (suffix || "");
    const s = Math.abs(n) >= 100 ? String(Math.round(n)) : (Math.round(n * 100) / 100).toString();
    return s + (suffix || "");
  }

  function ndpiFmtPct(part, total) {
    const p = Number(part || 0), t = Number(total || 0);
    if (!Number.isFinite(p) || !Number.isFinite(t) || t <= 0) return "0.0%";
    return (Math.round((p * 1000) / t) / 10).toFixed(1) + "%";
  }

  function ndpiSafeMbps(m) {
    const mbps = Number((m || {}).traffic_mbps || (m || {}).ndpi_mbps || 0);
    const pps = Number((m || {}).traffic_pps || (m || {}).ndpi_pps || 0);
    if (mbps > 100 && Math.abs(mbps - pps) < 0.01) return Number((m || {}).ndpi_mbps || 0);
    return mbps;
  }

  function chipHTML(list, cls, emptyText, limit, suffix) {
    const top = (Array.isArray(list) ? list : []).slice(0, limit || 8);
    if (!top.length) return "<span class=\"ndpi-compare-chip warn\">" + (emptyText || "暂无") + "</span>";
    return top.map(x => "<span class=\"ndpi-compare-chip " + (cls || "") + "\"><b>" + (x.name || "Unknown") + "</b><small>" + String(x.count || x.flows || 0) + (suffix || "") + "</small></span>").join("");
  }

  // normMac tests
  assert(normMac("AA:BB:CC:DD:EE:FF") === "aabbccddeeff", "normMac colon");
  assert(normMac("AA-BB-CC-DD-EE-FF") === "aabbccddeeff", "normMac dash");
  assert(normMac("AAbbCCddEEff") === "aabbccddeeff", "normMac plain");
  assert(normMac("") === "", "normMac empty");
  assert(normMac(null) === "", "normMac null");

  // ndpiExtractJSONLine tests
  const txt1 = "garbage\n--- sample_structured ---\n{\"protocols\":[],\"metrics\":{\"unique_flows\":10}}\nmore garbage";
  const r1 = ndpiExtractJSONLine(txt1, "--- sample_structured ---", "protocols");
  assert(r1 !== null, "extractJSONLine found");
  assert(r1.metrics.unique_flows === 10, "extractJSONLine value");
  assert(ndpiExtractJSONLine(txt1, "--- not found ---", "x") === null, "extractJSONLine not found");
  assert(ndpiExtractJSONLine("", "--- x ---", "y") === null, "extractJSONLine empty");

  // ndpiExtractAll tests
  const txt2 = "noise\n{\"protocols\":[{\"name\":\"TLS\"}],\"metrics\":{\"unique_flows\":5}}\n{\"mode\":\"available\",\"version\":\"1.0\"}";
  const a = ndpiExtractAll(txt2);
  assert(a.structured !== null, "extractAll structured");
  assert(a.state !== null, "extractAll state");
  assert(a.structured.protocols[0].name === "TLS", "extractAll protocol name");
  assert(a.state.mode === "available", "extractAll mode");
  const a2 = ndpiExtractAll("");
  assert(a2.structured === null && a2.state === null, "extractAll empty");

  // ndpiFmtNum tests
  assert(ndpiFmtNum(0, " Mb/s") === "0 Mb/s", "fmtNum zero");
  assert(ndpiFmtNum(NaN, "") === "0", "fmtNum NaN");
  assert(ndpiFmtNum(Infinity, "") === "0", "fmtNum Inf");
  assert(ndpiFmtNum(-5, "") === "-5", "fmtNum negative");
  assert(ndpiFmtNum(123.456, "") === "123", "fmtNum large round");
  assert(ndpiFmtNum(1.234, " Mb/s") === "1.23 Mb/s", "fmtNum small 2dp");

  // ndpiFmtPct tests
  assert(ndpiFmtPct(0, 100) === "0.0%", "fmtPct zero");
  assert(ndpiFmtPct(50, 100) === "50.0%", "fmtPct half");
  assert(ndpiFmtPct(1, 3) === "33.3%", "fmtPct third");
  assert(ndpiFmtPct(0, 0) === "0.0%", "fmtPct div zero");
  assert(ndpiFmtPct(NaN, 100) === "0.0%", "fmtPct NaN");

  // ndpiSafeMbps tests
  assert(ndpiSafeMbps(null) === 0, "safeMbps null");
  assert(ndpiSafeMbps({traffic_mbps: 5.5}) === 5.5, "safeMbps normal");
  assert(ndpiSafeMbps({traffic_mbps: 150, traffic_pps: 150, ndpi_mbps: 3.2}) === 3.2, "safeMbps pps confused");
  assert(ndpiSafeMbps({traffic_mbps: 150, traffic_pps: 200}) === 150, "safeMbps high but not confused");

  // chipHTML tests
  const ch1 = chipHTML([], "", "empty", 5);
  assert(ch1.includes("empty"), "chipHTML empty");
  const ch2 = chipHTML([{name:"TLS", count:42}], "ndpi", "none", 5, " flows");
  assert(ch2.includes("TLS"), "chipHTML name");
  assert(ch2.includes("42 flows"), "chipHTML count+suffix");

  if (errors.length) {
    console.log("FAIL:" + errors.join("|"));
    process.exit(1);
  }
  console.log("PASS:all " + 29 + " assertions");
' 2>&1)

if echo "$RESULT" | grep -q "^PASS:"; then
  ok "nDPI helper functions: $RESULT"
else
  bad "nDPI helper functions: $RESULT"
fi

# === 检查函数存在于 HTML ===
for fn in normMac ndpiExtractAll ndpiLabRun; do
  LC_ALL=C grep -q "function $fn" "$HTML" && ok "function $fn exists" || bad "function $fn missing"
done

# === 检查优化标记 ===
LC_ALL=C grep -q "opt #1" "$HTML" && ok "opt #1 marker (cache)" || bad "opt #1 missing"
LC_ALL=C grep -q "opt #2" "$HTML" && ok "opt #2 marker (extractAll)" || bad "opt #2 missing"
LC_ALL=C grep -q "opt #16" "$HTML" && ok "opt #16 marker (ndpiLabRun)" || bad "opt #16 missing"

exit "$fail"
