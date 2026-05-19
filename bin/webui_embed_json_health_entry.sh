#!/system/bin/sh
# HNC hotfix18.7: embed JSON health entry into current WebUI index.html.
# This script is intended to be run in the git repository root after copying changed-files:
#   sh bin/webui_embed_json_health_entry.sh .
# It is idempotent and does not replace the full index.html.

set -e
ROOT="${1:-.}"
INDEX="$ROOT/webroot/index.html"
MODPROP="$ROOT/module.prop"

if [ ! -f "$INDEX" ]; then
  echo "ERROR: $INDEX not found" >&2
  exit 1
fi

if grep -q 'HNC_JSON_HEALTH_ENTRY_START hotfix18.7' "$INDEX" 2>/dev/null; then
  echo "JSON health WebUI entry already embedded"
else
  SNIP="${TMPDIR:-/tmp}/hnc_json_health_entry_$$.html"
  cat > "$SNIP" <<'EOF_SNIP'
<!-- HNC_JSON_HEALTH_ENTRY_START hotfix18.7 -->
<style id="hnc-json-health-entry-style">
#hnc-json-health-entry{margin:12px 0;padding:14px;border-radius:18px;border:1px solid rgba(255,255,255,.12);background:rgba(255,255,255,.07);box-shadow:0 14px 32px rgba(0,0,0,.18);backdrop-filter:blur(14px);color:var(--text,#eef6ff);font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
#hnc-json-health-entry .hje-top{display:flex;align-items:center;justify-content:space-between;gap:10px}
#hnc-json-health-entry .hje-title{font-weight:800;font-size:14px;letter-spacing:.2px}
#hnc-json-health-entry .hje-sub{margin-top:4px;color:var(--muted,#91a4bd);font-size:12px;line-height:1.45}
#hnc-json-health-entry .hje-pill{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:6px 9px;font-size:12px;font-weight:800;background:rgba(145,164,189,.14);color:var(--muted,#91a4bd);white-space:nowrap}
#hnc-json-health-entry .hje-pill.ok{background:rgba(53,208,127,.16);color:#35d07f}
#hnc-json-health-entry .hje-pill.warn{background:rgba(255,209,102,.16);color:#ffd166}
#hnc-json-health-entry .hje-pill.fail{background:rgba(255,92,122,.16);color:#ff5c7a}
#hnc-json-health-entry .hje-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
#hnc-json-health-entry button{border:0;border-radius:13px;padding:9px 11px;color:#fff;background:linear-gradient(135deg,#4ea1ff,#7c5cff);font-weight:800;box-shadow:0 8px 22px rgba(78,161,255,.22)}
#hnc-json-health-entry button.secondary{background:rgba(255,255,255,.10);box-shadow:none;color:var(--text,#eef6ff);border:1px solid rgba(255,255,255,.10)}
#hnc-json-health-entry.hje-float{position:fixed;right:14px;bottom:14px;z-index:99999;width:min(330px,calc(100vw - 28px));margin:0}
#hnc-json-health-entry.hje-float .hje-sub{display:none}
@media (max-width:520px){#hnc-json-health-entry.hje-float{left:12px;right:12px;width:auto;bottom:12px}#hnc-json-health-entry .hje-top{align-items:flex-start;flex-direction:column}}
</style>
<script id="hnc-json-health-entry-script">
(function(){
  if(window.__hncJsonHealthEntry187) return;
  window.__hncJsonHealthEntry187 = true;
  var HNC = '/data/local/hnc';
  function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(m){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m];});}
  function execCmd(cmd){
    if(!window.ksu || typeof window.ksu.exec !== 'function') return Promise.reject(new Error('no window.ksu.exec'));
    return window.ksu.exec(cmd).then(function(r){
      if(typeof r === 'string') return r;
      if(r && typeof r.stdout === 'string') return r.stdout + (r.stderr ? '\n'+r.stderr : '');
      return JSON.stringify(r || {});
    });
  }
  function findPanelTarget(){
    var nodes = Array.prototype.slice.call(document.querySelectorAll('.card,.panel,.section,section,main,[class*=setting],[class*=diag],[id*=setting],[id*=diag]'));
    for(var i=0;i<nodes.length;i++){
      var t=(nodes[i].innerText||'').slice(0,300);
      if(/诊断|调试|设置|系统|日志|状态/.test(t)) return {node:nodes[i], floating:false};
    }
    var main=document.querySelector('main') || document.querySelector('.container') || document.querySelector('#app');
    if(main) return {node:main, floating:false};
    return {node:document.body, floating:true};
  }
  function pillClass(overall){
    overall=String(overall||'unknown').toLowerCase();
    if(overall==='ok') return 'ok';
    if(overall==='fail' || overall==='bad') return 'fail';
    if(overall==='warn' || overall==='missing') return 'warn';
    return '';
  }
  function setStatus(text, cls){
    var p=document.querySelector('#hnc-json-health-entry .hje-pill');
    if(!p) return;
    p.className='hje-pill '+(cls||'');
    p.textContent=text;
  }
  function refreshEntry(){
    setStatus('检测中…','');
    execCmd("su -c 'sh "+HNC+"/bin/json_health_panel.sh'").then(function(out){
      var m=String(out||'').match(/\{[\s\S]*\}/);
      var data=m?JSON.parse(m[0]):{};
      var overall=data.overall || 'unknown';
      var label=overall==='ok'?'JSON 正常':(overall==='fail'||overall==='bad'?'JSON 异常':(overall==='warn'?'JSON 警告':'JSON 未知'));
      setStatus(label,pillClass(overall));
    }).catch(function(){ setStatus('JSON 未知',''); });
  }
  function mount(){
    if(document.getElementById('hnc-json-health-entry')) return;
    var where=findPanelTarget();
    var div=document.createElement('div');
    div.id='hnc-json-health-entry';
    if(where.floating) div.className='hje-float';
    div.innerHTML=''
      + '<div class="hje-top"><div><div class="hje-title">JSON 健康 / 诊断</div>'
      + '<div class="hje-sub">检查 rules、设备名、模板、token JSON 状态，并可导出排障包。</div></div>'
      + '<span class="hje-pill">检测中…</span></div>'
      + '<div class="hje-actions"><button type="button" data-hje-open>打开诊断页</button>'
      + '<button type="button" class="secondary" data-hje-refresh>刷新</button></div>';
    where.node.appendChild(div);
    div.querySelector('[data-hje-open]').onclick=function(){ location.href='json-health.html'; };
    div.querySelector('[data-hje-refresh]').onclick=refreshEntry;
    refreshEntry();
  }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',mount); else mount();
})();
</script>
<!-- HNC_JSON_HEALTH_ENTRY_END -->
EOF_SNIP

  TMP="$INDEX.hnc18_7.$$"
  awk -v snip="$SNIP" '
    BEGIN{inserted=0; while((getline l < snip)>0){buf=buf l "\n"} close(snip)}
    tolower($0) ~ /<\/body>/ && inserted==0 { printf "%s", buf; inserted=1 }
    { print }
    END{ if(inserted==0) printf "%s", buf }
  ' "$INDEX" > "$TMP"
  mv "$TMP" "$INDEX"
  rm -f "$SNIP"
  echo "Embedded JSON health entry into $INDEX"
fi

if [ -f "$MODPROP" ]; then
  sed -i 's/version=v5.1.0-rc1-hotfix[0-9][0-9]*\.[0-9][0-9]*/version=v5.1.0-rc1-hotfix18.7/' "$MODPROP" 2>/dev/null || true
  sed -i 's/versionCode=50918[0-9]/versionCode=509187/' "$MODPROP" 2>/dev/null || true
  sed -i 's/hotfix18\.[0-9][0-9]*/hotfix18.7/g' "$MODPROP" 2>/dev/null || true
  echo "Updated module.prop to hotfix18.7 if matched"
fi
