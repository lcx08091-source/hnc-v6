# A12 前端 / CI / tools 审查记录（基线 v5.33.0-rc2）

## 范围
- 前端：webroot/index.html、webroot/glass.html、webroot/json-health.html、webroot/js/*.js（core、main、devices、settings、stats、apps、sheets、fx）、webroot/hyalite.js（只看安全相关：模板转义）、webroot/css/*（只看明显问题）、daemon/hnc_httpd/web/pair.html。changelog.html 不审。
- CI / 构建：.github/workflows/build.yml，及其调用的 bin/ci_preflight.sh、bin/artifact_*.sh（只看与 CI 的接线）、daemon/*/build.sh、src/launcher/build.sh（只看产物 / 打包相关错误）。
- tools/：import_v2fly.py、build_ip_owner.py、build_pkg_app_map.py、applabel/AppLabel.java、ui_mock/*.js。
- 只找真 bug，只记录不改代码。严重度：P0 远程可利用安全漏洞 / 数据丢失 / 断网；P1 常见路径功能错误；P2 边界 / 少见路径；P3 轻微隐患 / 文档不符。

## 已审文件

## Bug

### A12-001 [P2][确认] 首次 boot 失败后由轮询恢复连接，但从不重跑 boot()：配置/能力/模板/告警轮询/SSE 全部缺失
- **位置**：`webroot/js/main.js:553-557`（boot 的 catch）、`webroot/js/main.js:498`（pollOnce 恢复分支）
- **触发 / 现象**：打开 WebUI 时 hnc_httpd 还没起来或 /api/health 6 秒超时——最常见的是设置页「重启 HNC 服务」（main.js:362 在 2.5 秒后 `location.reload()`，此时 service.sh 往往还没把 httpd 拉起来）、开机后马上打开、「释放并重启资源」期间。boot() 失败 → `schedulePoll(4000)`；之后 `/api/live` 成功，`applyLive` 把 `S.connected` 置 true、横幅里的「重试连接」按钮消失，但 `loadConfig/loadCaps/loadTemplates/loadAppLimits/loadAlerts/loadOffload/startSlowPolls/startSSE/loadEncdns/alert_config` 一个都没跑。结果：模板弹层是空的（连默认模板都没有）、白名单模式开关总显示「关」、告警铃铛不再轮询、offload 横幅不出现、设备卡里按设备加密 DNS 块缺失、远程模式不开 SSE、`#mode-pill` 不显示，直到用户手动刷新页面。
- **原因**：
  ```js
  }).catch(function (e) {
    S.connected = false; S.bootErr = errText(e);
    ... schedulePoll(4000);                       // 只恢复轮询
  // pollOnce:
  if (!wasOk) { S.bootErr = ''; if (S.page === 'devices') renderDevices(false); }   // 不调用 boot()
  ```
  main.js:533 的注释声称「旧版 bug: health 失败后重试成功只恢复了设备轮询……这里 boot() 每次都走完整初始化」，但实现只有手动点「重试连接」才会走完整初始化。
- **建议修复**：pollOnce 在 `!S.booted && S.connected` 时调用一次 `boot(true)`（或在 boot 的 catch 里改成定时重试 boot 本身，而不是只排轮询）。

### A12-002 [P2][确认] 连接详情弹层用空 onClose 覆盖了「实时连接」弹层的清理回调，2 秒轮询定时器泄漏，且之后点设备卡里的连接行会被路由到旧设备
- **位置**：`webroot/js/devices.js:418-420`（connActSheet 的 `{ onClose: function () {} }`）、`webroot/js/devices.js:438`（dpiFixSheet 无 onClose）、`webroot/js/sheets.js:51`、`webroot/js/main.js:222`
- **触发 / 现象**：设备卡「实时连接 → 查看全部」打开 connSheet（setInterval 2 秒拉 `/api/connections?mac=`，onClose 里 `clearInterval(connT); S.connMac = null`）→ 点任意一条连接打开 connActSheet（或再进「纠正识别」）→ 点遮罩 / 下拉 / Esc 关闭弹层。此时 sheet() 已把 sheetOnClose 换成空函数，connT 继续每 2 秒请求一次（KSU 模式下每次拉起一个 curl 进程），直到下次再打开任意连接弹层；`S.connMac` 也一直保留旧设备 MAC，于是 (1) pollOnce 里 `!S.connMac` 恒假，展开卡片的连接摘要不再按 3 轮刷新；(2) 在另一台设备卡的连接摘要里点一条连接时，`var cm = S.connMac || ...` 取到的是旧设备，connActSheet 在旧设备的连接表里找不到这个 key，点击没有任何反应。
- **原因**：
  ```js
  // sheets.js:51
  $('#sheet-body').innerHTML = html; sheetOnClose = opt.onClose || null;   // 直接覆盖, 不先执行旧的清理
  // devices.js:418-420
  sheet('<h3>' + esc(c.name || c.dst) + ... , { onClose: function () {} });
  ```
- **建议修复**：sheet() 在替换前若旧弹层仍处于打开状态就先调用旧的 sheetOnClose；或 connActSheet / dpiFixSheet 的 onClose 里同样 `clearInterval(connT); connT = null; S.connMac = null`（返回按钮会重新 connSheet，不受影响）。

