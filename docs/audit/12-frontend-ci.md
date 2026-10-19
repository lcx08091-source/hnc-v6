# A12 前端 / CI / tools 审查记录（基线 v5.33.0-rc2）

## 范围
- 前端：webroot/index.html、webroot/glass.html、webroot/json-health.html、webroot/js/*.js（core、main、devices、settings、stats、apps、sheets、fx）、webroot/hyalite.js（只看安全相关：模板转义）、webroot/css/*（只看明显问题）、daemon/hnc_httpd/web/pair.html。changelog.html 不审。
- CI / 构建：.github/workflows/build.yml，及其调用的 bin/ci_preflight.sh、bin/artifact_*.sh（只看与 CI 的接线）、daemon/*/build.sh、src/launcher/build.sh（只看产物 / 打包相关错误）。
- tools/：import_v2fly.py、build_ip_owner.py、build_pkg_app_map.py、applabel/AppLabel.java、ui_mock/*.js。
- 只找真 bug，只记录不改代码。严重度：P0 远程可利用安全漏洞 / 数据丢失 / 断网；P1 常见路径功能错误；P2 边界 / 少见路径；P3 轻微隐患 / 文档不符。

## 已审文件

## Bug

