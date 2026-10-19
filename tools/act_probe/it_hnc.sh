#!/bin/sh
# it_hnc.sh — 可选集成测试: 在本机把真的 hnc_httpd(daemon/hnc_httpd)跑起来, 用 App 里原样的
# HncClient 走一遍「证书指纹固定 → 配对 → 带 cookie GET /api/devices」。daemon 的鉴权改了会在这里暴露。
#
# 需要: Go(按 daemon/hnc_httpd/go.mod 的版本)、JDK、root(要给 lo 临时加一个私网地址:
#       httpd 把 127.0.0.1 来的请求当本机 KSU WebUI 走另一套鉴权, App 也只接受私网地址)。
# 用法: sudo sh tools/act_probe/it_hnc.sh
# 只写 tools/act_probe/out/it/, 退出时停掉 httpd、删掉临时地址和 httpd 生成的证书私钥。不改仓库其他文件。
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
W="$HERE/out/it"
IP=${IT_IP:-10.254.254.1}
PORT=${IT_PORT:-18443}
PIN=135790

command -v go >/dev/null 2>&1 || { echo "跳过: 没有 go"; exit 0; }
command -v ip >/dev/null 2>&1 || { echo "跳过: 没有 ip 命令"; exit 0; }
[ "$(id -u)" = 0 ] || { echo "跳过: 需要 root(给 lo 加临时地址)"; exit 0; }

rm -rf "$W"
mkdir -p "$W/hnc/data" "$W/hnc/run" "$W/cls"
echo "[1/4] 构建 hnc_httpd"
(cd "$REPO/daemon/hnc_httpd" && go build -o "$W/hnc_httpd" .)

ADDED=0
cleanup() {
    if [ -f "$W/hnc/run/httpd.pid" ]; then
        P=$(cat "$W/hnc/run/httpd.pid")
        kill "$P" 2>/dev/null || true
        j=0
        while kill -0 "$P" 2>/dev/null && [ "$j" -lt 25 ]; do j=$((j + 1)); sleep 0.2; done
    fi
    [ "$ADDED" = 1 ] && ip addr del "$IP/32" dev lo 2>/dev/null || true
    # httpd 生成的私钥 / 令牌库不留在工作区(ci_preflight 会把 *.pem 当成仓库里的私钥报错)
    rm -rf "$W/hnc"
}
trap cleanup EXIT INT TERM
if ! ip -4 addr show lo | grep -q " $IP/"; then
    ip addr add "$IP/32" dev lo
    ADDED=1
fi

NOW=$(date +%s)
printf '{"remote_enabled": true, "auth_required": true, "devices": {}, "blacklist": []}\n' > "$W/hnc/data/rules.json"
printf '{"aa:bb:cc:00:00:02": {"ip": "%s", "hostname": "probe-phone", "last_seen": %s}}\n' "$IP" "$NOW" > "$W/hnc/data/devices.json"
printf '%s\nprobeItSession01\n%s\n' "$PIN" "$((NOW + 110))" > "$W/hnc/run/pair_pending"

echo "[2/4] 启动 hnc_httpd(:$PORT, 只开远程端口)"
"$W/hnc_httpd" -hnc-dir "$W/hnc" -port "$PORT" -http-port 0 -loopback-port 0 > "$W/httpd.out" 2>&1 &
# 远程端口在证书生成后才 Serve: 等证书文件出现再多等一秒(不用 /dev/tcp 之类的 bash 扩展)
i=0
while [ ! -s "$W/hnc/data/httpd_cert.pem" ]; do
    i=$((i + 1))
    [ "$i" -le 50 ] || { echo "httpd 没起来:"; tail -20 "$W/httpd.out"; exit 1; }
    sleep 0.2
done
sleep 1.5

echo "[3/4] 编译测试桩(App 的 HncClient + core + android.net.Network 桩)"
# shellcheck disable=SC2046
javac -encoding UTF-8 -nowarn -d "$W/cls" $(find "$HERE/src/core" -name '*.java') \
    "$HERE/src/app/io/hnc/probe/HncClient.java" \
    "$HERE/test/it/android/net/Network.java" "$HERE/test/it/io/hnc/probe/ITMain.java"

echo "[4/4] 跑集成测试"
FP=$(grep -v CERTIFICATE "$W/hnc/data/httpd_cert.pem" | tr -d '\n' | base64 -d | sha256sum | cut -d' ' -f1)
java -Dstdout.encoding=UTF-8 -Dhttps.proxyHost= -Dhttp.nonProxyHosts='*' -cp "$W/cls" io.hnc.probe.ITMain "$IP:$PORT" "$FP" "$PIN"
