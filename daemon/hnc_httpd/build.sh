#!/bin/sh
# 交叉编译 hnc_httpd arm64 Android 二进制
# 使用: sh build.sh
# 需要: Go 1.22+ 且 CGO 不依赖(CGO_ENABLED=0)
set -e
cd "$(dirname "$0")"

export GOOS=android
export GOARCH=arm64
export CGO_ENABLED=0
# hotfix17.3: build must really rebuild hnc_httpd in CI.
# Older hotfixes forced GOPROXY=off and -mod=vendor even when no vendor/ dir
# existed, so CI silently kept packaging an old hotfix4 binary. Use vendor only
# when present; otherwise allow the runner to download modules.
if [ -d vendor ]; then
    export GOPROXY=${GOPROXY:-off}
    export GOSUMDB=${GOSUMDB:-off}
    export GOFLAGS=${GOFLAGS:-"-mod=vendor"}
else
    export GOPROXY=${GOPROXY:-"https://proxy.golang.org,direct"}
    export GOSUMDB=${GOSUMDB:-sum.golang.org}
    export GOFLAGS=${GOFLAGS:-"-mod=mod"}
fi

# rc5.1.1 修 X-G2: 从 module.prop 读 version 注入 binary, 消除硬编码
# rc2 修 N4: 读不到 module.prop 直接失败, 不静默 fallback 到 "dev"
#          ("dev" 暴露给前端比老的硬编码版本更没信息量)
VERSION=$(grep "^version=" ../../module.prop 2>/dev/null | cut -d= -f2)
if [ -z "$VERSION" ]; then
    echo "ERROR: module.prop version= not found (cwd=$(pwd))" >&2
    echo "       run build.sh from daemon/hnc_httpd/ with module.prop at ../../" >&2
    exit 1
fi

echo "Building hnc_httpd for android/arm64 (version=$VERSION)..."
go build -ldflags="-s -w -X main.version=$VERSION" -o hnc_httpd .

echo "OK: $(ls -la hnc_httpd)"
file hnc_httpd

# v5.3.0-rc17: hard fail CI if the rebuilt backend loses DPI API routes/actions.
# This prevents GitHub Actions from publishing a zip whose WebUI calls
# /api/dpi_state or /api/dpi_probe but the freshly-built hnc_httpd returns 404.
for sym in \
    /api/dpi_state \
    /api/dpi_probe \
    apiDPIState \
    apiDPIProbe \
    dpi_rebind
do
    if ! strings hnc_httpd | grep -F "$sym" >/dev/null 2>&1; then
        echo "ERROR: rebuilt hnc_httpd missing required DPI API symbol/string: $sym" >&2
        exit 1
    fi
done
echo "OK: hnc_httpd includes DPI API routes/actions"
