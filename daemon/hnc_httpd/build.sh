#!/bin/sh
# 交叉编译 hnc_httpd Android 二进制
# 使用: sh build.sh            # arm64(默认, CGO_ENABLED=0, 产物 ./hnc_httpd)
#       sh build.sh arm        # v5.22: armeabi-v7a, 产物 ../../bin/armeabi-v7a/hnc_httpd
# 需要: Go 1.25+;arm 另需 Android NDK(ANDROID_NDK / ANDROID_NDK_HOME)——
#   Go 的 android/arm 不支持内部链接(“requires external (cgo) linking”),
#   必须 CGO_ENABLED=1 + NDK clang 外部链接。不用 GOOS=linux 静态编:
#   那样 time.Local 读不到 Android tzdata(恒为 UTC), 定时/日切全错。
set -e
cd "$(dirname "$0")"

HNC_ARCH="${1:-arm64}"
export GOOS=android
OUT_BIN=hnc_httpd
case "$HNC_ARCH" in
    arm64)
        export GOARCH=arm64
        export CGO_ENABLED=0
        ;;
    arm)
        export GOARCH=arm GOARM=7 CGO_ENABLED=1
        _ndk="${ANDROID_NDK:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
        [ -n "$_ndk" ] && [ -d "$_ndk" ] || { echo "ERROR: arm build needs ANDROID_NDK" >&2; exit 1; }
        _host="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
        export CC="$_ndk/toolchains/llvm/prebuilt/$_host/bin/armv7a-linux-androideabi21-clang"
        [ -x "$CC" ] || { echo "ERROR: NDK clang not found: $CC" >&2; exit 1; }
        mkdir -p ../../bin/armeabi-v7a
        OUT_BIN=../../bin/armeabi-v7a/hnc_httpd
        ;;
    *) echo "ERROR: unsupported arch '$HNC_ARCH' (arm64|arm)" >&2; exit 1 ;;
esac
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

# v5.9.9: versionCode 一并注入 —— 关于页此前把它写死在 HTML 的 data-vcode
# 属性里(580000), 版本升了 code 不变, 用户看到 "v5.9.8 · versionCode 580000"。
VERSION_CODE=$(grep "^versionCode=" ../../module.prop 2>/dev/null | cut -d= -f2)
[ -z "$VERSION_CODE" ] && VERSION_CODE=0

echo "Building hnc_httpd for android/$GOARCH (version=$VERSION code=$VERSION_CODE)..."
go build -ldflags="-s -w -X main.version=$VERSION -X main.versionCode=$VERSION_CODE" -o "$OUT_BIN" .

echo "OK: $(ls -la "$OUT_BIN")"
file "$OUT_BIN"

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
    if ! strings "$OUT_BIN" | grep -F "$sym" >/dev/null 2>&1; then
        echo "ERROR: rebuilt hnc_httpd missing required DPI API symbol/string: $sym" >&2
        exit 1
    fi
done
echo "OK: hnc_httpd includes DPI API routes/actions"
