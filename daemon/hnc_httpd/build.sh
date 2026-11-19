#!/bin/sh
# 交叉编译 hnc_httpd Android 二进制
# 使用: sh build.sh            # arm64(默认优先 CGO_ENABLED=0, 失败自动回退 NDK clang, 产物 ./hnc_httpd)
#       sh build.sh arm        # v5.22: armeabi-v7a, 产物 ../../bin/armeabi-v7a/hnc_httpd
# 需要: Go 1.27+; arm(及 arm64 回退路径)需 Android NDK(ANDROID_NDK / ANDROID_NDK_HOME)
set -e
cd "$(dirname "$0")"

HNC_ARCH="${1:-arm64}"
export GOOS=android
OUT_BIN=hnc_httpd
_ndk="${ANDROID_NDK:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
_host="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
_strip=""
if [ -n "$_ndk" ] && [ -x "$_ndk/toolchains/llvm/prebuilt/$_host/bin/llvm-strip" ]; then
    _strip="$_ndk/toolchains/llvm/prebuilt/$_host/bin/llvm-strip"
fi

case "$HNC_ARCH" in
    arm64)
        export GOARCH=arm64
        export CGO_ENABLED=0
        ;;
    arm)
        export GOARCH=arm GOARM=7 CGO_ENABLED=1
        [ -n "$_ndk" ] && [ -d "$_ndk" ] || { echo "ERROR: arm build needs ANDROID_NDK" >&2; exit 1; }
        export CC="$_ndk/toolchains/llvm/prebuilt/$_host/bin/armv7a-linux-androideabi28-clang"
        [ -x "$CC" ] || { echo "ERROR: NDK clang not found: $CC" >&2; exit 1; }
        mkdir -p ../../bin/armeabi-v7a
        OUT_BIN=../../bin/armeabi-v7a/hnc_httpd
        ;;
    *) echo "ERROR: unsupported arch '$HNC_ARCH' (arm64|arm)" >&2; exit 1 ;;
esac

# v5.40.2: 恢复 -mod=mod (避免 Go 1.27 在跨平台 GOOS=android 下因 -mod=readonly 阻断构建)
if [ -d vendor ]; then
    export GOPROXY=${GOPROXY:-off}
    export GOSUMDB=${GOSUMDB:-off}
    export GOFLAGS=${GOFLAGS:-"-mod=vendor"}
else
    export GOPROXY=${GOPROXY:-"https://proxy.golang.org,direct"}
    export GOSUMDB=${GOSUMDB:-sum.golang.org}
    export GOFLAGS=${GOFLAGS:-"-mod=mod"}
fi

VERSION=$(grep "^version=" ../../module.prop 2>/dev/null | cut -d= -f2 | tr -d '\r')
if [ -z "$VERSION" ]; then
    echo "ERROR: module.prop version= not found (cwd=$(pwd))" >&2
    echo "       run build.sh from daemon/hnc_httpd/ with module.prop at ../../" >&2
    exit 1
fi

VERSION_CODE=$(grep "^versionCode=" ../../module.prop 2>/dev/null | cut -d= -f2 | tr -d '\r')
[ -z "$VERSION_CODE" ] && VERSION_CODE=0

echo "Building hnc_httpd for android/$GOARCH (version=$VERSION code=$VERSION_CODE cgo=$CGO_ENABLED)..."
if [ "$HNC_ARCH" = "arm64" ]; then
    if ! go build -buildvcs=false -trimpath -ldflags="-s -w -X main.version=$VERSION -X main.versionCode=$VERSION_CODE" -o "$OUT_BIN" .; then
        _cc64="$_ndk/toolchains/llvm/prebuilt/$_host/bin/aarch64-linux-android28-clang"
        if [ -n "$_ndk" ] && [ -x "$_cc64" ]; then
            echo "WARN: CGO_ENABLED=0 android/arm64 build failed; retrying with CGO_ENABLED=1 and NDK clang ($_cc64)..." >&2
            CGO_ENABLED=1 CC="$_cc64" go build -buildvcs=false -trimpath \
                -ldflags="-s -w -X main.version=$VERSION -X main.versionCode=$VERSION_CODE -extldflags=-Wl,-z,max-page-size=16384" \
                -o "$OUT_BIN" .
            [ -n "$_strip" ] && "$_strip" "$OUT_BIN" 2>/dev/null || true
        else
            echo "ERROR: go build failed for android/arm64 and NDK clang unavailable" >&2
            exit 1
        fi
    fi
else
    go build -buildvcs=false -trimpath \
        -ldflags="-s -w -X main.version=$VERSION -X main.versionCode=$VERSION_CODE -extldflags=-Wl,-z,max-page-size=16384" \
        -o "$OUT_BIN" .
    [ -n "$_strip" ] && "$_strip" "$OUT_BIN" 2>/dev/null || true
fi

echo "OK: $(ls -la "$OUT_BIN")"
file "$OUT_BIN"

# v5.40.2: 直接扫描 ELF 原始字节校验关键路由、动作名与注入版本号(彻底规避 GNU strings 段过滤与超长拼接块问题)
if command -v python3 >/dev/null 2>&1; then
    python3 - "$OUT_BIN" "$VERSION" <<'PY'
import sys
bin_path, ver = sys.argv[1], sys.argv[2]
data = open(bin_path, "rb").read()
required = [
    ver,
    "/api/dpi_state",
    "/api/dpi_probe",
    "dpi_rebind",
    "/api/dataplane_verify",
    "dataplane_verify_run",
]
missing = [s for s in required if s.encode("utf-8") not in data]
if missing:
    sys.stderr.write(f"ERROR: rebuilt {bin_path} missing required byte markers: {missing}\n")
    sys.exit(1)
PY
else
    for sym in \
        "$VERSION" \
        /api/dpi_state \
        /api/dpi_probe \
        dpi_rebind \
        /api/dataplane_verify \
        dataplane_verify_run
    do
        if ! grep -a -F "$sym" "$OUT_BIN" >/dev/null 2>&1; then
            echo "ERROR: rebuilt hnc_httpd missing required DPI API route/action string: $sym" >&2
            exit 1
        fi
    done
fi
echo "OK: hnc_httpd includes version $VERSION and all DPI & dataplane API routes/actions"
