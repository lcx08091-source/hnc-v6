#!/bin/sh
# build.sh — 不用 Gradle, 直接用 Android SDK build-tools 编出 tools/act_probe/out/hnc-probe.apk
#   aapt2 link(清单 + assets)→ javac(对 android.jar)→ d8 → 塞 classes.dex → zipalign → apksigner
# 用法: sh tools/act_probe/build.sh
# 可选环境变量:
#   ANDROID_HOME / ANDROID_SDK_ROOT   SDK 根目录(默认 /opt/android/sdk)
#   BUILD_TOOLS                       build-tools 版本(默认 34.0.0)
#   ANDROID_JAR                       android.jar 路径(默认 platforms/android-34/android.jar)
#   PROBE_KEYSTORE                    签名用 keystore(默认 tools/act_probe/.keys/debug.keystore, 不存在则用 keytool 生成)
# out/ 与 .keys/ 都在 .gitignore 里, APK 和 keystore 不提交。
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
SDK=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/opt/android/sdk}}
BT="$SDK/build-tools/${BUILD_TOOLS:-34.0.0}"
JAR=${ANDROID_JAR:-$SDK/platforms/android-34/android.jar}
VERSION_NAME=0.1.0
VERSION_CODE=1
OUT="$HERE/out"
B="$OUT/build"
KS=${PROBE_KEYSTORE:-$HERE/.keys/debug.keystore}
KS_PASS=android
KS_ALIAS=hncprobe

die() { echo "ERROR: $*" >&2; exit 1; }

for t in aapt2 d8 zipalign apksigner; do
    [ -x "$BT/$t" ] || die "找不到 $BT/$t(设置 ANDROID_HOME / BUILD_TOOLS)"
done
[ -f "$JAR" ] || die "找不到 android.jar: $JAR"
command -v javac >/dev/null 2>&1 || die "找不到 javac"
command -v keytool >/dev/null 2>&1 || die "找不到 keytool"

rm -rf "$B"
mkdir -p "$B/classes" "$B/dex"

echo "[1/6] aapt2 link(清单 + assets, 没有要编译的资源)"
"$BT/aapt2" link -o "$B/base.apk" -I "$JAR" \
    --manifest "$HERE/AndroidManifest.xml" -A "$HERE/assets" \
    --min-sdk-version 26 --target-sdk-version 34 \
    --version-code "$VERSION_CODE" --version-name "$VERSION_NAME"

echo "[2/6] javac(core + app, 对 android-34 编译, 字节码 Java 8 交给 d8)"
# android.jar 不带 java.lang.invoke.LambdaMetafactory; build-tools 自带的 core-lambda-stubs.jar
# 只供 javac 编 lambda 用, d8 会把 lambda 脱糖, 不进 APK。
BOOTCP="$JAR"
[ -f "$BT/core-lambda-stubs.jar" ] && BOOTCP="$JAR:$BT/core-lambda-stubs.jar"
# shellcheck disable=SC2046
javac -encoding UTF-8 -source 8 -target 8 -Xlint:-options -Xlint:unchecked \
    -bootclasspath "$BOOTCP" -d "$B/classes" \
    $(find "$HERE/src/core" "$HERE/src/app" -name '*.java' | sort)

# JDK 21 的 javac 会给匿名类 / 非静态内部类构造器写 MethodParameters(隐式参数名为空),
# build-tools 34 的 d8 8.2 遇到会崩 —— 源码里一律用静态嵌套类 / lambda / 方法引用。这里提前给出可读的报错。
BAD=$(grep -rl MethodParameters "$B/classes" 2>/dev/null || true)
[ -z "$BAD" ] || die "这些 class 带 MethodParameters(把匿名类 / 内部类改成静态嵌套类或 lambda): $BAD"

echo "[3/6] d8 → classes.dex"
# shellcheck disable=SC2046
"$BT/d8" --release --min-api 26 --lib "$JAR" --output "$B/dex" \
    $(find "$B/classes" -name '*.class')
[ -s "$B/dex/classes.dex" ] || die "d8 没产出 classes.dex"

echo "[4/6] 把 classes.dex 放进 APK"
cp "$B/base.apk" "$B/unsigned.apk"
if command -v zip >/dev/null 2>&1; then
    (cd "$B/dex" && zip -q -X "$B/unsigned.apk" classes.dex)
else
    (cd "$B/dex" && "$BT/aapt" add "$B/unsigned.apk" classes.dex >/dev/null)
fi

echo "[5/6] zipalign"
"$BT/zipalign" -f -p 4 "$B/unsigned.apk" "$B/aligned.apk"

echo "[6/6] apksigner(调试签名)"
if [ ! -f "$KS" ]; then
    mkdir -p "$(dirname "$KS")"
    keytool -genkeypair -keystore "$KS" -storepass "$KS_PASS" -keypass "$KS_PASS" \
        -alias "$KS_ALIAS" -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=HNC Probe Debug, O=HNC" -noprompt
    echo "    生成了调试 keystore: $KS(不提交; 换了 keystore 要先卸载旧 APK 再装)"
fi
"$BT/apksigner" sign --ks "$KS" --ks-pass "pass:$KS_PASS" --key-pass "pass:$KS_PASS" \
    --ks-key-alias "$KS_ALIAS" --out "$OUT/hnc-probe.apk" "$B/aligned.apk"
"$BT/apksigner" verify --verbose "$OUT/hnc-probe.apk" | grep -E '^Verifies|^Verified using v[123]'

echo
"$BT/aapt2" dump badging "$OUT/hnc-probe.apk" | grep -E "^package:|^sdkVersion|^targetSdkVersion|^uses-permission|^application-label:|^launchable-activity"
ls -l "$OUT/hnc-probe.apk"
echo "OK: $OUT/hnc-probe.apk"
