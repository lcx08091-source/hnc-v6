#!/bin/sh
# test.sh — 纯 Java 核心逻辑测试(不依赖 Android / JUnit)
# 覆盖: 规则匹配、剧本解析、混淆计数、HNC /api/devices JSON 解析、root dumpsys 解析、会话存取。
# 用法: sh tools/act_probe/test.sh
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
OUT="$HERE/out/test"

command -v javac >/dev/null 2>&1 || { echo "ERROR: 找不到 javac(需要 JDK 11+)" >&2; exit 2; }

# 核心代码不得依赖 Android(否则普通 JVM 跑不了, 也说明分层破了)
if grep -rn '^import android\.' "$HERE/src/core" >/dev/null 2>&1; then
    echo "ERROR: src/core 里出现了 android.* import:" >&2
    grep -rn '^import android\.' "$HERE/src/core" >&2
    exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT"
# shellcheck disable=SC2046
# test/it/ 是 it_hnc.sh 用的集成测试桩(依赖 App 代码), 这里不编
javac -encoding UTF-8 -Xlint:all -Werror -d "$OUT" \
    $(find "$HERE/src/core" -name '*.java'; find "$HERE/test" -path "$HERE/test/it" -prune -o -name '*.java' -print)
java -Dfile.encoding=UTF-8 -Dstdout.encoding=UTF-8 -Dsun.stdout.encoding=UTF-8 \
    -cp "$OUT" io.hnc.probe.core.CoreTest "$HERE"
