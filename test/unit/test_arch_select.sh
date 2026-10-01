#!/system/bin/sh
# test/unit/test_arch_select.sh — v5.22 安装期 CPU ABI 选择(customize.sh + bin/hnc_arch.sh)
#
# 锁死的不变量:
#   1. 单 ABI 包: 包 ABI == 设备 ABI → 安装成功、二进制原地不动且 0755;
#      不匹配 → abort, 并提示该刷哪个包; x86/x86_64 → abort「不支持」。
#   2. 通用包(bin/<abi>/ 覆盖层): 按设备 ABI 覆盖到原路径(hnc_httpd →
#      daemon/hnc_httpd/hnc_httpd), 删除全部覆盖层, 写 bin/hnc_pkg_abi。
#   3. ABI 探测顺序: ro.product.cpu.abi > abilist 首项 > $ARCH > uname -m。
#   4. 装完后 service.sh 用到的原生二进制路径全部存在、可执行、ABI 与设备一致;
#      service.sh 的运行期 ABI 兜底块(从 service.sh 原文抽取执行)能补做覆盖层。
#
# fixture: 只写 20 字节 ELF 头(e_machine 在偏移 18: 0xb7 = AArch64, 0x28 = ARM),
# getprop 用 PATH 前置的假脚本(读 FAKE_ABI / FAKE_ABILIST)。

ROOT="$HNC_REPO_ROOT"
NATIVE="hotspotd hnc_ipc mdns_resolve hnc_tc_ingress hnc_clsact_ctl hnc_launcher fork_probe hnc_dpid hnc_watchdog hnc_dpid_supervisor"

# $1 = 路径, $2 = arm64|arm
mk_elf() {
    mkdir -p "$(dirname "$1")"
    if [ "$2" = arm64 ]; then
        printf '\177ELF\002\001\001\000\000\000\000\000\000\000\000\000\003\000\267\000' > "$1"
    else
        printf '\177ELF\001\001\001\000\000\000\000\000\000\000\000\000\003\000\050\000' > "$1"
    fi
    chmod 644 "$1"   # 模拟 Magisk 默认权限(文件 0644)
}

# $1 = 模块根, $2 = 原路径二进制 arm64|arm, $3 = 标记(空 = 不写), $4 = 覆盖层 abi(可空)
mk_module() {
    local m="$1" a="$2" marker="$3" ov="$4" b ova
    mkdir -p "$m/bin" "$m/daemon/hnc_httpd"
    cp "$ROOT/customize.sh" "$m/customize.sh"
    cp "$ROOT/bin/hnc_arch.sh" "$m/bin/hnc_arch.sh"
    printf '#!/system/bin/sh\necho hnc_json\n' > "$m/bin/hnc_json"
    printf 'BPF' > "$m/bin/hnc_clsact.o"
    : > "$m/service.sh"; : > "$m/post-fs-data.sh"
    for b in $NATIVE; do mk_elf "$m/bin/$b" "$a"; done
    mk_elf "$m/daemon/hnc_httpd/hnc_httpd" "$a"
    [ -n "$marker" ] && echo "$marker" > "$m/bin/hnc_pkg_abi"
    if [ -n "$ov" ]; then
        case "$ov" in armeabi-v7a) ova=arm ;; *) ova=arm64 ;; esac
        for b in $NATIVE hnc_httpd; do mk_elf "$m/bin/$ov/$b" "$ova"; done
    fi
}

# 假 getprop
mk_getprop() {
    mkdir -p "$HNC_TEST_DIR/fakebin"
    cat > "$HNC_TEST_DIR/fakebin/getprop" <<'EOF'
#!/bin/sh
case "$1" in
    ro.product.cpu.abi) printf '%s\n' "${FAKE_ABI:-}" ;;
    ro.product.cpu.abilist) printf '%s\n' "${FAKE_ABILIST:-}" ;;
    *) echo "" ;;
esac
EOF
    chmod 755 "$HNC_TEST_DIR/fakebin/getprop"
}

# 跑 customize.sh;输出写 $HNC_TEST_DIR/out, 返回其退出码
run_customize() {
    local m="$1"
    ( PATH="$HNC_TEST_DIR/fakebin:$PATH"; export PATH FAKE_ABI FAKE_ABILIST
      MODPATH="$m" sh "$m/customize.sh" ) > "$HNC_TEST_DIR/out" 2>&1
}

elf_abi() { ( . "$ROOT/bin/hnc_arch.sh"; hnc_arch_elf_abi "$1" ); }
mode_of() { stat -c %a "$1" 2>/dev/null; }

# 所有原生二进制都是期望 ABI 且 0755
all_abi_755() {
    local m="$1" want="$2" b bad=""
    for b in $NATIVE; do
        [ "$(elf_abi "$m/bin/$b")" = "$want" ] || bad="$bad $b:abi=$(elf_abi "$m/bin/$b")"
        [ "$(mode_of "$m/bin/$b")" = 755 ] || bad="$bad $b:mode=$(mode_of "$m/bin/$b")"
    done
    [ "$(elf_abi "$m/daemon/hnc_httpd/hnc_httpd")" = "$want" ] || bad="$bad hnc_httpd:abi"
    [ "$(mode_of "$m/daemon/hnc_httpd/hnc_httpd")" = 755 ] || bad="$bad hnc_httpd:mode"
    echo "$bad"
}

# ─── 1. 单 ABI 包 ──────────────────────────────────
test_start "arch: arm64 device + arm64 package installs, binaries 0755"
mk_getprop; M="$HNC_TEST_DIR/mod"; mk_module "$M" arm64 arm64-v8a ""
FAKE_ABI=arm64-v8a FAKE_ABILIST=arm64-v8a,armeabi-v7a,armeabi; export FAKE_ABI FAKE_ABILIST
run_customize "$M"; rc=$?
assert_exit_zero "$rc" "arm64 包装到 arm64 设备应成功: $(cat "$HNC_TEST_DIR/out")" && \
    assert_eq "" "$(all_abi_755 "$M" arm64-v8a)" "二进制应保持 arm64 且 0755" && \
    assert_eq "644" "$(mode_of "$M/bin/hnc_clsact.o")" "BPF .o 不应带 +x" && \
    test_pass

test_start "arch: armeabi-v7a device + armv7 package installs"
mk_getprop; M="$HNC_TEST_DIR/mod"; mk_module "$M" arm armeabi-v7a ""
FAKE_ABI=armeabi-v7a FAKE_ABILIST=armeabi-v7a,armeabi; export FAKE_ABI FAKE_ABILIST
run_customize "$M"; rc=$?
assert_exit_zero "$rc" "armv7 包装到 armv7 设备应成功: $(cat "$HNC_TEST_DIR/out")" && \
    assert_eq "" "$(all_abi_755 "$M" armeabi-v7a)" "二进制应为 armv7 且 0755" && \
    test_pass

test_start "arch: armeabi-v7a device + arm64 package aborts → suggests armv7 zip"
mk_getprop; M="$HNC_TEST_DIR/mod"; mk_module "$M" arm64 arm64-v8a ""
FAKE_ABI=armeabi-v7a FAKE_ABILIST=armeabi-v7a,armeabi; export FAKE_ABI FAKE_ABILIST
run_customize "$M"; rc=$?
assert_exit_nonzero "$rc" "32 位设备刷 arm64 包必须中止" && \
    assert_contains "$(cat "$HNC_TEST_DIR/out")" "armv7.zip" "应提示改刷 armv7 包" && \
    test_pass

test_start "arch: arm64 device + armv7 package aborts → suggests arm64 zip"
mk_getprop; M="$HNC_TEST_DIR/mod"; mk_module "$M" arm armeabi-v7a ""
FAKE_ABI=arm64-v8a FAKE_ABILIST=arm64-v8a; export FAKE_ABI FAKE_ABILIST
run_customize "$M"; rc=$?
assert_exit_nonzero "$rc" "64 位设备刷 armv7 包必须中止" && \
    assert_contains "$(cat "$HNC_TEST_DIR/out")" "arm64.zip" "应提示改刷 arm64 包" && \
    test_pass

test_start "arch: x86_64 device aborts with unsupported-arch message"
mk_getprop; M="$HNC_TEST_DIR/mod"; mk_module "$M" arm64 arm64-v8a ""
FAKE_ABI=x86_64 FAKE_ABILIST=x86_64,x86,arm64-v8a; export FAKE_ABI FAKE_ABILIST
run_customize "$M"; rc=$?
assert_exit_nonzero "$rc" "x86_64 必须中止" && \
    assert_contains "$(cat "$HNC_TEST_DIR/out")" "不支持的 CPU 架构: x86_64" "应说明架构不支持" && \
    test_pass

test_start "arch: no marker → ELF sniff decides (armv7 binaries on arm64 device abort)"
mk_getprop; M="$HNC_TEST_DIR/mod"; mk_module "$M" arm "" ""
FAKE_ABI=arm64-v8a FAKE_ABILIST=arm64-v8a; export FAKE_ABI FAKE_ABILIST
run_customize "$M"; rc=$?
assert_exit_nonzero "$rc" "无标记时应按 ELF 判出 armv7 并中止" && \
    assert_eq "armeabi-v7a" "$( . "$ROOT/bin/hnc_arch.sh"; hnc_arch_pkg_abi "$M")" "ELF 嗅探应得 armeabi-v7a" && \
    test_pass

# ─── 2. 通用包(覆盖层)───────────────────────────
test_start "arch: universal package on armeabi-v7a device applies overlay"
mk_getprop; M="$HNC_TEST_DIR/mod"; mk_module "$M" arm64 arm64-v8a armeabi-v7a
FAKE_ABI=armeabi-v7a FAKE_ABILIST=armeabi-v7a,armeabi; export FAKE_ABI FAKE_ABILIST
run_customize "$M"; rc=$?
assert_exit_zero "$rc" "通用包装到 armv7 设备应成功: $(cat "$HNC_TEST_DIR/out")" && \
    assert_eq "" "$(all_abi_755 "$M" armeabi-v7a)" "覆盖后原路径应全是 armv7 且 0755" && \
    assert_eq "armeabi-v7a" "$(cat "$M/bin/hnc_pkg_abi")" "标记应改写为 armeabi-v7a" && \
    assert_eq "no" "$([ -d "$M/bin/armeabi-v7a" ] && echo yes || echo no)" "覆盖层目录应被删除" && \
    test_pass

test_start "arch: universal package on arm64 device keeps arm64, drops overlay"
mk_getprop; M="$HNC_TEST_DIR/mod"; mk_module "$M" arm64 arm64-v8a armeabi-v7a
FAKE_ABI=arm64-v8a FAKE_ABILIST=arm64-v8a,armeabi-v7a; export FAKE_ABI FAKE_ABILIST
run_customize "$M"; rc=$?
assert_exit_zero "$rc" "通用包装到 arm64 设备应成功: $(cat "$HNC_TEST_DIR/out")" && \
    assert_eq "" "$(all_abi_755 "$M" arm64-v8a)" "原路径应保持 arm64" && \
    assert_eq "no" "$([ -d "$M/bin/armeabi-v7a" ] && echo yes || echo no)" "armv7 覆盖层应被删除" && \
    test_pass

# ─── 3. ABI 探测顺序 ──────────────────────────────
test_start "arch: device ABI detection order (abi > abilist > \$ARCH)"
mk_getprop
d1=$( PATH="$HNC_TEST_DIR/fakebin:$PATH" FAKE_ABI="" FAKE_ABILIST="armeabi-v7a,armeabi" sh -c ". '$ROOT/bin/hnc_arch.sh'; hnc_arch_device_abi" )
d2=$( PATH="$HNC_TEST_DIR/fakebin:$PATH" FAKE_ABI="" FAKE_ABILIST="" ARCH=arm sh -c ". '$ROOT/bin/hnc_arch.sh'; hnc_arch_device_abi" )
d3=$( PATH="$HNC_TEST_DIR/fakebin:$PATH" FAKE_ABI="armeabi-v7a" FAKE_ABILIST="arm64-v8a" ARCH=arm64 sh -c ". '$ROOT/bin/hnc_arch.sh'; hnc_arch_device_abi" )
d4=$( HNC_ABI_OVERRIDE=aarch64 sh -c ". '$ROOT/bin/hnc_arch.sh'; hnc_arch_device_abi" )
assert_eq "armeabi-v7a" "$d1" "abi 为空时取 abilist 首项" && \
    assert_eq "armeabi-v7a" "$d2" "getprop 全空时取 \$ARCH=arm" && \
    assert_eq "armeabi-v7a" "$d3" "ro.product.cpu.abi 优先(64 位 CPU + 32 位系统)" && \
    assert_eq "arm64-v8a" "$d4" "HNC_ABI_OVERRIDE 规范化 aarch64" && \
    test_pass

# ─── 4. 装完后 service.sh 的二进制解析 ─────────────
# 复刻 service.sh sync_runtime_from_moddir 的拷贝(cp -rf bin/* + hnc_httpd 单拷),
# 然后检查 service.sh 引用的每个原生二进制在运行目录可执行且 ABI 正确。
sync_like_service() { # $1 = MODDIR, $2 = HNC_DIR
    mkdir -p "$2/bin" "$2/daemon/hnc_httpd"
    cp -rf "$1/bin/"* "$2/bin/"
    cp -f "$1/daemon/hnc_httpd/hnc_httpd" "$2/daemon/hnc_httpd/hnc_httpd"
    chmod 755 "$2/daemon/hnc_httpd/hnc_httpd"
    for b in $NATIVE; do [ -f "$2/bin/$b" ] && chmod 755 "$2/bin/$b"; done
}

test_start "arch: post-install service.sh resolves every native binary (armv7)"
mk_getprop; M="$HNC_TEST_DIR/mod"; H="$HNC_TEST_DIR/run_hnc"
mk_module "$M" arm64 arm64-v8a armeabi-v7a
FAKE_ABI=armeabi-v7a FAKE_ABILIST=armeabi-v7a,armeabi; export FAKE_ABI FAKE_ABILIST
run_customize "$M"
sync_like_service "$M" "$H"
bad=""
for b in hnc_dpid hnc_watchdog hnc_dpid_supervisor hnc_launcher hnc_ipc hnc_clsact_ctl; do
    grep -q "\$HNC_DIR/bin/$b\"" "$ROOT/service.sh" || bad="$bad service.sh-no-longer-uses:$b"
done
for b in $NATIVE; do
    [ -x "$H/bin/$b" ] || bad="$bad $b:not-exec"
    [ "$(elf_abi "$H/bin/$b")" = armeabi-v7a ] || bad="$bad $b:abi"
done
[ -x "$H/daemon/hnc_httpd/hnc_httpd" ] || bad="$bad hnc_httpd:not-exec"
[ "$(elf_abi "$H/daemon/hnc_httpd/hnc_httpd")" = armeabi-v7a ] || bad="$bad hnc_httpd:abi"
[ -d "$H/bin/armeabi-v7a" ] && bad="$bad overlay-leaked-to-runtime"
assert_eq "" "$bad" "运行目录二进制应全部可执行且为 armv7" && \
    test_pass

# service.sh 原文里的 v5.22 ABI 兜底块: customize.sh 没跑(覆盖层随 cp -rf
# 进了运行目录)时, 应在 $HNC_DIR 上补做覆盖并清掉覆盖层。
extract_service_abi_block() {
    sed -n '/^# v5.22 (armeabi-v7a): ABI 兜底/,/^    unset _hnc_dev_abi _hnc_pkg_abi _b$/p' "$ROOT/service.sh"
    echo "fi"
}

test_start "arch: service.sh runtime ABI fallback applies overlay when customize.sh skipped"
mk_getprop; M="$HNC_TEST_DIR/mod"; H="$HNC_TEST_DIR/run_hnc"
mk_module "$M" arm64 arm64-v8a armeabi-v7a      # 不跑 customize.sh
sync_like_service "$M" "$H"
extract_service_abi_block > "$HNC_TEST_DIR/abi_block.sh"
blk_lines=$(wc -l < "$HNC_TEST_DIR/abi_block.sh" | tr -d ' ')
( PATH="$HNC_TEST_DIR/fakebin:$PATH"; FAKE_ABI=armeabi-v7a; export PATH FAKE_ABI
  HNC_DIR="$H"; log() { echo "$*" >> "$HNC_TEST_DIR/svc.log"; }
  . "$HNC_TEST_DIR/abi_block.sh" ) > /dev/null 2>&1
assert_ne "1" "$blk_lines" "应能从 service.sh 抽出 ABI 兜底块" && \
    assert_eq "" "$(all_abi_755 "$H" armeabi-v7a)" "兜底块应把 armv7 覆盖到运行目录" && \
    assert_eq "no" "$([ -d "$H/bin/armeabi-v7a" ] && echo yes || echo no)" "运行目录覆盖层应被清掉" && \
    assert_contains "$(cat "$HNC_TEST_DIR/svc.log" 2>/dev/null)" "device=armeabi-v7a binaries=armeabi-v7a" "应记录 ABI 一致" && \
    test_pass

test_start "arch: service.sh runtime ABI fallback logs mismatch (arm64 pkg on armv7)"
mk_getprop; M="$HNC_TEST_DIR/mod"; H="$HNC_TEST_DIR/run_hnc"
mk_module "$M" arm64 arm64-v8a ""
sync_like_service "$M" "$H"
extract_service_abi_block > "$HNC_TEST_DIR/abi_block.sh"
( PATH="$HNC_TEST_DIR/fakebin:$PATH"; FAKE_ABI=armeabi-v7a; export PATH FAKE_ABI
  HNC_DIR="$H"; log() { echo "$*" >> "$HNC_TEST_DIR/svc.log"; }
  . "$HNC_TEST_DIR/abi_block.sh" ) > /dev/null 2>&1
assert_contains "$(cat "$HNC_TEST_DIR/svc.log" 2>/dev/null)" "ABI ERROR: device=armeabi-v7a but binaries=arm64-v8a" "ABI 不符应打 ERROR 日志" && \
    test_pass

unset FAKE_ABI FAKE_ABILIST
