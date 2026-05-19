#!/system/bin/sh
# bin/device_class.sh — Patch 4 D1 · MAC OUI → device_class 分类
#
# 用法:
#   device_class.sh <mac>           查询设备类型(带缓存)
#   device_class.sh -n <mac>        不读不写缓存(测试/诊断)
#
# 输出 (stdout):
#   一行字符串,可能是:
#     Apple / Android / Windows / Linux / IoT / Network / Other / Privacy
#   出错时输出空字符串(caller 应当回退默认值)
#
# 算法:
#   1. MAC 第二字符判 LSB:
#      - 奇数(1/3/5/7/9/B/D/F) → "Privacy" (locally-administered MAC,
#                                典型来自 iOS/Android 隐私模式)
#      - 偶数(0/2/4/6/8/A/C/E) → 走 OUI 表 lookup
#   2. OUI 表 = $HNC_DIR/data/oui.txt 格式: <6字符大写OUI>\t<vendor>\t<class>
#   3. MAC 前 6 字符大写无冒号 grep
#   4. 命中 → 输出 class 字段
#   5. 不命中 → "Other"
#
# 缓存:
#   $HNC_DIR/run/dev_class_cache 行格式 "<MAC>\t<class>\t<ts>"
#   TTL 24h. 命中即返回,不命中查 oui.txt 后写入.
#   shell 这里不做并发锁,因为单条 line append 是原子的(<128 字节满足
#   PIPE_BUF 保证),最差结果只是同一 MAC 写多条,不影响正确性.

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && \
    export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-/data/local/hnc}
OUI_FILE="$HNC_DIR/data/oui.txt"
CACHE_FILE="$HNC_DIR/run/dev_class_cache"
CACHE_TTL=86400   # 24 小时

NO_CACHE=0
if [ "$1" = "-n" ]; then
    NO_CACHE=1
    shift
fi

MAC=$1
if [ -z "$MAC" ]; then
    echo ""
    exit 1
fi

# 标准化 MAC: 转小写
MAC_LC=$(echo "$MAC" | tr 'A-F' 'a-f')

# ── 1. 缓存查询 ────────────────────────────────────────────────
if [ "$NO_CACHE" = "0" ] && [ -f "$CACHE_FILE" ]; then
    NOW=$(date +%s)
    # awk 一次扫:命中 + 未过期 → 输出 class 退出
    HIT=$(awk -F'\t' -v m="$MAC_LC" -v now="$NOW" -v ttl="$CACHE_TTL" '
        $1 == m && (now - $3) < ttl { print $2; exit }
    ' "$CACHE_FILE" 2>/dev/null)
    if [ -n "$HIT" ]; then
        echo "$HIT"
        exit 0
    fi
fi

# ── 2. 判断 locally-administered (Privacy MAC) ─────────────────
# IEEE 802 MAC 第 1 字节结构: aaaa aaul
#   bit 0 (LSB) = u/m (unicast/multicast)
#   bit 1       = u/l (universal/locally-administered)
# Privacy MAC = bit 1 set = (byte & 0x02) != 0
#
# 第 2 个 hex 字符的二进制低位决定 bit 1:
#   hex  binary  bit1
#    0   0000     0    universal
#    2   0010     1    Privacy ✓
#    4   0100     0    universal
#    6   0110     1    Privacy ✓
#    8   1000     0    universal
#    A   1010     1    Privacy ✓
#    C   1100     0    universal
#    E   1110     1    Privacy ✓
#    1/3/5/7/9/B/D/F  → multicast(LSB=1), 不是合法的源 MAC,但保险起见
#                      也按 universal 分类(虽然这不该出现在 ARP 表里)
SECOND_CHAR=$(echo "$MAC_LC" | cut -c2)
case "$SECOND_CHAR" in
    2|6|a|e)
        CLASS="Privacy"
        ;;
    *)
        # universal admin → 真厂商 → OUI 查表
        OUI=$(echo "$MAC_LC" | tr -d ':' | cut -c1-6 | tr 'a-f' 'A-F')
        if [ -n "$OUI" ] && [ -f "$OUI_FILE" ]; then
            CLASS=$(awk -F'\t' -v o="$OUI" '$1 == o { print $3; exit }' "$OUI_FILE" 2>/dev/null)
        fi
        [ -z "$CLASS" ] && CLASS="Other"
        ;;
esac

# ── 3. 写缓存 ──────────────────────────────────────────────────
# rc3.1.34 修 #25: 之前 append-only 不去重, 长跑 (设备上线/掉线无数次) 缓存
# 文件 unbounded 增长. awk lookup 仍然取 first hit (TTL 校验), 但每次扫全文件.
# 修法: append 前先把同 MAC 的旧行去掉. 用 awk 重写一遍, 比 sed/grep 更可靠
# (避免 MAC 字符串里有 regex 元字符的边缘 case, 实际 MAC 只含 0-9a-f: 不会触发).
# 用 printf 避免 echo -e 在 Android sh 输出 "-e " 字面字符串的 bug
if [ "$NO_CACHE" = "0" ]; then
    [ -d "$(dirname "$CACHE_FILE")" ] || mkdir -p "$(dirname "$CACHE_FILE")" 2>/dev/null
    if [ -f "$CACHE_FILE" ]; then
        # 先去重: 把同 MAC 的旧行删掉, 输出到 tmp 再 mv
        awk -F'\t' -v m="$MAC_LC" '$1 != m { print }' "$CACHE_FILE" \
            > "${CACHE_FILE}.tmp.$$" 2>/dev/null \
            && mv "${CACHE_FILE}.tmp.$$" "$CACHE_FILE" 2>/dev/null
    fi
    printf '%s\t%s\t%s\n' "$MAC_LC" "$CLASS" "$(date +%s)" >> "$CACHE_FILE" 2>/dev/null
fi

echo "$CLASS"
