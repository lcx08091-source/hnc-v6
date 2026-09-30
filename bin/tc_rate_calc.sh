#!/system/bin/sh
# tc_rate_calc.sh — v5.20 HTB class 参数(burst / quantum)纯计算, 无副作用。
# 被 tc_manager.sh(设备限速)与 apply_app_limits.sh(应用限速)共同 source,
# 保证两条路径同一套算法。只定义函数, 不执行任何命令。
#
# 设计依据(沿用 tc_manager.sh 文件头的 v3.2.0/hotfix17.5 取舍):
#   - burst 按"时间窗"定: compat 2.5k/Mbps ≈ 20.5ms 数据量, precise 1k/Mbps ≈ 8.2ms。旧的"1 秒量"
#     burst 会让多线程同时命中令牌桶窗口冲破限速线, 所以窗口保持在毫秒级;
#     相对超发上限 ≈ 窗口/测速窗口(20ms/1s = 2%), 与速率无关。
#   - 低速(<1Mbps): 旧下限 16k 在 0.1Mbps 下 ≈ 1.3 秒量, 短时超发明显。新下限按
#     速率缩放: clamp(rate×125ms, 2×MTU, 16k)(precise: rate×62.5ms, 上限 8k),
#     ≥~1.05Mbps 时与旧值完全一致, 只有 <1Mbps 变严。
#   - 高速(≥100Mbps): 旧值固定 200k, 300Mbps 下只有 5ms, Wi-Fi 驱动成批完成
#     TX(A-MPDU)时 HTB 追不上 → 实测低于设定值。新值 = max(200k, 时间窗量),
#     compat 上限 4096k, precise 上限 1024k。
#   - ≥1000Mbps 视为"不限"(DEFAULT_RATE=1000mbit), 保留历史 200k。
#   - 输出单位 k(tc size: 1k = 1024 字节), 向上取整, 与历史输出格式一致。
#   - quantum: HTB 缺省 quantum = rate/r2q(r2q=10), 低于 ~121kbit 时 <MTU 触发内核
#     "quantum is small" 告警, 高于 16Mbit 时 >200000 触发 "quantum is big"。显式给
#     quantum = clamp(rate_Bps/10, 1514, 60000), 消除告警并让兄弟类 DRR 轮转更细。
#     设备 class ceil=rate(不借用), quantum 只影响公平性, 不影响限速上限。

# hnc_burst_k <mbps> [compat|precise] → "<n>k"
hnc_burst_k() {
    awk -v v="${1:-0}" -v m="${2:-compat}" 'BEGIN {
        v = v + 0
        if (v <= 0) { print "16k"; exit }
        if (v >= 1000) { print "200k"; exit }
        bps = v * 1000000 / 8
        mtu2 = 3028
        if (m == "precise") {
            # 1k/Mbps ≈ 8.2ms(与 hotfix17.5 precise 的 int(v×1.0)k 一致)
            win = 0.008192; fl = bps * 0.0625; flmax = 8192
            cap = (v >= 100) ? 1024 * 1024 : 64 * 1024
        } else {
            # 2.5k/Mbps ≈ 20.5ms(与 v3.2.0 起 compat 的 int(v×2.5)k 一致)
            win = 0.02048; fl = bps * 0.125; flmax = 16384
            cap = (v >= 100) ? 4096 * 1024 : 256 * 1024
        }
        if (fl < mtu2) fl = mtu2
        if (fl > flmax) fl = flmax
        b = bps * win
        if (b < fl) b = fl
        if (b > cap) b = cap
        if (v >= 100 && b < 200 * 1024) b = 200 * 1024
        k = int(b / 1024 + 0.9999)   # 向上取整(容忍浮点误差)
        print k "k"
    }'
}

# hnc_quantum <mbps> → 整数字节
hnc_quantum() {
    awk -v v="${1:-0}" 'BEGIN {
        q = int((v + 0) * 1000000 / 8 / 10)
        if (q < 1514) q = 1514
        if (q > 60000) q = 60000
        print q
    }'
}
