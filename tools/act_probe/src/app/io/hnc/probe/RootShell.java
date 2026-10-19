package io.hnc.probe;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import io.hnc.probe.core.RootParsers;

/**
 * root 模式用的常驻 su 会话(避免每 3 秒拉起一次 su)。
 * 只执行白名单里的固定只读命令(dumpsys / cat /sys/... / id), 不拼接任何外部输入, 不改系统任何东西。
 * 超时或出错就关掉整个会话(避免输出错位), 下次需要时再开。
 */
final class RootShell {
    static final Set<String> ALLOWED = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "id", RootParsers.SAMPLE_CMD, RootParsers.MAC_CMD)));

    private static final String EOF = new String("<EOF>");

    private Process proc;
    private OutputStream stdin;
    private Thread reader;
    private final LinkedBlockingQueue<String> lines = new LinkedBlockingQueue<>();
    private int seq;

    /** 打开并确认是 uid=0。第一次可能要等用户在 root 管理器里点允许, 所以超时给长一点。 */
    synchronized boolean open(long timeoutMs) {
        if (proc != null) return true;
        try {
            proc = new ProcessBuilder("su").redirectErrorStream(true).start();
        } catch (IOException e) {
            proc = null;
            return false;
        }
        stdin = proc.getOutputStream();
        final Process p = proc;
        lines.clear();
        reader = new Thread(() -> {
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String l;
                while ((l = r.readLine()) != null) lines.offer(l);
            } catch (IOException ignored) {
                // 进程退出
            }
            lines.offer(EOF);
        }, "su-reader");
        reader.setDaemon(true);
        reader.start();
        String id = run("id", timeoutMs);
        if (id == null || !id.contains("uid=0")) {
            close();
            return false;
        }
        return true;
    }

    synchronized boolean isOpen() { return proc != null; }

    /** 执行一条白名单命令, 返回输出; 超时 / 会话断了返回 null。 */
    synchronized String run(String cmd, long timeoutMs) {
        if (!ALLOWED.contains(cmd)) throw new IllegalArgumentException("命令不在只读白名单里");
        if (proc == null) return null;
        String marker = "__HNC_PROBE_END_" + (++seq) + "__";
        lines.clear();
        try {
            stdin.write((cmd + "\necho " + marker + "\n").getBytes(StandardCharsets.UTF_8));
            stdin.flush();
        } catch (IOException e) {
            close();
            return null;
        }
        StringBuilder b = new StringBuilder();
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (true) {
            long left = deadline - System.currentTimeMillis();
            String l;
            try {
                l = left > 0 ? lines.poll(left, TimeUnit.MILLISECONDS) : null;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                l = null;
            }
            if (l == null || l == EOF) {
                close();
                return null;
            }
            if (l.equals(marker)) return b.toString();
            if (b.length() < (256 << 10)) b.append(l).append('\n');
        }
    }

    synchronized void close() {
        if (proc != null) {
            try {
                stdin.write("exit\n".getBytes(StandardCharsets.UTF_8));
                stdin.flush();
            } catch (IOException ignored) {
                // 已经断了
            }
            proc.destroy();
        }
        proc = null;
        stdin = null;
        reader = null;
    }
}
