/*
 * hnc_launcher.c — HNC DPID 守护进程
 *
 * 功能:
 *   - fork + execv 启动 hnc_dpid
 *   - 子进程挂掉自动重启 (带 crash loop 保护)
 *   - 优雅处理 SIGTERM / SIGINT / SIGHUP
 *   - 写 PID 文件 (dpid.pid + dpid_guard.pid)
 *   - 维护 crash flag 给上游知道发生过崩溃
 *   - 检测自身重复启动 (基于 dpid_guard.pid)
 *
 * 为什么用 C:
 *   ColorOS 16 + SukiSU 上 Go runtime 的 fork+execv 路径会被内核策略拦下报 EPERM
 *   (CLONE_VM|CLONE_VFORK 触发某条 hardening rule). 标准 C fork() + execv() 100%
 *   工作. 所以 v5.3.0 引入 C launcher 替代 Go supervisor.
 *
 * 启动决策由 service.sh 完成 (基于 fork_probe 探测), 详见:
 *   - service.sh 中 LAUNCHER_CHOICE 逻辑
 *
 * Crash Loop 保护:
 *   如果 RESTART_WINDOW_SEC (默认 60s) 内崩溃次数 >= CRASH_LIMIT (默认 5),
 *   写 crashflag 并进入 observe 模式 (不再重启). 需手动删 crashflag 恢复.
 *   这样防止 dpid 持续闪退把日志和系统资源刷爆.
 *
 * Build:
 *   $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang \
 *       -static -O2 -Wall -o hnc_launcher hnc_launcher.c
 *
 *   静态链接是因为 dpid_launcher 可能在 post-fs-data 早期阶段启动,
 *   /system/lib64 还未必 mount, 动态链接可能加载失败.
 *
 * Version: 0.1.0-rc30.12
 * Author: Claude (Anthropic AI) + Ling
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>		/* rc30.12.29: flock() for singleton lock */

/* ─── 编译期常量 ───────────────────────────────────────────────────── */

#define VERSION                 "0.1.0-rc30.13.1"

#define BIN_DPID                "/data/local/hnc/bin/hnc_dpid"
#define DPID_CONFIG             "/data/local/hnc/etc/dpi_config.json"
#define PID_DPID                "/data/local/hnc/run/dpid.pid"
#define PID_GUARD               "/data/local/hnc/run/dpid_guard.pid"
#define CRASH_FLAG              "/data/local/hnc/run/dpid_crashflag"
#define LOG_LAUNCHER            "/data/local/hnc/logs/dpid_launcher.log"
#define LOG_DPID                "/data/local/hnc/logs/dpid.log"

/* 重启策略 */
#define RESTART_BACKOFF_MIN     2          /* 第一次重启等 2s */
#define RESTART_BACKOFF_MAX     30         /* 最长 30s (指数退避封顶) */
#define CRASH_WINDOW_SEC        60         /* 60s 滑动窗口 */
#define CRASH_LIMIT             5          /* 窗口内 5 次崩溃 → observe 模式 */

/* ─── 全局状态 ─────────────────────────────────────────────────────── */

static volatile sig_atomic_t g_shutdown = 0;
static volatile sig_atomic_t g_child_pid = 0;

/* ─── 日志 ─────────────────────────────────────────────────────────── */

/*
 * 用 line-buffered FILE* 输出. open() + dup2() 把 stdout/stderr 重定向到日志
 * 是更干净的做法, 但保留 fprintf 兼容 strings 里 "[%s] [LAUNCHER] %s" 格式.
 */
static FILE *g_log = NULL;

static void log_open(void)
{
	g_log = fopen(LOG_LAUNCHER, "a");
	if (g_log == NULL)
		g_log = stderr;
	setvbuf(g_log, NULL, _IOLBF, 0);
}

static void log_msg(const char *fmt, ...)
{
	char tbuf[32];
	time_t now = time(NULL);
	struct tm tm;
	va_list ap;

	if (g_log == NULL)
		log_open();

	localtime_r(&now, &tm);
	strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm);

	fprintf(g_log, "[%s] [LAUNCHER] ", tbuf);
	va_start(ap, fmt);
	vfprintf(g_log, fmt, ap);
	va_end(ap);
	fputc('\n', g_log);
}

/* ─── 文件操作 helpers ─────────────────────────────────────────────── */

static int file_exists(const char *path)
{
	struct stat st;
	return stat(path, &st) == 0;
}

static int write_pid_file(const char *path, pid_t pid)
{
	FILE *f = fopen(path, "w");
	if (f == NULL)
		return -1;
	fprintf(f, "%d\n", (int)pid);
	fclose(f);
	return 0;
}

static pid_t read_pid_file(const char *path)
{
	FILE *f = fopen(path, "r");
	pid_t pid = 0;
	if (f == NULL)
		return 0;
	if (fscanf(f, "%d", (int *)&pid) != 1)
		pid = 0;
	fclose(f);
	return pid;
}

/* rc30.12.29 (P1.10): pid_alive() 已删除 — check_singleton 改 flock 后不再使用 */

/* ─── 单实例保护 ──────────────────────────────────────────────────── */

/* rc30.12.29 (P1.10): TOCTOU 修复.
 * 之前 check_singleton 是 read_pid → kill(pid, 0) → write_pid_file 两阶段,
 * 中间窗口里两个 launcher 同时启动可能都过检查然后都写 pid, 后写者赢但实际
 * 有两个 launcher 在抢 dpid.
 *
 * 现在: open(O_CREAT|O_RDWR) + flock(LOCK_EX|LOCK_NB) 一步原子锁定.
 * fd 故意全程不 close — kernel 在进程退出时自动释放 flock, 干净.
 * 如果锁被另一个 launcher 持有, 读 pid 报告并退出. */
static int g_lock_fd = -1;

static int check_singleton(void)
{
	int fd = open(PID_GUARD, O_CREAT | O_RDWR | O_CLOEXEC, 0644);
	if (fd < 0) {
		log_msg("cannot open %s: errno=%d %s",
			PID_GUARD, errno, strerror(errno));
		return -1;
	}
	if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
		/* 另一个 launcher 已持锁 — 读它的 pid 用于日志 */
		pid_t existing = read_pid_file(PID_GUARD);
		log_msg("another launcher running (PID=%d), exiting",
			(int)existing);
		close(fd);
		return -1;
	}
	/* 持锁成功. 写自己的 pid. ftruncate 清掉前一个 launcher 残留的 pid. */
	if (ftruncate(fd, 0) < 0) {
		log_msg("ftruncate %s failed: errno=%d %s",
			PID_GUARD, errno, strerror(errno));
		/* 非致命, 继续 */
	}
	char buf[32];
	int n = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
	if (n <= 0 || write(fd, buf, (size_t)n) != n) {
		log_msg("write pid to %s failed: errno=%d %s",
			PID_GUARD, errno, strerror(errno));
		close(fd);
		return -1;
	}
	/* fd 不 close — 持续持有 flock 直到进程退出 */
	g_lock_fd = fd;
	return 0;
}

/* ─── Crash loop 保护 ─────────────────────────────────────────────── */

struct crash_tracker {
	time_t timestamps[CRASH_LIMIT];
	int count;
};

static void crash_tracker_init(struct crash_tracker *t)
{
	memset(t, 0, sizeof(*t));
}

/* 记录一次崩溃. 返回 1 表示窗口内崩溃数 >= 阈值 (需进 observe 模式) */
/* rc30.12.29 (P1.9): 重写为 "先压缩窗口外, 再追加新崩溃" 的两步语义.
 * 之前是 "滑动窗口里现有几次 + 加新条目 + 滚动覆盖" 三步交错,
 * 在窗口边界滚动时容易让人误读. 行为等价, 代码更直白. */
static int crash_tracker_record(struct crash_tracker *t)
{
	time_t now = time(NULL);
	int kept = 0;
	int i;

	/* 1. 压缩: 把窗口内的留下, 窗口外的丢掉 */
	for (i = 0; i < t->count; i++) {
		if (now - t->timestamps[i] <= CRASH_WINDOW_SEC)
			t->timestamps[kept++] = t->timestamps[i];
	}

	/* 2. 追加当前崩溃 (数组满了就丢最老的, 用 memmove 保留语义) */
	if (kept >= CRASH_LIMIT) {
		memmove(&t->timestamps[0], &t->timestamps[1],
			sizeof(time_t) * (CRASH_LIMIT - 1));
		t->timestamps[CRASH_LIMIT - 1] = now;
		t->count = CRASH_LIMIT;
	} else {
		t->timestamps[kept++] = now;
		t->count = kept;
	}

	return t->count >= CRASH_LIMIT;
}

static void write_crash_flag(void)
{
	FILE *f = fopen(CRASH_FLAG, "w");
	if (f) {
		fprintf(f, "%ld\n", (long)time(NULL));
		fclose(f);
	}
}

/* ─── Signal 处理 ─────────────────────────────────────────────────── */

static void on_term_signal(int sig)
{
	g_shutdown = 1;
	if (g_child_pid > 0)
		kill(g_child_pid, SIGTERM);
}

static void on_child_signal(int sig)
{
	/* SIGCHLD 不在主循环里 reap, 让 waitpid 在主循环阻塞 */
	(void)sig;
}

static int install_signal_handlers(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_term_signal;
	sigemptyset(&sa.sa_mask);
	/* 不要 SA_RESTART, 让 waitpid 被信号打断 */
	if (sigaction(SIGTERM, &sa, NULL) < 0 ||
	    sigaction(SIGINT, &sa, NULL) < 0 ||
	    sigaction(SIGHUP, &sa, NULL) < 0)
		return -1;

	sa.sa_handler = on_child_signal;
	if (sigaction(SIGCHLD, &sa, NULL) < 0)
		return -1;

	/* SIGPIPE 忽略 (写日志文件时如果磁盘满可能触发) */
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);

	return 0;
}

/* ─── DPID 子进程 ─────────────────────────────────────────────────── */

/*
 * 启动 dpid. 返回 pid (子进程), 失败返回 -1.
 * 标准输出和标准错误重定向到 dpid.log.
 */
static pid_t spawn_dpid(void)
{
	pid_t pid;

	log_msg("bin_dpid=%s", BIN_DPID);
	log_msg("dpid_config=%s", DPID_CONFIG);

	pid = fork();
	if (pid < 0) {
		log_msg("fork failed: errno=%d %s", errno, strerror(errno));
		return -1;
	}

	if (pid == 0) {
		/* 子进程: 重定向 stdout/stderr 到 dpid.log */
		int fd = open(LOG_DPID, O_WRONLY | O_CREAT | O_APPEND, 0644);
		if (fd >= 0) {
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			if (fd > 2)
				close(fd);
		}

		/*
		 * argv[]: { "hnc_dpid", "-config", DPID_CONFIG, NULL }
		 * execv 不查 PATH, 必须传绝对路径.
		 */
		char *const dpid_argv[] = {
			(char *)"hnc_dpid",
			(char *)"-config",
			(char *)DPID_CONFIG,
			NULL,
		};
		execv(BIN_DPID, dpid_argv);

		/* execv 失败. fprintf 到 stderr 现在指向 dpid.log */
		fprintf(stderr, "execv failed: errno=%d %s\n", errno, strerror(errno));
		_exit(127);
	}

	/* 父进程 */
	write_pid_file(PID_DPID, pid);
	g_child_pid = pid;
	log_msg("dpid spawned, pid=%d", (int)pid);
	return pid;
}

/* 等待子进程退出. 返回 0=干净退出, 1=异常退出, -1=waitpid 错误 */
static int wait_dpid(pid_t pid, int *out_rc, int *out_signum)
{
	int status;
	pid_t r;

	*out_rc = 0;
	*out_signum = 0;

	for (;;) {
		r = waitpid(pid, &status, 0);
		if (r < 0) {
			if (errno == EINTR) {
				if (g_shutdown)
					return -1;
				continue;
			}
			log_msg("waitpid failed: errno=%d %s", errno, strerror(errno));
			return -1;
		}
		break;
	}

	g_child_pid = 0;
	unlink(PID_DPID); /* dpid 不在了, 删 pid 文件 */

	if (WIFEXITED(status)) {
		int rc = WEXITSTATUS(status);
		*out_rc = rc;
		if (rc == 0) {
			log_msg("dpid pid=%d exited cleanly (rc=0)", (int)pid);
			return 0;
		}
		log_msg("dpid pid=%d exited with rc=%d", (int)pid, rc);
		return 1;
	}

	if (WIFSIGNALED(status)) {
		int sig = WTERMSIG(status);
		*out_signum = sig;
		log_msg("dpid pid=%d killed by signal %d", (int)pid, sig);
		return 1;
	}

	log_msg("dpid pid=%d exited abnormally (status=0x%x)", (int)pid, status);
	return 1;
}

/* ─── 主循环 ──────────────────────────────────────────────────────── */

static int run_supervise_loop(void)
{
	struct crash_tracker crashes;
	struct crash_tracker fork_fails;  /* rc30.13.1: 独立追踪 fork 失败 */
	int backoff = RESTART_BACKOFF_MIN;

	crash_tracker_init(&crashes);
	crash_tracker_init(&fork_fails);

	while (!g_shutdown) {
		pid_t pid;
		int rc, signum, abnormal;

		/* 启动 dpid */
		pid = spawn_dpid();
		if (pid < 0) {
			/* rc30.13.1 fix: 上一版日志 "spawning dpid anyway (it will
			 * go blind mode)" 误导 — fork 失败根本没 spawn 任何东西.
			 * 改成据实描述. 同时加 fork 失败的 crash tracker, 防止系统
			 * OOM / ulimit 触顶时无限重试 (上一版只在 dpid 真跑起来后
			 * 异常退出才计数, fork 失败永远不进 observe 模式). */
			log_msg("fork failed (errno=%d), retrying after %ds backoff",
				errno, backoff);
			if (crash_tracker_record(&fork_fails)) {
				log_msg("FORK_LOOP: %d fork failures in %ds window, "
					"refusing to retry. Clear %s manually to recover.",
					CRASH_LIMIT, CRASH_WINDOW_SEC, CRASH_FLAG);
				write_crash_flag();
				return 1;
			}
			if (g_shutdown)
				break;
			sleep(backoff);
			if (backoff < RESTART_BACKOFF_MAX)
				backoff *= 2;
			continue;
		}

		/* 等子进程退出 */
		abnormal = wait_dpid(pid, &rc, &signum);
		if (abnormal < 0) {
			/* waitpid 错误或被 shutdown 打断 */
			break;
		}

		if (g_shutdown)
			break;

		if (abnormal == 0) {
			/* dpid rc=0 退出 = 主动停止, 不重启 */
			log_msg("dpid exited cleanly, supervisor stopping");
			break;
		}

		/* 异常退出 — 记崩溃, 检查 loop 保护 */
		if (crash_tracker_record(&crashes)) {
			log_msg("CRASH_LOOP: %d crashes in %ds window, refusing to restart. "
				"Clear %s manually to recover.",
				CRASH_LIMIT, CRASH_WINDOW_SEC, CRASH_FLAG);
			write_crash_flag();
			return 1;
		}

		/* 重启 */
		log_msg("restarting dpid in %ds...", backoff);
		sleep(backoff);
		if (backoff < RESTART_BACKOFF_MAX)
			backoff *= 2;
	}

	log_msg("shutting down (signal received)");

	/* 如果子进程还在, 等它退 */
	if (g_child_pid > 0) {
		int status;
		log_msg("waiting for dpid pid=%d to exit", (int)g_child_pid);
		waitpid(g_child_pid, &status, 0);
		unlink(PID_DPID);
	}

	return 0;
}

/* ─── main ────────────────────────────────────────────────────────── */

static void print_usage(const char *argv0)
{
	fprintf(stdout,
		"hnc_launcher %s — HNC DPID supervisor\n"
		"\n"
		"Usage: %s [--version] [--help]\n"
		"\n"
		"Runs in foreground (under nohup). Supervises %s, restarting it\n"
		"on abnormal exit with exponential backoff. Exits cleanly when:\n"
		"  - dpid exits with rc=0 (manual stop)\n"
		"  - SIGTERM/SIGINT received\n"
		"  - crash loop threshold (%d crashes in %ds) reached\n"
		"\n"
		"Files:\n"
		"  pid file:    %s (self)\n"
		"               %s (dpid)\n"
		"  log file:    %s\n"
		"  crash flag:  %s (clear to resume after crash loop)\n",
		VERSION, argv0, BIN_DPID,
		CRASH_LIMIT, CRASH_WINDOW_SEC,
		PID_GUARD, PID_DPID, LOG_LAUNCHER, CRASH_FLAG);
}

int main(int argc, char **argv)
{
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--version") == 0) {
			printf("hnc_launcher %s\n", VERSION);
			return 0;
		}
		if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
			print_usage(argv[0]);
			return 0;
		}
		fprintf(stderr, "unknown argument: %s\n", argv[i]);
		print_usage(argv[0]);
		return 2;
	}

	log_open();
	log_msg("hnc_launcher %s starting (pid=%d)", VERSION, (int)getpid());

	/* 单实例检查 */
	if (check_singleton() < 0)
		return 1;

	/* 检查 crashflag — 存在则进 observe 模式 */
	if (file_exists(CRASH_FLAG)) {
		log_msg("crashflag exists (%s), starting in observe mode (no auto-restart). "
			"Delete the file to resume.", CRASH_FLAG);
		/* observe 模式: 不启动 dpid, 等待信号 */
		install_signal_handlers();
		while (!g_shutdown)
			pause();
		log_msg("observe mode: shutting down (signal received)");
		return 0;
	}

	if (install_signal_handlers() < 0) {
		log_msg("failed to install signal handlers: errno=%d %s",
			errno, strerror(errno));
		return 1;
	}

	return run_supervise_loop();
}
