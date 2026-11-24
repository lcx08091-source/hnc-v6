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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>		/* rc30.12.29: flock() for singleton lock */

/* ─── 编译期常量 ───────────────────────────────────────────────────── */

/* 编译期由 build.sh 从根目录 module.prop 自动注入 -DHNC_VERSION;
 * 保留 0.1.0- 代际前缀并嵌入模块版本。 */
#ifndef HNC_VERSION
#define HNC_VERSION             "dev"
#endif
#define VERSION                 ("0.1.0-" HNC_VERSION)

#define BIN_DPID                "/data/local/hnc/bin/hnc_dpid"
#define DPID_CONFIG             "/data/local/hnc/etc/dpi_config.json"
#define PID_DPID                "/data/local/hnc/run/dpid.pid"
#define PID_GUARD               "/data/local/hnc/run/dpid_guard.pid"
#define CRASH_FLAG              "/data/local/hnc/run/dpid.crashflag"
#define LOG_LAUNCHER            "/data/local/hnc/logs/dpid_launcher.log"
#define LOG_DPID                "/data/local/hnc/logs/dpid.log"

/* 重启策略 */
#define RESTART_BACKOFF_MIN     2          /* 第一次重启等 2s */
#define RESTART_BACKOFF_MAX     30         /* 最长 30s (指数退避封顶) */
#define STABLE_RUN_RESET_SEC    30         /* 稳定运行 >=30s 后重置 backoff = 2s */
#define CRASH_WINDOW_SEC        60         /* 60s 滑动窗口 */
#define CRASH_LIMIT             5          /* 窗口内 5 次崩溃 → 进入冷却(非永久放弃) */
#define CRASH_COOLDOWN_SEC      120        /* rc12: 崩溃风暴后冷却 120s 再自愈重试 */
#define CRASH_FLAG_MAX_BYTES    4096       /* dpid.crashflag 4KB 硬上限裁剪 */

/* ─── 全局状态 ─────────────────────────────────────────────────────── */

static volatile sig_atomic_t g_shutdown = 0;
static volatile sig_atomic_t g_child_pid = 0;

/* ─── 日志 ─────────────────────────────────────────────────────────── */

static FILE *g_log = NULL;

static void log_open(void)
{
	/* v5.12: "e" = O_CLOEXEC。旧 "a" 打开的日志 fd 会被每个 fork+execv 出来的
	 * hnc_dpid 继承, dpid 全程无意义地持有 launcher 日志 fd。 */
	g_log = fopen(LOG_LAUNCHER, "ae");
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

/* ─── 文件操作与进程加固 helpers ───────────────────────────────────── */

static void set_oom_score_adj(const char *val)
{
	int fd = open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	(void)write(fd, val, strlen(val));
	close(fd);
}

static int write_pid_file(const char *path, pid_t pid)
{
	FILE *f = fopen(path, "we");
	if (f == NULL)
		return -1;
	fprintf(f, "%d\n", (int)pid);
	fclose(f);
	return 0;
}

static pid_t read_pid_file(const char *path)
{
	FILE *f = fopen(path, "re");
	int raw_pid = 0;
	if (f == NULL)
		return 0;
	if (fscanf(f, "%d", &raw_pid) != 1 || raw_pid <= 0)
		raw_pid = 0;
	fclose(f);
	return (pid_t)raw_pid;
}

/* ─── 单实例保护 (flock + fstat/stat inode 校验防 unlink 孤岛双实例) ── */

static int g_lock_fd = -1;

static int check_singleton(void)
{
	int attempt;

	for (attempt = 0; attempt < 4; attempt++) {
		int fd = open(PID_GUARD, O_CREAT | O_RDWR | O_CLOEXEC, 0644);
		if (fd < 0) {
			log_msg("cannot open %s: errno=%d %s",
				PID_GUARD, errno, strerror(errno));
			return -1;
		}
		if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
			pid_t existing = read_pid_file(PID_GUARD);
			log_msg("another launcher running (PID=%d), exiting",
				(int)existing);
			close(fd);
			return -1;
		}

		struct stat st_fd, st_path;
		if (fstat(fd, &st_fd) != 0 || stat(PID_GUARD, &st_path) != 0 ||
		    st_fd.st_dev != st_path.st_dev || st_fd.st_ino != st_path.st_ino) {
			close(fd);
			continue; /* 旧实例退出瞬间刚 unlink 了该孤岛 inode, 重试当前路径 */
		}

		if (ftruncate(fd, 0) < 0) {
			log_msg("ftruncate %s failed: errno=%d %s",
				PID_GUARD, errno, strerror(errno));
		}
		(void)lseek(fd, 0, SEEK_SET);
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

	log_msg("failed to acquire stable inode lock on %s", PID_GUARD);
	return -1;
}

static void cleanup_singleton_and_log(void)
{
	if (g_lock_fd >= 0) {
		struct stat st_fd, st_path;
		if (fstat(g_lock_fd, &st_fd) == 0 &&
		    stat(PID_GUARD, &st_path) == 0 &&
		    st_fd.st_dev == st_path.st_dev &&
		    st_fd.st_ino == st_path.st_ino) {
			unlink(PID_GUARD);
		}
		close(g_lock_fd);
		g_lock_fd = -1;
	}
	if (g_log != NULL && g_log != stderr) {
		fclose(g_log);
		g_log = NULL;
	}
}

/* ─── Crash loop 保护 ─────────────────────────────────────────────── */

struct crash_tracker {
	int64_t timestamps[CRASH_LIMIT];
	int count;
};

static void crash_tracker_init(struct crash_tracker *t)
{
	memset(t, 0, sizeof(*t));
}

static int64_t mono_sec(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
		return (int64_t)ts.tv_sec;
	return (int64_t)time(NULL);
}

static int crash_tracker_record(struct crash_tracker *t)
{
	int64_t now = mono_sec();
	int kept = 0;
	int i;

	/* 1. 压缩: 把窗口内的留下, 窗口外的丢掉 (CLOCK_MONOTONIC 防 NTP 跳变) */
	for (i = 0; i < t->count; i++) {
		if (now >= t->timestamps[i] &&
		    now - t->timestamps[i] <= (int64_t)CRASH_WINDOW_SEC)
			t->timestamps[kept++] = t->timestamps[i];
	}

	/* 2. 追加当前崩溃 (数组满了就丢最老的, 用 memmove 保留语义) */
	if (kept >= CRASH_LIMIT) {
		memmove(&t->timestamps[0], &t->timestamps[1],
			sizeof(int64_t) * (CRASH_LIMIT - 1));
		t->timestamps[CRASH_LIMIT - 1] = now;
		t->count = CRASH_LIMIT;
	} else {
		t->timestamps[kept++] = now;
		t->count = kept;
	}

	return t->count >= CRASH_LIMIT;
}

/* 对 dpid.crashflag 实施 4KB 裁剪, 保留尾部完整行防止长期零星重启撑爆文件 */
static void trim_crash_flag_if_needed(void)
{
	struct stat st;
	if (stat(CRASH_FLAG, &st) != 0 || st.st_size <= (off_t)CRASH_FLAG_MAX_BYTES)
		return;

	int fd = open(CRASH_FLAG, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return;

	char tail[CRASH_FLAG_MAX_BYTES / 2];
	off_t keep_off = st.st_size - (off_t)sizeof(tail);
	if (keep_off < 0)
		keep_off = 0;

	ssize_t n = 0;
	if (lseek(fd, keep_off, SEEK_SET) >= 0)
		n = read(fd, tail, sizeof(tail));

	if (n <= 0) {
		(void)ftruncate(fd, 0);
		close(fd);
		return;
	}

	size_t start = 0;
	if (keep_off > 0) {
		while (start < (size_t)n && tail[start] != '\n')
			start++;
		if (start < (size_t)n)
			start++;
	}

	size_t kept_len = (size_t)n - start;
	if (lseek(fd, 0, SEEK_SET) == 0) {
		if (kept_len > 0)
			(void)write(fd, tail + start, kept_len);
		(void)ftruncate(fd, (off_t)kept_len);
	}
	close(fd);
}

static void write_crash_flag(void)
{
	trim_crash_flag_if_needed();
	FILE *f = fopen(CRASH_FLAG, "ae");
	if (f) {
		fprintf(f, "%lld\n", (long long)time(NULL));
		fclose(f);
	}
}

/* 读取 CRASH_FLAG, 统计窗口 CRASH_WINDOW_SEC 内的有效 Unix 秒时间戳行数.
 * 注意: Go dpid 正常启动前 5 分钟内文件恒有 1 行 armed 时间戳, 严禁凭文件存在即睡 120s! */
static int count_recent_crash_flags(void)
{
	trim_crash_flag_if_needed();

	FILE *f = fopen(CRASH_FLAG, "re");
	char line[64];
	long long now_ll;
	int recent = 0;

	if (f == NULL)
		return 0;

	now_ll = (long long)time(NULL);
	while (fgets(line, sizeof(line), f) != NULL) {
		char *p = line;
		char *endp = NULL;
		long long ts;

		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '\0' || *p == '\r' || *p == '\n')
			continue;
		errno = 0;
		ts = strtoll(p, &endp, 10);
		if (errno != 0 || endp == p || ts <= 0)
			continue;
		while (*endp == ' ' || *endp == '\t' || *endp == '\r' || *endp == '\n')
			endp++;
		if (*endp != '\0')
			continue;
		if (ts <= now_ll + 5 && now_ll - ts <= CRASH_WINDOW_SEC)
			recent++;
	}
	fclose(f);
	return recent;
}

static void cooldown_sleep(int sec)
{
	int waited = 0;
	while (waited < sec && !g_shutdown) {
		sleep(1);
		waited++;
	}
}

/* ─── Signal 处理 ─────────────────────────────────────────────────── */

static void on_term_signal(int sig)
{
	int saved_errno = errno;
	pid_t cpid;
	(void)sig;
	g_shutdown = 1;
	cpid = (pid_t)g_child_pid;
	if (cpid > 0)
		kill(cpid, SIGTERM);
	errno = saved_errno;
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
	sigaddset(&sa.sa_mask, SIGTERM);
	sigaddset(&sa.sa_mask, SIGINT);
	sigaddset(&sa.sa_mask, SIGHUP);
	/* 不要 SA_RESTART, 让 waitpid 被信号打断 */
	if (sigaction(SIGTERM, &sa, NULL) < 0 ||
	    sigaction(SIGINT, &sa, NULL) < 0 ||
	    sigaction(SIGHUP, &sa, NULL) < 0)
		return -1;

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = on_child_signal;
	if (sigaction(SIGCHLD, &sa, NULL) < 0)
		return -1;

	/* SIGPIPE 忽略 (写日志文件时如果磁盘满可能触发) */
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);

	return 0;
}

/* ─── DPID 子进程 ─────────────────────────────────────────────────── */

static int dup2_nocloexec(int fd, int target)
{
	if (fd == target) {
		int fl = fcntl(target, F_GETFD);
		if (fl < 0)
			return -1;
		if (fl & FD_CLOEXEC) {
			if (fcntl(target, F_SETFD, fl & ~FD_CLOEXEC) < 0)
				return -1;
		}
		return target;
	}
	return dup2(fd, target);
}

static void close_inherited_fds(void)
{
	DIR *dir = opendir("/proc/self/fd");
	if (dir != NULL) {
		int dfd = dirfd(dir);
		struct dirent *de;
		while ((de = readdir(dir)) != NULL) {
			char *endp = NULL;
			long fd;
			if (de->d_name[0] < '0' || de->d_name[0] > '9')
				continue;
			errno = 0;
			fd = strtol(de->d_name, &endp, 10);
			if (errno != 0 || endp == de->d_name || *endp != '\0')
				continue;
			if (fd > STDERR_FILENO && fd != (long)dfd && fd <= 1048576L)
				(void)close((int)fd);
		}
		closedir(dir);
		return;
	}
	long max_fd = sysconf(_SC_OPEN_MAX);
	if (max_fd < 0 || max_fd > 4096)
		max_fd = 1024;
	for (long fd = STDERR_FILENO + 1; fd < max_fd; fd++)
		(void)close((int)fd);
}

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
		/* 子进程恢复默认 oom_score_adj=0 (不继承守护进程 -900 免死金牌) */
		set_oom_score_adj("0\n");

		struct sigaction sa_dfl;
		sigset_t empty_mask;
		memset(&sa_dfl, 0, sizeof(sa_dfl));
		sa_dfl.sa_handler = SIG_DFL;
		sigemptyset(&sa_dfl.sa_mask);
		sigaction(SIGPIPE, &sa_dfl, NULL);
		sigemptyset(&empty_mask);
		sigprocmask(SIG_SETMASK, &empty_mask, NULL);

		int null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
		if (null_fd >= 0) {
			(void)dup2_nocloexec(null_fd, STDIN_FILENO);
			if (null_fd != STDIN_FILENO)
				close(null_fd);
		}

		int fd = open(LOG_DPID, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
		if (fd >= 0) {
			(void)dup2_nocloexec(fd, STDOUT_FILENO);
			(void)dup2_nocloexec(fd, STDERR_FILENO);
			if (fd != STDOUT_FILENO && fd != STDERR_FILENO)
				close(fd);
		}

		close_inherited_fds();

		char *const dpid_argv[] = {
			(char *)"hnc_dpid",
			(char *)"-config",
			(char *)DPID_CONFIG,
			NULL,
		};
		execv(BIN_DPID, dpid_argv);

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
		if (g_shutdown)
			return -1;
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
	struct crash_tracker fork_fails;
	int backoff = RESTART_BACKOFF_MIN;

	crash_tracker_init(&crashes);
	crash_tracker_init(&fork_fails);

	while (!g_shutdown) {
		pid_t pid;
		int rc, signum, abnormal;
		int64_t spawn_mono = mono_sec();

		/* 启动 dpid */
		pid = spawn_dpid();
		if (pid < 0) {
			log_msg("fork failed (errno=%d), retrying after %ds backoff",
				errno, backoff);
			if (crash_tracker_record(&fork_fails)) {
				log_msg("FORK_LOOP: %d fork failures in %ds; cooling down %ds then self-healing "
					"(no permanent give-up)",
					CRASH_LIMIT, CRASH_WINDOW_SEC, CRASH_COOLDOWN_SEC);
				write_crash_flag();
				cooldown_sleep(CRASH_COOLDOWN_SEC);
				if (g_shutdown)
					break;
				unlink(CRASH_FLAG);
				crash_tracker_init(&fork_fails);
				backoff = RESTART_BACKOFF_MIN;
				continue;
			}
			if (g_shutdown)
				break;
			sleep((unsigned int)backoff);
			if (g_shutdown)
				break;
			if (backoff < RESTART_BACKOFF_MAX) {
				backoff *= 2;
				if (backoff > RESTART_BACKOFF_MAX)
					backoff = RESTART_BACKOFF_MAX;
			}
			continue;
		}

		if (g_shutdown) {
			kill(pid, SIGTERM);
			break;
		}

		/* 等子进程退出 */
		abnormal = wait_dpid(pid, &rc, &signum);
		if (abnormal < 0) {
			/* waitpid 错误或被 shutdown 打断 */
			break;
		}

		if (g_shutdown)
			break;

		/* 子进程已稳定运行 >=30s, 重置指数退避为初始 2s */
		if (mono_sec() - spawn_mono >= (int64_t)STABLE_RUN_RESET_SEC)
			backoff = RESTART_BACKOFF_MIN;

		if (abnormal == 0) {
			log_msg("dpid exited rc=0 without supervisor shutdown "
				"(external SIGTERM / stale guard?); treating as unexpected, restarting");
		}

		/* 异常退出 或 意外的 rc=0 — 记崩溃, 检查 loop 保护 */
		if (crash_tracker_record(&crashes)) {
			log_msg("CRASH_LOOP: %d crashes in %ds; cooling down %ds then self-healing "
				"(no permanent give-up)",
				CRASH_LIMIT, CRASH_WINDOW_SEC, CRASH_COOLDOWN_SEC);
			if (count_recent_crash_flags() == 0)
				write_crash_flag();
			cooldown_sleep(CRASH_COOLDOWN_SEC);
			if (g_shutdown)
				break;
			unlink(CRASH_FLAG);
			crash_tracker_init(&crashes);
			backoff = RESTART_BACKOFF_MIN;
			continue;
		}

		/* 重启 */
		log_msg("restarting dpid in %ds...", backoff);
		sleep((unsigned int)backoff);
		if (g_shutdown)
			break;
		if (backoff < RESTART_BACKOFF_MAX) {
			backoff *= 2;
			if (backoff > RESTART_BACKOFF_MAX)
				backoff = RESTART_BACKOFF_MAX;
		}
	}

	log_msg("shutting down (signal received)");

	/* 如果子进程还在, 等它退 */
	if (g_child_pid > 0) {
		int status;
		int waited;
		pid_t cpid = (pid_t)g_child_pid;
		log_msg("waiting for dpid pid=%d to exit", (int)cpid);
		kill(cpid, SIGTERM);
		for (waited = 0; waited < 100; waited++) {	/* 100 × 100ms = 10s */
			pid_t r = waitpid(cpid, &status, WNOHANG);
			if (r == cpid || (r < 0 && errno != EINTR))
				break;
			usleep(100 * 1000);
		}
		if (waited >= 100) {
			log_msg("dpid pid=%d did not exit in 10s, SIGKILL", (int)cpid);
			kill(cpid, SIGKILL);
			while (waitpid(cpid, &status, 0) < 0 && errno == EINTR)
				;
		}
		g_child_pid = 0;
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
	int recent_crashes;

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
	if (check_singleton() < 0) {
		if (g_log != NULL && g_log != stderr)
			fclose(g_log);
		return 1;
	}

	/* 守护进程自身写 oom_score_adj=-900 防 LMKD 误杀 (子进程在 fork 后重置为 0) */
	set_oom_score_adj("-900\n");

	if (install_signal_handlers() < 0) {
		log_msg("failed to install signal handlers: errno=%d %s",
			errno, strerror(errno));
		cleanup_singleton_and_log();
		return 1;
	}

	recent_crashes = count_recent_crash_flags();
	if (recent_crashes >= CRASH_LIMIT) {
		log_msg("crashflag storm active (%s, recent=%d >= %d in %ds); cooling down %ds "
			"then resuming supervision (self-heal, no permanent observe)",
			CRASH_FLAG, recent_crashes, CRASH_LIMIT, CRASH_WINDOW_SEC, CRASH_COOLDOWN_SEC);
		cooldown_sleep(CRASH_COOLDOWN_SEC);
		if (g_shutdown) {
			log_msg("crashflag cooldown interrupted by signal; exiting");
			cleanup_singleton_and_log();
			return 0;
		}
		unlink(CRASH_FLAG);
	}

	int rc = run_supervise_loop();
	cleanup_singleton_and_log();
	return rc;
}
