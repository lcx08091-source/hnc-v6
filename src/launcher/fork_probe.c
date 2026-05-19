/*
 * fork_probe.c — HNC C fork+execv 能力探针
 *
 * 用途:
 *   service.sh 启动时跑这个探针,看 C fork+execv 在当前 ROM/内核能不能工作.
 *   能工作 → 用 hnc_launcher (C, 最优路径)
 *   不能工作 → 降级到 hnc_dpid_guard.sh (shell, 兼容)
 *
 * 背景:
 *   ColorOS 16 + SukiSU 内核组合上, Go runtime 用 CLONE_VM|CLONE_VFORK 的
 *   fork 路径会被某条内核策略拦下报 EPERM. 但同环境下 C 标准 fork() + execv()
 *   100% 工作. fork_probe 用最干净的 syscall 序列验证这一点.
 *
 * 用法:
 *   fork_probe /system/bin/true       # 简单探测 (推荐)
 *   fork_probe /system/bin/id         # 验证子进程能正常运行
 *
 * 退出码:
 *   0   = fork+execv 工作正常
 *   非0 = 失败 (具体看 stderr)
 *
 * Build:
 *   $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang \
 *       -O2 -Wall -o fork_probe fork_probe.c
 *
 * Author: Claude (Anthropic AI) + Ling
 * License: 同 HNC 项目主 license
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>

/* execv 失败时子进程退出码. 选 111 而不是 1, 跟正常 target 程序的 exit code 区分. */
#define EXIT_EXECV_FAIL 111

static void print_banner(void)
{
	fprintf(stdout, "=== fork_probe v1 ===\n");
	fprintf(stdout, "self pid=%d\n", (int)getpid());
}

int main(int argc, char **argv)
{
	const char *target;
	pid_t pid;
	int status;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <target_binary> [args...]\n", argv[0]);
		fprintf(stderr, "  example: %s /system/bin/true\n", argv[0]);
		return 2;
	}
	target = argv[1];

	print_banner();
	fprintf(stdout, "target=%s\n", target);
	fflush(stdout);

	/* [1/3] fork */
	fprintf(stdout, "[1/3] calling fork()...\n");
	fflush(stdout);

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "  FORK FAILED: errno=%d (%s)\n", errno, strerror(errno));
		return 1;
	}

	if (pid == 0) {
		/* 子进程 */
		fprintf(stdout, "  fork OK, in child (pid=%d, ppid=%d)\n",
			(int)getpid(), (int)getppid());
		fflush(stdout);

		/* [2/3] execv */
		fprintf(stdout, "[2/3] calling execv(%s)...\n", target);
		fflush(stdout);

		/* 用 target 自身作为 argv[0], 加上 main 收到的剩余参数 */
		execv(target, &argv[1]);

		/* execv 返回 = 失败. 否则永远到不了这里. */
		fprintf(stderr, "  EXECV FAILED: errno=%d (%s)\n", errno, strerror(errno));
		_exit(EXIT_EXECV_FAIL);
	}

	/* 父进程 */
	fprintf(stdout, "  fork OK, child pid=%d\n", (int)pid);
	fprintf(stdout, "[3/3] waiting for child...\n");
	fflush(stdout);

	if (waitpid(pid, &status, 0) < 0) {
		fprintf(stderr, "  WAITPID FAILED: errno=%d (%s)\n", errno, strerror(errno));
		return 1;
	}

	if (WIFEXITED(status)) {
		int rc = WEXITSTATUS(status);
		if (rc == 0) {
			fprintf(stdout, "  child exited 0  SUCCESS!\n");
			fprintf(stdout, "=== RESULT: C fork+execv WORKS on this device ===\n");
			return 0;
		}
		if (rc == EXIT_EXECV_FAIL) {
			fprintf(stdout, "  child exited with %d (execv failed, see stderr above)\n", rc);
			return 1;
		}
		/* execv 成功, target 本身退出非 0 — 仍说明 fork+execv 工作 */
		fprintf(stdout, "  child exited %d (non-zero but not %d  execv ran but target returned error)\n",
			rc, EXIT_EXECV_FAIL);
		fprintf(stdout, "=== RESULT: C fork+execv WORKS (target itself returned %d) ===\n", rc);
		return 0;
	}

	if (WIFSIGNALED(status)) {
		fprintf(stdout, "  child killed by signal %d\n", WTERMSIG(status));
		return 1;
	}

	fprintf(stderr, "  child died in unknown state (status=0x%x)\n", status);
	return 1;
}
