#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include "../hnc_helpers.h"

static double elapsed_ms(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) * 1000.0 + (b.tv_nsec - a.tv_nsec) / 1000000.0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strncmp(argv[1], "--child-", 8) == 0) {
        if (strcmp(argv[1], "--child-descendant") == 0) {
            pid_t descendant = fork();
            if (descendant < 0) return 2;
            if (descendant > 0) {
                char pid_buf[32];
                int len = snprintf(pid_buf, sizeof(pid_buf), "%ld", (long)descendant);
                (void)write(STDOUT_FILENO, pid_buf, (size_t)len);
                return 0;
            }
            /* Inherit stdout after the direct child exits. */
        }
        if (strcmp(argv[1], "--child-full") == 0) {
            char full[256];
            memset(full, 'x', sizeof(full));
            (void)write(STDOUT_FILENO, full, sizeof(full));
        }
        if (strcmp(argv[1], "--child-output") == 0 || strcmp(argv[1], "--child-quick") == 0)
            (void)write(STDOUT_FILENO, "hello", 5);
        if (strcmp(argv[1], "--child-quick") == 0) return 0;
        if (strcmp(argv[1], "--child-eof") == 0 || strcmp(argv[1], "--child-output") == 0)
            close(STDOUT_FILENO);
        struct timespec pause = {.tv_sec = 2, .tv_nsec = 0};
        while (nanosleep(&pause, &pause) < 0 && errno == EINTR) {}
        return 0;
    }
    alarm(10);
    const char *cases[] = {"--child-eof", "--child-output", "--child-silent", "--child-quick", "--child-full"};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char *cmd[] = {argv[0], (char *)cases[i], NULL};
        char buf[128];
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        int n = hnc_run_cmd_timeout(cmd, buf, sizeof(buf), 100);
        clock_gettime(CLOCK_MONOTONIC, &end);
        double elapsed = elapsed_ms(start, end);
        int want = (i == 1 || i == 3) ? 5 : (i == 4 ? 127 : 0);
        if (n != want || ((i == 1 || i == 3) && strcmp(buf, "hello") != 0) || elapsed >= 1500) {
            fprintf(stderr, "FAIL %s: bytes=%d wanted=%d elapsed=%.0fms\n", cases[i], n, want, elapsed);
            return 1;
        }
        int status;
        if (waitpid(-1, &status, WNOHANG) != -1 || errno != ECHILD) {
            fprintf(stderr, "FAIL %s: child not reaped\n", cases[i]);
            return 1;
        }
        printf("PASS %s: bytes=%d elapsed=%.0fms\n", cases[i], n, elapsed);
    }
    /* Adopt the short-lived descendant so this host-only test leaves no orphan. */
    if (prctl(PR_SET_CHILD_SUBREAPER, 1) != 0) {
        perror("PR_SET_CHILD_SUBREAPER");
        return 1;
    }
    char *cmd[] = {argv[0], "--child-descendant", NULL};
    char buf[128];
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int n = hnc_run_cmd_timeout(cmd, buf, sizeof(buf), 100);
    clock_gettime(CLOCK_MONOTONIC, &end);
    long descendant = 0;
    if (n <= 0 || sscanf(buf, "%ld", &descendant) != 1 || descendant <= 0) {
        fprintf(stderr, "FAIL descendant pid: %s\n", buf);
        return 1;
    }
    kill((pid_t)descendant, SIGKILL);
    int status;
    while (waitpid((pid_t)descendant, &status, 0) < 0 && errno == EINTR) {}
    double elapsed = elapsed_ms(start, end);
    if (elapsed >= 1500) {
        fprintf(stderr, "FAIL inherited stdout: elapsed=%.0fms\n", elapsed);
        return 1;
    }
    printf("PASS inherited stdout: elapsed=%.0fms\n", elapsed);
    return 0;
}
