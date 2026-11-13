package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func (r actionResult) ok() bool { return r.err == nil && r.exitCode == 0 }

// runBoundedCommand distinguishes a command that never started from a successful
// exit. Timeout cancels the complete child process group, including grandchildren.
func runBoundedCommand(timeout time.Duration, capture bool, name string, args ...string) actionResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 2 * time.Second
	var out []byte
	var err error
	if capture {
		out, err = cmd.Output()
	} else {
		// nil streams use /dev/null, without copying goroutines or inherited pipes.
		err = cmd.Run()
	}
	res := actionResult{stdout: strings.TrimSpace(string(out))}
	if ctx.Err() != nil {
		res.exitCode, res.err = -1, fmt.Errorf("command %s timed out after %v: %w", name, timeout, ctx.Err())
		return res
	}
	if err != nil {
		var ee *exec.ExitError
		switch {
		case errors.As(err, &ee):
			res.exitCode = ee.ExitCode()
		case errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil:
			// The script completed; a deliberately detached descendant kept stdout.
			res.exitCode = cmd.ProcessState.ExitCode()
		default:
			res.exitCode, res.err = -1, err
		}
	}
	return res
}
