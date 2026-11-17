package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// parentPIDEnv names the process whose exit ends this proxy (asm patch). The
// supervisor runs iron-proxy in its own process group, so a supervisor that dies
// without shutting it down (SIGKILL, crash) would otherwise leave it holding the
// listen ports.
const parentPIDEnv = "IRON_PARENT_PID"

// parentPollInterval is the fallback check interval where kqueue is unavailable.
const parentPollInterval = 500 * time.Millisecond

// parentFromEnv returns the pid in IRON_PARENT_PID, 0 when unset.
func parentFromEnv(getenv func(string) string) (int, error) {
	raw := getenv(parentPIDEnv)
	if raw == "" {
		return 0, nil
	}
	pid, err := strconv.Atoi(raw)
	if err != nil || pid <= 1 {
		return 0, fmt.Errorf("%s: invalid pid %q", parentPIDEnv, raw)
	}
	return pid, nil
}

// watchParent returns a channel that is closed once process pid has exited.
// Already gone (or reparented away from pid) when called → closed at once.
func watchParent(pid int) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		if waitExitKqueue(pid) {
			return
		}
		// Fallback: we were started by pid, so its exit reparents us.
		for os.Getppid() == pid {
			time.Sleep(parentPollInterval)
		}
	}()
	return done
}
