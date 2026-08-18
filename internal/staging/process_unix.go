//go:build !windows

package staging

import (
	"errors"
	"os"
	"syscall"
)

// processIsRunning reports whether a process with the given PID currently
// exists.
//
// On Unix, os.FindProcess never fails, so liveness has to be probed by sending
// signal 0. ESRCH means the process is gone; EPERM means it exists but belongs
// to another user, which still counts as running.
func processIsRunning(pid int) bool {
	if pid <= 0 {
		return false
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	err = process.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}

	return errors.Is(err, syscall.EPERM)
}
