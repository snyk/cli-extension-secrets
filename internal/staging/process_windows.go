//go:build windows

package staging

import "os"

// processIsRunning reports whether a process with the given PID currently
// exists.
//
// On Windows, os.FindProcess opens a handle to the process and fails when no
// such process exists, so it is sufficient on its own. A handle to an
// already-exited-but-not-reaped process can still be opened, which biases this
// towards reporting "running" - the safe direction, since the caller only uses
// this to decide whether to leave a directory alone.
func processIsRunning(pid int) bool {
	if pid <= 0 {
		return false
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	defer func() { _ = process.Release() }()

	return true
}
