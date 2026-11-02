//go:build unix

package secretstest

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// availableBytes returns the free space, in bytes, that an unprivileged process can use on the volume holding dir.
func availableBytes(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, fmt.Errorf("failed to read free space of %q: %w", dir, err)
	}

	// Bavail is the space available to non-root users, unlike Bfree which includes the root reserve.
	// The field types differ between platforms, hence the conversion.
	return st.Bavail * uint64(st.Bsize), nil //nolint:gosec // the block size is never negative
}
