//go:build windows

package secretstest

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// availableBytes returns the free space, in bytes, that the current user can use on the volume holding dir.
func availableBytes(dir string) (uint64, error) {
	dirPtr, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, fmt.Errorf("invalid directory %q: %w", dir, err)
	}

	// The first value respects the user's disk quota, unlike the total free bytes.
	var freeForUser, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(dirPtr, &freeForUser, &total, &totalFree); err != nil {
		return 0, fmt.Errorf("failed to read free space of %q: %w", dir, err)
	}

	return freeForUser, nil
}
