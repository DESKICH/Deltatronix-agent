//go:build !windows

package packruntime

import (
	"golang.org/x/sys/unix"
	"os"
)

// Nonblocking open prevents a regular file replaced by a FIFO from stalling
// verification before the descriptor/identity checks can refuse it.
func openRegularCandidate(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
