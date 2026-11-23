//go:build !windows

package packruntime

import (
	"golang.org/x/sys/unix"
	"path/filepath"
	"testing"
	"time"
)

func TestRegularCandidateDoesNotBlockOnReplacementFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replaced")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		f, err := openRegularCandidate(path)
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("opening replacement FIFO blocked")
	}
	if _, err := RegularFile(path); err == nil {
		t.Fatal("FIFO accepted as regular input")
	}
}
