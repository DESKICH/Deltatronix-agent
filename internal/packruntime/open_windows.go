//go:build windows

package packruntime

import "os"

func openRegularCandidate(path string) (*os.File, error) { return os.Open(path) }
