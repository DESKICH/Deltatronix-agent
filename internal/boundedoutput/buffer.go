// Package boundedoutput shares the existing native child output fence.
package boundedoutput

import (
	"bytes"
	"context"
	"errors"
	"sync"
)

var ErrLimit = errors.New("native output limit exceeded")

type Buffer struct {
	mu       sync.Mutex
	b        bytes.Buffer
	Max      int
	Overflow context.CancelFunc
	Observe  func([]byte) error
}

func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.b.Len()+len(p) > b.Max {
		b.Overflow()
		return 0, ErrLimit
	}
	if b.Observe != nil {
		if err := b.Observe(p); err != nil {
			b.Overflow()
			return 0, err
		}
	}
	return b.b.Write(p)
}
func (b *Buffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.b.Bytes()...)
}
