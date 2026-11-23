package boundedoutput

import (
	"bytes"
	"errors"
	"testing"
)

func TestBufferCancelsWithoutRetainingOverflow(t *testing.T) {
	cancelled := 0
	b := &Buffer{Max: 3, Overflow: func() { cancelled++ }}
	if n, e := b.Write([]byte("abc")); n != 3 || e != nil {
		t.Fatal(n, e)
	}
	if n, e := b.Write([]byte("d")); n != 0 || !errors.Is(e, ErrLimit) || cancelled != 1 {
		t.Fatal(n, e, cancelled)
	}
	detached := b.Bytes()
	detached[0] = 'x'
	if !bytes.Equal(b.Bytes(), []byte("abc")) {
		t.Fatal("buffer ownership escaped")
	}
}
func TestBufferObserverRefusalCancelsBeforeStore(t *testing.T) {
	cancelled := false
	refusal := errors.New("bad frame")
	b := &Buffer{Max: 3, Overflow: func() { cancelled = true }, Observe: func([]byte) error { return refusal }}
	if n, e := b.Write([]byte("a")); n != 0 || !errors.Is(e, refusal) || !cancelled || len(b.Bytes()) != 0 {
		t.Fatal(n, e, cancelled)
	}
}
