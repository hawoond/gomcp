package server

import (
	"bytes"
	"errors"
	"sync"
)

var errOutputLimitExceeded = errors.New("output limit exceeded")

type limitedBuffer struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	remaining int64
	exceeded  bool
}

func newLimitedBuffer(limit int64) *limitedBuffer {
	return &limitedBuffer{remaining: limit}
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.remaining <= 0 {
		b.exceeded = true
		return 0, errOutputLimitExceeded
	}
	writeLength := int64(len(data))
	if writeLength > b.remaining {
		writeLength = b.remaining
		b.exceeded = true
	}
	written, err := b.buffer.Write(data[:writeLength])
	b.remaining -= int64(written)
	if err != nil {
		return written, err
	}
	if written < len(data) {
		return written, errOutputLimitExceeded
	}
	return written, nil
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func (b *limitedBuffer) Exceeded() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exceeded
}
