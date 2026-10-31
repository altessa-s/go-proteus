// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package goloader

import (
	"context"
	"sync"

	"github.com/altessa-s/go-proteus"
)

// processHandles retains handles and terminal loader failures for the process lifetime.
var processHandles = newHandleCache()

type cacheEntry struct {
	done     chan struct{}
	terminal bool
	symbols  proteus.Symbols
	err      error
}

type handleCache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
}

func newHandleCache() *handleCache { return &handleCache{entries: make(map[string]*cacheEntry)} }

func (c *handleCache) getOrOpen(ctx context.Context, digest string, fn func() (proteus.Symbols, bool, error)) (proteus.Symbols, bool, error) {
	c.mu.Lock()
	if entry, ok := c.entries[digest]; ok {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-entry.done:
			return entry.symbols, entry.terminal, entry.err
		}
	}
	entry := &cacheEntry{done: make(chan struct{})}
	c.entries[digest] = entry
	c.mu.Unlock()

	// Package initializers may open other images; never run them under the registry lock.
	entry.symbols, entry.terminal, entry.err = fn()
	c.mu.Lock()
	if !entry.terminal {
		delete(c.entries, digest)
	}
	close(entry.done)
	c.mu.Unlock()
	return entry.symbols, entry.terminal, entry.err
}
