// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package goloader

import (
	"sync"

	"github.com/altessa-s/go-proteus"
)

// processHandles retains handles and terminal loader failures for the process lifetime.
var processHandles = newHandleCache()

type cacheEntry struct {
	symbols proteus.Symbols
	err     error
}

type handleCache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
}

func newHandleCache() *handleCache { return &handleCache{entries: make(map[string]cacheEntry)} }

func (c *handleCache) getOrOpen(digest string, fn func() (proteus.Symbols, bool, error)) (proteus.Symbols, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[digest]; ok {
		return entry.symbols, true, entry.err
	}
	syms, terminal, err := fn()
	if terminal {
		c.entries[digest] = cacheEntry{symbols: syms, err: err}
	}
	return syms, terminal, err
}
