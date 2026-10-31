// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package goloader

import (
	"sync"

	"github.com/altessa-s/go-proteus"
)

type cacheEntry struct {
	once    sync.Once
	symbols proteus.Symbols
	err     error
}

type handleCache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
}

func newHandleCache() *handleCache {
	return &handleCache{
		entries: make(map[string]*cacheEntry),
	}
}

func (c *handleCache) getOrOpen(sha256 string, fn func() (proteus.Symbols, error)) (proteus.Symbols, error) {
	c.mu.Lock()
	entry, ok := c.entries[sha256]
	if !ok {
		entry = &cacheEntry{}
		c.entries[sha256] = entry
	}
	c.mu.Unlock()

	entry.once.Do(func() {
		entry.symbols, entry.err = fn()
	})
	return entry.symbols, entry.err
}
