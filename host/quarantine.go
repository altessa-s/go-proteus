// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package host

import (
	"cmp"
	"slices"
	"sync"
	"time"

	"github.com/altessa-s/go-proteus"
)

type quarantineBook struct {
	mu      sync.RWMutex
	entries map[string]proteus.QuarantineEntry
}

func newQuarantineBook() *quarantineBook {
	return &quarantineBook{
		entries: make(map[string]proteus.QuarantineEntry),
	}
}

func (q *quarantineBook) add(source, sha256 string, reason error, now time.Time) (proteus.QuarantineEntry, bool) {
	if !proteus.IsValidSHA256Hex(sha256) || reason == nil {
		return proteus.QuarantineEntry{}, false
	}
	entry := proteus.QuarantineEntry{
		Source: source,
		SHA256: sha256,
		Reason: reason,
		Since:  now.UTC(),
	}
	q.mu.Lock()
	q.entries[sha256] = entry
	q.mu.Unlock()
	return entry, true
}

func (q *quarantineBook) isQuarantined(sha256 string) bool {
	if !proteus.IsValidSHA256Hex(sha256) {
		return false
	}
	q.mu.RLock()
	_, ok := q.entries[sha256]
	q.mu.RUnlock()
	return ok
}

func (q *quarantineBook) remove(sha256 string) bool {
	q.mu.Lock()
	_, ok := q.entries[sha256]
	if ok {
		delete(q.entries, sha256)
	}
	q.mu.Unlock()
	return ok
}

func (q *quarantineBook) clear() {
	q.mu.Lock()
	clear(q.entries)
	q.mu.Unlock()
}

func (q *quarantineBook) len() int {
	q.mu.RLock()
	n := len(q.entries)
	q.mu.RUnlock()
	return n
}

func (q *quarantineBook) snapshot() []proteus.QuarantineEntry {
	q.mu.RLock()
	out := make([]proteus.QuarantineEntry, 0, len(q.entries))
	for _, entry := range q.entries {
		out = append(out, entry)
	}
	q.mu.RUnlock()
	slices.SortFunc(out, func(a, b proteus.QuarantineEntry) int {
		if c := cmp.Compare(a.Source, b.Source); c != 0 {
			return c
		}
		return cmp.Compare(a.SHA256, b.SHA256)
	})
	return out
}
