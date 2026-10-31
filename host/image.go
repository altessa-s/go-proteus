// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package host

import (
	"context"
	"sync"

	"github.com/altessa-s/go-proteus"
)

// Mapped images cannot be initialized again after their last owner releases them.
var images = struct {
	sync.Mutex
	entries map[string]*imageEntry
}{entries: make(map[string]*imageEntry)}

type imageEntry struct {
	done    chan struct{}
	refs    int
	err     error
	closeFn func(context.Context) error
}

func acquireImage(
	ctx context.Context, opened proteus.Opened, initialize func() error, closeFn func(context.Context) error,
) (func(context.Context) error, error) {
	if !opened.Mapped {
		if err := initialize(); err != nil {
			return nil, err
		}
		return closeFn, nil
	}
	images.Lock()
	if entry, ok := images.entries[opened.SHA256]; ok {
		images.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-entry.done:
		}
		images.Lock()
		defer images.Unlock()
		if entry.err != nil {
			return nil, entry.err
		}
		if entry.refs == 0 {
			return nil, proteus.ErrAlreadyLoaded
		}
		entry.refs++
		return entry.release, nil
	}
	entry := &imageEntry{done: make(chan struct{}), closeFn: closeFn}
	images.entries[opened.SHA256] = entry
	images.Unlock()
	err := initialize()
	images.Lock()
	entry.err = err
	if err == nil {
		entry.refs = 1
	}
	close(entry.done)
	images.Unlock()
	if err != nil {
		return nil, err
	}
	return entry.release, nil
}

func (e *imageEntry) release(ctx context.Context) error {
	images.Lock()
	e.refs--
	last := e.refs == 0
	images.Unlock()
	if last {
		return e.closeFn(ctx)
	}
	return nil
}
