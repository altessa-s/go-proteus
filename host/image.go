// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package host

import (
	"context"
	"sync"
	"time"

	"github.com/altessa-s/go-proteus"
)

// Mapped images cannot be initialized again after their last owner releases them.
var images = struct {
	sync.Mutex
	entries map[string]*imageEntry
}{entries: make(map[string]*imageEntry)}

type imageEntry struct {
	done chan struct{}
	refs int
	err  error
	// Store only the hook; each releasing manager supplies its own watchdog.
	closeFn func(context.Context) error
}

// acquireImage distinguishes terminal image failures from callers abandoning a shared wait.
func acquireImage(
	ctx context.Context, timeout time.Duration, opened proteus.Opened, initialize func() error, closeFn func(context.Context) error,
) (release func(context.Context) error, contentFailure bool, err error) {
	if !opened.Mapped {
		if err = initialize(); err != nil {
			return nil, true, err
		}
		return (&imageEntry{closeFn: closeFn, refs: 1}).release, false, nil
	}
	images.Lock()
	if entry, ok := images.entries[opened.SHA256]; ok {
		images.Unlock()
		waitCtx := ctx
		if timeout > 0 {
			var cancel context.CancelFunc
			waitCtx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		select {
		case <-waitCtx.Done():
			return nil, false, waitCtx.Err()
		case <-entry.done:
		}
		images.Lock()
		defer images.Unlock()
		if entry.err != nil {
			return nil, true, entry.err
		}
		if entry.refs == 0 {
			return nil, true, proteus.ErrAlreadyLoaded
		}
		entry.refs++
		return entry.release, false, nil
	}
	entry := &imageEntry{done: make(chan struct{}), closeFn: closeFn}
	images.entries[opened.SHA256] = entry
	images.Unlock()
	err = initialize()
	images.Lock()
	entry.err = err
	if err == nil {
		entry.refs = 1
	}
	close(entry.done)
	images.Unlock()
	if err != nil {
		return nil, true, err
	}
	return entry.release, false, nil
}

func (e *imageEntry) release(ctx context.Context) error {
	images.Lock()
	e.refs--
	last := e.refs == 0
	images.Unlock()
	if last && e.closeFn != nil {
		return e.closeFn(ctx)
	}
	return nil
}
