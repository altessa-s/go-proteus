// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package goloader

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"

	"github.com/altessa-s/go-proteus"
)

// White-box access isolates registry scheduling from filesystem I/O and the real loader.
func TestHandleCacheConcurrentOpens(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		cache := newHandleCache()
		success := func() (proteus.Symbols, bool, error) { return nil, true, nil }
		if _, _, err := cache.getOrOpen(t.Context(), "cached", success); err != nil {
			t.Fatal(err)
		}
		unblock := make(chan struct{})
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			_, _, _ = cache.getOrOpen(t.Context(), "blocked", func() (proteus.Symbols, bool, error) {
				<-unblock
				symbols, err := invokeOpenSafe(t.Context(), "", func(context.Context, string) (proteus.Symbols, error) { panic("init panic") })
				return symbols, true, err
			})
		}()
		synctest.Wait()
		if _, _, err := cache.getOrOpen(t.Context(), "cached", success); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		waited := make(chan error, 1)
		go func() {
			_, terminal, err := cache.getOrOpen(ctx, "blocked", success)
			if terminal {
				t.Error("canceled wait is terminal")
			}
			waited <- err
		}()
		synctest.Wait()
		cancel()
		if err := <-waited; !errors.Is(err, context.Canceled) {
			t.Fatalf("wait: %v", err)
		}
		close(unblock)
		<-finished
		_, terminal, err := cache.getOrOpen(t.Context(), "blocked", success)
		if !terminal || !errors.Is(err, proteus.ErrPanicked) {
			t.Fatalf("cached panic: %v, %v", terminal, err)
		}
	})
}

func TestHandleCacheNestedDifferentDigests(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		cache := newHandleCache()
		_, _, err := cache.getOrOpen(t.Context(), "outer", func() (proteus.Symbols, bool, error) {
			return cache.getOrOpen(t.Context(), "inner", func() (proteus.Symbols, bool, error) { return nil, true, nil })
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}
