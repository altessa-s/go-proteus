// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package watch_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/watch"
)

type funcReloader func(ctx context.Context) (proteus.LoadReport, error)

func (f funcReloader) Reload(ctx context.Context) (proteus.LoadReport, error) {
	return f(ctx)
}

func TestWatcherSettleCoalescing_D15(t *testing.T) {
	dir := t.TempDir()

	synctest.Test(t, func(t *testing.T) {
		var reloads atomic.Int32

		reloader := funcReloader(func(context.Context) (proteus.LoadReport, error) {
			reloads.Add(1)
			return proteus.LoadReport{}, nil
		})

		w, err := watch.New(dir, reloader,
			watch.WithSettle(100*time.Millisecond),
			watch.WithExtension(".so"),
			watch.WithSignatureSuffix(".sig"),
			watch.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
			watch.WithDisableFsnotify(),
		)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := w.Start(ctx); err != nil {
			t.Fatal(err)
		}

		if !w.Running() {
			t.Fatal("expected Running() == true")
		}

		// Simulate rapid burst of .so and .so.sig events spaced 40ms apart (< 100ms settle).
		w.Notify("greeter.so")
		time.Sleep(40 * time.Millisecond)
		w.Notify("greeter.so")
		time.Sleep(40 * time.Millisecond)
		w.Notify("greeter.so.sig")
		w.Notify("ignored.txt")
		w.Notify(".hidden.so")

		// At 80ms since last event, Reload must NOT have fired yet!
		time.Sleep(80 * time.Millisecond)

		if got := reloads.Load(); got != 0 {
			t.Fatalf("expected 0 reloads before settle window elapses, got %d", got)
		}

		// Advance past the 100ms quiet settle window: exactly 1 coalesced Reload fires.
		time.Sleep(50 * time.Millisecond)

		if got := reloads.Load(); got != 1 {
			t.Fatalf("expected exactly 1 coalesced Reload after settle window, got %d", got)
		}

		if err := w.Stop(); err != nil {
			t.Fatal(err)
		}

		if w.Running() {
			t.Fatal("expected Running() == false after Stop")
		}
	})
}

func TestWatcherFsnotifyErrorRecordingAndLifecycle(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Validation errors.
	if _, err := watch.New("", funcReloader(nil)); err == nil {
		t.Fatal("expected error for empty dir")
	}

	if _, err := watch.New(dir, nil); err == nil {
		t.Fatal("expected error for nil reloader")
	}

	if _, err := watch.New(filepath.Join(dir, "missing"), funcReloader(nil)); err == nil {
		t.Fatal("expected error for nonexistent dir")
	}

	fileInDir := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(fileInDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := watch.New(fileInDir, funcReloader(func(context.Context) (proteus.LoadReport, error) {
		return proteus.LoadReport{}, nil
	})); err == nil {
		t.Fatal("expected error when dir is a file")
	}

	reloadTriggered := make(chan struct{}, 4)
	errTriggered := make(chan error, 4)

	var step atomic.Int32

	reloader := funcReloader(func(context.Context) (proteus.LoadReport, error) {
		switch step.Add(1) {
		case 1:
			return proteus.LoadReport{
				Failed: []proteus.CandidateReport{{Source: "bad.so", Err: errors.New("candidate failed")}},
			}, nil
		case 2:
			return proteus.LoadReport{}, errors.New("source error")
		default:
			panic("reloader boom")
		}
	})

	w, err := watch.New(dir, reloader,
		watch.WithSettle(25*time.Millisecond),
		watch.WithOnReload(func(proteus.LoadReport) {
			select {
			case reloadTriggered <- struct{}{}:
			default:
			}
		}),
		watch.WithOnError(func(err error) {
			select {
			case errTriggered <- err:
			default:
			}
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := w.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Starting an already-running watcher fails.
	if err := w.Start(context.Background()); err == nil {
		t.Fatal("expected error when calling Start twice")
	}

	// Trigger step 1 via real filesystem write to a .so.sig file.
	sigPath := filepath.Join(dir, "real.so.sig")
	if err := os.WriteFile(sigPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	select {
	case <-reloadTriggered:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for fsnotify reload")
	}

	select {
	case <-errTriggered:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for step 1 error callback")
	}

	if w.LastErr() == nil {
		t.Fatal("expected LastErr() to record report failure")
	}

	// Trigger step 2 (reloader returns error).
	w.Notify("second.so")

	select {
	case <-errTriggered:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for error callback")
	}

	// Trigger step 3 (reloader panics -> recovered as ErrPanicked).
	w.Notify("third.so")

	select {
	case gotErr := <-errTriggered:
		if !errors.Is(gotErr, proteus.ErrPanicked) {
			t.Fatalf("expected ErrPanicked from panicking reloader, got %v", gotErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for panic recovery error")
	}

	if err := w.Stop(); err != nil {
		t.Fatal(err)
	}
	// Stop is idempotent, and Start after Stop returns ErrClosed.
	if err := w.Stop(); err != nil {
		t.Fatal(err)
	}

	if err := w.Start(context.Background()); !errors.Is(err, proteus.ErrClosed) {
		t.Fatalf("expected ErrClosed on Start after Stop, got %v", err)
	}

	// Canceled context on Start and pointer string options.
	extPtr := ".so"
	sigPtr := ".sig"

	w2, err := watch.New(dir, reloader,
		watch.WithExtension(&extPtr),
		watch.WithSignatureSuffix(&sigPtr),
	)
	if err != nil {
		t.Fatal(err)
	}

	cctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := w2.Start(cctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled on Start, got %v", err)
	}

	if err := w2.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestWatcherPanicPrivacy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	synctest.Test(t, func(t *testing.T) {
		const canary = "private-watcher-canary"

		var logs bytes.Buffer

		w, err := watch.New(dir, funcReloader(func(context.Context) (proteus.LoadReport, error) { panic(canary) }), watch.WithDisableFsnotify(), watch.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
		if err != nil {
			t.Fatal(err)
		}

		if err := w.Start(t.Context()); err != nil {
			t.Fatal(err)
		}

		w.Notify("p.so")
		time.Sleep(time.Second)
		synctest.Wait()

		if err := w.Stop(); err != nil {
			t.Fatal(err)
		}

		if !errors.Is(w.LastErr(), proteus.ErrPanicked) {
			t.Fatalf("unexpected error: %v", w.LastErr())
		}

		if strings.Contains(w.LastErr().Error(), canary) || strings.Contains(logs.String(), canary) {
			t.Fatal("panic payload leaked")
		}
	})
}
