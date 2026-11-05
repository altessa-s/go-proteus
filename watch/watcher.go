// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package watch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/altessa-s/go-proteus"
)

// Reloader is the port invoked by [Watcher] when filesystem changes settle.
// [*github.com/altessa-s/go-proteus/host.Manager] satisfies Reloader.
type Reloader interface {
	// Reload discovers and admits newly added plugin candidates.
	Reload(ctx context.Context) (proteus.LoadReport, error)
}

type errHolder struct {
	err error
}

// Watcher monitors a plugin directory and calls [Reloader.Reload] after a quiet settle window.
type Watcher struct {
	dir             string
	reloader        Reloader
	settle          time.Duration
	extension       string
	signatureSuffix string
	logger          *slog.Logger
	onError         func(error)
	onReload        func(proteus.LoadReport)
	disableFsnotify bool

	mu       sync.Mutex
	running  atomic.Bool
	closed   bool
	cancel   context.CancelFunc
	done     chan struct{}
	notifyCh chan string
	lastErr  atomic.Pointer[errHolder]
}

// New constructs a [Watcher] for dir that notifies reloader after filesystem bursts settle.
func New(dir string, reloader Reloader, opts ...Option) (*Watcher, error) {
	cleaned := strings.TrimSpace(dir)
	if cleaned == "" {
		return nil, errors.New("watch: directory path is required")
	}

	if reloader == nil {
		return nil, errors.New("watch: reloader is required")
	}

	cleaned = filepath.Clean(cleaned)

	info, err := os.Stat(cleaned)
	if err != nil {
		return nil, fmt.Errorf("watch: stat directory %q: %w", cleaned, err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("watch: %q is not a directory", cleaned)
	}

	cfg := newOptions(opts...)

	settle := cfg.settle
	if settle <= 0 {
		settle = DefaultSettle
	}

	ext := cfg.extension
	if ext == "" {
		ext = DefaultExtension
	}

	sigSuffix := cfg.signatureSuffix
	if sigSuffix == "" {
		sigSuffix = DefaultSignatureSuffix
	}

	logger := cfg.logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	return &Watcher{
		dir:             cleaned,
		reloader:        reloader,
		settle:          settle,
		extension:       ext,
		signatureSuffix: sigSuffix,
		logger:          logger,
		onError:         cfg.onError,
		onReload:        cfg.onReload,
		disableFsnotify: cfg.disableFsnotify,
		notifyCh:        make(chan string, 64),
	}, nil
}

// Start launches the background watcher loop tied to ctx.
// Calling Start on an already-running or stopped watcher returns an error.
func (w *Watcher) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return proteus.ErrClosed
	}

	if w.running.Load() {
		w.mu.Unlock()
		return errors.New("watch: watcher is already running")
	}

	var fsw *fsnotify.Watcher

	if !w.disableFsnotify {
		var err error

		fsw, err = fsnotify.NewWatcher()
		if err != nil {
			w.mu.Unlock()
			return fmt.Errorf("watch: create fsnotify watcher: %w", err)
		}

		if err := fsw.Add(w.dir); err != nil {
			_ = fsw.Close()
			w.mu.Unlock()

			return fmt.Errorf("watch: watch directory %q: %w", w.dir, err)
		}
	}

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	w.cancel = cancel
	w.done = done
	w.running.Store(true)
	w.mu.Unlock()

	go w.loop(runCtx, fsw, done)

	return nil
}

// Stop terminates the background watcher loop and waits for it to exit.
// Subsequent calls to Stop are idempotent and return nil.
func (w *Watcher) Stop() error {
	w.mu.Lock()
	if w.closed {
		done := w.done
		w.mu.Unlock()

		if done != nil {
			<-done
		}

		return nil
	}

	w.closed = true
	cancel := w.cancel
	done := w.done
	w.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	if done != nil {
		<-done
	}

	return nil
}

// Running reports whether the watcher loop is currently active.
func (w *Watcher) Running() bool {
	return w.running.Load()
}

// LastErr returns the most recent reload or watcher error, or nil if none has occurred.
func (w *Watcher) LastErr() error {
	if box := w.lastErr.Load(); box != nil {
		return box.err
	}

	return nil
}

// Notify synthetic-triggers a candidate filename event (for example, "plugin.so") into the settle
// state machine. It is used by deterministic tests and manual reload triggers.
func (w *Watcher) Notify(name string) {
	if !w.isRelevantName(name) {
		return
	}

	select {
	case w.notifyCh <- name:
	default:
	}
}

func (w *Watcher) loop(ctx context.Context, fsw *fsnotify.Watcher, done chan struct{}) {
	defer func() {
		w.running.Store(false)

		if fsw != nil {
			_ = fsw.Close()
		}

		close(done)
	}()

	var (
		eventsCh <-chan fsnotify.Event
		errorsCh <-chan error
	)
	if fsw != nil {
		eventsCh = fsw.Events
		errorsCh = fsw.Errors
	}

	var (
		timer   *time.Timer
		timerCh <-chan time.Time
	)

	resetTimer := func() {
		if timer == nil {
			timer = time.NewTimer(w.settle)
			timerCh = timer.C

			return
		}

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}

		timer.Reset(w.settle)
		timerCh = timer.C
	}

	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case name := <-w.notifyCh:
			if w.isRelevantName(name) {
				resetTimer()
			}
		case ev, ok := <-eventsCh:
			if !ok {
				return
			}

			if w.isRelevantEvent(ev) {
				resetTimer()
			}
		case fsErr, ok := <-errorsCh:
			if !ok {
				return
			}

			if fsErr != nil {
				w.recordError(fsErr)
			}
		case <-timerCh:
			timerCh = nil

			w.executeReload(ctx)
		}
	}
}

func (w *Watcher) executeReload(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	defer func() {
		if r := recover(); r != nil {
			w.recordError(fmt.Errorf("%w: reloader panicked (%T)", proteus.ErrPanicked, r))
		}
	}()

	report, err := w.reloader.Reload(ctx)
	if err != nil {
		w.recordError(err)
		return
	}

	if repErr := report.Err(); repErr != nil {
		w.recordError(repErr)
	}

	if w.onReload != nil {
		w.onReload(report)
	}
}

func (w *Watcher) recordError(err error) {
	if err == nil {
		return
	}

	w.lastErr.Store(&errHolder{err: err})
	w.logger.Warn("plugin watcher error", slog.Any("err", err))

	if w.onError != nil {
		w.onError(err)
	}
}

func (w *Watcher) isRelevantEvent(ev fsnotify.Event) bool {
	const mask = fsnotify.Create | fsnotify.Write | fsnotify.Rename | fsnotify.Remove
	if ev.Op&mask == 0 {
		return false
	}

	return w.isRelevantName(ev.Name)
}

func (w *Watcher) isRelevantName(path string) bool {
	base := filepath.Base(path)
	if strings.HasPrefix(base, ".") {
		return false
	}

	sigExt := w.extension + w.signatureSuffix

	return strings.HasSuffix(base, w.extension) || strings.HasSuffix(base, sigExt)
}
