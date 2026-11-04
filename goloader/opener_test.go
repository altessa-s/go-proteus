// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package goloader_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/goloader"

	coreio "github.com/altessa-s/go-atlas-core/io"
)

type stubSymbols map[string]any

func (s stubSymbols) Lookup(name string) (any, error) {
	v, ok := s[name]
	if !ok {
		return nil, errors.New("missing")
	}

	return v, nil
}

func makeCandidate(id string, data []byte) (proteus.Candidate, string) {
	sum := sha256.Sum256(data)
	hexHash := hex.EncodeToString(sum[:])

	return proteus.Candidate{
		ID: id,
		Open: func() (proteus.Artifact, error) {
			return proteus.Artifact{
				Reader: io.NopCloser(bytes.NewReader(data)),
				Size:   int64(len(data)),
			}, nil
		},
	}, hexHash
}

func TestPackageInitPanicContainedAndCached_D1(t *testing.T) {
	t.Parallel()

	workDir := filepath.Join(t.TempDir(), "snaps")

	var openCount atomic.Int32

	opener, err := goloader.New(workDir,
		goloader.WithOpenFunc(func(_ context.Context, _ string) (proteus.Symbols, error) {
			openCount.Add(1)
			panic("plugin package init exploded")
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	cand, expectedHash := makeCandidate("panic.so", []byte("panic-plugin-bytes"))

	// First Open: recovers panic and returns ErrPanicked.
	opened1, err1 := opener.Open(context.Background(), cand, expectedHash, 0)
	if !errors.Is(err1, proteus.ErrPanicked) {
		t.Fatalf("expected ErrPanicked on package init panic, got %v", err1)
	}

	if opened1.SHA256 != expectedHash {
		t.Fatalf("expected SHA256 %s on failed open, got %s", expectedHash, opened1.SHA256)
	}

	// Second Open for the same SHA-256: returns cached ErrPanicked without calling openFn again.
	_, err2 := opener.Open(context.Background(), cand, expectedHash, 0)
	if !errors.Is(err2, proteus.ErrPanicked) {
		t.Fatalf("expected cached ErrPanicked on second open, got %v", err2)
	}

	if got := openCount.Load(); got != 1 {
		t.Fatalf("expected openFn called exactly once, got %d", got)
	}
}

func TestStreamingSnapshotAndTOCTOUDetection_D14(t *testing.T) {
	t.Parallel()

	workDir := filepath.Join(t.TempDir(), "snaps")

	var openCount atomic.Int32

	opener, err := goloader.New(workDir,
		goloader.WithOpenFunc(func(_ context.Context, path string) (proteus.Symbols, error) {
			openCount.Add(1)

			if _, statErr := os.Stat(path); statErr != nil {
				return nil, statErr
			}

			return stubSymbols{"Descriptor": "ok"}, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	if opener.WorkDir() != filepath.Clean(workDir) {
		t.Fatalf("unexpected WorkDir(): %s", opener.WorkDir())
	}

	cand, expectedHash := makeCandidate("good.so", []byte("verified-plugin-payload"))

	// Open and cache hit.
	res1, err := opener.Open(context.Background(), cand, expectedHash, 0)
	if err != nil {
		t.Fatalf("first Open failed: %v", err)
	}

	if res1.SHA256 != expectedHash || res1.Size != int64(len("verified-plugin-payload")) {
		t.Fatalf("unexpected Opened result: %+v", res1)
	}

	val, err := res1.Symbols.Lookup("Descriptor")
	if err != nil || val != "ok" {
		t.Fatalf("unexpected Lookup result: %v, %v", val, err)
	}

	res2, err := opener.Open(context.Background(), cand, expectedHash, 0)
	if err != nil || res2.SHA256 != expectedHash {
		t.Fatalf("second Open failed: %v", err)
	}

	if openCount.Load() != 1 {
		t.Fatalf("expected handle cache hit (1 open call), got %d", openCount.Load())
	}

	// Manifest SHA-256 mismatch rejected before openFn.
	badCand, _ := makeCandidate("mismatch.so", []byte("different-bytes"))

	_, mmErr := opener.Open(context.Background(), badCand, expectedHash, 0)
	if !errors.Is(mmErr, proteus.ErrManifestMismatch) {
		t.Fatalf("expected ErrManifestMismatch, got %v", mmErr)
	}

	if openCount.Load() != 1 {
		t.Fatal("openFn must not be called on manifest hash mismatch")
	}

	// TOCTOU tamper detection between snapshot write and re-hash returns ErrSnapshotModified.
	tamperDir := filepath.Join(t.TempDir(), "tamper")

	tamperOpener, err := goloader.New(tamperDir,
		goloader.WithAfterWriteHook(func(snapshotPath string) {
			_ = os.WriteFile(snapshotPath, []byte("tampered-on-disk"), 0o600)
		}),
		goloader.WithOpenFunc(func(context.Context, string) (proteus.Symbols, error) {
			t.Fatal("openFn must not be called when snapshot is modified on disk")
			return nil, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	tamperCand, tamperHash := makeCandidate("tamper.so", []byte("original-bytes"))
	if _, err := tamperOpener.Open(context.Background(), tamperCand, tamperHash, 0); !errors.Is(err, proteus.ErrSnapshotModified) {
		t.Fatalf("expected ErrSnapshotModified on TOCTOU tamper, got %v", err)
	}
}

func TestWorkDirPermissionsLimitsAndDefaultOpen(t *testing.T) {
	t.Parallel()

	if _, err := goloader.New("  "); err == nil {
		t.Fatal("expected error for empty workDir")
	}

	// Group/world-writable workDir without sticky bit is rejected.
	insecureDir := filepath.Join(t.TempDir(), "insecure")
	if err := os.MkdirAll(insecureDir, 0o777); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(insecureDir, 0o777); err != nil {
		t.Fatal(err)
	}

	if _, err := goloader.New(insecureDir); !errors.Is(err, proteus.ErrInsecurePermissions) {
		t.Fatalf("expected ErrInsecurePermissions on 0777 workDir, got %v", err)
	}

	if _, err := goloader.New(insecureDir, goloader.WithSkipPermissionChecks()); err != nil {
		t.Fatalf("expected WithSkipPermissionChecks() to allow 0777 workDir, got %v", err)
	}

	// File path instead of directory for workDir is rejected.
	fileAsDir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := goloader.New(fileAsDir); err == nil {
		t.Fatal("expected error when workDir is a regular file")
	}

	// Oversized artifact is rejected.
	limitDir := filepath.Join(t.TempDir(), "limit")

	limitOpener, err := goloader.New(limitDir, goloader.WithMaxArtifactBytes(8))
	if err != nil {
		t.Fatal(err)
	}

	bigCand, _ := makeCandidate("big.so", []byte("0123456789abcdef"))
	if _, err := limitOpener.Open(context.Background(), bigCand, "", 0); !errors.Is(err, coreio.ErrReadLimitExceeded) {
		t.Fatalf("expected ErrReadLimitExceeded, got %v", err)
	}

	streamBigCand := proteus.Candidate{
		ID: "stream-big.so",
		Open: func() (proteus.Artifact, error) {
			return proteus.Artifact{
				Reader: io.NopCloser(bytes.NewReader([]byte("0123456789abcdef"))),
				Size:   4,
			}, nil
		},
	}
	if _, err := limitOpener.Open(context.Background(), streamBigCand, "", 0); !errors.Is(err, coreio.ErrReadLimitExceeded) {
		t.Fatalf("expected stream ErrReadLimitExceeded, got %v", err)
	}

	openErrCand := proteus.Candidate{
		ID: "open-err.so",
		Open: func() (proteus.Artifact, error) {
			return proteus.Artifact{}, errors.New("open failed")
		},
	}
	if _, err := limitOpener.Open(context.Background(), openErrCand, "", 0); err == nil {
		t.Fatal("expected error when Candidate.Open fails")
	}

	// Nil candidate Open function and canceled context.
	if _, err := limitOpener.Open(context.Background(), proteus.Candidate{ID: "nil"}, "", 0); err == nil {
		t.Fatal("expected error for nil Candidate.Open")
	}

	cctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := limitOpener.Open(cctx, bigCand, "", 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	// Default openFn (stdlib plugin.Open) on invalid ELF/Mach-O bytes returns an error cleanly.
	defaultDir := filepath.Join(t.TempDir(), "default")

	defaultOpener, err := goloader.New(defaultDir)
	if err != nil {
		t.Fatal(err)
	}

	notSO, notSOHash := makeCandidate("not-a-plugin.so", []byte("not-an-elf-or-macho"))
	if _, err := defaultOpener.Open(context.Background(), notSO, notSOHash, 0); err == nil {
		t.Fatal("expected error from default plugin.Open on non-plugin bytes")
	}
}

func TestSizeCheckedBeforeLoaderAndSnapshotsRemoved(t *testing.T) {
	t.Parallel()

	cand, digest := makeCandidate("size", []byte("payload"))
	calls := 0
	dir := t.TempDir()

	opener, err := goloader.New(dir, goloader.WithOpenFunc(func(context.Context, string) (proteus.Symbols, error) { calls++; return stubSymbols{}, nil }))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := opener.Open(t.Context(), cand, digest, 99); !errors.Is(err, proteus.ErrManifestMismatch) {
		t.Fatalf("size mismatch: %v", err)
	}

	if calls != 0 {
		t.Fatal("executed wrong-size artifact")
	}

	if _, err := opener.Open(t.Context(), cand, digest, 7); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("snapshots leaked: %v %v", entries, err)
	}
}

func TestIndependentOpenersOwnSnapshots(t *testing.T) {
	t.Parallel()

	cand, digest := makeCandidate("shared", []byte("shared snapshot"))
	dir := t.TempDir()
	entered := make(chan string, 1)

	resume := make(chan struct{})
	defer close(resume)

	a, err := goloader.New(dir, goloader.WithOpenFunc(func(_ context.Context, path string) (proteus.Symbols, error) {
		entered <- path

		<-resume

		data, err := os.ReadFile(path)
		if err == nil && string(data) != "shared snapshot" {
			err = errors.New("snapshot content changed")
		}

		return stubSymbols{}, err
	}))
	require.NoError(t, err)

	done := make(chan error, 1)

	go func() {
		_, err := a.Open(t.Context(), cand, digest, 0)
		done <- err
	}()

	aPath := <-entered

	var bPath string

	b, err := goloader.New(dir, goloader.WithOpenFunc(func(_ context.Context, path string) (proteus.Symbols, error) {
		bPath = path

		data, err := os.ReadFile(path)
		if err == nil && string(data) != "shared snapshot" {
			err = errors.New("snapshot content changed")
		}

		return stubSymbols{}, err
	}))
	require.NoError(t, err)
	_, err = b.Open(t.Context(), cand, digest, 0)
	require.NoError(t, err)
	require.NotEqual(t, aPath, bPath)
	_, err = os.Stat(bPath)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(aPath)
	require.NoError(t, err, "second opener cleanup removed the first snapshot")

	resume <- struct{}{}

	require.NoError(t, <-done)
	_, err = a.Open(t.Context(), cand, digest, 0)
	require.NoError(t, err, "successful result must remain cached")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestPackageInitGoexitContainedAndCached(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32

	opener, err := goloader.New(t.TempDir(), goloader.WithOpenFunc(func(context.Context, string) (proteus.Symbols, error) {
		calls.Add(1)
		runtime.Goexit()

		return nil, nil
	}))
	require.NoError(t, err)

	candidate, digest := makeCandidate("goexit.so", []byte("goexit"))
	for range 2 {
		opened, err := opener.Open(t.Context(), candidate, digest, 0)
		require.ErrorIs(t, err, proteus.ErrPanicked)
		require.True(t, opened.ContentFailure)
	}

	require.EqualValues(t, 1, calls.Load())

	entries, err := os.ReadDir(opener.WorkDir())
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestLoaderPanicPrivacy(t *testing.T) {
	t.Parallel()

	const canary = "private-loader-canary"

	opener, err := goloader.New(t.TempDir(), goloader.WithOpenFunc(func(context.Context, string) (proteus.Symbols, error) { panic(canary) }))
	require.NoError(t, err)

	cand, digest := makeCandidate("p.so", []byte(t.Name()))
	for range 2 {
		_, err := opener.Open(t.Context(), cand, digest, 0)
		require.ErrorIs(t, err, proteus.ErrPanicked)
		require.NotContains(t, err.Error(), canary)
	}
}
