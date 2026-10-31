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
	"sync/atomic"
	"testing"

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
	opened1, err1 := opener.Open(context.Background(), cand, expectedHash)
	if !errors.Is(err1, proteus.ErrPanicked) {
		t.Fatalf("expected ErrPanicked on package init panic, got %v", err1)
	}
	if opened1.SHA256 != expectedHash {
		t.Fatalf("expected SHA256 %s on failed open, got %s", expectedHash, opened1.SHA256)
	}

	// Second Open for the same SHA-256: returns cached ErrPanicked without calling openFn again.
	_, err2 := opener.Open(context.Background(), cand, expectedHash)
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
	res1, err := opener.Open(context.Background(), cand, expectedHash)
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

	res2, err := opener.Open(context.Background(), cand, expectedHash)
	if err != nil || res2.SHA256 != expectedHash {
		t.Fatalf("second Open failed: %v", err)
	}
	if openCount.Load() != 1 {
		t.Fatalf("expected handle cache hit (1 open call), got %d", openCount.Load())
	}

	// Manifest SHA-256 mismatch rejected before openFn.
	badCand, _ := makeCandidate("mismatch.so", []byte("different-bytes"))
	_, mmErr := opener.Open(context.Background(), badCand, expectedHash)
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
	if _, err := tamperOpener.Open(context.Background(), tamperCand, tamperHash); !errors.Is(err, proteus.ErrSnapshotModified) {
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
	if _, err := limitOpener.Open(context.Background(), bigCand, ""); !errors.Is(err, coreio.ErrReadLimitExceeded) {
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
	if _, err := limitOpener.Open(context.Background(), streamBigCand, ""); !errors.Is(err, coreio.ErrReadLimitExceeded) {
		t.Fatalf("expected stream ErrReadLimitExceeded, got %v", err)
	}
	openErrCand := proteus.Candidate{
		ID: "open-err.so",
		Open: func() (proteus.Artifact, error) {
			return proteus.Artifact{}, errors.New("open failed")
		},
	}
	if _, err := limitOpener.Open(context.Background(), openErrCand, ""); err == nil {
		t.Fatal("expected error when Candidate.Open fails")
	}

	// Nil candidate Open function and cancelled context.
	if _, err := limitOpener.Open(context.Background(), proteus.Candidate{ID: "nil"}, ""); err == nil {
		t.Fatal("expected error for nil Candidate.Open")
	}
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := limitOpener.Open(cctx, bigCand, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	// Default openFn (stdlib plugin.Open) on invalid ELF/Mach-O bytes returns an error cleanly.
	defaultDir := filepath.Join(t.TempDir(), "default")
	defaultOpener, err := goloader.New(defaultDir)
	if err != nil {
		t.Fatal(err)
	}
	notSO, notSOHash := makeCandidate("not-a-plugin.so", []byte("not-an-elf-or-macho"))
	if _, err := defaultOpener.Open(context.Background(), notSO, notSOHash); err == nil {
		t.Fatal("expected error from default plugin.Open on non-plugin bytes")
	}
}
