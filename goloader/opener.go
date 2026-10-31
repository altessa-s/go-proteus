// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package goloader

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/altessa-s/go-atlas-core/encoding/hash"
	"github.com/altessa-s/go-atlas-core/io/files"
	"github.com/altessa-s/go-atlas-core/runtime/panics"

	"github.com/altessa-s/go-proteus"

	coreio "github.com/altessa-s/go-atlas-core/io"
)

const writableByGroupOrOther fs.FileMode = 0o022

// Opener implements [proteus.Opener] using content-addressed snapshot files and a handle cache.
type Opener struct {
	workDir          string
	maxArtifactBytes int64
	checkPermissions bool
	openFn           OpenFunc
	afterWriteHook   func(snapshotPath string)
	cache            *handleCache
}

// New constructs an [Opener] that writes private plugin snapshots inside workDir.
// If workDir does not exist, it is created with mode 0o700.
func New(workDir string, opts ...Option) (*Opener, error) {
	cleaned := strings.TrimSpace(workDir)
	if cleaned == "" {
		return nil, errors.New("goloader: workDir is required")
	}
	cleaned = filepath.Clean(cleaned)

	cfg := newOptions(opts...)
	maxBytes := cfg.maxArtifactBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxArtifactBytes
	}
	openFn := cfg.openFunc
	if openFn == nil {
		openFn = defaultOpenPlugin
	}

	if err := ensureSecureWorkDir(cleaned, !cfg.skipPermissionChecks); err != nil {
		return nil, err
	}

	return &Opener{
		workDir:          cleaned,
		maxArtifactBytes: maxBytes,
		checkPermissions: !cfg.skipPermissionChecks,
		openFn:           openFn,
		afterWriteHook:   cfg.afterWriteHook,
		cache:            newHandleCache(),
	}, nil
}

// WorkDir returns the snapshot directory configured on o.
func (o *Opener) WorkDir() string { return o.workDir }

// Open streams c into a temporary snapshot file while hashing, verifies the digest against
// verifiedSHA256 when non-empty, re-hashes the snapshot from disk to close TOCTOU windows, and
// opens (or returns a cached handle for) the shared object.
func (o *Opener) Open(ctx context.Context, c proteus.Candidate, verifiedSHA256 string) (proteus.Opened, error) {
	if err := ctx.Err(); err != nil {
		return proteus.Opened{}, err
	}
	if c.Open == nil {
		return proteus.Opened{}, errors.New("goloader: candidate Open function is nil")
	}
	if err := ensureSecureWorkDir(o.workDir, o.checkPermissions); err != nil {
		return proteus.Opened{}, err
	}

	art, err := c.Open()
	if err != nil {
		return proteus.Opened{}, fmt.Errorf("goloader: open candidate %q: %w", c.ID, err)
	}
	defer func() { _ = art.Reader.Close() }()

	if art.Size > o.maxArtifactBytes {
		return proteus.Opened{}, fmt.Errorf(
			"%w: candidate %q size %d exceeds maximum %d",
			coreio.ErrReadLimitExceeded,
			c.ID,
			art.Size,
			o.maxArtifactBytes,
		)
	}

	tmpPath, streamHash, writtenSize, err := o.streamToTempFile(art.Reader)
	if err != nil {
		return proteus.Opened{}, err
	}
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if verifiedSHA256 != "" && !strings.EqualFold(streamHash, verifiedSHA256) {
		return proteus.Opened{
			SHA256: streamHash,
			Size:   writtenSize,
		}, fmt.Errorf(
			"%w: candidate %q sha256 %s does not match manifest %s",
			proteus.ErrManifestMismatch,
			c.ID,
			streamHash,
			verifiedSHA256,
		)
	}

	if o.afterWriteHook != nil {
		o.afterWriteHook(tmpPath)
	}

	diskHash, diskSize, err := rehashSnapshotFile(tmpPath, o.maxArtifactBytes)
	if err != nil {
		return proteus.Opened{SHA256: streamHash, Size: writtenSize}, err
	}
	if diskHash != streamHash || diskSize != writtenSize {
		return proteus.Opened{
			SHA256: streamHash,
			Size:   writtenSize,
		}, fmt.Errorf(
			"%w: snapshot for %q changed on disk before open",
			proteus.ErrSnapshotModified,
			c.ID,
		)
	}

	syms, err := o.cache.getOrOpen(streamHash, func() (proteus.Symbols, error) {
		finalPath := filepath.Join(o.workDir, streamHash+".so")
		if renameErr := os.Rename(tmpPath, finalPath); renameErr != nil {
			return nil, fmt.Errorf("goloader: commit snapshot %q: %w", finalPath, renameErr)
		}
		cleanupTmp = false
		return invokeOpenSafe(ctx, finalPath, o.openFn)
	})
	if err != nil {
		return proteus.Opened{
			SHA256: streamHash,
			Size:   writtenSize,
		}, err
	}

	return proteus.Opened{
		Symbols: syms,
		SHA256:  streamHash,
		Size:    writtenSize,
	}, nil
}

func (o *Opener) streamToTempFile(r io.Reader) (string, string, int64, error) {
	tmpFile, err := os.CreateTemp(o.workDir, ".proteus-snap-*.tmp")
	if err != nil {
		return "", "", 0, fmt.Errorf("goloader: create snapshot temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return "", "", 0, fmt.Errorf("goloader: chmod snapshot temp file: %w", err)
	}

	limited := coreio.NewLimitedReadCloser(io.NopCloser(r), o.maxArtifactBytes)
	hasher := hash.NewSHA256Hasher()
	written, copyErr := io.Copy(io.MultiWriter(tmpFile, hasher), limited)
	syncErr := tmpFile.Sync()
	closeErr := tmpFile.Close()

	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return "", "", 0, fmt.Errorf("goloader: stream artifact to snapshot: %w", copyErr)
	}
	if syncErr != nil {
		_ = os.Remove(tmpPath)
		return "", "", 0, fmt.Errorf("goloader: sync snapshot file: %w", syncErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return "", "", 0, fmt.Errorf("goloader: close snapshot file: %w", closeErr)
	}

	return tmpPath, hasher.SumHex(), written, nil
}

func rehashSnapshotFile(path string, maxBytes int64) (string, int64, error) {
	f, err := files.OpenRegular(path)
	if err != nil {
		return "", 0, fmt.Errorf("%w: open snapshot for re-hash: %w", proteus.ErrSnapshotModified, err)
	}
	defer func() { _ = f.Close() }()

	limited := coreio.NewLimitedReadCloser(f, maxBytes)
	hasher := hash.NewSHA256Hasher()
	n, err := io.Copy(hasher, limited)
	if err != nil {
		return "", 0, fmt.Errorf("%w: re-hash snapshot: %w", proteus.ErrSnapshotModified, err)
	}
	return hasher.SumHex(), n, nil
}

// invokeOpenSafe wraps openFn in [panics.HandleWithOpts] so any panic raised by a plugin's package
// init() during plugin.Open is recovered and returned as [proteus.ErrPanicked] (Defect 1).
func invokeOpenSafe(ctx context.Context, path string, openFn OpenFunc) (syms proteus.Symbols, err error) {
	opts := panics.NewHandleOpts().SetReallyPanic(false)
	defer panics.HandleWithOpts(ctx, opts, func(_ context.Context, r any) {
		syms = nil
		err = fmt.Errorf("%w: plugin package init panicked during open: %v", proteus.ErrPanicked, r)
	})
	return openFn(ctx, path)
}

func ensureSecureWorkDir(dir string, checkPerms bool) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("goloader: create workDir %q: %w", dir, err)
	}
	linfo, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("goloader: stat workDir %q: %w", dir, err)
	}
	if !linfo.IsDir() {
		return fmt.Errorf("%w: workDir %q is not a directory", proteus.ErrInsecurePermissions, dir)
	}
	if checkPerms && runtime.GOOS != "windows" {
		mode := linfo.Mode()
		// Group/world-writable directories without the sticky bit are rejected.
		if mode.Perm()&writableByGroupOrOther != 0 && mode&os.ModeSticky == 0 {
			return fmt.Errorf(
				"%w: snapshot workDir %q has insecure permissions %04o",
				proteus.ErrInsecurePermissions,
				dir,
				mode.Perm(),
			)
		}
	}
	return nil
}
