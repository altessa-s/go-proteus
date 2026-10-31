// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package dirsource

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/altessa-s/go-atlas-core/io/files"

	"github.com/altessa-s/go-proteus"

	coreio "github.com/altessa-s/go-atlas-core/io"
)

const writableByGroupOrOther fs.FileMode = 0o022

// Source discovers plugin candidates inside a confined directory.
type Source struct {
	dir               string
	checkPermissions  bool
	followSymlinks    bool
	maxSignatureBytes int64
	maxArtifactBytes  int64
	extension         string
	signatureSuffix   string
}

// New constructs a [Source] rooted at dir and configured with opts.
func New(dir string, opts ...Option) (*Source, error) {
	cleaned := strings.TrimSpace(dir)
	if cleaned == "" {
		return nil, errors.New("dirsource: directory path is required")
	}
	cfg := newOptions(opts...)
	ext := cfg.extension
	if ext == "" {
		ext = DefaultExtension
	}
	sigSuffix := cfg.signatureSuffix
	if sigSuffix == "" {
		sigSuffix = DefaultSignatureSuffix
	}
	maxSig := cfg.maxSignatureBytes
	if maxSig <= 0 {
		maxSig = DefaultMaxSignatureBytes
	}
	maxArt := cfg.maxArtifactBytes
	if maxArt <= 0 {
		maxArt = DefaultMaxArtifactBytes
	}
	return &Source{
		dir:               filepath.Clean(cleaned),
		checkPermissions:  !cfg.skipPermissionChecks,
		followSymlinks:    cfg.followSymlinks,
		maxSignatureBytes: maxSig,
		maxArtifactBytes:  maxArt,
		extension:         ext,
		signatureSuffix:   sigSuffix,
	}, nil
}

// Dir returns the cleaned directory path configured on s.
func (s *Source) Dir() string { return s.dir }

// Candidates scans the directory for plugin artifacts and their companion signature files.
func (s *Source) Candidates(ctx context.Context) ([]proteus.Candidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	root, err := s.openVerifiedRoot()
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("dirsource: read directory %q: %w", s.dir, err)
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int {
		return cmp.Compare(a.Name(), b.Name())
	})

	sigExt := s.extension + s.signatureSuffix
	var out []proteus.Candidate

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := entry.Name()
		if strings.HasSuffix(name, sigExt) || !strings.HasSuffix(name, s.extension) || entry.IsDir() {
			continue
		}

		f, _, err := s.openVerifiedFileInRoot(root, name, s.maxArtifactBytes)
		if err != nil {
			out = append(out, proteus.Candidate{ID: name, Err: err})
			continue
		}
		_ = f.Close()

		sigBytes, err := s.readSignatureInRoot(root, name+s.signatureSuffix)
		if err != nil {
			out = append(out, proteus.Candidate{ID: name, Err: err})
			continue
		}

		candidateName := name
		out = append(out, proteus.Candidate{
			ID:        candidateName,
			Signature: sigBytes,
			Open: func() (proteus.Artifact, error) {
				return s.openArtifact(candidateName)
			},
		})
	}

	return out, nil
}

func (s *Source) openVerifiedRoot() (*os.Root, error) {
	dirLstat, err := os.Lstat(s.dir)
	if err != nil {
		return nil, fmt.Errorf("dirsource: stat plugin directory %q: %w", s.dir, err)
	}
	if !s.followSymlinks && dirLstat.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: plugin directory %q is a symlink", proteus.ErrInsecurePermissions, s.dir)
	}

	root, err := files.OpenRootDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("dirsource: open root %q: %w", s.dir, err)
	}
	rootInfo, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("dirsource: stat opened root %q: %w", s.dir, err)
	}
	if s.checkPermissions && isInsecureMode(rootInfo.Mode()) {
		_ = root.Close()
		return nil, fmt.Errorf(
			"%w: plugin directory %q has insecure permissions %04o",
			proteus.ErrInsecurePermissions,
			s.dir,
			rootInfo.Mode().Perm(),
		)
	}
	return root, nil
}

func (s *Source) openVerifiedFileInRoot(root *os.Root, name string, maxBytes int64) (*os.File, fs.FileInfo, error) {
	linfo, err := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if linfo.Mode()&os.ModeSymlink != 0 && !s.followSymlinks {
		return nil, nil, fmt.Errorf("%w: %q is a symlink", proteus.ErrInsecurePermissions, name)
	}

	f, err := files.OpenRegularIn(root, name)
	if err != nil {
		return nil, nil, fmt.Errorf("dirsource: open %q: %w", name, err)
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("dirsource: stat %q: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%w: %q is not a regular file", files.ErrNotRegular, name)
	}
	if s.checkPermissions && isInsecureMode(info.Mode()) {
		_ = f.Close()
		return nil, nil, fmt.Errorf(
			"%w: %q has insecure permissions %04o",
			proteus.ErrInsecurePermissions,
			name,
			info.Mode().Perm(),
		)
	}
	if info.Size() > maxBytes {
		_ = f.Close()
		return nil, nil, fmt.Errorf(
			"%w: %q size %d exceeds maximum %d",
			coreio.ErrReadLimitExceeded,
			name,
			info.Size(),
			maxBytes,
		)
	}
	return f, info, nil
}

func (s *Source) readSignatureInRoot(root *os.Root, sigName string) ([]byte, error) {
	f, _, err := s.openVerifiedFileInRoot(root, sigName, s.maxSignatureBytes)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	data, err := coreio.ReadAllLimited(f, s.maxSignatureBytes)
	if err != nil {
		return nil, fmt.Errorf("dirsource: read signature %q: %w", sigName, err)
	}
	return data, nil
}

func (s *Source) openArtifact(name string) (proteus.Artifact, error) {
	root, err := s.openVerifiedRoot()
	if err != nil {
		return proteus.Artifact{}, err
	}

	f, info, err := s.openVerifiedFileInRoot(root, name, s.maxArtifactBytes)
	if err != nil {
		_ = root.Close()
		return proteus.Artifact{}, err
	}

	rc := &rootFileCloser{file: f, root: root}
	limited := coreio.NewLimitedReadCloser(rc, s.maxArtifactBytes)
	return proteus.Artifact{
		Reader: limited,
		Size:   info.Size(),
	}, nil
}

type rootFileCloser struct {
	file io.ReadCloser
	root *os.Root
}

func (r *rootFileCloser) Read(p []byte) (int, error) {
	return r.file.Read(p)
}

func (r *rootFileCloser) Close() error {
	fErr := r.file.Close()
	rErr := r.root.Close()
	return errors.Join(fErr, rErr)
}

func isInsecureMode(mode fs.FileMode) bool {
	if runtime.GOOS == "windows" {
		return false
	}
	return mode.Perm()&writableByGroupOrOther != 0
}
