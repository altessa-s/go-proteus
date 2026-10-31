// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package dirsource_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/dirsource"

	coreio "github.com/altessa-s/go-atlas-core/io"
)

func createSecureDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "plugins")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeSecureFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCandidatesAndOpenArtifact(t *testing.T) {
	t.Parallel()

	if _, err := dirsource.New("   "); err == nil {
		t.Fatal("expected error for empty directory")
	}

	dir := createSecureDir(t)
	writeSecureFile(t, filepath.Join(dir, "b.so"), []byte("binary-b"))
	writeSecureFile(t, filepath.Join(dir, "b.so.sig"), []byte("sig-b"))
	writeSecureFile(t, filepath.Join(dir, "a.so"), []byte("binary-a"))
	writeSecureFile(t, filepath.Join(dir, "readme.txt"), []byte("ignored"))
	if err := os.Mkdir(filepath.Join(dir, "subdir.so"), 0o700); err != nil {
		t.Fatal(err)
	}

	src, err := dirsource.New(dir,
		dirsource.WithExtension(".so"),
		dirsource.WithSignatureSuffix(".sig"),
		dirsource.WithMaxSignatureBytes(1024),
		dirsource.WithMaxArtifactBytes(4096),
	)
	if err != nil {
		t.Fatal(err)
	}
	if src.Dir() != filepath.Clean(dir) {
		t.Fatalf("unexpected Dir(): %s", src.Dir())
	}

	cands, err := src.Candidates(context.Background())
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if len(cands) != 2 || cands[0].ID != "a.so" || cands[1].ID != "b.so" {
		t.Fatalf("expected [a.so b.so], got %+v", cands)
	}
	if len(cands[0].Signature) != 0 {
		t.Fatal("expected nil signature on a.so")
	}
	if string(cands[1].Signature) != "sig-b" {
		t.Fatalf("expected sig-b on b.so, got %q", string(cands[1].Signature))
	}

	art, err := cands[0].Open()
	if err != nil {
		t.Fatalf("Open a.so: %v", err)
	}
	data, err := io.ReadAll(art.Reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if err := art.Reader.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if string(data) != "binary-a" || art.Size != int64(len("binary-a")) {
		t.Fatalf("unexpected artifact content/size: %q (%d)", string(data), art.Size)
	}
}

func TestRootConfinementSymlinksAndPermissions_D9(t *testing.T) {
	t.Parallel()

	// 1. Symlinked plugin directory rejected by default.
	realDir := createSecureDir(t)
	linkDir := filepath.Join(t.TempDir(), "plugins-link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	srcLinkDir, err := dirsource.New(linkDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srcLinkDir.Candidates(context.Background()); !errors.Is(err, proteus.ErrInsecurePermissions) {
		t.Fatalf("expected symlinked directory rejected with ErrInsecurePermissions, got %v", err)
	}

	// 2. Group/world-writable directory rejected.
	badDir := createSecureDir(t)
	if err := os.Chmod(badDir, 0o777); err != nil {
		t.Fatal(err)
	}
	srcBadDir, err := dirsource.New(badDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srcBadDir.Candidates(context.Background()); !errors.Is(err, proteus.ErrInsecurePermissions) {
		t.Fatalf("expected 0777 directory rejected with ErrInsecurePermissions, got %v", err)
	}

	// 3. Group/world-writable .so file rejected.
	dirPermSO := createSecureDir(t)
	soPath := filepath.Join(dirPermSO, "writable.so")
	writeSecureFile(t, soPath, []byte("code"))
	if err := os.Chmod(soPath, 0o666); err != nil {
		t.Fatal(err)
	}
	srcPermSO, err := dirsource.New(dirPermSO)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srcPermSO.Candidates(context.Background()); !errors.Is(err, proteus.ErrInsecurePermissions) {
		t.Fatalf("expected 0666 .so rejected with ErrInsecurePermissions, got %v", err)
	}
	// Allowed when WithSkipPermissionChecks() is set.
	srcNoCheck, err := dirsource.New(dirPermSO, dirsource.WithSkipPermissionChecks())
	if err != nil {
		t.Fatal(err)
	}
	if cands, err := srcNoCheck.Candidates(context.Background()); err != nil || len(cands) != 1 {
		t.Fatalf("expected 1 candidate when WithSkipPermissionChecks(), got %d (%v)", len(cands), err)
	}

	// 4. Group/world-writable .so.sig rejected.
	dirPermSig := createSecureDir(t)
	writeSecureFile(t, filepath.Join(dirPermSig, "p.so"), []byte("code"))
	sigPath := filepath.Join(dirPermSig, "p.so.sig")
	writeSecureFile(t, sigPath, []byte("sig"))
	if err := os.Chmod(sigPath, 0o666); err != nil {
		t.Fatal(err)
	}
	srcPermSig, err := dirsource.New(dirPermSig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srcPermSig.Candidates(context.Background()); !errors.Is(err, proteus.ErrInsecurePermissions) {
		t.Fatalf("expected 0666 .so.sig rejected with ErrInsecurePermissions, got %v", err)
	}

	// 5. Symlink .so inside directory rejected by default, allowed with WithFollowSymlinks(),
	// while symlink escaping outside os.Root is always rejected!
	dirSymlink := createSecureDir(t)
	writeSecureFile(t, filepath.Join(dirSymlink, "target.bin"), []byte("payload"))
	if err := os.Symlink("target.bin", filepath.Join(dirSymlink, "linked.so")); err != nil {
		t.Fatal(err)
	}
	srcNoFollow, err := dirsource.New(dirSymlink)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srcNoFollow.Candidates(context.Background()); !errors.Is(err, proteus.ErrInsecurePermissions) {
		t.Fatalf("expected symlink .so rejected when FollowSymlinks=false, got %v", err)
	}

	srcFollow, err := dirsource.New(dirSymlink, dirsource.WithFollowSymlinks())
	if err != nil {
		t.Fatal(err)
	}
	followCands, err := srcFollow.Candidates(context.Background())
	if err != nil || len(followCands) != 1 {
		t.Fatalf("expected in-root symlink allowed with WithFollowSymlinks, got %d (%v)", len(followCands), err)
	}
	art, err := followCands[0].Open()
	if err != nil {
		t.Fatalf("Open in-root symlink: %v", err)
	}
	_ = art.Reader.Close()

	// Symlink escaping outside root must fail even with WithFollowSymlinks() because of os.Root confinement!
	outsideFile := filepath.Join(t.TempDir(), "outside.so")
	writeSecureFile(t, outsideFile, []byte("outside"))
	if err := os.Symlink(outsideFile, filepath.Join(dirSymlink, "escape.so")); err != nil {
		t.Fatal(err)
	}
	if _, err := srcFollow.Candidates(context.Background()); err == nil {
		t.Fatal("expected symlink escaping outside os.Root to be rejected")
	}

	// 6. Oversized signature and oversized artifact rejected.
	dirSize := createSecureDir(t)
	writeSecureFile(t, filepath.Join(dirSize, "big.so"), make([]byte, 128))
	writeSecureFile(t, filepath.Join(dirSize, "big.so.sig"), make([]byte, 128))

	srcTinySig, err := dirsource.New(dirSize, dirsource.WithMaxSignatureBytes(16))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srcTinySig.Candidates(context.Background()); !errors.Is(err, coreio.ErrReadLimitExceeded) {
		t.Fatalf("expected ErrReadLimitExceeded for oversized signature, got %v", err)
	}

	srcTinyArt, err := dirsource.New(dirSize, dirsource.WithMaxArtifactBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srcTinyArt.Candidates(context.Background()); !errors.Is(err, coreio.ErrReadLimitExceeded) {
		t.Fatalf("expected ErrReadLimitExceeded for oversized artifact, got %v", err)
	}

	// 7. Missing directory, cancelled context, and removed file before Open().
	srcMissing, err := dirsource.New(filepath.Join(t.TempDir(), "nonexistent"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srcMissing.Candidates(context.Background()); err == nil {
		t.Fatal("expected error for nonexistent directory")
	}

	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := srcTinyArt.Candidates(cctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	dirVanish := createSecureDir(t)
	vanishPath := filepath.Join(dirVanish, "vanish.so")
	writeSecureFile(t, vanishPath, []byte("abc"))
	extPtr := ".so"
	sigPtr := ".sig"
	srcVanish, err := dirsource.New(dirVanish,
		dirsource.WithExtension(&extPtr),
		dirsource.WithSignatureSuffix(&sigPtr),
	)
	if err != nil {
		t.Fatal(err)
	}
	vCands, err := srcVanish.Candidates(context.Background())
	if err != nil || len(vCands) != 1 {
		t.Fatalf("expected 1 candidate, got %d (%v)", len(vCands), err)
	}
	_ = os.Remove(vanishPath)
	if _, err := vCands[0].Open(); err == nil {
		t.Fatal("expected Open() to fail after file removal")
	}
}
