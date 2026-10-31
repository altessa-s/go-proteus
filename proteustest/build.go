// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package proteustest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
)

// BuildPlugin compiles the Go plugin package at pkgDir into a shared object
// (`.so`) using `go build -buildmode=plugin`, mirroring `-race` and `-cover`
// settings from the running test binary. Built artifacts are cached by source
// digest and build flags in the system temp directory and copied into
// `tb.TempDir()` with mode `0600` so each test operates on an isolated file.
//
// BuildPlugin calls `tb.Skip` on platforms where Go plugins are unsupported
// (such as Windows or when CGO_ENABLED=0).
func BuildPlugin(tb testing.TB, pkgDir string) string {
	tb.Helper()
	if runtime.GOOS == "windows" {
		tb.Skip("Go plugins (-buildmode=plugin) are not supported on Windows")
	}
	if os.Getenv("CGO_ENABLED") == "0" {
		tb.Skip("Go plugins (-buildmode=plugin) require cgo")
	}

	absDir, err := filepath.Abs(pkgDir)
	if err != nil {
		tb.Fatalf("proteustest.BuildPlugin: resolve path %q: %v", pkgDir, err)
	}

	raceEnabled, coverEnabled := currentBuildFlags()
	cachePath, err := ensureCachedPlugin(absDir, raceEnabled, coverEnabled)
	if err != nil {
		tb.Fatalf("proteustest.BuildPlugin(%q): %v", pkgDir, err)
	}

	data, err := os.ReadFile(cachePath)
	if err != nil {
		tb.Fatalf("proteustest.BuildPlugin: read cached .so %q: %v", cachePath, err)
	}
	outPath := filepath.Join(tb.TempDir(), filepath.Base(absDir)+".so")
	if err := os.WriteFile(outPath, data, 0o600); err != nil {
		tb.Fatalf("proteustest.BuildPlugin: write isolated .so %q: %v", outPath, err)
	}
	return outPath
}

func currentBuildFlags() (raceEnabled, coverEnabled bool) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return false, false
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "-race":
			raceEnabled = s.Value == "true"
		case "-cover":
			coverEnabled = s.Value == "true"
		}
	}
	return raceEnabled, coverEnabled
}

func ensureCachedPlugin(absDir string, raceEnabled, coverEnabled bool) (string, error) {
	entries, err := os.ReadDir(absDir)
	if err != nil {
		return "", fmt.Errorf("read dir %q: %w", absDir, err)
	}
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%s/%s|race=%t|cover=%t\n",
		absDir, runtime.Version(), runtime.GOOS, runtime.GOARCH, raceEnabled, coverEnabled)
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".go" {
			continue
		}
		src, readErr := os.ReadFile(filepath.Join(absDir, e.Name()))
		if readErr != nil {
			return "", fmt.Errorf("read %q: %w", e.Name(), readErr)
		}
		_, _ = h.Write([]byte(e.Name()))
		_, _ = h.Write(src)
	}
	digest := hex.EncodeToString(h.Sum(nil))[:24]

	cacheDir := filepath.Join(os.TempDir(), "proteustest-plugin-cache")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return "", fmt.Errorf("create cache dir: %w", err)
	}
	cachedSO := filepath.Join(cacheDir, filepath.Base(absDir)+"-"+digest+".so")
	if info, statErr := os.Stat(cachedSO); statErr == nil && info.Size() > 0 {
		return cachedSO, nil
	}

	tmpFile, err := os.CreateTemp(cacheDir, ".build-*.so")
	if err != nil {
		return "", fmt.Errorf("create temp build output: %w", err)
	}
	tmpSO := tmpFile.Name()
	_ = tmpFile.Close()
	defer func() { _ = os.Remove(tmpSO) }()

	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(goBin); err != nil {
		goBin = "go"
	}

	args := []string{"build", "-buildmode=plugin"}
	if raceEnabled {
		args = append(args, "-race")
	}
	if coverEnabled {
		args = append(args, "-cover")
	}
	args = append(args, "-o", tmpSO, ".")

	cmd := exec.Command(goBin, args...)
	cmd.Dir = absDir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("go %v failed: %w\n%s", args, err, string(output))
	}
	if err := os.Chmod(tmpSO, 0o600); err != nil {
		return "", fmt.Errorf("chmod built plugin: %w", err)
	}
	if err := os.Rename(tmpSO, cachedSO); err != nil {
		return "", fmt.Errorf("rename cached plugin: %w", err)
	}
	return cachedSO, nil
}
