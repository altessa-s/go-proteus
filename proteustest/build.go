// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package proteustest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

const (
	pluginFilePerm = 0o600
)

// BuildPlugin compiles the Go plugin package at pkgDir into a shared object
// (`.so`) using `go build -buildmode=plugin`, mirroring `-race` and `-cover`
// settings from the running test binary. Each invocation builds a fresh output
// in tb.TempDir(); Go's build cache tracks the complete dependency graph.
//
// BuildPlugin calls `tb.Skip` on platforms where Go plugins are unsupported
// (such as Windows or when CGO_ENABLED=0).
func BuildPlugin(tb testing.TB, pkgDir string) string {
	tb.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "freebsd" {
		tb.Skip("Go plugins (-buildmode=plugin) are not supported on this platform")
	}
	if !cgoEnabled {
		tb.Skip("Go plugins (-buildmode=plugin) require cgo")
	}

	absDir, err := filepath.Abs(pkgDir)
	if err != nil {
		tb.Fatalf("proteustest.BuildPlugin: resolve path %q: %v", pkgDir, err)
	}

	coverEnabled := testing.CoverMode() != ""
	outPath := filepath.Join(tb.TempDir(), filepath.Base(absDir)+".so")
	if err := buildPlugin(tb.Context(), absDir, outPath, raceEnabled, coverEnabled); err != nil {
		tb.Fatalf("proteustest.BuildPlugin(%q): %v", pkgDir, err)
	}
	return outPath
}

func buildPlugin(ctx context.Context, absDir, outPath string, raceEnabled, coverEnabled bool) error {
	args := []string{"build", "-buildmode=plugin"}
	if raceEnabled {
		args = append(args, "-race")
	}
	if coverEnabled {
		args = append(args, "-cover")
	}
	args = append(args, "-o", outPath, ".")
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = absDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go %v failed: %w\n%s", args, err, output)
	}
	return os.Chmod(outPath, pluginFilePerm)
}
