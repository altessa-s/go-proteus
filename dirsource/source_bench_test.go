// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package dirsource_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/altessa-s/go-proteus/dirsource"
)

func BenchmarkCandidates(b *testing.B) {
	dir := filepath.Join(b.TempDir(), "plugins")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		b.Fatal(err)
	}
	for _, name := range []string{"a.so", "b.so", "c.so"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("binary"), 0o600); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(p+".sig", []byte("sig"), 0o600); err != nil {
			b.Fatal(err)
		}
	}
	src, err := dirsource.New(dir)
	if err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := src.Candidates(ctx); err != nil {
			b.Fatal(err)
		}
	}
}
