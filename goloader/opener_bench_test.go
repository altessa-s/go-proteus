// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package goloader_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/goloader"
)

func BenchmarkOpenerCached(b *testing.B) {
	workDir := filepath.Join(b.TempDir(), "snaps")
	opener, err := goloader.New(workDir,
		goloader.WithOpenFunc(func(context.Context, string) (proteus.Symbols, error) {
			return stubSymbols{"Descriptor": "ok"}, nil
		}),
	)
	if err != nil {
		b.Fatal(err)
	}
	cand, h := makeCandidate("bench.so", make([]byte, 4096))
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		if _, err := opener.Open(ctx, cand, h, 0); err != nil {
			b.Fatal(err)
		}
	}
}
