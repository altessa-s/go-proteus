// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/altessa-s/go-proteus/signature"

	coreio "github.com/altessa-s/go-atlas-core/io"
)

func TestMetadataReadLimit(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "oversized.sig")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := f.Truncate(signature.DefaultMaxEnvelopeBytes + 1); err != nil {
		t.Fatal(err)
	}

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := readRegularFile(path); !errors.Is(err, coreio.ErrReadLimitExceeded) {
		t.Fatalf("expected read limit, got %v", err)
	}

	if _, err := execCLI(t, "inspect", path); !errors.Is(err, coreio.ErrReadLimitExceeded) {
		t.Fatalf("expected inspect limit, got %v", err)
	}
}
