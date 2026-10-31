// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package sdk_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/altessa-s/go-proteus/sdk"
)

func FuzzUnwrapAll(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Add([]byte{1, 1, 2, 0, 2, 1})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, ops []byte) {
		if len(ops) > 64 {
			ops = ops[:64]
		}
		var current error
		for i, op := range ops {
			switch op % 3 {
			case 0:
				leaf := fmt.Errorf("leaf-%d", i)
				if current == nil {
					current = leaf
				} else {
					current = fmt.Errorf("wrap-%d: %w", i, current)
				}
			case 1:
				other := fmt.Errorf("branch-%d", i)
				if current == nil {
					current = other
				} else {
					current = errors.Join(current, other)
				}
			case 2:
				if current != nil {
					current = fmt.Errorf("layer-%d: %w", i, current)
				}
			}
		}
		got := sdk.UnwrapAll(current)
		if current == nil && len(got) != 0 {
			t.Fatalf("expected empty slice for nil error, got %d", len(got))
		}
		if current != nil && len(got) == 0 {
			t.Fatal("expected non-empty slice for non-nil error")
		}
	})
}
