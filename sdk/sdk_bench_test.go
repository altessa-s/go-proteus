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

func BenchmarkUnwrapAll(b *testing.B) {
	leaf1 := errors.New("leaf1")
	leaf2 := errors.New("leaf2")
	chain := fmt.Errorf("l3: %w", errors.Join(fmt.Errorf("l2: %w", leaf1), leaf2))

	b.ReportAllocs()
	for b.Loop() {
		_ = sdk.UnwrapAll(chain)
	}
}
