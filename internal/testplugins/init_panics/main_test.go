// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import (
	"context"
	"testing"
)

func TestInitPanicsSymbol(t *testing.T) {
	t.Parallel()
	main()

	defer func() {
		if recover() == nil {
			t.Fatal("expected Init to panic")
		}
	}()

	_ = Init(context.Background())
}
