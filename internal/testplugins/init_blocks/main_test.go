// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import (
	"context"
	"testing"
)

func TestInitBlocksSymbol(t *testing.T) {
	t.Parallel()
	main()
	close(Release)

	if err := Init(context.Background()); err != nil {
		t.Fatal(err)
	}
}
