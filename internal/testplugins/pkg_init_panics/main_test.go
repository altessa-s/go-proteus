// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import "testing"

func TestPkgInitPanicsSymbol(t *testing.T) {
	t.Parallel()
	main()

	defer func() {
		if recover() == nil {
			t.Fatal("expected triggerInitPanic to panic")
		}
	}()

	triggerInitPanic()
}
