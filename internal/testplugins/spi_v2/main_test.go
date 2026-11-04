// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import "testing"

func TestSPIV2Symbols(t *testing.T) {
	t.Parallel()
	main()

	g := v2Greeter{}
	if g.SPIVersion().Major != 2 || g.Greet("x") != "v2:x" {
		t.Fatal("unexpected v2Greeter behavior")
	}
}
