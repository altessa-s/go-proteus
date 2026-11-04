// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import "testing"

func TestSPIV1Symbols(t *testing.T) {
	t.Parallel()
	main()

	g := v1Greeter{}
	if g.SPIVersion().Major != 1 || g.Greet("x") != "v1:x" {
		t.Fatal("unexpected v1Greeter behavior")
	}
}
