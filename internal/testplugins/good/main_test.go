// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import (
	"context"
	"testing"
)

func TestGoodPluginSymbols(t *testing.T) {
	t.Parallel()
	main()
	if err := Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := HealthCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	g := goodGreeter{}
	if g.SPIVersion().Contract != "greeter" || g.Greet("x") != "hello, x" {
		t.Fatal("unexpected greeter behavior")
	}
}
