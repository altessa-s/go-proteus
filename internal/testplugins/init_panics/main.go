// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import (
	"context"

	"github.com/altessa-s/go-proteus/sdk"
)

// Descriptor identifies the init_panics fixture plugin.
var Descriptor = sdk.Descriptor{
	Name:        "init_panics",
	Version:     "1.0.0",
	Description: "Fixture plugin that panics in Init",
}

// Init panics unconditionally.
func Init(_ context.Context) error {
	panic("init_panics: intentional panic during Init")
}

func main() {}
