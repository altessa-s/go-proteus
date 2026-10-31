// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import (
	"os"
	"strings"

	"github.com/altessa-s/go-proteus/sdk"
)

// Descriptor identifies the pkg_init_panics fixture plugin.
var Descriptor = sdk.Descriptor{
	Name:        "pkg_init_panics",
	Version:     "1.0.0",
	Description: "Fixture plugin that panics in package init()",
}

func init() {
	if !strings.Contains(os.Args[0], "pkg_init_panics.test") {
		triggerInitPanic()
	}
}

func triggerInitPanic() {
	panic("pkg_init_panics: intentional panic in package init()")
}

func main() {}
