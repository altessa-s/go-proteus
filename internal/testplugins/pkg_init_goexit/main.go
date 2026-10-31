// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import (
	"runtime"

	"github.com/altessa-s/go-proteus/sdk"
)

// Descriptor initializes the fixture through the same boundary as package init.
var Descriptor = exitDuringInitialization()

func exitDuringInitialization() sdk.Descriptor {
	runtime.Goexit()
	return sdk.Descriptor{}
}

func main() {}
