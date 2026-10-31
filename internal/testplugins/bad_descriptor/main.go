// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import "github.com/altessa-s/go-proteus/sdk"

// Descriptor has an empty Name and Version, which violates the sdk.Descriptor contract.
var Descriptor = sdk.Descriptor{}

func main() {}
