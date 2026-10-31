// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import "github.com/altessa-s/go-proteus/sdk"

// Descriptor exports "actual_name" while tests sign the manifest as "expected_name".
var Descriptor = sdk.Descriptor{
	Name:        "actual_name",
	Version:     "1.0.0",
	Description: "Fixture plugin with mismatched Descriptor name",
}

func main() {}
