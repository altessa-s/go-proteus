// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Package sdk defines the minimal contract imported by Go plugin binaries loaded by go-proteus.
//
// Plugin authors import only this package to declare their required [Descriptor] symbol and optional
// [SPIVersion] or [DepInfo] symbols without pulling host-side dependencies into the plugin binary.
//
// Example plugin declaration:
//
//	package main
//
//	import "github.com/altessa-s/go-proteus/sdk"
//
//	var Descriptor = sdk.Descriptor{
//	    Name:        "greeter",
//	    Version:     "1.0.0",
//	    Description: "Greeter plugin",
//	}
//
//	var DepInfo = sdk.NewDepInfoFromBuild()
package sdk
