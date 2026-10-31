// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import "github.com/altessa-s/go-proteus/sdk"

const v2SPIMajor = 2

// Descriptor identifies the spi_v2 fixture plugin.
var Descriptor = sdk.Descriptor{
	Name:        "spi_v2",
	Version:     "2.0.0",
	Description: "Fixture plugin implementing greeter SPI v2.0",
}

// SPIVersion declares the greeter contract version implemented by this plugin.
var SPIVersion = sdk.SPIVersion{Contract: "greeter", Major: v2SPIMajor, Minor: 0}

// Greeter is the exported v2.0 SPI provider.
var Greeter any = v2Greeter{}

type v2Greeter struct{}

func (v2Greeter) SPIVersion() sdk.SPIVersion {
	return SPIVersion
}

func (v2Greeter) Greet(name string) string {
	return "v2:" + name
}

func main() {}
