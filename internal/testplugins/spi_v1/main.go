// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import "github.com/altessa-s/go-proteus/sdk"

// Descriptor identifies the spi_v1 fixture plugin.
var Descriptor = sdk.Descriptor{
	Name:        "spi_v1",
	Version:     "1.0.0",
	Description: "Fixture plugin implementing greeter SPI v1.0",
}

// SPIVersion declares the greeter contract version implemented by this plugin.
var SPIVersion = sdk.SPIVersion{Contract: "greeter", Major: 1, Minor: 0}

// Greeter is the exported v1.0 SPI provider.
var Greeter any = v1Greeter{}

type v1Greeter struct{}

func (v1Greeter) SPIVersion() sdk.SPIVersion {
	return sdk.SPIVersion{Contract: "greeter", Major: 1, Minor: 0}
}

func (v1Greeter) Greet(name string) string {
	return "v1:" + name
}

func main() {}
