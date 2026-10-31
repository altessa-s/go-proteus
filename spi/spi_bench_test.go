// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package spi_test

import (
	"strings"
	"testing"
	"time"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/sdk"
	"github.com/altessa-s/go-proteus/spi"
)

func BenchmarkProviders(b *testing.B) {
	ver := sdk.SPIVersion{Contract: "Greeter", Major: 1, Minor: 0}
	p := proteus.NewPlugin(
		sdk.Descriptor{Name: "greeter", Version: "1.0.0"},
		proteus.Manifest{},
		"greeter.so",
		strings.Repeat("a", 64),
		time.Now().UTC(),
		fakeSymbols{
			"Greeter":           &greeterImpl{prefix: "hi"},
			"GreeterSPIVersion": &ver,
		},
	)
	reg := &fakeRegistry{plugins: []*proteus.Plugin{p}}

	b.ReportAllocs()
	for b.Loop() {
		for g := range spi.Providers[Greeter](reg, "Greeter", spi.WithMajor(1)) {
			_ = g.Greet("bench")
		}
	}
}
