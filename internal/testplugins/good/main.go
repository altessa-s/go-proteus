// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import (
	"context"
	"sync/atomic"

	"github.com/altessa-s/go-proteus/sdk"
)

const (
	goodSPIMajor = 1
	goodSPIMinor = 2
)

// Descriptor identifies the good fixture plugin.
var Descriptor = sdk.Descriptor{
	Name:        "good",
	Version:     "1.2.0",
	Description: "Well-behaved fixture plugin",
}

// DepInfo exposes build dependency metadata.
var DepInfo = sdk.NewDepInfoFromBuild()

// SPIVersion declares the greeter contract version implemented by this plugin.
var SPIVersion = sdk.SPIVersion{Contract: "greeter", Major: goodSPIMajor, Minor: goodSPIMinor}

// Greeter is the exported SPI provider symbol.
var Greeter any = goodGreeter{}

type goodGreeter struct{}

func (goodGreeter) SPIVersion() sdk.SPIVersion {
	return SPIVersion
}

func (goodGreeter) Greet(name string) string {
	return "hello, " + name
}

// Init initializes the fixture plugin.
func Init(ctx context.Context) error { initCalls.Add(1); return ctx.Err() }

// Close shuts down the fixture plugin.
func Close(ctx context.Context) error { closeCalls.Add(1); return ctx.Err() }

// HealthCheck reports healthy status for the fixture plugin.
func HealthCheck(ctx context.Context) error { return ctx.Err() }

func main() {}

var initCalls, closeCalls atomic.Int32

// LifecycleCounts reports calls for integration assertions.
func LifecycleCounts() (int32, int32) { return initCalls.Load(), closeCalls.Load() }
