// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import (
	"context"
	"time"

	"github.com/altessa-s/go-proteus/sdk"
)

const blockDuration = 200 * time.Millisecond

// Descriptor identifies the init_blocks fixture plugin.
var Descriptor = sdk.Descriptor{
	Name:        "init_blocks",
	Version:     "1.0.0",
	Description: "Fixture plugin that blocks in Init",
}

// Release can be closed by tests to unblock Init immediately after watchdog verification.
var Release = make(chan struct{})

// Init ignores ctx.Done() until Release is closed or blockDuration elapses.
func Init(ctx context.Context) error {
	select {
	case <-Release:
	case <-time.After(blockDuration):
	}

	return ctx.Err()
}

func main() {}
