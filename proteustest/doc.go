// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Package proteustest provides in-memory test doubles, signing helpers,
// fixture plugin builders, and goroutine leak checks for [github.com/altessa-s/go-proteus]
// and its consumers. Production code must never import it.
//
// # Fakes
//
// [MemSource], [MemOpener], [MapSymbols], and [RecordingObserver] implement
// [proteus.Source], [proteus.Opener], [proteus.Symbols], and [proteus.Observer]
// entirely in memory so host admission and SPI tests run without filesystem or
// cgo overhead.
//
// # Signing Helpers
//
// [MustGenerateKey] and [SignedCandidate] construct signed [proteus.Candidate]
// values and matching [signature.KeySet] roots in a single call.
//
// # Fixture Builders and Leak Checks
//
// [BuildPlugin] compiles a fixture plugin package with `go build -buildmode=plugin`,
// mirroring `-race` and `-cover` flags from the running test binary and caching
// compiled `.so` artifacts across tests in the same binary. [GoroutineLeaks]
// reports permanently blocked goroutines via `go-atlas-core/runtime/leakcheck`.
package proteustest
