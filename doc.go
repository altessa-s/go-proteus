// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Package proteus defines the core domain model, ports, policies, and sentinel errors for
// admitting, verifying, loading, and supervising dynamic Go .so plugins.
//
// Host applications wire a [Source], [Opener], and [Verifier] into the manager in package
// [github.com/altessa-s/go-proteus/host], while plugin authors import only the minimal contract
// in package [github.com/altessa-s/go-proteus/sdk].
package proteus
