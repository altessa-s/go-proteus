// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Package host implements the plugin lifecycle [Manager] for go-proteus.
//
// [Manager] coordinates candidate discovery via [proteus.Source], DSSE manifest verification via
// [proteus.Verifier], policy evaluation, binary opening via [proteus.Opener], bounded initialization
// with a watchdog timer, hash-based quarantine, health probing, and hot reload of newly added plugins.
package host
