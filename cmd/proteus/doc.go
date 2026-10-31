// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Command proteus generates signing key pairs, signs plugin shared objects into
// detached DSSE `.so.sig` envelopes, verifies signed plugins against a trusted
// public key set, and inspects `.so` or `.so.sig` artifacts.
//
// # Subcommands
//
//   - `proteus keygen`: generate Ed25519 or ECDSA P-256 key pairs.
//   - `proteus sign`: hash a `.so` artifact, construct a [proteus.Manifest], and
//     atomically write its signed DSSE envelope to `<plugin>.so.sig`.
//   - `proteus verify`: verify a `<plugin>.so` and `<plugin>.so.sig` pair against
//     one or more public key PEM files.
//   - `proteus inspect`: decode and display a `.so.sig` DSSE envelope or compute
//     the SHA-256 digest and size of a `.so` binary.
package main
