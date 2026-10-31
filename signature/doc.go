// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Package signature implements Dead Simple Signing Envelope (DSSE) v1 verification, strict JSON v2
// manifest encoding, and public key set management for go-proteus plugins.
//
// Only Ed25519 and ECDSA P-256 keys are accepted; RSA and other elliptic curves are rejected with
// [ErrKeyPolicy].
package signature
