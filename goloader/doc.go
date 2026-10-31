// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Package goloader implements [proteus.Opener] over the standard library [plugin] package.
//
// It streams candidate bytes into a private 0o600 snapshot file while computing a SHA-256 digest,
// re-hashes the snapshot from disk to close TOCTOU windows, caches opened handles by content hash,
// and recovers panics raised by plugin package init() functions during [plugin.Open].
package goloader
