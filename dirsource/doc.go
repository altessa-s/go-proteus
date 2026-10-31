// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Package dirsource implements [proteus.Source] over a local filesystem directory confined via
// [os.Root].
//
// It enforces regular-file checks, symlink confinement, group/world-writable permission checks,
// and bounded reads for both .so artifacts and detached .so.sig DSSE envelopes.
package dirsource
