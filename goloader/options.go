// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package goloader

import (
	"context"

	proteus "github.com/altessa-s/go-proteus"
)

//go:generate optgen generate --type=options

// DefaultMaxArtifactBytes is the default maximum size (256 MiB) streamed into a snapshot file.
const DefaultMaxArtifactBytes int64 = 256 << 20

// OpenFunc is the low-level shared-object loader signature used by [Opener].
type OpenFunc func(ctx context.Context, path string) (proteus.Symbols, error)

type options struct {
	maxArtifactBytes     int64 `optgen:"default=DefaultMaxArtifactBytes"`
	skipPermissionChecks bool
	openFunc             OpenFunc
	afterWriteHook       func(snapshotPath string)
}
