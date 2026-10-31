// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package watch

import (
	"log/slog"
	"time"

	proteus "github.com/altessa-s/go-proteus"
)

//go:generate optgen generate --type=options

// Default configuration constants for [Watcher].
const (
	// DefaultSettle is the default quiet window duration before a filesystem burst triggers Reload.
	DefaultSettle = 200 * time.Millisecond

	// DefaultExtension is the default plugin binary suffix observed by the watcher.
	DefaultExtension = ".so"

	// DefaultSignatureSuffix is the default signature suffix observed by the watcher.
	DefaultSignatureSuffix = ".sig"
)

type options struct {
	settle          time.Duration `optgen:"default=DefaultSettle"`
	extension       string        `optgen:"default=DefaultExtension"`
	signatureSuffix string        `optgen:"default=DefaultSignatureSuffix"`
	logger          *slog.Logger
	onError         func(error)
	onReload        func(proteus.LoadReport)
	disableFsnotify bool
}
