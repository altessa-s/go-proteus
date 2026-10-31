//go:build (!linux && !darwin) || !cgo

// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package goloader

import (
	"context"

	"github.com/altessa-s/go-proteus"
)

func defaultOpenPlugin(_ context.Context, _ string) (proteus.Symbols, error) {
	return nil, proteus.ErrUnsupportedPlatform
}
