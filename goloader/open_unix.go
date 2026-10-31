//go:build (linux || darwin) && cgo

// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package goloader

import (
	"context"
	"plugin"

	"github.com/altessa-s/go-proteus"
)

type stdPluginSymbols struct {
	raw *plugin.Plugin
}

func (s stdPluginSymbols) Lookup(name string) (any, error) {
	return s.raw.Lookup(name)
}

func defaultOpenPlugin(_ context.Context, path string) (proteus.Symbols, error) {
	p, err := plugin.Open(path)
	if err != nil {
		return nil, err
	}
	return stdPluginSymbols{raw: p}, nil
}
