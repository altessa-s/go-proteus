// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package spi

//go:generate optgen generate --type=options

type options struct {
	symbol         string
	major          int
	minMinor       int
	requireVersion bool
	onSkip         func(SkipEvent)
	onPanic        func(pluginName string, recovered any, stack []byte)
}
