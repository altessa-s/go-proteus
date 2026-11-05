// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package spi

import (
	"context"
	"fmt"
	"runtime/debug"

	"github.com/altessa-s/go-proteus"
)

// Guard invokes fn(ctx) and recovers any panic raised inside plugin code, converting it into
// an error wrapping [proteus.ErrPanicked].
func Guard(ctx context.Context, pluginName string, fn func(context.Context) error, opts ...Option) (err error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}

	if fn == nil {
		return nil
	}

	cfg := newOptions(opts...)

	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			if cfg.onPanic != nil {
				cfg.onPanic(pluginName, r, stack)
			}

			err = fmt.Errorf("%w: plugin %q panicked (%T)", proteus.ErrPanicked, pluginName, r)
		}
	}()

	return fn(ctx)
}
