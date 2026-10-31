// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package spi_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/spi"
)

func ExampleGuard() {
	err := spi.Guard(context.Background(), "demo-plugin", func(context.Context) error {
		panic("unexpected nil dereference")
	})
	fmt.Println(errors.Is(err, proteus.ErrPanicked))
	// Output:
	// true
}
