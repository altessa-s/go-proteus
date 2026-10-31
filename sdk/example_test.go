// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package sdk_test

import (
	"errors"
	"fmt"

	"github.com/altessa-s/go-proteus/sdk"
)

func ExampleUnwrapAll() {
	errA := errors.New("db timeout")
	errB := errors.New("cache miss")
	combined := fmt.Errorf("request failed: %w", errors.Join(errA, errB))

	for _, err := range sdk.UnwrapAll(combined) {
		fmt.Println(err.Error())
	}
	// Output:
	// request failed: db timeout
	// cache miss
	// db timeout
	// cache miss
	// db timeout
	// cache miss
}
