// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package proteustest_test

import (
	"context"
	"fmt"

	"github.com/altessa-s/go-proteus/proteustest"

	proteus "github.com/altessa-s/go-proteus"
)

func ExampleNewMemSource() {
	src := proteustest.NewMemSource(proteus.Candidate{ID: "greeter.so"})
	candidates, err := src.Candidates(context.Background())
	fmt.Println(err == nil, len(candidates), candidates[0].ID)
	// Output:
	// true 1 greeter.so
}
