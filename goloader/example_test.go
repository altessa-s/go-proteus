// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package goloader_test

import (
	"context"
	"fmt"
	"os"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/goloader"
)

func ExampleOpener() {
	tmp, err := os.MkdirTemp("", "proteus-goloader-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmp)
	_ = os.Chmod(tmp, 0o700)

	opener, err := goloader.New(tmp,
		goloader.WithOpenFunc(func(context.Context, string) (proteus.Symbols, error) {
			return stubSymbols{"Hello": "world"}, nil
		}),
	)
	if err != nil {
		panic(err)
	}
	cand, h := makeCandidate("demo.so", []byte("demo-binary"))
	opened, err := opener.Open(context.Background(), cand, h)
	if err != nil {
		panic(err)
	}
	val, _ := opened.Symbols.Lookup("Hello")
	fmt.Println(val, opened.Size)
	// Output:
	// world 11
}
