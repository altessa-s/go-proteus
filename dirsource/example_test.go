// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package dirsource_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/altessa-s/go-proteus/dirsource"
)

func ExampleSource() {
	tmp, err := os.MkdirTemp("", "proteus-dirsource-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmp)
	_ = os.Chmod(tmp, 0o700)

	soPath := filepath.Join(tmp, "greeter.so")
	_ = os.WriteFile(soPath, []byte("fake-so"), 0o600)

	src, err := dirsource.New(tmp)
	if err != nil {
		panic(err)
	}
	cands, err := src.Candidates(context.Background())
	if err != nil {
		panic(err)
	}
	fmt.Println(len(cands), cands[0].ID)
	// Output:
	// 1 greeter.so
}
