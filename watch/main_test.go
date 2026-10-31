// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package watch_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/altessa-s/go-proteus/proteustest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	if err := proteustest.GoroutineLeaks(); code == 0 && err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}
