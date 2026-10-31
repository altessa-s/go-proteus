// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package proteustest

import (
	"github.com/altessa-s/go-atlas-core/runtime/leakcheck"
)

// GoroutineLeaks checks the Go 1.27 goroutineleak profile via
// [leakcheck.Check] and reports permanently blocked goroutines with their stacks.
//
// Call it from TestMain after m.Run():
//
//	func TestMain(m *testing.M) {
//		code := m.Run()
//		if err := proteustest.GoroutineLeaks(); code == 0 && err != nil {
//			fmt.Fprintln(os.Stderr, err)
//			code = 1
//		}
//		os.Exit(code)
//	}
func GoroutineLeaks() error {
	return leakcheck.Check()
}
