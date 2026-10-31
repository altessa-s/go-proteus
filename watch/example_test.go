// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package watch_test

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/watch"
)

func ExampleWatcher() {
	tmp, err := os.MkdirTemp("", "proteus-watch-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmp)

	reloader := funcReloader(func(context.Context) (proteus.LoadReport, error) {
		return proteus.LoadReport{}, nil
	})

	w, err := watch.New(tmp, reloader, watch.WithSettle(50*time.Millisecond))
	if err != nil {
		panic(err)
	}
	if err := w.Start(context.Background()); err != nil {
		panic(err)
	}
	fmt.Println(w.Running())
	_ = w.Stop()
	fmt.Println(w.Running())
	// Output:
	// true
	// false
}
