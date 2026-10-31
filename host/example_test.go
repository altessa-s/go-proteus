// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package host_test

import (
	"context"
	"fmt"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/host"
	"github.com/altessa-s/go-proteus/sdk"
)

func ExampleManager() {
	opener := newFakeOpener()
	h := hashOf("demo.so")
	opener.results["demo.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{
			Symbols: memSymbols{
				sdk.SymbolDescriptor: sdk.Descriptor{Name: "demo", Version: "1.0.0"},
			},
			SHA256: h,
			Size:   256,
		}, nil
	}
	src := &memSource{candidates: []proteus.Candidate{{ID: "demo.so"}}}

	mgr, err := host.New(src, opener, host.WithUnsigned(proteus.UnsignedAllow))
	if err != nil {
		panic(err)
	}
	defer mgr.Close(context.Background())

	report, err := mgr.Load(context.Background())
	if err != nil {
		panic(err)
	}
	fmt.Println(len(report.Loaded), report.Loaded[0].Name())
	// Output:
	// 1 demo
}
