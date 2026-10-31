// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package host_test

import (
	"testing"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/host"
	"github.com/altessa-s/go-proteus/sdk"
)

func BenchmarkManagerGetAndLookup(b *testing.B) {
	ts := newTestSigner(&testing.T{})
	opener := newFakeOpener()
	cand, _ := makeSignedCandidate(&testing.T{}, ts, opener, "bench.so", "bench", "1.0.0", 0, memSymbols{
		sdk.SymbolDescriptor: sdk.Descriptor{Name: "bench", Version: "1.0.0"},
		"Provider":           "instance",
	})
	src := &memSource{candidates: []proteus.Candidate{cand}}
	mgr, err := host.New(src, opener,
		host.WithVerifier(ts.verifier),
		host.WithGoos("linux"),
		host.WithGoarch("arm64"),
	)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := mgr.Load(b.Context()); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		p, ok := mgr.Get("bench")
		if !ok {
			b.Fatal("missing bench plugin")
		}
		if _, ok := p.Lookup("Provider"); !ok {
			b.Fatal("missing Provider symbol")
		}
	}
}
