// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package spi_test

import (
	"context"
	"errors"
	"iter"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/sdk"
	"github.com/altessa-s/go-proteus/spi"
)

type Greeter interface {
	Greet(name string) string
}

type greeterImpl struct {
	prefix string
}

func (g *greeterImpl) Greet(name string) string {
	return g.prefix + " " + name
}

type fakeSymbols map[string]any

func (f fakeSymbols) Lookup(name string) (any, error) {
	v, ok := f[name]
	if !ok {
		return nil, errors.New("missing")
	}
	return v, nil
}

type fakeRegistry struct {
	plugins []*proteus.Plugin
}

func (r *fakeRegistry) LookupAll(symbol string) iter.Seq2[*proteus.Plugin, any] {
	return func(yield func(*proteus.Plugin, any) bool) {
		for _, p := range r.plugins {
			if sym, ok := p.Lookup(symbol); ok {
				if !yield(p, sym) {
					return
				}
			}
		}
	}
}

func makePlugin(name string, syms fakeSymbols) *proteus.Plugin {
	return proteus.NewPlugin(
		sdk.Descriptor{Name: name, Version: "1.0.0"},
		proteus.Manifest{},
		name+".so",
		strings.Repeat("a", 64),
		time.Now().UTC(),
		syms,
	)
}

func TestProviders_D19(t *testing.T) {
	t.Parallel()

	g1 := Greeter(&greeterImpl{prefix: "hello"})
	v1 := sdk.SPIVersion{Contract: "Greeter", Major: 1, Minor: 2}
	v1Ptr := &v1

	pDirect := makePlugin("p-direct", fakeSymbols{
		"Greeter":           &greeterImpl{prefix: "hi"},
		"GreeterSPIVersion": v1,
	})
	pPtrInterface := makePlugin("p-ptr", fakeSymbols{
		"Greeter":           &g1,
		"GreeterSPIVersion": &v1Ptr,
	})
	pMajorMismatch := makePlugin("p-v2", fakeSymbols{
		"Greeter":           &greeterImpl{prefix: "v2"},
		"GreeterSPIVersion": &sdk.SPIVersion{Contract: "Greeter", Major: 2, Minor: 0},
	})
	pMinorMismatch := makePlugin("p-minor", fakeSymbols{
		"Greeter":           &greeterImpl{prefix: "old"},
		"GreeterSPIVersion": &sdk.SPIVersion{Contract: "Greeter", Major: 1, Minor: 0},
	})
	pWrongContract := makePlugin("p-contract", fakeSymbols{
		"Greeter":           &greeterImpl{prefix: "wrong"},
		"GreeterSPIVersion": &sdk.SPIVersion{Contract: "Other", Major: 1, Minor: 2},
	})
	pMalformedVer := makePlugin("p-badver", fakeSymbols{
		"Greeter":           &greeterImpl{prefix: "badver"},
		"GreeterSPIVersion": "not-an-spi-version",
	})
	pWrongType := makePlugin("p-badtype", fakeSymbols{
		"Greeter":           42,
		"GreeterSPIVersion": &v1,
	})
	pUnversioned := makePlugin("p-unver", fakeSymbols{
		"Greeter": &greeterImpl{prefix: "unver"},
	})
	pFallbackVer := makePlugin("p-fallback-ver", fakeSymbols{
		"CustomSym":  &greeterImpl{prefix: "custom"},
		"SPIVersion": (*sdk.SPIVersion)(nil),
	})

	reg := &fakeRegistry{
		plugins: []*proteus.Plugin{
			pDirect,
			pPtrInterface,
			pMajorMismatch,
			pMinorMismatch,
			pWrongContract,
			pMalformedVer,
			pWrongType,
			pUnversioned,
		},
	}

	var skips []spi.SkipEvent
	var matched []string
	for prov, plug := range spi.Providers[Greeter](
		reg,
		"Greeter",
		spi.WithMajor(1),
		spi.WithMinMinor(1),
		spi.WithRequireVersion(),
		spi.WithOnSkip(func(ev spi.SkipEvent) {
			skips = append(skips, ev)
		}),
	) {
		if prov.Greet("world") == "" {
			t.Fatal("empty greeting")
		}
		matched = append(matched, plug.Name())
	}

	if len(matched) != 2 || matched[0] != "p-direct" || matched[1] != "p-ptr" {
		t.Fatalf("expected [p-direct p-ptr], got %v", matched)
	}
	if len(skips) != 6 {
		t.Fatalf("expected 6 skip events, got %d: %+v", len(skips), skips)
	}

	// Unversioned allowed when WithRequireVersion is not set, and early break from range works.
	count := 0
	for range spi.Providers[Greeter](reg, "Greeter", spi.WithMajor(1)) {
		count++
		if count == 1 {
			break
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 iteration before break, got %d", count)
	}

	// Custom symbol + nil *sdk.SPIVersion pointer + double-pointer nil.
	var nilVerPtr *sdk.SPIVersion
	pDoubleNil := makePlugin("p-doublenil", fakeSymbols{
		"CustomSym":           &greeterImpl{prefix: "custom"},
		"CustomSymSPIVersion": &nilVerPtr,
	})
	pNilSym := makePlugin("p-nilsym", fakeSymbols{
		"CustomSym": nil,
	})
	regCustom := &fakeRegistry{plugins: []*proteus.Plugin{pFallbackVer, pDoubleNil, pNilSym}}
	var customSkips []spi.SkipReason
	for range spi.Providers[Greeter](
		regCustom,
		"Greeter",
		spi.WithSymbol("CustomSym"),
		spi.WithMajor(1),
		spi.WithOnSkip(func(ev spi.SkipEvent) {
			customSkips = append(customSkips, ev.Reason)
		}),
	) {
		t.Fatal("expected no valid providers in regCustom")
	}
	if len(customSkips) != 3 {
		t.Fatalf("expected 3 skips in regCustom, got %v", customSkips)
	}

	// Nil registry is a safe no-op.
	for range spi.Providers[Greeter](nil, "Greeter") {
		t.Fatal("expected zero items from nil registry")
	}
}

func TestGuard(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	if err := spi.Guard(ctx, "p1", nil); err != nil {
		t.Fatalf("expected nil for nil fn, got %v", err)
	}

	var gotPlugin string
	var gotRecovered any
	var gotStack []byte
	err := spi.Guard(ctx, "p-panic", func(context.Context) error {
		panic("kaboom")
	}, spi.WithOnPanic(func(pluginName string, recovered any, stack []byte) {
		gotPlugin = pluginName
		gotRecovered = recovered
		gotStack = stack
	}))
	if !errors.Is(err, proteus.ErrPanicked) {
		t.Fatalf("expected ErrPanicked, got %v", err)
	}
	if strings.Contains(err.Error(), "kaboom") {
		t.Fatal("panic payload leaked")
	}

	if gotPlugin != "p-panic" || gotRecovered != "kaboom" || len(gotStack) == 0 {
		t.Fatalf("unexpected onPanic callback args: plugin=%q recovered=%v stackLen=%d", gotPlugin, gotRecovered, len(gotStack))
	}

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := spi.Guard(cctx, "p1", func(context.Context) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestMajorZeroAndMinorOnly(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		opts         []spi.Option
		major, minor int
		want         bool
	}{
		{"zero accepted", []spi.Option{spi.WithMajor(0)}, 0, 0, true},
		{"zero enforced", []spi.Option{spi.WithMajor(0)}, 1, 0, false},
		{"minor rejected", []spi.Option{spi.WithMinMinor(2)}, 9, 1, false},
		{"minor accepted", []spi.Option{spi.WithMinMinor(2)}, 9, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := makePlugin("p", fakeSymbols{"Greeter": &greeterImpl{}, "GreeterSPIVersion": sdk.SPIVersion{Major: tc.major, Minor: tc.minor}})
			count := 0
			for range spi.Providers[Greeter](&fakeRegistry{plugins: []*proteus.Plugin{p}}, "Greeter", tc.opts...) {
				count++
			}
			if (count == 1) != tc.want {
				t.Fatalf("provider count: %d", count)
			}
		})
	}
}

func TestProvidersExportedVariables(t *testing.T) {
	t.Parallel()
	concrete := &greeterImpl{prefix: "hello"}
	var nilInterface Greeter
	var nilConcrete *greeterImpl
	var typedNil Greeter = nilConcrete
	var boxed any = concrete
	for _, tc := range []struct {
		name string
		raw  any
		want bool
	}{
		{"direct", concrete, true},
		{"concrete variable", &concrete, true},
		{"any variable", &boxed, true},
		{"nil interface variable", &nilInterface, false},
		{"nil concrete variable", &nilConcrete, false},
		{"typed nil interface variable", &typedNil, false},
		{"direct typed nil", nilConcrete, false},
		{"nil variable pointer", (**greeterImpl)(nil), false},
		{"wrong type", new(42), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := makePlugin("p", fakeSymbols{"Greeter": tc.raw})
			var skips []spi.SkipEvent
			count := 0
			for g := range spi.Providers[Greeter](&fakeRegistry{plugins: []*proteus.Plugin{p}}, "Greeter",
				spi.WithOnSkip(func(ev spi.SkipEvent) { skips = append(skips, ev) })) {
				count++
				require.Equal(t, "hello world", g.Greet("world"))
			}
			if tc.want {
				require.Equal(t, 1, count)
				require.Empty(t, skips)
			} else {
				require.Zero(t, count)
				require.Len(t, skips, 1)
				require.ErrorIs(t, skips[0].Err, proteus.ErrInvalidSymbol)
			}
		})
	}
}
