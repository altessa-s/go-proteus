// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package host_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/host"
	"github.com/altessa-s/go-proteus/sdk"
)

type callbackObserver struct {
	proteus.NoopObserver
	callback func()
}

func (o callbackObserver) Admitted(proteus.AdmissionEvent) { o.callback() }
func (o callbackObserver) Initialized(proteus.InitEvent)   { o.callback() }
func (o callbackObserver) RegistryChanged(proteus.Stats)   { o.callback() }

func TestSharedMappedLifecycle(t *testing.T) {
	t.Parallel()
	src := &memSource{candidates: []proteus.Candidate{{ID: t.Name()}}}
	opener := newFakeOpener()
	var inits, closes atomic.Int32
	opener.results[t.Name()] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{Mapped: true, SHA256: hashOf(t.Name()), Symbols: memSymbols{
			sdk.SymbolDescriptor: sdk.Descriptor{Name: "shared", Version: "1.0.0"},
			sdk.SymbolInit:       func(context.Context) error { inits.Add(1); return nil },
			sdk.SymbolClose:      func(context.Context) error { closes.Add(1); return nil },
		}}, nil
	}
	create := func() *host.Manager {
		m, err := host.New(src, opener, host.WithUnsigned(proteus.UnsignedAllow))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	first, second := create(), create()
	for _, m := range []*host.Manager{first, second} {
		r, err := m.Load(t.Context())
		if err != nil || len(r.Loaded) != 1 {
			t.Fatalf("load: %+v %v", r, err)
		}
	}
	if inits.Load() != 1 {
		t.Fatalf("Init calls: %d", inits.Load())
	}
	if err := first.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if closes.Load() != 0 {
		t.Fatal("closed shared image while owned")
	}
	if p, ok := second.Get("shared"); !ok || p.State() != proteus.StateReady {
		t.Fatal("second owner lost ready image")
	}
	if err := second.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if closes.Load() != 1 {
		t.Fatalf("Close calls: %d", closes.Load())
	}
	third := create()
	r, err := third.Load(t.Context())
	if err != nil || !errors.Is(r.Err(), proteus.ErrAlreadyLoaded) {
		t.Fatalf("terminal image admitted: %+v %v", r, err)
	}
	if inits.Load() != 1 {
		t.Fatal("reinitialized terminal image")
	}
}

func TestCallbacksCanReadRegistryAndRuntimeQuarantine(t *testing.T) {
	t.Parallel()
	src := &memSource{candidates: []proteus.Candidate{{ID: "dep"}, {ID: "consumer"}}}
	opener := newFakeOpener()
	var m *host.Manager
	var closes int
	for _, name := range []string{"dep", "consumer"} {
		opener.results[name] = func(proteus.Candidate, string) (proteus.Opened, error) {
			return proteus.Opened{SHA256: hashOf(name), Symbols: memSymbols{
				sdk.SymbolDescriptor: sdk.Descriptor{Name: name, Version: "1.0.0"},
				sdk.SymbolInit: func(context.Context) error {
					if name == "consumer" {
						if _, ok := m.Get("dep"); !ok {
							return errors.New("dependency unavailable")
						}
					}
					return nil
				},
				sdk.SymbolClose: func(context.Context) error { closes++; return nil },
				"Provider":      42,
			}}, nil
		}
	}
	observer := callbackObserver{callback: func() { _ = slices.Collect(m.All()); _, _ = m.Get("dep") }}
	var err error
	m, err = host.New(src, opener, host.WithUnsigned(proteus.UnsignedAllow), host.WithObserver(observer))
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.Load(t.Context())
	if err != nil || len(r.Loaded) != 2 {
		t.Fatalf("load: %+v %v", r, err)
	}
	if err := m.Quarantine("consumer"); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Get("consumer"); ok {
		t.Fatal("quarantined plugin still exposed")
	}
	if len(slices.Collect(m.All())) != 1 || len(slices.Collect(m.Failed())) != 1 || closes != 1 {
		t.Fatal("inconsistent runtime quarantine")
	}
	count := 0
	for range m.LookupAll("Provider") {
		count++
	}
	if count != 1 {
		t.Fatal("quarantined provider exposed")
	}
	if m.Health(t.Context()).Status != proteus.StatusDegraded {
		t.Fatal("health ignores runtime quarantine")
	}
	r, err = m.Reload(t.Context())
	if err != nil || len(r.Loaded) != 0 {
		t.Fatalf("quarantine reload: %+v %v", r, err)
	}
	if err := m.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownUnsignedPolicyRejected(t *testing.T) {
	t.Parallel()
	for _, policy := range []proteus.UnsignedPolicy{-1, 99} {
		if _, err := host.New(&memSource{}, newFakeOpener(), host.WithUnsigned(policy)); err == nil {
			t.Fatalf("accepted policy %d", policy)
		}
	}
}

func TestTemporaryOpenFailureCanRecover(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	cand := proteus.Candidate{ID: "retry", Signature: signer.signManifest(t, proteus.Manifest{Name: "retry", PluginVer: "1.0.0", SHA256: hashOf("retry"), Size: 10})}
	src := &memSource{candidates: []proteus.Candidate{cand}}
	opener := newFakeOpener()
	attempt := 0
	opener.results[cand.ID] = func(proteus.Candidate, string) (proteus.Opened, error) {
		attempt++
		if attempt == 1 {
			return proteus.Opened{}, errors.New("temporary storage failure")
		}
		return proteus.Opened{SHA256: hashOf("retry"), Size: 10, Symbols: memSymbols{sdk.SymbolDescriptor: sdk.Descriptor{Name: "retry", Version: "1.0.0"}}}, nil
	}
	m, err := host.New(src, opener, host.WithVerifier(signer.verifier), host.WithGoos("linux"), host.WithGoarch("arm64"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.Load(t.Context())
	if err != nil || len(r.Failed) != 1 || len(m.Quarantined()) != 0 {
		t.Fatalf("first load: %+v %v", r, err)
	}
	if m.Health(t.Context()).Status != proteus.StatusNotServing {
		t.Fatal("failure missing from health")
	}
	r, err = m.Reload(t.Context())
	if err != nil || len(r.Loaded) != 1 || len(slices.Collect(m.Failed())) != 0 {
		t.Fatalf("retry: %+v %v", r, err)
	}
}

func TestSemverPrereleaseAdmission(t *testing.T) {
	t.Parallel()
	cases := []struct {
		version, floor string
		accept         bool
	}{
		{"1.0.0-rc1", "1.0.0", false}, {"1.0.0", "1.0.0-rc1", true},
		{"1.0.0-rc.2", "1.0.0-rc.10", false}, {"1.0.0-rc.10", "1.0.0-rc.2", true},
		{"1.0.0-1", "1.0.0-alpha", false}, {"1.0.0-alpha.1", "1.0.0-alpha", true},
		{"1.0.0+build.123", "1.0.0+other", true}, {"1.0.0-01", "1.0.0", false},
		{"1.0.0+", "1.0.0", false}, {"01.0.0", "1.0.0", false},
	}
	for _, tc := range cases {
		t.Run(tc.version+"/"+tc.floor, func(t *testing.T) {
			src := &memSource{candidates: []proteus.Candidate{{ID: "p"}}}
			opener := newFakeOpener()
			opener.results["p"] = func(proteus.Candidate, string) (proteus.Opened, error) {
				return proteus.Opened{SHA256: hashOf(tc.version), Symbols: memSymbols{sdk.SymbolDescriptor: sdk.Descriptor{Name: "p", Version: tc.version}}}, nil
			}
			m, err := host.New(src, opener, host.WithUnsigned(proteus.UnsignedAllow), host.WithMinVersions(map[string]string{"p": tc.floor}))
			if err != nil {
				t.Fatal(err)
			}
			r, err := m.Load(t.Context())
			if err != nil || (len(r.Loaded) == 1) != tc.accept {
				t.Fatalf("load: %+v %v", r, err)
			}
		})
	}
}

func TestConcurrentMappedInitAndTerminalFailure(t *testing.T) {
	t.Parallel()
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				src := &memSource{candidates: []proteus.Candidate{{ID: "shared"}}}
				opener := newFakeOpener()
				releaseInit := make(chan struct{})
				var calls atomic.Int32
				opener.results["shared"] = func(proteus.Candidate, string) (proteus.Opened, error) {
					return proteus.Opened{Mapped: true, SHA256: hashOf(t.Name()), Symbols: memSymbols{
						sdk.SymbolDescriptor: sdk.Descriptor{Name: "shared", Version: "1.0.0"},
						sdk.SymbolInit: func(context.Context) error {
							calls.Add(1)
							<-releaseInit
							if fail {
								return errors.New("failed init")
							}
							return nil
						},
					}}, nil
				}
				create := func() *host.Manager {
					m, err := host.New(src, opener, host.WithUnsigned(proteus.UnsignedAllow))
					if err != nil {
						t.Fatal(err)
					}
					return m
				}
				a, b := create(), create()
				reports := make(chan proteus.LoadReport, 2)
				go func() { r, _ := a.Load(t.Context()); reports <- r }()
				synctest.Wait()
				go func() { r, _ := b.Load(t.Context()); reports <- r }()
				synctest.Wait()
				if calls.Load() != 1 {
					t.Fatalf("parallel Init calls: %d", calls.Load())
				}
				close(releaseInit)
				for range 2 {
					r := <-reports
					if (r.Err() != nil) != fail {
						t.Fatalf("unexpected result: %+v", r)
					}
				}
				if err := a.Close(t.Context()); err != nil {
					t.Fatal(err)
				}
				if err := b.Close(t.Context()); err != nil {
					t.Fatal(err)
				}
				if fail {
					c := create()
					r, err := c.Load(t.Context())
					if err != nil || !errors.Is(r.Err(), proteus.ErrInitFailed) || calls.Load() != 1 {
						t.Fatalf("failed image retried: %+v %v", r, err)
					}
				}
			})
		})
	}
}

func TestSharedInitWaitAbandonment(t *testing.T) {
	t.Parallel()
	for _, canceled := range []bool{false, true} {
		t.Run(fmt.Sprint(canceled), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				src := &memSource{candidates: []proteus.Candidate{{ID: "shared"}}}
				opener := newFakeOpener()
				unblock := make(chan struct{})
				var calls atomic.Int32
				opener.results["shared"] = func(proteus.Candidate, string) (proteus.Opened, error) {
					return proteus.Opened{Mapped: true, SHA256: hashOf(t.Name()), Symbols: memSymbols{
						sdk.SymbolDescriptor: sdk.Descriptor{Name: "shared", Version: "1.0.0"},
						sdk.SymbolInit:       func(context.Context) error { calls.Add(1); <-unblock; return nil },
					}}, nil
				}
				create := func(timeout time.Duration) *host.Manager {
					m, err := host.New(src, opener, host.WithUnsigned(proteus.UnsignedAllow), host.WithInitTimeout(timeout))
					if err != nil {
						t.Fatal(err)
					}
					return m
				}
				owner, waiter := create(time.Hour), create(50*time.Millisecond)
				ownerReport := make(chan proteus.LoadReport, 1)
				go func() { r, _ := owner.Load(t.Context()); ownerReport <- r }()
				synctest.Wait()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				result := make(chan proteus.LoadReport, 1)
				start := time.Now()
				go func() { r, _ := waiter.Load(ctx); result <- r }()
				synctest.Wait()
				want := context.DeadlineExceeded
				if canceled {
					cancel()
					want = context.Canceled
				}
				r := <-result
				if !errors.Is(r.Err(), want) {
					t.Fatalf("wait: %+v", r)
				}
				if !canceled && time.Since(start) != 50*time.Millisecond {
					t.Fatalf("wait duration: %v", time.Since(start))
				}
				if len(waiter.Quarantined()) != 0 {
					t.Fatal("abandoned wait quarantined image")
				}
				close(unblock)
				if r := <-ownerReport; r.Err() != nil || len(r.Loaded) != 1 {
					t.Fatalf("owner: %+v", r)
				}
				r, err := waiter.Reload(t.Context())
				if err != nil || r.Err() != nil || len(r.Loaded) != 1 || calls.Load() != 1 {
					t.Fatalf("reacquire: %+v %v, Init calls %d", r, err, calls.Load())
				}
				if err := owner.Close(t.Context()); err != nil {
					t.Fatal(err)
				}
				if err := waiter.Close(t.Context()); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}
