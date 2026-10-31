// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package host_test

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/host"
	"github.com/altessa-s/go-proteus/sdk"
)

func TestInitGoexit(t *testing.T) {
	t.Parallel()
	for _, mapped := range []bool{false, true} {
		name := "isolated"
		if mapped {
			name = "shared"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int32
				unblock := make(chan struct{})
				src := &memSource{candidates: []proteus.Candidate{{ID: "p"}}}
				opener := newFakeOpener()
				opener.results["p"] = func(proteus.Candidate, string) (proteus.Opened, error) {
					return proteus.Opened{Mapped: mapped, SHA256: hashOf(t.Name()), Symbols: memSymbols{
						sdk.SymbolDescriptor: sdk.Descriptor{Name: "p", Version: "1.0.0"},
						sdk.SymbolInit: func(context.Context) error {
							calls.Add(1)
							<-unblock
							runtime.Goexit()
							return nil
						},
					}}, nil
				}
				create := func() *host.Manager {
					m, err := host.New(src, opener, host.WithUnsigned(proteus.UnsignedAllow))
					require.NoError(t, err)
					return m
				}
				a, b := create(), create()
				load := func(m *host.Manager) <-chan proteus.LoadReport {
					done := make(chan proteus.LoadReport, 1)
					go func() {
						r, err := m.Load(t.Context())
						if err != nil {
							t.Error(err)
						}
						done <- r
					}()
					return done
				}
				first := load(a)
				synctest.Wait()
				second := load(b)
				synctest.Wait()
				close(unblock)
				for _, done := range []<-chan proteus.LoadReport{first, second} {
					r := <-done
					require.Empty(t, r.Loaded)
					require.ErrorIs(t, r.Err(), proteus.ErrInitFailed)
					require.ErrorIs(t, r.Err(), proteus.ErrHookExited)
					require.NotErrorIs(t, r.Err(), proteus.ErrPanicked)
				}
				for _, m := range []*host.Manager{a, b} {
					_, ok := m.Get("p")
					require.False(t, ok)
					require.Len(t, m.Quarantined(), 1)
					require.NoError(t, m.Close(t.Context()))
				}
				if mapped {
					require.EqualValues(t, 1, calls.Load())
					r, err := create().Load(t.Context())
					require.NoError(t, err)
					require.ErrorIs(t, r.Err(), proteus.ErrHookExited)
					require.Empty(t, r.Loaded)
					require.EqualValues(t, 1, calls.Load())
				} else {
					require.EqualValues(t, 2, calls.Load())
				}
			})
		})
	}
}

func TestHealthAndCloseGoexit(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		src := &memSource{candidates: []proteus.Candidate{{ID: "p"}}}
		opener := newFakeOpener()
		exit := func(context.Context) error { runtime.Goexit(); return nil }
		opener.results["p"] = func(proteus.Candidate, string) (proteus.Opened, error) {
			return proteus.Opened{SHA256: hashOf(t.Name()), Symbols: memSymbols{
				sdk.SymbolDescriptor: sdk.Descriptor{Name: "p", Version: "1.0.0"},
				sdk.SymbolHealth:     exit,
				sdk.SymbolClose:      exit,
			}}, nil
		}
		m, err := host.New(src, opener, host.WithUnsigned(proteus.UnsignedAllow))
		require.NoError(t, err)
		r, err := m.Load(t.Context())
		require.NoError(t, err)
		require.Len(t, r.Loaded, 1)
		report := m.Health(t.Context())
		require.Zero(t, report.Ready)
		require.NotEqual(t, proteus.StatusServing, report.Status)
		require.Len(t, report.Plugins, 1)
		require.ErrorIs(t, report.Plugins[0].Err, proteus.ErrHookExited)
		require.ErrorIs(t, m.Close(t.Context()), proteus.ErrHookExited)
	})
}
