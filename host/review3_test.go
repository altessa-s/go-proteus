// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package host_test

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/host"
	"github.com/altessa-s/go-proteus/sdk"
)

func TestSharedCloseUsesReleasingManagerTimeout(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		unblock := make(chan struct{})

		var closes atomic.Int32

		src := &memSource{candidates: []proteus.Candidate{{ID: "shared"}}}
		opener := newFakeOpener()
		opener.results["shared"] = func(proteus.Candidate, string) (proteus.Opened, error) {
			return proteus.Opened{Mapped: true, SHA256: hashOf(t.Name()), Symbols: memSymbols{
				sdk.SymbolDescriptor: sdk.Descriptor{Name: "shared", Version: "1.0.0"},
				sdk.SymbolClose:      func(context.Context) error { closes.Add(1); <-unblock; return nil },
			}}, nil
		}
		create := func(timeout time.Duration) *host.Manager {
			m, err := host.New(src, opener, host.WithUnsigned(proteus.UnsignedAllow), host.WithCloseTimeout(timeout))
			require.NoError(t, err)

			return m
		}

		a, b := create(time.Hour), create(50*time.Millisecond)
		for _, m := range []*host.Manager{a, b} {
			r, err := m.Load(t.Context())
			require.NoError(t, err)
			require.Len(t, r.Loaded, 1)
		}

		require.NoError(t, a.Close(t.Context()))
		require.Zero(t, closes.Load())

		start := time.Now()

		require.ErrorIs(t, b.Close(context.Background()), context.DeadlineExceeded)
		require.Equal(t, 50*time.Millisecond, time.Since(start))
		require.EqualValues(t, 1, closes.Load())

		c := create(time.Second)
		r, err := c.Load(t.Context())
		require.NoError(t, err)
		require.ErrorIs(t, r.Err(), proteus.ErrAlreadyLoaded)
		close(unblock)
		synctest.Wait()
		require.NoError(t, b.Close(t.Context()))
		require.EqualValues(t, 1, closes.Load())
	})
}

func TestHealthRetainsResourcesUntilWorkerFinishes(t *testing.T) {
	t.Parallel()

	for _, action := range []string{"unload", "close", "quarantine"} {
		for _, abandoned := range []bool{false, true} {
			name := action + "/active"
			if abandoned {
				name = action + "/abandoned"
			}

			t.Run(name, func(t *testing.T) {
				t.Parallel()
				synctest.Test(t, func(t *testing.T) {
					unblock := make(chan struct{})

					var (
						probes, closes atomic.Int32
						m              *host.Manager
					)

					src := &memSource{candidates: []proteus.Candidate{{ID: "p"}}}
					opener := newFakeOpener()
					opener.results["p"] = func(proteus.Candidate, string) (proteus.Opened, error) {
						return proteus.Opened{SHA256: hashOf(t.Name()), Symbols: memSymbols{
							sdk.SymbolDescriptor: sdk.Descriptor{Name: "p", Version: "1.0.0"},
							"HealthCheck": func(context.Context) error {
								probes.Add(1)

								_, _ = m.Get("p") // No registry lock may be held across this callback.

								<-unblock

								if closes.Load() != 0 {
									return proteus.ErrClosed
								}

								return nil
							},
							sdk.SymbolClose: func(ctx context.Context) error {
								if err := ctx.Err(); err != nil {
									return err
								}

								closes.Add(1)

								return nil
							},
						}}, nil
					}

					healthTimeout := time.Hour
					if abandoned {
						healthTimeout = time.Millisecond
					}

					var err error

					m, err = host.New(src, opener, host.WithUnsigned(proteus.UnsignedAllow), host.WithHealthTimeout(healthTimeout), host.WithCloseTimeout(50*time.Millisecond))
					require.NoError(t, err)
					r, err := m.Load(t.Context())
					require.NoError(t, err)
					require.Len(t, r.Loaded, 1)

					health := make(chan proteus.HealthReport, 1)
					go func() { health <- m.Health(t.Context()) }()

					synctest.Wait()
					require.EqualValues(t, 1, probes.Load())

					if abandoned {
						report := <-health
						require.ErrorIs(t, report.Plugins[0].Err, context.DeadlineExceeded)
					}

					removed := make(chan error, 1)

					go func() {
						switch action {
						case "unload":
							removed <- m.Unload(t.Context(), "p")
						case "close":
							removed <- m.Close(t.Context())
						case "quarantine":
							removed <- m.Quarantine("p")
						}
					}()

					synctest.Wait()

					_, ok := m.Get("p")
					require.False(t, ok)
					_ = m.Health(t.Context())
					require.EqualValues(t, 1, probes.Load())
					require.Zero(t, closes.Load())

					if abandoned {
						require.ErrorIs(t, <-removed, context.DeadlineExceeded)
						require.Zero(t, closes.Load())
					}

					close(unblock)
					synctest.Wait()

					if !abandoned {
						require.NoError(t, <-removed)

						report := <-health
						require.Zero(t, report.Ready)
						require.NotEqual(t, proteus.StateReady, report.Plugins[0].State)
						require.NoError(t, report.Plugins[0].Err)
					}

					require.EqualValues(t, 1, closes.Load())
				})
			})
		}
	}
}

func TestHealthSkipsRemovedSnapshotEntries(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		unblock := make(chan struct{})

		var probes atomic.Int32

		src := &memSource{candidates: []proteus.Candidate{{ID: "a"}, {ID: "b"}}}

		opener := newFakeOpener()
		for _, name := range []string{"a", "b"} {
			opener.results[name] = func(proteus.Candidate, string) (proteus.Opened, error) {
				return proteus.Opened{SHA256: hashOf(t.Name() + name), Symbols: memSymbols{
					sdk.SymbolDescriptor: sdk.Descriptor{Name: name, Version: "1.0.0"},
					"HealthCheck":        func(context.Context) error { probes.Add(1); <-unblock; return nil },
				}}, nil
			}
		}

		m, err := host.New(src, opener, host.WithUnsigned(proteus.UnsignedAllow), host.WithHealthTimeout(time.Hour), host.WithCloseTimeout(time.Millisecond))
		require.NoError(t, err)
		r, err := m.Load(t.Context())
		require.NoError(t, err)
		require.Len(t, r.Loaded, 2)

		health := make(chan proteus.HealthReport, 1)
		go func() { health <- m.Health(t.Context()) }()

		synctest.Wait()
		require.EqualValues(t, 1, probes.Load())
		require.ErrorIs(t, m.Close(t.Context()), context.DeadlineExceeded)
		close(unblock)

		report := <-health
		require.Zero(t, report.Ready)
		require.Len(t, report.Plugins, 2)

		for _, p := range report.Plugins {
			require.Equal(t, proteus.StateUnloaded, p.State)
		}

		require.EqualValues(t, 1, probes.Load())
		synctest.Wait()
	})
}

// A removed manager retains its image reference until its abandoned probe exits.
func TestSharedImageRetainsAbandonedHealthProbe(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		unblock := make(chan struct{})

		var closes atomic.Int32

		src := &memSource{candidates: []proteus.Candidate{{ID: "shared"}}}
		opener := newFakeOpener()
		opener.results["shared"] = func(proteus.Candidate, string) (proteus.Opened, error) {
			return proteus.Opened{Mapped: true, SHA256: hashOf(t.Name()), Symbols: memSymbols{
				sdk.SymbolDescriptor: sdk.Descriptor{Name: "shared", Version: "1.0.0"},
				sdk.SymbolHealth:     func(context.Context) error { <-unblock; return nil },
				sdk.SymbolClose: func(ctx context.Context) error {
					if err := ctx.Err(); err != nil {
						return err
					}

					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) != 50*time.Millisecond {
						return proteus.ErrClosed
					}

					closes.Add(1)

					return nil
				},
			}}, nil
		}
		create := func(timeout time.Duration) *host.Manager {
			m, err := host.New(src, opener, host.WithUnsigned(proteus.UnsignedAllow),
				host.WithHealthTimeout(time.Millisecond), host.WithCloseTimeout(timeout))
			require.NoError(t, err)
			r, err := m.Load(t.Context())
			require.NoError(t, err)
			require.Len(t, r.Loaded, 1)

			return m
		}
		a, b := create(50*time.Millisecond), create(time.Hour)
		report := a.Health(t.Context())
		require.ErrorIs(t, report.Plugins[0].Err, context.DeadlineExceeded)
		require.ErrorIs(t, a.Close(t.Context()), context.DeadlineExceeded)
		require.NoError(t, b.Close(t.Context()))
		require.Zero(t, closes.Load())
		close(unblock)
		synctest.Wait()
		require.EqualValues(t, 1, closes.Load())
		require.NoError(t, a.Close(t.Context()))
		require.NoError(t, b.Close(t.Context()))
		require.EqualValues(t, 1, closes.Load())

		c, err := host.New(src, opener, host.WithUnsigned(proteus.UnsignedAllow))
		require.NoError(t, err)
		r, err := c.Load(t.Context())
		require.NoError(t, err)
		require.ErrorIs(t, r.Err(), proteus.ErrAlreadyLoaded)
	})
}
