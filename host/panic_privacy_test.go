// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package host_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/host"
	"github.com/altessa-s/go-proteus/sdk"
)

func TestLifecyclePanicPrivacy(t *testing.T) {
	t.Parallel()

	for _, hook := range []string{sdk.SymbolInit, sdk.SymbolHealth, sdk.SymbolClose} {
		t.Run(hook, func(t *testing.T) {
			t.Parallel()

			const canary = "private-panic-canary"

			var logs bytes.Buffer

			src := &memSource{candidates: []proteus.Candidate{{ID: "p"}}}
			opener := newFakeOpener()
			opener.results["p"] = func(proteus.Candidate, string) (proteus.Opened, error) {
				return proteus.Opened{SHA256: hashOf(t.Name()), Symbols: memSymbols{
					sdk.SymbolDescriptor: sdk.Descriptor{Name: "p", Version: "1.0.0"},
					hook:                 func(context.Context) error { panic(canary) },
				}}, nil
			}
			m, err := host.New(src, opener, host.WithUnsigned(proteus.UnsignedAllow), host.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
			require.NoError(t, err)
			report, err := m.Load(t.Context())
			require.NoError(t, err)

			var failure error

			switch hook {
			case sdk.SymbolInit:
				failure = report.Err()
			case sdk.SymbolHealth:
				failure = m.Health(t.Context()).Plugins[0].Err
			case sdk.SymbolClose:
				failure = m.Close(t.Context())
			}

			require.ErrorIs(t, failure, proteus.ErrPanicked)
			require.NotContains(t, failure.Error(), canary)
			require.NoError(t, m.Close(t.Context()))
			require.NotContains(t, logs.String(), canary)
		})
	}
}
