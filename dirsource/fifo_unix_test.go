// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

//go:build linux || darwin

package dirsource_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/dirsource"
	"github.com/altessa-s/go-proteus/host"
	"github.com/altessa-s/go-proteus/proteustest"
	"github.com/altessa-s/go-proteus/sdk"
)

func TestFollowSymlinksRejectsFIFO(t *testing.T) {
	t.Parallel()

	for _, signature := range []bool{false, true} {
		for _, link := range []bool{false, true} {
			dir := createSecureDir(t)

			name := "p.so"
			if signature {
				writeSecureFile(t, filepath.Join(dir, name), []byte("plugin"))
				name += ".sig"
			}

			fifo := name
			if link {
				fifo = "pipe"
			}

			if err := syscall.Mkfifo(filepath.Join(dir, fifo), 0o600); err != nil {
				t.Fatal(err)
			}

			if link {
				if err := os.Symlink(fifo, filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			}

			writeSecureFile(t, filepath.Join(dir, "good.so"), []byte("good"))

			source, err := dirsource.New(dir, dirsource.WithFollowSymlinks())
			if err != nil {
				t.Fatal(err)
			}

			opener := proteustest.NewMemOpener(map[string]proteus.Symbols{"good.so": proteustest.MapSymbols{sdk.SymbolDescriptor: sdk.Descriptor{Name: "good", Version: "1.0.0"}}})
			manager, err := host.New(source, opener, host.WithUnsigned(proteus.UnsignedAllow))
			require.NoError(t, err)
			report, err := manager.Load(t.Context())
			require.NoError(t, err)
			require.Len(t, report.Loaded, 1)
			require.Len(t, report.Failed, 1)
			require.Equal(t, "p.so", report.Failed[0].Source)
			require.Equal(t, proteus.StatusDegraded, manager.Health(t.Context()).Status)
			require.NoError(t, os.Remove(filepath.Join(dir, "p.so")))
			_, err = manager.Reload(t.Context())
			require.NoError(t, err)
			require.Equal(t, proteus.StatusServing, manager.Health(t.Context()).Status)
			require.NoError(t, manager.Close(t.Context()))
		}
	}
}
