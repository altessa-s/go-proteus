// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package dirsource_test

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/dirsource"
	"github.com/altessa-s/go-proteus/host"
	"github.com/altessa-s/go-proteus/proteustest"
	"github.com/altessa-s/go-proteus/sdk"
	"github.com/altessa-s/go-proteus/signature"
	"github.com/altessa-s/go-proteus/signing"
)

func TestMixedDiscoveryFailuresAndRecovery(t *testing.T) {
	t.Parallel()

	for _, kind := range []string{"permissions", "signature size", "artifact size"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "permissions" && runtime.GOOS == "windows" {
				t.Skip("Unix permissions")
			}

			dir := createSecureDir(t)
			_, public, signer := proteustest.MustGenerateKey(t, signature.AlgEd25519)
			keys, err := signature.NewKeySet(public)
			require.NoError(t, err)
			verifier, err := signature.NewVerifier(keys)
			require.NoError(t, err)

			opener := proteustest.NewMemOpener(nil)

			for _, name := range []string{"a", "b", "c"} {
				path := filepath.Join(dir, name+".so")
				writeSecureFile(t, path, []byte(name))
				envelope, _, err := signing.SignFile(path, name, "1.0.0", signer)
				require.NoError(t, err)
				writeSecureFile(t, path+".sig", envelope)
				opener.SetSymbols(name+".so", proteustest.MapSymbols{sdk.SymbolDescriptor: sdk.Descriptor{Name: name, Version: "1.0.0"}})
			}

			badPath := filepath.Join(dir, "b.so")
			originalSig, err := os.ReadFile(badPath + ".sig")
			require.NoError(t, err)

			switch kind {
			case "permissions":
				require.NoError(t, os.Chmod(badPath, 0o666))
			case "signature size":
				writeSecureFile(t, badPath+".sig", make([]byte, 4097))
			case "artifact size":
				writeSecureFile(t, badPath, make([]byte, 17))
			}

			source, err := dirsource.New(dir, dirsource.WithMaxSignatureBytes(4096), dirsource.WithMaxArtifactBytes(16))
			require.NoError(t, err)
			manager, err := host.New(source, opener, host.WithVerifier(verifier))

			require.NoError(t, err)
			defer func() { require.NoError(t, manager.Close(t.Context())) }()

			report, err := manager.Load(t.Context())
			require.NoError(t, err)
			require.Len(t, report.Loaded, 2)
			require.Len(t, report.Failed, 1)
			require.Equal(t, "b.so", report.Failed[0].Source)
			require.Len(t, slices.Collect(manager.Failed()), 1)
			require.Equal(t, proteus.StatusDegraded, manager.Health(t.Context()).Status)
			require.Empty(t, manager.Quarantined())
			writeSecureFile(t, badPath, []byte("b"))
			writeSecureFile(t, badPath+".sig", originalSig)
			report, err = manager.Reload(t.Context())
			require.NoError(t, err)
			require.Len(t, report.Loaded, 1)
			require.Empty(t, report.Failed)
			require.Empty(t, slices.Collect(manager.Failed()))
			require.Equal(t, proteus.StatusServing, manager.Health(t.Context()).Status)
		})
	}
}

func TestDirectoryDiscoveryFailureRecovery(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "plugins")
	source, err := dirsource.New(dir)
	require.NoError(t, err)

	opener := proteustest.NewMemOpener(map[string]proteus.Symbols{"good.so": proteustest.MapSymbols{sdk.SymbolDescriptor: sdk.Descriptor{Name: "good", Version: "1.0.0"}}})
	manager, err := host.New(source, opener, host.WithUnsigned(proteus.UnsignedAllow))

	require.NoError(t, err)
	defer func() { require.NoError(t, manager.Close(t.Context())) }()

	_, err = manager.Load(t.Context())
	require.Error(t, err)
	health := manager.Health(t.Context())
	require.ErrorIs(t, health.DiscoveryErr, os.ErrNotExist)
	require.Equal(t, proteus.StatusNotServing, health.Status)
	require.Zero(t, health.Failed)
	require.NoError(t, os.Mkdir(dir, 0o700))
	writeSecureFile(t, filepath.Join(dir, "good.so"), []byte("good"))
	_, err = manager.Reload(t.Context())
	require.NoError(t, err)
	require.NoError(t, manager.Health(t.Context()).DiscoveryErr)
	require.Equal(t, proteus.StatusServing, manager.Health(t.Context()).Status)

	moved := dir + "-moved"
	require.NoError(t, os.Rename(dir, moved))
	_, err = manager.Reload(t.Context())
	require.Error(t, err)
	require.Equal(t, proteus.StatusDegraded, manager.Health(t.Context()).Status)
	require.NoError(t, os.Rename(moved, dir))
	_, err = manager.Reload(t.Context())
	require.NoError(t, err)
	require.NoError(t, manager.Health(t.Context()).DiscoveryErr)
	require.Equal(t, proteus.StatusServing, manager.Health(t.Context()).Status)
}

func TestLoadedSignatureRepairClearsFailure(t *testing.T) {
	t.Parallel()
	dir := createSecureDir(t)
	path := filepath.Join(dir, "p.so")
	writeSecureFile(t, path, []byte("plugin"))
	_, public, signer := proteustest.MustGenerateKey(t, signature.AlgEd25519)
	keys, err := signature.NewKeySet(public)
	require.NoError(t, err)
	verifier, err := signature.NewVerifier(keys)
	require.NoError(t, err)
	envelope, _, err := signing.SignFile(path, "p", "1.0.0", signer)
	require.NoError(t, err)
	writeSecureFile(t, path+".sig", envelope)

	source, err := dirsource.New(dir)
	require.NoError(t, err)

	opener := proteustest.NewMemOpener(map[string]proteus.Symbols{"p.so": proteustest.MapSymbols{sdk.SymbolDescriptor: sdk.Descriptor{Name: "p", Version: "1.0.0"}}})
	manager, err := host.New(source, opener, host.WithVerifier(verifier))

	require.NoError(t, err)
	defer func() { require.NoError(t, manager.Close(t.Context())) }()

	report, err := manager.Load(t.Context())
	require.NoError(t, err)
	require.Len(t, report.Loaded, 1)
	writeSecureFile(t, path+".sig", []byte("damaged envelope"))
	report, err = manager.Reload(t.Context())
	require.NoError(t, err)
	require.Len(t, report.Failed, 1)
	require.Equal(t, proteus.StatusDegraded, manager.Health(t.Context()).Status)
	writeSecureFile(t, path+".sig", envelope)
	report, err = manager.Reload(t.Context())
	require.NoError(t, err)
	require.Len(t, report.Skipped, 1)
	require.Empty(t, report.Loaded)
	require.Empty(t, slices.Collect(manager.Failed()))
	require.Equal(t, proteus.StatusServing, manager.Health(t.Context()).Status)
}
