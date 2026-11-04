// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

//go:build integration && cgo

package proteus_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/altessa-s/go-proteus/dirsource"
	"github.com/altessa-s/go-proteus/goloader"
	"github.com/altessa-s/go-proteus/host"
	"github.com/altessa-s/go-proteus/proteustest"
	"github.com/altessa-s/go-proteus/signature"
	"github.com/altessa-s/go-proteus/signing"
	"github.com/altessa-s/go-proteus/spi"

	proteus "github.com/altessa-s/go-proteus"
)

type greeterContract interface {
	Greet(name string) string
}

func TestIntegrationFullPipelineAndSPI(t *testing.T) {
	t.Parallel()
	pluginsDir := filepath.Join(t.TempDir(), "plugins")

	snapDir := filepath.Join(t.TempDir(), "snaps")
	if err := os.MkdirAll(pluginsDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		t.Fatal(err)
	}

	_, pubKey, signer := proteustest.MustGenerateKey(t, signature.AlgEd25519)

	ks, err := signature.NewKeySet(pubKey)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := signature.NewVerifier(ks)
	if err != nil {
		t.Fatal(err)
	}

	fixtures := []struct {
		dir     string
		file    string
		name    string
		version string
	}{
		{dir: "internal/testplugins/good", file: "good.so", name: "good", version: "1.2.0"},
		{dir: "internal/testplugins/spi_v1", file: "spi_v1.so", name: "spi_v1", version: "1.0.0"},
		{dir: "internal/testplugins/spi_v2", file: "spi_v2.so", name: "spi_v2", version: "2.0.0"},
	}

	for _, fx := range fixtures {
		builtSO := proteustest.BuildPlugin(t, fx.dir)

		data, err := os.ReadFile(builtSO)
		if err != nil {
			t.Fatal(err)
		}

		dstSO := filepath.Join(pluginsDir, fx.file)
		if err := signing.WriteFileAtomic(dstSO, data, 0o600); err != nil {
			t.Fatal(err)
		}

		envBytes, _, err := signing.SignFile(dstSO, fx.name, fx.version, signer)
		if err != nil {
			t.Fatal(err)
		}

		if err := signing.WriteFileAtomic(dstSO+".sig", envBytes, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	src, err := dirsource.New(pluginsDir)
	if err != nil {
		t.Fatal(err)
	}

	opener, err := goloader.New(snapDir)
	if err != nil {
		t.Fatal(err)
	}

	mgr, err := host.New(src, opener, host.WithVerifier(verifier))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = mgr.Close(t.Context()) })

	report, err := mgr.Load(t.Context())
	if err != nil {
		t.Fatalf("Load failed: %v (report: %+v)", err, report)
	}

	health := mgr.Health(t.Context())
	if len(report.Loaded) != 3 || health.Status != proteus.StatusServing {
		t.Fatalf("expected 3 loaded plugins and StatusServing, got report=%+v health=%+v", report, health)
	}

	// spi_v1 exports a concrete *v1Greeter variable; Lookup returns **v1Greeter.
	var (
		greeted []string
		skipped []string
	)

	for g, p := range spi.Providers[greeterContract](
		mgr,
		"greeter",
		spi.WithSymbol("Greeter"),
		spi.WithMajor(1),
		spi.WithMinMinor(0),
		spi.WithOnSkip(func(ev spi.SkipEvent) {
			skipped = append(skipped, ev.Plugin.Name())
		}),
	) {
		greeted = append(greeted, p.Name()+"="+g.Greet("world"))
	}

	slices.Sort(greeted)

	if !slices.Equal(greeted, []string{"good=hello, world", "spi_v1=v1:world"}) {
		t.Fatalf("unexpected SPI providers: %v", greeted)
	}

	if !slices.Equal(skipped, []string{"spi_v2"}) {
		t.Fatalf("expected spi_v2 skipped by major constraint, got %v", skipped)
	}
	// Independent opener instances must share mapped handles and lifecycle ownership.
	otherOpener, err := goloader.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	other, err := host.New(src, otherOpener, host.WithVerifier(verifier))
	if err != nil {
		t.Fatal(err)
	}

	otherReport, err := other.Load(t.Context())
	if err != nil || len(otherReport.Loaded) != 3 {
		t.Fatalf("second manager: %+v %v", otherReport, err)
	}

	good, _ := other.Get("good")
	rawCounts, ok := good.Lookup("LifecycleCounts")

	counts, valid := rawCounts.(func() (int32, int32))
	if !ok || !valid {
		t.Fatal("missing lifecycle counter")
	}

	if inits, closes := counts(); inits != 1 || closes != 0 {
		t.Fatalf("shared lifecycle: %d %d", inits, closes)
	}

	if err := mgr.Close(t.Context()); err != nil {
		t.Fatal(err)
	}

	if p, ok := other.Get("good"); !ok || p.State() != proteus.StateReady {
		t.Fatal("first Close invalidated second owner")
	}

	if _, closes := counts(); closes != 0 {
		t.Fatal("closed while another owner exists")
	}

	if err := other.Close(t.Context()); err != nil {
		t.Fatal(err)
	}

	if inits, closes := counts(); inits != 1 || closes != 1 {
		t.Fatalf("released lifecycle: %d %d", inits, closes)
	}

	recreated, err := host.New(src, otherOpener, host.WithVerifier(verifier))
	if err != nil {
		t.Fatal(err)
	}

	retry, err := recreated.Load(t.Context())
	if err != nil || len(retry.Loaded) != 0 || !errors.Is(retry.Err(), proteus.ErrAlreadyLoaded) {
		t.Fatalf("recreated manager: %+v %v", retry, err)
	}

	for _, dir := range []string{snapDir, otherOpener.WorkDir()} {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("snapshot leak: %v %v", entries, err)
		}
	}
}

func TestIntegrationFaultIsolation_D1_D3_D9(t *testing.T) {
	t.Parallel()
	pluginsDir := filepath.Join(t.TempDir(), "plugins")

	snapDir := filepath.Join(t.TempDir(), "snaps")
	if err := os.MkdirAll(pluginsDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		t.Fatal(err)
	}

	_, pubKey, signer := proteustest.MustGenerateKey(t, signature.AlgEd25519)

	ks, err := signature.NewKeySet(pubKey)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := signature.NewVerifier(ks)
	if err != nil {
		t.Fatal(err)
	}

	fixtures := []struct {
		dir     string
		file    string
		name    string
		version string
	}{
		{dir: "internal/testplugins/pkg_init_panics", file: "01_pkg_init_panics.so", name: "pkg_init_panics", version: "1.0.0"},
		{dir: "internal/testplugins/init_panics", file: "02_init_panics.so", name: "init_panics", version: "1.0.0"},
		{dir: "internal/testplugins/init_blocks", file: "03_init_blocks.so", name: "init_blocks", version: "1.0.0"},
		{dir: "internal/testplugins/bad_descriptor", file: "04_bad_descriptor.so", name: "bad_descriptor", version: "1.0.0"},
		{dir: "internal/testplugins/name_mismatch", file: "05_name_mismatch.so", name: "expected_name", version: "1.0.0"},
	}

	for _, fx := range fixtures {
		builtSO := proteustest.BuildPlugin(t, fx.dir)

		data, err := os.ReadFile(builtSO)
		if err != nil {
			t.Fatal(err)
		}

		dstSO := filepath.Join(pluginsDir, fx.file)
		if err := signing.WriteFileAtomic(dstSO, data, 0o600); err != nil {
			t.Fatal(err)
		}

		envBytes, _, err := signing.SignFile(dstSO, fx.name, fx.version, signer)
		if err != nil {
			t.Fatal(err)
		}

		if err := signing.WriteFileAtomic(dstSO+".sig", envBytes, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	src, err := dirsource.New(pluginsDir)
	if err != nil {
		t.Fatal(err)
	}

	opener, err := goloader.New(snapDir)
	if err != nil {
		t.Fatal(err)
	}

	mgr, err := host.New(
		src,
		opener,
		host.WithVerifier(verifier),
		host.WithInitTimeout(25*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = mgr.Close(t.Context()) })

	report, err := mgr.Load(t.Context())
	if err != nil {
		t.Fatalf("Load returned source error: %v", err)
	}

	loadErr := report.Err()
	if loadErr == nil {
		t.Fatal("expected joined error from faulty plugins in report.Err()")
	}

	if !errors.Is(loadErr, proteus.ErrPanicked) ||
		!errors.Is(loadErr, proteus.ErrInitFailed) ||
		!errors.Is(loadErr, proteus.ErrInvalidDescriptor) ||
		!errors.Is(loadErr, proteus.ErrManifestMismatch) {
		t.Fatalf("expected ErrPanicked, ErrInitFailed, ErrInvalidDescriptor, and ErrManifestMismatch in %v", loadErr)
	}

	if len(report.Loaded) != 0 || len(slices.Collect(mgr.All())) != 0 {
		t.Fatalf("expected 0 active plugins, got loaded=%v", report.Loaded)
	}

	if len(mgr.Quarantined()) != 5 {
		t.Fatalf("expected all 5 faulty plugins quarantined, got %d", len(mgr.Quarantined()))
	}

	if got := mgr.Health(t.Context()); got.Status != proteus.StatusNotServing || got.Failed != 5 {
		t.Fatalf("failed admission health: %+v", got)
	}
	// A package-init panic leaves stdlib's load channel unfinished. A new opener
	// must return the cached failure without entering plugin.Open again.
	candidates, err := src.Candidates(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	for _, dir := range []string{snapDir, t.TempDir()} {
		retryOpener, err := goloader.New(dir)
		if err != nil {
			t.Fatal(err)
		}

		opened, err := retryOpener.Open(t.Context(), candidates[0], "", 0)
		if !errors.Is(err, proteus.ErrPanicked) || !opened.ContentFailure {
			t.Fatalf("package-init retry: %+v %v", opened, err)
		}
	}
}

func TestIntegrationPackageInitGoexitIndependentOpeners(t *testing.T) {
	t.Parallel()
	path := proteustest.BuildPlugin(t, "internal/testplugins/pkg_init_goexit")

	source, err := dirsource.New(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}

	for range 2 {
		opener, err := goloader.New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}

		manager, err := host.New(source, opener, host.WithUnsigned(proteus.UnsignedAllow))
		if err != nil {
			t.Fatal(err)
		}

		report, err := manager.Load(t.Context())
		if err != nil {
			t.Fatal(err)
		}

		if len(report.Failed) != 1 || !errors.Is(report.Err(), proteus.ErrPanicked) {
			t.Fatalf("load: %+v", report)
		}

		if health := manager.Health(t.Context()); health.Status != proteus.StatusNotServing {
			t.Fatalf("health: %+v", health)
		}

		if err := manager.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}
