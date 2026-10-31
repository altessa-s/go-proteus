// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package proteustest_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/altessa-s/go-proteus/host"
	"github.com/altessa-s/go-proteus/proteustest"
	"github.com/altessa-s/go-proteus/sdk"
	"github.com/altessa-s/go-proteus/signature"

	proteus "github.com/altessa-s/go-proteus"
)

func TestFakesAndSigningHelpers(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)

	_, pubKey, signer := proteustest.MustGenerateKey(t, signature.AlgEd25519)
	ks, err := signature.NewKeySet(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signature.NewVerifier(ks, signature.WithNow(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}

	cand := proteustest.SignedCandidate(
		t,
		"sample.so",
		"sample",
		"1.0.0",
		[]byte("elf-bytes"),
		signer,
		now,
	)

	src := proteustest.NewMemSource(cand)
	src.SetError(errors.New("temporary failure"))
	if _, err := src.Candidates(t.Context()); err == nil {
		t.Fatal("expected error from MemSource")
	}
	src.SetError(nil)
	src.SetCandidates(cand)

	syms := proteustest.MapSymbols{
		sdk.SymbolDescriptor: &sdk.Descriptor{Name: "sample", Version: "1.0.0"},
		sdk.SymbolInit: func(context.Context) error {
			return nil
		},
	}
	if _, err := syms.Lookup("missing"); err == nil {
		t.Fatal("expected error for missing symbol")
	}

	opener := proteustest.NewMemOpener(nil)
	if _, err := opener.Open(t.Context(), cand, ""); err == nil {
		t.Fatal("expected error for unregistered candidate")
	}
	opener.SetSymbols(cand.ID, syms)
	opener.SetOpenFunc(func(ctx context.Context, c proteus.Candidate, sha string) (proteus.Opened, error) {
		return proteus.Opened{Symbols: syms, SHA256: sha, Size: 9}, nil
	})
	if _, err := opener.Open(t.Context(), cand, "abc"); err != nil {
		t.Fatalf("custom OpenFunc failed: %v", err)
	}
	opener.SetOpenFunc(nil)

	obs := proteustest.NewRecordingObserver()
	mgr, err := host.New(
		src,
		opener,
		host.WithVerifier(verifier),
		host.WithObserver(obs),
	)
	if err != nil {
		t.Fatal(err)
	}
	report, err := mgr.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Loaded) != 1 || opener.OpenCount(cand.ID) < 1 || len(opener.OpenedIDs()) < 1 {
		t.Fatalf("unexpected report/opener state: %+v / %v", report, opener.OpenedIDs())
	}

	// Trigger a quarantine event to cover Quarantined() on RecordingObserver.
	badCand := proteustest.SignedCandidate(t, "bad.so", "bad", "1.0.0", []byte("bad-bytes"), signer, time.Time{})
	opener.SetSymbols(badCand.ID, proteustest.MapSymbols{
		sdk.SymbolDescriptor: &sdk.Descriptor{Name: "bad", Version: "1.0.0"},
		sdk.SymbolInit: func(context.Context) error {
			return errors.New("init boom")
		},
	})
	src.SetCandidates(cand, badCand)
	_, _ = mgr.Reload(t.Context())

	if len(obs.Admissions()) == 0 || len(obs.Inits()) == 0 || len(obs.Quarantines()) == 0 || len(obs.StatsHistory()) == 0 {
		t.Fatalf("expected all observer slices populated: adm=%d init=%d quar=%d stats=%d",
			len(obs.Admissions()), len(obs.Inits()), len(obs.Quarantines()), len(obs.StatsHistory()))
	}
	obs.Reset()
	if len(obs.Admissions()) != 0 {
		t.Fatalf("expected empty admissions after Reset, got %v", obs.Admissions())
	}
	_ = mgr.Close(t.Context())

	if err := proteustest.GoroutineLeaks(); err != nil {
		t.Fatalf("unexpected goroutine leak: %v", err)
	}
}

func TestBuildPluginCachesArtifact(t *testing.T) {
	t.Parallel()
	pkgDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pkgDir, "go.mod"), []byte("module example.com/testplugin\n\ngo 1.27\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := `package main

var Exported = "hello"
`
	if err := os.WriteFile(filepath.Join(pkgDir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	so1 := proteustest.BuildPlugin(t, pkgDir)
	so2 := proteustest.BuildPlugin(t, pkgDir)
	if so1 == so2 {
		t.Fatalf("expected distinct isolated paths per call, got %q", so1)
	}
	info1, err := os.Stat(so1)
	if err != nil || info1.Size() == 0 {
		t.Fatalf("invalid built plugin %q: %v", so1, err)
	}
}
