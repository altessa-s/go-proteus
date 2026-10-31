// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package host_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"runtime/debug"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/host"
	"github.com/altessa-s/go-proteus/sdk"
	"github.com/altessa-s/go-proteus/signature"
)

type memSymbols map[string]any

func (m memSymbols) Lookup(name string) (any, error) {
	v, ok := m[name]
	if !ok {
		return nil, errors.New("symbol not found")
	}
	return v, nil
}

type memSource struct {
	mu         sync.Mutex
	candidates []proteus.Candidate
	err        error
}

func (s *memSource) Candidates(ctx context.Context) ([]proteus.Candidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return slices.Clone(s.candidates), nil
}

type fakeOpener struct {
	mu      sync.Mutex
	calls   []string
	results map[string]func(proteus.Candidate, string) (proteus.Opened, error)
}

func newFakeOpener() *fakeOpener {
	return &fakeOpener{
		results: make(map[string]func(proteus.Candidate, string) (proteus.Opened, error)),
	}
}

func (o *fakeOpener) Open(ctx context.Context, c proteus.Candidate, verifiedSHA256 string, _ int64) (proteus.Opened, error) {
	if err := ctx.Err(); err != nil {
		return proteus.Opened{}, err
	}
	o.mu.Lock()
	o.calls = append(o.calls, c.ID)
	fn, ok := o.results[c.ID]
	o.mu.Unlock()
	if !ok {
		return proteus.Opened{}, errors.New("unexpected open for " + c.ID)
	}
	return fn(c, verifiedSHA256)
}

func (o *fakeOpener) callCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.calls)
}

type recObserver struct {
	mu          sync.Mutex
	admissions  []proteus.AdmissionEvent
	inits       []proteus.InitEvent
	quarantines []proteus.QuarantineEntry
	stats       []proteus.Stats
}

func (r *recObserver) Admitted(ev proteus.AdmissionEvent) {
	r.mu.Lock()
	r.admissions = append(r.admissions, ev)
	r.mu.Unlock()
}

func (r *recObserver) Initialized(ev proteus.InitEvent) {
	r.mu.Lock()
	r.inits = append(r.inits, ev)
	r.mu.Unlock()
}

func (r *recObserver) Quarantined(q proteus.QuarantineEntry) {
	r.mu.Lock()
	r.quarantines = append(r.quarantines, q)
	r.mu.Unlock()
}

func (r *recObserver) RegistryChanged(st proteus.Stats) {
	r.mu.Lock()
	r.stats = append(r.stats, st)
	r.mu.Unlock()
}

type testSigner struct {
	priv     ed25519.PrivateKey
	key      signature.Key
	verifier *signature.Verifier
	now      time.Time
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := signature.NewKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := signature.NewKeySet(key)
	if err != nil {
		t.Fatal(err)
	}
	v, err := signature.NewVerifier(ks, signature.WithNow(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	return &testSigner{priv: priv, key: key, verifier: v, now: now}
}

func (s *testSigner) signManifest(t *testing.T, m proteus.Manifest) []byte {
	t.Helper()
	if m.Version == 0 {
		m.Version = proteus.ManifestVersion
	}
	if m.GOOS == "" {
		m.GOOS = "linux"
	}
	if m.GOARCH == "" {
		m.GOARCH = "arm64"
	}
	if m.IssuedAt.IsZero() {
		m.IssuedAt = s.now
	}
	payload, err := signature.MarshalManifest(m)
	if err != nil {
		t.Fatalf("MarshalManifest: %v", err)
	}
	pae := signature.PAE(proteus.ManifestPayloadType, payload)
	sig := ed25519.Sign(s.priv, pae)
	raw, err := signature.MarshalEnvelope(signature.Envelope{
		PayloadType: proteus.ManifestPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []signature.Entry{
			{KeyID: s.key.ID(), Sig: base64.StdEncoding.EncodeToString(sig)},
		},
	})
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	return raw
}

func hashOf(tag string) string {
	sum := sha256.Sum256([]byte(tag))
	return hex.EncodeToString(sum[:])
}

func makeSignedCandidate(
	t *testing.T,
	ts *testSigner,
	opener *fakeOpener,
	id string,
	name string,
	ver string,
	hostMajor int,
	syms memSymbols,
) (proteus.Candidate, string) {
	t.Helper()
	h := hashOf(id + ":" + name + ":" + ver)
	const size int64 = 1024
	if _, ok := syms[sdk.SymbolDescriptor]; !ok {
		desc := sdk.Descriptor{Name: name, Version: ver, Description: name + " desc"}
		syms[sdk.SymbolDescriptor] = &desc
	}
	m := proteus.Manifest{
		Version:   proteus.ManifestVersion,
		Name:      name,
		PluginVer: ver,
		SHA256:    h,
		Size:      size,
		GOOS:      "linux",
		GOARCH:    "arm64",
		HostMajor: hostMajor,
		IssuedAt:  ts.now,
	}
	sig := ts.signManifest(t, m)
	opener.results[id] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{
			Symbols: syms,
			SHA256:  h,
			Size:    size,
		}, nil
	}
	return proteus.Candidate{
		ID: id,
		Open: func() (proteus.Artifact, error) {
			return proteus.Artifact{Reader: io.NopCloser(bytes.NewReader([]byte(id))), Size: size}, nil
		},
		Signature: sig,
	}, h
}

func TestFailClosedUnsignedDefault_D8(t *testing.T) {
	t.Parallel()
	src := &memSource{}
	opener := newFakeOpener()

	// Without Verifier under default UnsignedReject, New fails immediately.
	if _, err := host.New(src, opener); !errors.Is(err, proteus.ErrSignatureMissing) {
		t.Fatalf("expected ErrSignatureMissing when verifier is nil under UnsignedReject, got %v", err)
	}
	if _, err := host.New(nil, opener); err == nil {
		t.Fatal("expected error for nil source")
	}
	if _, err := host.New(src, nil); err == nil {
		t.Fatal("expected error for nil opener")
	}

	ts := newTestSigner(t)
	src.candidates = []proteus.Candidate{
		{ID: "unsigned.so", Signature: nil},
	}
	mgr, err := host.New(src, opener,
		host.WithVerifier(ts.verifier),
		host.WithGoos("linux"),
		host.WithGoarch("arm64"),
	)
	if err != nil {
		t.Fatal(err)
	}
	report, err := mgr.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Failed) != 1 || !errors.Is(report.Failed[0].Err, proteus.ErrSignatureMissing) || !report.Failed[0].Unsigned {
		t.Fatalf("expected unsigned candidate rejected with ErrSignatureMissing, got %+v", report.Failed)
	}
	if opener.callCount() != 0 {
		t.Fatalf("expected Opener not called for rejected unsigned candidate, got %d calls", opener.callCount())
	}

	// UnsignedWarn and UnsignedAllow admit unsigned candidates and evaluate WithAllow/WithDeny on Descriptor.Name after open (Q8).
	hAllowed := hashOf("allowed-unsigned")
	hDenied := hashOf("denied-unsigned")
	deniedInitCalled := false
	opener.results["allowed.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{
			Symbols: memSymbols{
				sdk.SymbolDescriptor: sdk.Descriptor{Name: "allowed", Version: "1.0.0"},
			},
			SHA256: hAllowed,
			Size:   512,
		}, nil
	}
	opener.results["denied.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{
			Symbols: memSymbols{
				sdk.SymbolDescriptor: sdk.Descriptor{Name: "denied", Version: "1.0.0"},
				sdk.SymbolInit: func(context.Context) error {
					deniedInitCalled = true
					return nil
				},
			},
			SHA256: hDenied,
			Size:   512,
		}, nil
	}
	src.candidates = []proteus.Candidate{
		{ID: "allowed.so"},
		{ID: "denied.so"},
	}

	devMgr, err := host.New(src, opener,
		host.WithUnsigned(proteus.UnsignedWarn),
		host.WithAllow("allowed"),
		host.WithDeny("denied"),
	)
	if err != nil {
		t.Fatal(err)
	}
	devReport, err := devMgr.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(devReport.Loaded) != 1 || !devReport.Loaded[0].Unsigned() || devReport.Loaded[0].Name() != "allowed" {
		t.Fatalf("expected 1 unsigned plugin 'allowed', got %+v", devReport.Loaded)
	}
	if len(devReport.Skipped) != 1 || !errors.Is(devReport.Skipped[0].Err, proteus.ErrDisabled) || !devReport.Skipped[0].Unsigned {
		t.Fatalf("expected denied unsigned plugin skipped with ErrDisabled and Unsigned=true, got %+v", devReport.Skipped)
	}
	if deniedInitCalled {
		t.Fatal("denied unsigned plugin must not run Init")
	}
}

func TestInitWatchdogTimeout_D2(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		defer close(release)

		ts := newTestSigner(t)
		opener := newFakeOpener()
		cand, h := makeSignedCandidate(t, ts, opener, "hung.so", "hung", "1.0.0", 0, memSymbols{
			sdk.SymbolInit: func(context.Context) error {
				<-release
				return nil
			},
		})
		src := &memSource{candidates: []proteus.Candidate{cand}}

		mgr, err := host.New(src, opener,
			host.WithVerifier(ts.verifier),
			host.WithGoos("linux"),
			host.WithGoarch("arm64"),
			host.WithInitTimeout(50*time.Millisecond),
		)
		if err != nil {
			t.Fatal(err)
		}

		report, err := mgr.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Loaded) != 0 || len(report.Failed) != 1 {
			t.Fatalf("expected hung plugin to fail Init, got loaded=%d failed=%d", len(report.Loaded), len(report.Failed))
		}
		if !errors.Is(report.Failed[0].Err, proteus.ErrInitFailed) || !errors.Is(report.Failed[0].Err, context.DeadlineExceeded) {
			t.Fatalf("expected ErrInitFailed + DeadlineExceeded, got %v", report.Failed[0].Err)
		}
		if _, ok := mgr.Get("hung"); ok {
			t.Fatal("hung plugin must not be in active registry")
		}
		q := mgr.Quarantined()
		if len(q) != 1 || q[0].SHA256 != h {
			t.Fatalf("expected hung plugin quarantined with hash %s, got %+v", h, q)
		}
	})
}

func TestFailedPluginsExcludedFromRegistryAndHealth_D3_AndObserver_D4(t *testing.T) {
	t.Parallel()

	ts := newTestSigner(t)
	opener := newFakeOpener()
	obs := &recObserver{}

	cGood, _ := makeSignedCandidate(t, ts, opener, "good.so", "good", "1.0.0", 0, memSymbols{
		"Greeter": "hello",
	})
	cErr, hErr := makeSignedCandidate(t, ts, opener, "err.so", "errplug", "1.0.0", 0, memSymbols{
		sdk.SymbolInit: func(context.Context) error {
			return errors.New("db down")
		},
	})
	cPanic, hPanic := makeSignedCandidate(t, ts, opener, "panic.so", "panicplug", "1.0.0", 0, memSymbols{
		sdk.SymbolInit: func(context.Context) error {
			panic("init boom")
		},
	})

	src := &memSource{candidates: []proteus.Candidate{cGood, cErr, cPanic}}
	mgr, err := host.New(src, opener,
		host.WithVerifier(ts.verifier),
		host.WithGoos("linux"),
		host.WithGoarch("arm64"),
		host.WithObserver(obs),
	)
	if err != nil {
		t.Fatal(err)
	}

	report, err := mgr.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Loaded) != 1 || report.Loaded[0].Name() != "good" {
		t.Fatalf("expected only 'good' in Loaded, got %+v", report.Loaded)
	}
	if len(report.Failed) != 2 {
		t.Fatalf("expected 2 failed plugins, got %+v", report.Failed)
	}
	if !errors.Is(report.Err(), proteus.ErrInitFailed) || !errors.Is(report.Err(), proteus.ErrPanicked) {
		t.Fatalf("expected report.Err() to match ErrInitFailed and ErrPanicked, got %v", report.Err())
	}

	// Failed plugins must NEVER appear in Get, All, or LookupAll (Defect 3).
	if _, ok := mgr.Get("errplug"); ok {
		t.Fatal("failed plugin errplug must not be returned by Get")
	}
	if _, ok := mgr.Get("panicplug"); ok {
		t.Fatal("failed plugin panicplug must not be returned by Get")
	}
	var activeNames []string
	for p := range mgr.All() {
		activeNames = append(activeNames, p.Name())
	}
	if !slices.Equal(activeNames, []string{"good"}) {
		t.Fatalf("expected All() == [good], got %v", activeNames)
	}

	var failedNames []string
	for fp := range mgr.Failed() {
		if fp.State() != proteus.StateFailed {
			t.Fatalf("expected StateFailed, got %v", fp.State())
		}
		failedNames = append(failedNames, fp.Name())
	}
	if !slices.Equal(failedNames, []string{"errplug", "panicplug"}) {
		t.Fatalf("expected Failed() == [errplug panicplug], got %v", failedNames)
	}

	// Health with 1 ready and 2 failed is StatusDegraded.
	hr := mgr.Health(context.Background())
	if hr.Status != proteus.StatusDegraded || hr.Ready != 1 || hr.Failed != 2 || hr.Quarantined != 2 {
		t.Fatalf("expected StatusDegraded (ready=1, failed=2, quarantined=2), got %+v", hr)
	}

	// Unload 'good': now Ready == 0 && Failed == 2 -> StatusNotServing.
	if err := mgr.Unload(context.Background(), "good"); err != nil {
		t.Fatalf("Unload(good): %v", err)
	}
	hrAfterUnload := mgr.Health(context.Background())
	if hrAfterUnload.Status != proteus.StatusNotServing || hrAfterUnload.Ready != 0 || hrAfterUnload.Failed != 2 {
		t.Fatalf("expected StatusNotServing after unloading only ready plugin, got %+v", hrAfterUnload)
	}

	// Verify quarantine contains hErr and hPanic.
	q := mgr.Quarantined()
	if len(q) != 2 || q[0].SHA256 != hErr || q[1].SHA256 != hPanic {
		t.Fatalf("unexpected Quarantine snapshot: %+v", q)
	}

	// Verify Observer events (Defect 4).
	obs.mu.Lock()
	if len(obs.admissions) != 3 || len(obs.inits) != 3 || len(obs.quarantines) != 2 || len(obs.stats) != 2 {
		t.Fatalf("unexpected observer counts: adm=%d init=%d quar=%d stats=%d",
			len(obs.admissions), len(obs.inits), len(obs.quarantines), len(obs.stats))
	}
	obs.mu.Unlock()
}

func TestSignedPreOpenGates_D5_NameCollision_D11_UnloadReload_D10_AndQuarantineEmptyHash_D16(t *testing.T) {
	t.Parallel()

	ts := newTestSigner(t)
	opener := newFakeOpener()

	revokedCand, revokedHash := makeSignedCandidate(t, ts, opener, "revoked.so", "revoked", "1.0.0", 0, memSymbols{})
	disabledCand, _ := makeSignedCandidate(t, ts, opener, "disabled.so", "disabled", "1.0.0", 0, memSymbols{})
	wrongHostCand, _ := makeSignedCandidate(t, ts, opener, "wronghost.so", "wronghost", "1.0.0", 99, memSymbols{})
	lowVerCand, _ := makeSignedCandidate(t, ts, opener, "lowver.so", "lowver", "1.0.0", 2, memSymbols{})

	// Platform mismatch candidate.
	platHash := hashOf("plat.so")
	platManifest := proteus.Manifest{
		Version:   proteus.ManifestVersion,
		Name:      "plat",
		PluginVer: "1.0.0",
		SHA256:    platHash,
		Size:      1024,
		GOOS:      "windows",
		GOARCH:    "amd64",
		IssuedAt:  ts.now,
	}
	platCand := proteus.Candidate{
		ID:        "plat.so",
		Signature: ts.signManifest(t, platManifest),
	}

	src := &memSource{
		candidates: []proteus.Candidate{
			revokedCand,
			disabledCand,
			wrongHostCand,
			lowVerCand,
			platCand,
		},
	}

	mgr, err := host.New(src, opener,
		host.WithVerifier(ts.verifier),
		host.WithGoos("linux"),
		host.WithGoarch("arm64"),
		host.WithRevoked(revokedHash),
		host.WithDeny("disabled"),
		host.WithHostVersion("2.1.0"),
		host.WithMinVersions(map[string]string{"lowver": "2.0.0"}),
	)
	if err != nil {
		t.Fatal(err)
	}

	report, err := mgr.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// None of these 5 pre-open gated candidates should have reached Opener.Open!
	if opener.callCount() != 0 {
		t.Fatalf("expected 0 Opener.Open calls for pre-open gated candidates, got %d", opener.callCount())
	}
	if len(report.Skipped) != 1 || !errors.Is(report.Skipped[0].Err, proteus.ErrDisabled) {
		t.Fatalf("expected 1 skipped disabled candidate, got %+v", report.Skipped)
	}
	if len(report.Failed) != 4 {
		t.Fatalf("expected 4 failed candidates, got %+v", report.Failed)
	}

	// Defect 11: Duplicate plugin name must be rejected before Init runs on the duplicate.
	dupInit1 := 0
	dupInit2 := 0
	cDup1, _ := makeSignedCandidate(t, ts, opener, "dup1.so", "same-name", "1.0.0", 2, memSymbols{
		sdk.SymbolInit: func(context.Context) error {
			dupInit1++
			return nil
		},
	})
	cDup2, _ := makeSignedCandidate(t, ts, opener, "dup2.so", "same-name", "1.0.0", 2, memSymbols{
		sdk.SymbolInit: func(context.Context) error {
			dupInit2++
			return nil
		},
	})
	src.candidates = []proteus.Candidate{cDup1, cDup2}
	dupReport, err := mgr.Reload(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(dupReport.Loaded) != 1 || dupInit1 != 1 || dupInit2 != 0 {
		t.Fatalf("expected first loaded and second rejected before Init (init1=%d, init2=%d)", dupInit1, dupInit2)
	}
	if len(dupReport.Failed) != 1 || !errors.Is(dupReport.Failed[0].Err, proteus.ErrAlreadyLoaded) {
		t.Fatalf("expected ErrAlreadyLoaded on duplicate name, got %+v", dupReport.Failed)
	}

	// Defect 10: Unloading 'same-name' and calling Reload must not re-run Init on cDup1!
	if err := mgr.Unload(context.Background(), "same-name"); err != nil {
		t.Fatal(err)
	}
	src.candidates = []proteus.Candidate{cDup1}
	reloadAfterUnload, err := mgr.Reload(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(reloadAfterUnload.Loaded) != 0 || len(reloadAfterUnload.Skipped) != 1 || dupInit1 != 1 {
		t.Fatalf("expected unloaded hash to be skipped on Reload without re-running Init (init1=%d)", dupInit1)
	}

	// Defect 16: Pre-hash failure and ErrSnapshotModified must never insert "" into quarantine.
	mgr.ClearQuarantine("")
	if len(mgr.Quarantined()) != 0 {
		t.Fatal("expected empty quarantine after ClearQuarantine")
	}
	opener.results["ioerr.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{SHA256: ""}, errors.New("disk read error before hashing")
	}
	opener.results["tamper.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{SHA256: hashOf("tamper")}, proteus.ErrSnapshotModified
	}
	devMgr, err := host.New(
		&memSource{candidates: []proteus.Candidate{{ID: "ioerr.so"}, {ID: "tamper.so"}}},
		opener,
		host.WithUnsigned(proteus.UnsignedAllow),
	)
	if err != nil {
		t.Fatal(err)
	}
	qReport, err := devMgr.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(qReport.Failed) != 2 || len(devMgr.Quarantined()) != 0 {
		t.Fatalf("expected 0 quarantined entries for pre-hash I/O error and ErrSnapshotModified, got %+v", devMgr.Quarantined())
	}
}

func TestManifestMismatchDepSkewHealthAndClose(t *testing.T) {
	t.Parallel()

	ts := newTestSigner(t)
	opener := newFakeOpener()

	// Candidate whose Descriptor.Name disagrees with its signed Manifest.Name.
	cMismatch, _ := makeSignedCandidate(t, ts, opener, "mismatch.so", "manifest-name", "1.0.0", 1, memSymbols{
		sdk.SymbolDescriptor: sdk.Descriptor{Name: "other-name", Version: "1.0.0"},
	})

	// Candidate with DepInfo skew, custom HealthCheck, and Close hook.
	dep := sdk.DepInfo{
		GoVersion: "go1.26.0",
		Deps:      []sdk.ModDep{{Path: "example.com/shared", Version: "v1.0.0"}},
	}
	healthy := true
	closed := false
	cFull, _ := makeSignedCandidate(t, ts, opener, "full.so", "full", "1.2.0", 1, memSymbols{
		sdk.SymbolDepInfo: &dep,
		sdk.SymbolHealth: func(context.Context) error {
			if !healthy {
				return errors.New("unhealthy")
			}
			return nil
		},
		sdk.SymbolClose: func(context.Context) error {
			closed = true
			return nil
		},
		"CustomSym": "val",
	})

	src := &memSource{candidates: []proteus.Candidate{cMismatch, cFull}}
	mgr, err := host.New(src, opener,
		host.WithVerifier(ts.verifier),
		host.WithGoos("linux"),
		host.WithGoarch("arm64"),
		host.WithHostVersion("v1.0.0"),
		host.WithHostVersionPolicy(proteus.VersionWarn),
		host.WithMinVersions(map[string]string{"full": "1.0.0"}),
		host.WithMinVersionPolicy(proteus.VersionWarn),
		host.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		host.WithHostBuildInfo(func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{
				GoVersion: "go1.27.3",
				Deps: []*debug.Module{
					{Path: "example.com/shared", Version: "v2.0.0"},
				},
			}, true
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	report, err := mgr.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Loaded) != 1 || len(report.Failed) != 1 {
		t.Fatalf("expected 1 loaded and 1 failed, got %+v", report)
	}
	if !errors.Is(report.Failed[0].Err, proteus.ErrManifestMismatch) {
		t.Fatalf("expected ErrManifestMismatch, got %v", report.Failed[0].Err)
	}

	// LookupAll finds CustomSym on 'full'.
	foundSym := false
	for p, sym := range mgr.LookupAll("CustomSym") {
		if p.Name() == "full" && sym == "val" {
			foundSym = true
		}
	}
	if !foundSym {
		t.Fatal("expected LookupAll to find CustomSym on 'full'")
	}

	// Make 'full' fail its HealthCheck probe.
	healthy = false
	hr := mgr.Health(context.Background())
	if hr.Status != proteus.StatusNotServing || hr.Ready != 0 {
		t.Fatalf("expected StatusNotServing when HealthCheck fails, got %+v", hr)
	}

	// Clear specific quarantine hash.
	if len(mgr.Quarantined()) == 1 {
		mgr.ClearQuarantine(mgr.Quarantined()[0].SHA256)
		if len(mgr.Quarantined()) != 0 {
			t.Fatal("expected quarantine cleared by specific SHA256")
		}
	}

	// Close manager and verify idempotency and ErrClosed.
	if err := mgr.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !closed {
		t.Fatal("expected plugin Close hook to run")
	}
	if err := mgr.Close(context.Background()); err != nil {
		t.Fatalf("second Close should be nil, got %v", err)
	}
	if _, err := mgr.Load(context.Background()); !errors.Is(err, proteus.ErrClosed) {
		t.Fatalf("expected ErrClosed from Load after Close, got %v", err)
	}
	if err := mgr.Unload(context.Background(), "full"); !errors.Is(err, proteus.ErrClosed) {
		t.Fatalf("expected ErrClosed from Unload after Close, got %v", err)
	}
	if mgr.Health(context.Background()).Status != proteus.StatusNotServing {
		t.Fatal("expected StatusNotServing on closed manager")
	}
}

func TestUnsignedAdmissionSymbolErrorsAndOptionValidation(t *testing.T) {
	t.Parallel()

	src := &memSource{}
	opener := newFakeOpener()

	// Construction-time option validation errors.
	if _, err := host.New(src, opener, host.WithUnsigned(proteus.UnsignedAllow), host.WithHostVersion("bad-ver")); err == nil {
		t.Fatal("expected error for invalid hostVersion")
	}
	if _, err := host.New(src, opener, host.WithUnsigned(proteus.UnsignedAllow), host.WithMinVersions(map[string]string{"p": "bad"})); err == nil {
		t.Fatal("expected error for invalid minVersions")
	}
	if _, err := host.New(src, opener, host.WithUnsigned(proteus.UnsignedAllow), host.WithRevoked("not-a-sha256")); err == nil {
		t.Fatal("expected error for invalid revoked hash")
	}

	revHash := hashOf("unsigned-revoked")
	opener.results["urev.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{SHA256: revHash, Size: 100}, nil
	}
	opener.results["unodesc.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{Symbols: memSymbols{}, SHA256: hashOf("unodesc"), Size: 100}, nil
	}
	opener.results["ubaddesc.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{Symbols: memSymbols{sdk.SymbolDescriptor: 123}, SHA256: hashOf("ubaddesc"), Size: 100}, nil
	}
	opener.results["uemptydesc.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{Symbols: memSymbols{sdk.SymbolDescriptor: sdk.Descriptor{}}, SHA256: hashOf("uemptydesc"), Size: 100}, nil
	}
	opener.results["unoever.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{Symbols: memSymbols{sdk.SymbolDescriptor: sdk.Descriptor{Name: "p"}}, SHA256: hashOf("unoever"), Size: 100}, nil
	}
	opener.results["ubaddep.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{
			Symbols: memSymbols{
				sdk.SymbolDescriptor: sdk.Descriptor{Name: "pdep", Version: "1.0.0"},
				sdk.SymbolDepInfo:    "bad-dep",
			},
			SHA256: hashOf("ubaddep"),
			Size:   100,
		}, nil
	}
	opener.results["ubadinit.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{
			Symbols: memSymbols{
				sdk.SymbolDescriptor: sdk.Descriptor{Name: "pinit", Version: "1.0.0"},
				sdk.SymbolInit:       "bad-init",
			},
			SHA256: hashOf("ubadinit"),
			Size:   100,
		}, nil
	}
	opener.results["ubadclose.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{
			Symbols: memSymbols{
				sdk.SymbolDescriptor: sdk.Descriptor{Name: "pclose", Version: "1.0.0"},
				sdk.SymbolClose:      "bad-close",
			},
			SHA256: hashOf("ubadclose"),
			Size:   100,
		}, nil
	}
	opener.results["ubadhealth.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{
			Symbols: memSymbols{
				sdk.SymbolDescriptor: sdk.Descriptor{Name: "phealth", Version: "1.0.0"},
				sdk.SymbolHealth:     "bad-health",
			},
			SHA256: hashOf("ubadhealth"),
			Size:   100,
		}, nil
	}

	descPtr := &sdk.Descriptor{Name: "upointers", Version: "1.0.0-rc1+build1"}
	depVal := sdk.DepInfo{GoVersion: "go1.27.3"}
	depPtr := &depVal
	var initFn func(context.Context) error = func(context.Context) error { return nil }
	var closeFn func(context.Context) error = func(context.Context) error { return errors.New("close err") }
	uPtrHash := hashOf("upointers")
	opener.results["upointers.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{
			Symbols: memSymbols{
				sdk.SymbolDescriptor: &descPtr,
				sdk.SymbolDepInfo:    &depPtr,
				sdk.SymbolInit:       &initFn,
				sdk.SymbolClose:      &closeFn,
			},
			SHA256: uPtrHash,
			Size:   100,
		}, nil
	}
	opener.results["udup.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{
			Symbols: memSymbols{
				sdk.SymbolDescriptor: sdk.Descriptor{Name: "upointers", Version: "1.0.0"},
			},
			SHA256: hashOf("udup"),
			Size:   100,
		}, nil
	}
	opener.results["ulowver.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{
			Symbols: memSymbols{
				sdk.SymbolDescriptor: sdk.Descriptor{Name: "ulow", Version: "0.1.0"},
			},
			SHA256: hashOf("ulowver"),
			Size:   100,
		}, nil
	}

	src.candidates = []proteus.Candidate{
		{ID: "urev.so"},
		{ID: "unodesc.so"},
		{ID: "ubaddesc.so"},
		{ID: "uemptydesc.so"},
		{ID: "unoever.so"},
		{ID: "ubaddep.so"},
		{ID: "ubadinit.so"},
		{ID: "ubadclose.so"},
		{ID: "ubadhealth.so"},
		{ID: "upointers.so", Signature: []byte("ignored-when-no-verifier")},
		{ID: "udup.so"},
		{ID: "ulowver.so"},
	}

	mgr, err := host.New(src, opener,
		host.WithUnsigned(proteus.UnsignedAllow),
		host.WithRevoked(revHash),
		host.WithMinVersions(map[string]string{"ulow": "1.0.0", "upointers": "1.0.0-rc1"}),
		host.WithCloseTimeout(time.Second),
		host.WithHealthTimeout(time.Second),
		host.WithNow(time.Now),
	)
	if err != nil {
		t.Fatal(err)
	}

	rep, err := mgr.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Loaded) != 1 || rep.Loaded[0].Name() != "upointers" {
		t.Fatalf("expected only upointers loaded, got %+v", rep.Loaded)
	}

	// Reload skips already-loaded and already-quarantined unsigned candidates.
	rep2, err := mgr.Reload(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep2.Skipped) == 0 {
		t.Fatal("expected skipped candidates on second Reload")
	}

	// Unload missing plugin returns ErrNotFound.
	if err := mgr.Unload(context.Background(), "no-such-plugin"); !errors.Is(err, proteus.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// Close returns joined close error from upointers.
	if err := mgr.Close(context.Background()); err == nil {
		t.Fatal("expected Close error from upointers close hook")
	}
}

func TestSignedErrorPathsAndVersionCompare(t *testing.T) {
	t.Parallel()

	ts := newTestSigner(t)
	opener := newFakeOpener()

	// 1. Corrupt signature bytes.
	cBadSig := proteus.Candidate{
		ID:        "badsig.so",
		Signature: []byte("corrupt-envelope"),
	}
	// 2. Signed candidate where opener returns ErrSnapshotModified.
	cSnapMod, _ := makeSignedCandidate(t, ts, opener, "snapmod.so", "snapmod", "1.0.0", 0, memSymbols{})
	opener.results["snapmod.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{}, proteus.ErrSnapshotModified
	}
	// 3. Signed candidate where opener returns generic open error.
	cOpenErr, _ := makeSignedCandidate(t, ts, opener, "openerr.so", "openerr", "1.0.0", 0, memSymbols{})
	opener.results["openerr.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{SHA256: hashOf("other")}, errors.New("dlopen failed")
	}
	// 4. Signed candidate where opened size disagrees with manifest size.
	cSizeMismatch, hSizeMismatch := makeSignedCandidate(t, ts, opener, "sizemm.so", "sizemm", "1.0.0", 0, memSymbols{})
	opener.results["sizemm.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{SHA256: hSizeMismatch, Size: 99999}, nil
	}
	// 5. Signed candidate where resolvePluginSymbols fails (missing Descriptor).
	cNoDesc, hNoDesc := makeSignedCandidate(t, ts, opener, "nodesc.so", "nodesc", "1.0.0", 0, memSymbols{})
	opener.results["nodesc.so"] = func(proteus.Candidate, string) (proteus.Opened, error) {
		return proteus.Opened{Symbols: memSymbols{}, SHA256: hNoDesc, Size: 1024}, nil
	}
	// 6. Signed candidate with non-semver version under VersionWarn.
	cNonSemver, _ := makeSignedCandidate(t, ts, opener, "nonsemver.so", "nonsemver", "not-semver", 9, memSymbols{
		sdk.SymbolDescriptor: sdk.Descriptor{Name: "nonsemver", Version: "not-semver"},
	})
	// 7. Signed candidate with higher major/minor/patch than minVersion.
	cHighVer, _ := makeSignedCandidate(t, ts, opener, "highver.so", "highver", "2.3.4", 1, memSymbols{})

	src := &memSource{
		candidates: []proteus.Candidate{
			cBadSig,
			cSnapMod,
			cOpenErr,
			cSizeMismatch,
			cNoDesc,
			cNonSemver,
			cHighVer,
		},
	}

	mgr, err := host.New(src, opener,
		host.WithVerifier(ts.verifier),
		host.WithGoos("linux"),
		host.WithGoarch("arm64"),
		host.WithHostVersion("1.0.0"),
		host.WithHostVersionPolicy(proteus.VersionWarn),
		host.WithMinVersions(map[string]string{
			"nonsemver": "1.0.0",
			"highver":   "1.2.3",
		}),
		host.WithMinVersionPolicy(proteus.VersionWarn),
	)
	if err != nil {
		t.Fatal(err)
	}

	rep1, err := mgr.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep1.Loaded) != 2 {
		t.Fatalf("expected 2 loaded plugins (nonsemver, highver), got %d", len(rep1.Loaded))
	}

	// Second Reload skips already-quarantined signed candidates (cSizeMismatch, cNoDesc) and already-loaded ones.
	rep2, err := mgr.Reload(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep2.Skipped) < 4 {
		t.Fatalf("expected >= 4 skipped candidates on second Reload, got %d", len(rep2.Skipped))
	}

	// Verify Get returns true for highver, and early break on LookupAll works.
	if _, ok := mgr.Get("highver"); !ok {
		t.Fatal("expected highver in Get")
	}
	for range mgr.LookupAll(sdk.SymbolDescriptor) {
		break
	}
}
