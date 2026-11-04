// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package proteus_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/sdk"
)

type mapSymbols map[string]any

func (m mapSymbols) Lookup(name string) (any, error) {
	v, ok := m[name]
	if !ok {
		return nil, errors.New("symbol not found")
	}

	return v, nil
}

func TestManifestValidateAndExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	validHash := strings.Repeat("a", 64)

	base := proteus.Manifest{
		Version:   proteus.ManifestVersion,
		Name:      "greeter",
		PluginVer: "1.2.3",
		SHA256:    validHash,
		Size:      4096,
		GOOS:      "linux",
		GOARCH:    "arm64",
		HostMajor: 2,
		IssuedAt:  now,
		NotAfter:  now.Add(time.Hour),
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("expected valid manifest, got %v", err)
	}

	if base.IsExpired(now.Add(30 * time.Minute)) {
		t.Fatal("expected manifest not expired at +30m")
	}

	if !base.IsExpired(now.Add(2 * time.Hour)) {
		t.Fatal("expected manifest expired at +2h")
	}

	cases := []struct {
		name   string
		mutate func(*proteus.Manifest)
	}{
		{"bad version", func(m *proteus.Manifest) { m.Version = 2 }},
		{"empty name", func(m *proteus.Manifest) { m.Name = "" }},
		{"empty plugin version", func(m *proteus.Manifest) { m.PluginVer = "" }},
		{"short sha256", func(m *proteus.Manifest) { m.SHA256 = "abcd" }},
		{"uppercase sha256", func(m *proteus.Manifest) { m.SHA256 = strings.Repeat("A", 64) }},
		{"zero size", func(m *proteus.Manifest) { m.Size = 0 }},
		{"empty goos", func(m *proteus.Manifest) { m.GOOS = "" }},
		{"empty goarch", func(m *proteus.Manifest) { m.GOARCH = "" }},
		{"negative hostMajor", func(m *proteus.Manifest) { m.HostMajor = -1 }},
		{"zero issuedAt", func(m *proteus.Manifest) { m.IssuedAt = time.Time{} }},
		{"notAfter before issuedAt", func(m *proteus.Manifest) { m.NotAfter = now.Add(-time.Minute) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := base
			tc.mutate(&m)

			err := m.Validate()
			if !errors.Is(err, proteus.ErrManifestInvalid) {
				t.Fatalf("expected ErrManifestInvalid, got %v", err)
			}
		})
	}
}

func TestPluginLifecycleAndLookup(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	hash := strings.Repeat("b", 64)
	desc := sdk.Descriptor{
		Name:        "auth",
		Version:     "2.0.0",
		Description: "Auth plugin",
		Build:       "abc1234",
		Custom:      map[string]any{"tier": "core"},
	}
	manifest := proteus.Manifest{
		Version:   proteus.ManifestVersion,
		Name:      "auth",
		PluginVer: "2.0.0",
		SHA256:    hash,
		Size:      1024,
		GOOS:      "linux",
		GOARCH:    "amd64",
		IssuedAt:  now,
	}

	syms := mapSymbols{"Provider": "ok-provider"}
	p, setState := proteus.NewManagedPlugin(desc, manifest, "auth.so", hash, now, syms)

	if p.Name() != "auth" || p.Version() != "2.0.0" || p.Description() != "Auth plugin" {
		t.Fatalf("unexpected plugin identity: %s %s %s", p.Name(), p.Version(), p.Description())
	}

	if p.Source() != "auth.so" || p.SHA256() != hash || !p.LoadedAt().Equal(now) {
		t.Fatalf("unexpected plugin source/hash/time")
	}

	if p.Unsigned() {
		t.Fatal("expected signed plugin")
	}

	if gotM, signed := p.Manifest(); !signed || gotM.Name != "auth" {
		t.Fatalf("unexpected Manifest(): %+v, %v", gotM, signed)
	}

	if p.State() != proteus.StateReady || p.State().String() != "ready" {
		t.Fatalf("unexpected initial state: %v", p.State())
	}

	if p.Err() != nil {
		t.Fatalf("expected nil Err(), got %v", p.Err())
	}

	// Descriptor copy isolation.
	dCopy := p.Descriptor()

	dCopy.Custom["tier"] = "mutated"
	if p.Descriptor().Custom["tier"] != "core" {
		t.Fatal("Descriptor() did not clone Custom map")
	}

	// Lookup and cached lookup.
	val, ok := p.Lookup("Provider")
	if !ok || val != "ok-provider" {
		t.Fatalf("expected Provider symbol, got %v, %v", val, ok)
	}

	val2, ok2 := p.Lookup("Provider")
	if !ok2 || val2 != "ok-provider" {
		t.Fatalf("expected cached Provider symbol, got %v, %v", val2, ok2)
	}

	if _, ok := p.Lookup("Missing"); ok {
		t.Fatal("expected missing symbol to return false")
	}

	failErr := errors.New("boom")
	setState(proteus.StateFailed, failErr)

	if p.State() != proteus.StateFailed || p.State().String() != "failed" || !errors.Is(p.Err(), failErr) {
		t.Fatalf("unexpected state after MarkFailed: %v, err=%v", p.State(), p.Err())
	}

	unloadErr := errors.New("close failed")
	setState(proteus.StateUnloaded, unloadErr)

	if p.State() != proteus.StateUnloaded || p.State().String() != "unloaded" || !errors.Is(p.Err(), unloadErr) {
		t.Fatalf("unexpected state after MarkUnloaded: %v, err=%v", p.State(), p.Err())
	}

	// Failed constructor & nil symbols.
	fp := proteus.NewFailedPlugin(desc, proteus.Manifest{}, "auth.so", hash, now, failErr)
	if !fp.Unsigned() || fp.State() != proteus.StateFailed {
		t.Fatalf("unexpected failed plugin: unsigned=%v state=%v", fp.Unsigned(), fp.State())
	}

	if _, ok := fp.Lookup("Provider"); ok {
		t.Fatal("expected false Lookup on nil symbols")
	}
}

func TestEnumsReportsAndNoopObserver(t *testing.T) {
	t.Parallel()

	if proteus.State(99).String() != "unknown" {
		t.Fatal("expected unknown state string")
	}

	if proteus.UnsignedReject.String() != "reject" ||
		proteus.UnsignedWarn.String() != "warn" ||
		proteus.UnsignedAllow.String() != "allow" ||
		proteus.UnsignedPolicy(99).String() != "unknown" {
		t.Fatal("unexpected UnsignedPolicy strings")
	}

	if proteus.VersionEnforce.String() != "enforce" ||
		proteus.VersionWarn.String() != "warn" ||
		proteus.VersionIgnore.String() != "ignore" ||
		proteus.VersionPolicy(99).String() != "unknown" {
		t.Fatal("unexpected VersionPolicy strings")
	}

	if proteus.StatusServing.String() != "serving" ||
		proteus.StatusDegraded.String() != "degraded" ||
		proteus.StatusNotServing.String() != "not_serving" ||
		proteus.HealthStatus(99).String() != "unknown" {
		t.Fatal("unexpected HealthStatus strings")
	}

	var emptyReport proteus.LoadReport
	if emptyReport.Err() != nil {
		t.Fatalf("expected nil Err() on empty LoadReport, got %v", emptyReport.Err())
	}

	errA := errors.New("errA")
	errB := errors.New("errB")

	report := proteus.LoadReport{
		Failed: []proteus.CandidateReport{
			{Source: "a.so", Err: errA},
			{Source: "b.so", Err: errB},
		},
	}
	if !errors.Is(report.Err(), errA) || !errors.Is(report.Err(), errB) {
		t.Fatalf("expected joined error to match both errA and errB, got %v", report.Err())
	}

	var obs proteus.NoopObserver
	obs.Admitted(proteus.AdmissionEvent{})
	obs.Initialized(proteus.InitEvent{})
	obs.Quarantined(proteus.QuarantineEntry{})
	obs.RegistryChanged(proteus.Stats{})
}
