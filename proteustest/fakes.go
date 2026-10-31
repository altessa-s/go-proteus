// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package proteustest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/altessa-s/go-proteus/signature"
	"github.com/altessa-s/go-proteus/signing"

	proteus "github.com/altessa-s/go-proteus"
)

// MemSource is an in-memory [proteus.Source] safe for concurrent use.
type MemSource struct {
	mu         sync.Mutex
	candidates []proteus.Candidate
	err        error
}

// NewMemSource returns an in-memory [proteus.Source] seeded with candidates.
func NewMemSource(candidates ...proteus.Candidate) *MemSource {
	return &MemSource{candidates: slices.Clone(candidates)}
}

// SetCandidates replaces the candidate slice returned by [MemSource.Candidates].
func (s *MemSource) SetCandidates(candidates ...proteus.Candidate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.candidates = slices.Clone(candidates)
}

// SetError sets the error returned by [MemSource.Candidates].
func (s *MemSource) SetError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

// Candidates returns a copy of the configured candidates or the configured error.
func (s *MemSource) Candidates(_ context.Context) ([]proteus.Candidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return slices.Clone(s.candidates), nil
}

// MapSymbols is an in-memory [proteus.Symbols] table backed by a map.
type MapSymbols map[string]any

// Lookup returns the exported symbol value for name or an error when absent.
func (m MapSymbols) Lookup(name string) (any, error) {
	v, ok := m[name]
	if !ok {
		return nil, fmt.Errorf("symbol %q not found", name)
	}
	return v, nil
}

// MemOpener is an in-memory [proteus.Opener] safe for concurrent use.
type MemOpener struct {
	mu     sync.Mutex
	byID   map[string]proteus.Symbols
	openFn func(context.Context, proteus.Candidate, string) (proteus.Opened, error)
	opened []string
	counts map[string]int
}

// NewMemOpener returns an in-memory [proteus.Opener] mapping candidate IDs to
// [proteus.Symbols].
func NewMemOpener(byID map[string]proteus.Symbols) *MemOpener {
	cloned := make(map[string]proteus.Symbols, len(byID))
	maps.Copy(cloned, byID)
	return &MemOpener{
		byID:   cloned,
		counts: make(map[string]int),
	}
}

// SetSymbols registers symbols for candidate ID.
func (o *MemOpener) SetSymbols(id string, syms proteus.Symbols) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.byID == nil {
		o.byID = make(map[string]proteus.Symbols)
	}
	o.byID[id] = syms
}

// SetOpenFunc overrides symbol resolution with a custom callback.
func (o *MemOpener) SetOpenFunc(fn func(context.Context, proteus.Candidate, string) (proteus.Opened, error)) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.openFn = fn
}

// Open streams the candidate artifact, verifies its digest against verifiedSHA256
// when non-empty, records the candidate ID, and resolves its symbols.
func (o *MemOpener) Open(ctx context.Context, c proteus.Candidate, verifiedSHA256 string, verifiedSize int64) (proteus.Opened, error) {
	o.mu.Lock()
	o.opened = append(o.opened, c.ID)
	if o.counts == nil {
		o.counts = make(map[string]int)
	}
	o.counts[c.ID]++
	fn := o.openFn
	syms, ok := o.byID[c.ID]
	o.mu.Unlock()

	if fn != nil {
		return fn(ctx, c, verifiedSHA256)
	}
	if !ok {
		return proteus.Opened{}, fmt.Errorf("no symbols registered for candidate %q", c.ID)
	}
	if c.Open == nil {
		return proteus.Opened{}, errors.New("candidate Open is nil")
	}
	artifact, err := c.Open()
	if err != nil {
		return proteus.Opened{}, err
	}
	defer func() { _ = artifact.Reader.Close() }()

	data, err := io.ReadAll(artifact.Reader)
	if err != nil {
		return proteus.Opened{}, err
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if (verifiedSHA256 != "" && digest != verifiedSHA256) || (verifiedSize > 0 && int64(len(data)) != verifiedSize) {
		return proteus.Opened{}, fmt.Errorf("%w: digest %s != %s", proteus.ErrManifestMismatch, digest, verifiedSHA256)
	}
	return proteus.Opened{
		Symbols: syms,
		SHA256:  digest,
		Size:    int64(len(data)),
	}, nil
}

// OpenedIDs returns the candidate IDs passed to [MemOpener.Open] in call order.
func (o *MemOpener) OpenedIDs() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.opened)
}

// OpenCount returns how many times candidate ID was passed to [MemOpener.Open].
func (o *MemOpener) OpenCount(id string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.counts[id]
}

// RecordingObserver is a thread-safe [proteus.Observer] that records all
// lifecycle telemetry events emitted by a [host.Manager].
type RecordingObserver struct {
	mu          sync.Mutex
	admissions  []proteus.AdmissionEvent
	inits       []proteus.InitEvent
	quarantines []proteus.QuarantineEntry
	stats       []proteus.Stats
}

// NewRecordingObserver returns an empty [RecordingObserver].
func NewRecordingObserver() *RecordingObserver {
	return &RecordingObserver{}
}

// Admitted implements [proteus.Observer].
func (o *RecordingObserver) Admitted(e proteus.AdmissionEvent) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.admissions = append(o.admissions, e)
}

// Initialized implements [proteus.Observer].
func (o *RecordingObserver) Initialized(e proteus.InitEvent) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.inits = append(o.inits, e)
}

// Quarantined implements [proteus.Observer].
func (o *RecordingObserver) Quarantined(e proteus.QuarantineEntry) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.quarantines = append(o.quarantines, e)
}

// RegistryChanged implements [proteus.Observer].
func (o *RecordingObserver) RegistryChanged(s proteus.Stats) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.stats = append(o.stats, s)
}

// Admissions returns a snapshot of recorded admission events in call order.
func (o *RecordingObserver) Admissions() []proteus.AdmissionEvent {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.admissions)
}

// Inits returns a snapshot of recorded initialization events in call order.
func (o *RecordingObserver) Inits() []proteus.InitEvent {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.inits)
}

// Quarantines returns a snapshot of recorded quarantine entries in call order.
func (o *RecordingObserver) Quarantines() []proteus.QuarantineEntry {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.quarantines)
}

// StatsHistory returns a snapshot of recorded registry stats in call order.
func (o *RecordingObserver) StatsHistory() []proteus.Stats {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.stats)
}

// Reset clears all recorded observer events.
func (o *RecordingObserver) Reset() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.admissions = nil
	o.inits = nil
	o.quarantines = nil
	o.stats = nil
}

// MustGenerateKey generates a signing keypair for alg ([signature.AlgEd25519]
// or [signature.AlgECDSAP256]) and returns the [signing.KeyPair], parsed
// [signature.Key], and [crypto.Signer].
func MustGenerateKey(tb testing.TB, alg signature.Algorithm) (signing.KeyPair, signature.Key, crypto.Signer) {
	tb.Helper()
	pair, err := signing.GenerateKey(alg)
	if err != nil {
		tb.Fatalf("proteustest.MustGenerateKey(%q): %v", alg, err)
	}
	return pair, pair.PublicKey, pair.PrivateKey
}

// SignedCandidate builds an in-memory [proteus.Candidate] for id, name, version,
// and payload, signs its [proteus.Manifest] with signer at issuedAt, and returns
// the candidate ready for admission.
func SignedCandidate(
	tb testing.TB,
	id, name, version string,
	payload []byte,
	signer crypto.Signer,
	issuedAt time.Time,
) proteus.Candidate {
	tb.Helper()
	if issuedAt.IsZero() {
		issuedAt = time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	}
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	m := proteus.Manifest{
		Version:   proteus.ManifestVersion,
		Name:      name,
		PluginVer: version,
		SHA256:    digest,
		Size:      int64(len(payload)),
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		IssuedAt:  issuedAt.UTC(),
	}
	envBytes, err := signing.SignManifest(m, signer)
	if err != nil {
		tb.Fatalf("proteustest.SignedCandidate SignManifest: %v", err)
	}
	clonedPayload := slices.Clone(payload)
	return proteus.Candidate{
		ID: id,
		Open: func() (proteus.Artifact, error) {
			return proteus.Artifact{
				Reader: io.NopCloser(bytes.NewReader(clonedPayload)),
				Size:   int64(len(clonedPayload)),
			}, nil
		},
		Signature: envBytes,
	}
}
