// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package proteus

import (
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/altessa-s/go-proteus/sdk"
)

// State represents the lifecycle state of a [Plugin].
type State int32

const (
	// StateReady indicates that the plugin was admitted and its Init hook completed without error.
	StateReady State = iota + 1

	// StateFailed indicates that the plugin failed initialization or a post-load lifecycle check.
	StateFailed

	// StateUnloaded indicates that the plugin was explicitly unloaded or closed by the manager.
	StateUnloaded
)

// String returns the lowercase name of the lifecycle state.
func (s State) String() string {
	switch s {
	case StateReady:
		return "ready"
	case StateFailed:
		return "failed"
	case StateUnloaded:
		return "unloaded"
	default:
		return "unknown"
	}
}

// UnsignedPolicy controls how the host manager treats plugin candidates that lack a detached .so.sig file.
type UnsignedPolicy int

const (
	// UnsignedReject refuses any candidate without a valid detached DSSE signature (fail-closed default).
	UnsignedReject UnsignedPolicy = iota

	// UnsignedWarn admits unsigned candidates in development mode and logs a warning per unsigned plugin.
	UnsignedWarn

	// UnsignedAllow admits unsigned candidates in development mode without warnings.
	UnsignedAllow
)

// String returns the lowercase name of the unsigned policy.
func (p UnsignedPolicy) String() string {
	switch p {
	case UnsignedReject:
		return "reject"
	case UnsignedWarn:
		return "warn"
	case UnsignedAllow:
		return "allow"
	default:
		return "unknown"
	}
}

// VersionPolicy controls how the host manager enforces host major version and minimum plugin version rules.
type VersionPolicy int

const (
	// VersionEnforce rejects and quarantines plugins that violate version constraints (default).
	VersionEnforce VersionPolicy = iota

	// VersionWarn logs a warning and continues admitting the plugin when a version constraint mismatches.
	VersionWarn

	// VersionIgnore disables the version check completely.
	VersionIgnore
)

// String returns the lowercase name of the version policy.
func (p VersionPolicy) String() string {
	switch p {
	case VersionEnforce:
		return "enforce"
	case VersionWarn:
		return "warn"
	case VersionIgnore:
		return "ignore"
	default:
		return "unknown"
	}
}

type symbolEntry struct {
	val any
	ok  bool
}

type errBox struct {
	err error
}

// Plugin represents a plugin entity managed by the host.
//
// Identity fields are immutable after construction; lifecycle state and error fields are accessed
// atomically so [Plugin] is safe for concurrent use across goroutines.
type Plugin struct {
	descriptor sdk.Descriptor
	manifest   Manifest
	unsigned   bool
	source     string
	sha256     string
	loadedAt   time.Time
	rawSymbols Symbols

	state   atomic.Int32
	lastErr atomic.Pointer[errBox]
	cache   sync.Map
}

// NewPlugin constructs a [Plugin] in [StateReady].
// When manifest.Version is zero, the plugin is marked as unsigned.
func NewPlugin(
	desc sdk.Descriptor,
	manifest Manifest,
	source string,
	sha256 string,
	loadedAt time.Time,
	symbols Symbols,
) *Plugin {
	clonedDesc := desc
	if desc.Custom != nil {
		clonedDesc.Custom = maps.Clone(desc.Custom)
	}
	p := &Plugin{
		descriptor: clonedDesc,
		manifest:   manifest,
		unsigned:   manifest.Version == 0,
		source:     source,
		sha256:     sha256,
		loadedAt:   loadedAt,
		rawSymbols: symbols,
	}
	p.state.Store(int32(StateReady))
	return p
}

// NewFailedPlugin constructs a [Plugin] in [StateFailed] with the given failure cause.
func NewFailedPlugin(
	desc sdk.Descriptor,
	manifest Manifest,
	source string,
	sha256 string,
	loadedAt time.Time,
	err error,
) *Plugin {
	p := NewPlugin(desc, manifest, source, sha256, loadedAt, nil)
	p.MarkFailed(err)
	return p
}

// Name returns the unique plugin name from its [sdk.Descriptor].
func (p *Plugin) Name() string { return p.descriptor.Name }

// Version returns the semantic version string from its [sdk.Descriptor].
func (p *Plugin) Version() string { return p.descriptor.Version }

// Description returns the human-readable description from its [sdk.Descriptor].
func (p *Plugin) Description() string { return p.descriptor.Description }

// Descriptor returns a copy of the plugin's [sdk.Descriptor].
func (p *Plugin) Descriptor() sdk.Descriptor {
	d := p.descriptor
	if d.Custom != nil {
		d.Custom = maps.Clone(d.Custom)
	}
	return d
}

// Manifest returns the verified [Manifest] associated with the plugin and a boolean reporting
// whether the plugin was signed.
func (p *Plugin) Manifest() (Manifest, bool) {
	return p.manifest, !p.unsigned
}

// Unsigned reports whether the plugin was admitted without a detached DSSE signature.
func (p *Plugin) Unsigned() bool { return p.unsigned }

// Source returns the candidate source identifier (typically the filename within the plugin directory).
func (p *Plugin) Source() string { return p.source }

// SHA256 returns the verified 64-character lowercase hex SHA-256 digest of the plugin binary.
func (p *Plugin) SHA256() string { return p.sha256 }

// LoadedAt returns the timestamp when the plugin was loaded by the host.
func (p *Plugin) LoadedAt() time.Time { return p.loadedAt }

// State returns the current lifecycle [State] of the plugin.
func (p *Plugin) State() State { return State(p.state.Load()) }

// Err returns the last lifecycle error recorded on the plugin, or nil if none.
func (p *Plugin) Err() error {
	if box := p.lastErr.Load(); box != nil {
		return box.err
	}
	return nil
}

// MarkFailed transitions the plugin to [StateFailed] and records err.
func (p *Plugin) MarkFailed(err error) {
	if err != nil {
		p.lastErr.Store(&errBox{err: err})
	}
	p.state.Store(int32(StateFailed))
}

// MarkUnloaded transitions the plugin to [StateUnloaded]. If err is non-nil, it is recorded.
func (p *Plugin) MarkUnloaded(err error) {
	if err != nil {
		p.lastErr.Store(&errBox{err: err})
	}
	p.state.Store(int32(StateUnloaded))
}

// Lookup resolves and caches a symbol exported by the plugin.
// It returns (nil, false) when the symbol is not found or when the plugin has no symbol table.
func (p *Plugin) Lookup(name string) (any, bool) {
	if v, ok := p.cache.Load(name); ok {
		entry, _ := v.(symbolEntry)
		return entry.val, entry.ok
	}
	if p.rawSymbols == nil {
		return nil, false
	}
	val, err := p.rawSymbols.Lookup(name)
	entry := symbolEntry{val: val, ok: err == nil}
	p.cache.Store(name, entry)
	return entry.val, entry.ok
}
