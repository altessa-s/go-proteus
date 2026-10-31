// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package host

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/sdk"
)

type readyPlugin struct {
	probes   *sync.WaitGroup
	plugin   *proteus.Plugin
	healthFn lifecycleHook
	release  func(context.Context) error
	setState func(proteus.State, error)
}

// Manager orchestrates discovery, admission, initialization, health probing, quarantine, and shutdown
// of dynamic Go plugins.
type Manager struct {
	source            proteus.Source
	opener            proteus.Opener
	verifier          proteus.Verifier
	unsigned          proteus.UnsignedPolicy
	allow             map[string]struct{}
	deny              map[string]struct{}
	revoked           map[string]struct{}
	hasHostMajor      bool
	hostMajor         int
	hostVersionPolicy proteus.VersionPolicy
	minVersions       map[string]semver
	minVersionPolicy  proteus.VersionPolicy
	initTimeout       time.Duration
	closeTimeout      time.Duration
	healthTimeout     time.Duration
	logger            *slog.Logger
	observer          proteus.Observer
	now               func() time.Time
	goos              string
	goarch            string
	hostBuildInfo     func() (*debug.BuildInfo, bool)

	loadMu            sync.Mutex
	mu                sync.RWMutex
	closed            bool
	discoveryErr      error
	discoveryFailures []string
	ready             map[string]readyPlugin
	failed            map[string]*proteus.Plugin
	loadedHashes      map[string]string
	unloadedHashes    map[string]struct{}
	quarantine        *quarantineBook
}

// New constructs a [Manager] using source, opener, and opts.
// By default, [proteus.UnsignedReject] is active and a non-nil [proteus.Verifier] is required.
func New(source proteus.Source, opener proteus.Opener, opts ...Option) (*Manager, error) {
	if source == nil {
		return nil, errors.New("host: source is required")
	}
	if opener == nil {
		return nil, errors.New("host: opener is required")
	}
	cfg := newOptions(opts...)
	if cfg.unsigned != proteus.UnsignedReject && cfg.unsigned != proteus.UnsignedWarn && cfg.unsigned != proteus.UnsignedAllow {
		return nil, fmt.Errorf("host: unknown unsigned policy %d", cfg.unsigned)
	}

	// Defect 8: Fail-closed unsigned default requires a Verifier at construction time.
	if cfg.unsigned == proteus.UnsignedReject && cfg.verifier == nil {
		return nil, fmt.Errorf("%w: verifier is required when unsigned policy is reject", proteus.ErrSignatureMissing)
	}

	var hasHostMajor bool
	var hostMajor int
	if cfg.hostVersion != "" {
		sv, err := parseSemver(cfg.hostVersion)
		if err != nil {
			return nil, fmt.Errorf("host: invalid hostVersion %q: %w", cfg.hostVersion, err)
		}
		hasHostMajor = true
		hostMajor = sv.major
	}

	minVers := make(map[string]semver, len(cfg.minVersions))
	for name, rawVer := range cfg.minVersions {
		sv, err := parseSemver(rawVer)
		if err != nil {
			return nil, fmt.Errorf("host: invalid minVersion for plugin %q (%q): %w", name, rawVer, err)
		}
		minVers[name] = sv
	}

	revoked := make(map[string]struct{}, len(cfg.revoked))
	for _, h := range cfg.revoked {
		norm := strings.ToLower(strings.TrimSpace(h))
		if !proteus.IsValidSHA256Hex(norm) {
			return nil, fmt.Errorf("host: invalid revoked sha256 digest %q", h)
		}
		revoked[norm] = struct{}{}
	}

	allow := make(map[string]struct{}, len(cfg.allow))
	for _, name := range cfg.allow {
		if name != "" {
			allow[name] = struct{}{}
		}
	}

	deny := make(map[string]struct{}, len(cfg.deny))
	for _, name := range cfg.deny {
		if name != "" {
			deny[name] = struct{}{}
		}
	}

	logger := cfg.logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	obs := cfg.observer
	if obs == nil {
		obs = proteus.NoopObserver{}
	}
	nowFn := cfg.now
	if nowFn == nil {
		nowFn = time.Now
	}
	goos := cfg.goos
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch := cfg.goarch
	if goarch == "" {
		goarch = runtime.GOARCH
	}

	return &Manager{
		source:            source,
		opener:            opener,
		verifier:          cfg.verifier,
		unsigned:          cfg.unsigned,
		allow:             allow,
		deny:              deny,
		revoked:           revoked,
		hasHostMajor:      hasHostMajor,
		hostMajor:         hostMajor,
		hostVersionPolicy: cfg.hostVersionPolicy,
		minVersions:       minVers,
		minVersionPolicy:  cfg.minVersionPolicy,
		initTimeout:       cfg.initTimeout,
		closeTimeout:      cfg.closeTimeout,
		healthTimeout:     cfg.healthTimeout,
		logger:            logger,
		observer:          obs,
		now:               nowFn,
		goos:              goos,
		goarch:            goarch,
		hostBuildInfo:     cfg.hostBuildInfo,
		ready:             make(map[string]readyPlugin),
		failed:            make(map[string]*proteus.Plugin),
		loadedHashes:      make(map[string]string),
		unloadedHashes:    make(map[string]struct{}),
		quarantine:        newQuarantineBook(),
	}, nil
}

// Load discovers and admits all eligible plugin candidates from the configured [proteus.Source].
func (m *Manager) Load(ctx context.Context) (proteus.LoadReport, error) {
	if err := ctx.Err(); err != nil {
		return proteus.LoadReport{}, err
	}
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	m.mu.RLock()
	closed := m.closed
	m.mu.RUnlock()
	if closed {
		return proteus.LoadReport{}, proteus.ErrClosed
	}

	candidates, err := m.source.Candidates(ctx)
	m.mu.Lock()
	m.discoveryErr = err
	if err == nil {
		// Discovery failures describe the latest successful scan, including removed entries.
		for _, key := range m.discoveryFailures {
			delete(m.failed, key)
		}
		m.discoveryFailures = nil
	}
	m.mu.Unlock()
	if err != nil {
		return proteus.LoadReport{}, err
	}

	var report proteus.LoadReport
	for _, cand := range candidates {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		before := len(report.Failed)
		m.admitCandidate(ctx, cand, &report)
		if cand.Err != nil {
			m.mu.Lock()
			m.discoveryFailures = append(m.discoveryFailures, "source:"+cand.ID)
			m.mu.Unlock()
		}
		for _, failure := range report.Failed[before:] {
			m.recordFailedPlugin(sdk.Descriptor{Name: failure.Name}, proteus.Manifest{}, failure.Source, failure.SHA256, failure.Err)
		}
	}

	report.Quarantine = m.quarantine.snapshot()
	m.mu.RLock()
	stats := m.statsLocked()
	m.mu.RUnlock()
	m.observer.RegistryChanged(stats)
	return report, nil
}

// Reload discovers and admits any new plugin candidates added since the previous Load or Reload.
// Already-loaded plugins and hashes previously unloaded in this process are skipped without re-running Init.
func (m *Manager) Reload(ctx context.Context) (proteus.LoadReport, error) {
	return m.Load(ctx)
}

// Unload removes a ready plugin by name, invokes its optional Close hook with a bounded timeout,
// transitions it to [proteus.StateUnloaded], and records its content hash so it will not be
// re-initialized by subsequent Reload calls in the same process.
func (m *Manager) Unload(ctx context.Context, name string) error {
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return proteus.ErrClosed
	}
	entry, ok := m.ready[name]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("%w: %s", proteus.ErrNotFound, name)
	}
	delete(m.ready, name)
	entry.setState(proteus.StateUnloaded, nil)
	hash := entry.plugin.SHA256()
	delete(m.loadedHashes, hash)
	if proteus.IsValidSHA256Hex(hash) {
		m.unloadedHashes[hash] = struct{}{}
	}
	stats := m.statsLocked()
	m.mu.Unlock()

	closeErr := entry.release(ctx)
	entry.setState(proteus.StateUnloaded, closeErr)
	m.observer.RegistryChanged(stats)
	return closeErr
}

// Close shuts down all ready plugins in reverse alphabetical order and marks the manager closed.
// Subsequent calls to Close are idempotent and return nil.
func (m *Manager) Close(ctx context.Context) error {
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	entries := make([]readyPlugin, 0, len(m.ready))
	for _, entry := range m.ready {
		entry.setState(proteus.StateUnloaded, nil)
		entries = append(entries, entry)
	}
	clear(m.ready)
	clear(m.loadedHashes)
	stats := m.statsLocked()
	m.mu.Unlock()

	slices.SortFunc(entries, func(a, b readyPlugin) int {
		return cmp.Compare(b.plugin.Name(), a.plugin.Name())
	})

	var errs []error
	for _, entry := range entries {
		err := entry.release(ctx)
		entry.setState(proteus.StateUnloaded, err)
		if err != nil {
			errs = append(errs, err)
		}
	}

	m.observer.RegistryChanged(stats)
	return errors.Join(errs...)
}

// Get retrieves a ready plugin by name. Failed or unloaded plugins are never returned by Get.
func (m *Manager) Get(name string) (*proteus.Plugin, bool) {
	m.mu.RLock()
	entry, ok := m.ready[name]
	m.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return entry.plugin, true
}

// All returns a deterministic iterator over all plugins currently in [proteus.StateReady], sorted by name.
func (m *Manager) All() iter.Seq[*proteus.Plugin] {
	m.mu.RLock()
	list := make([]*proteus.Plugin, 0, len(m.ready))
	for _, entry := range m.ready {
		list = append(list, entry.plugin)
	}
	m.mu.RUnlock()
	slices.SortFunc(list, func(a, b *proteus.Plugin) int {
		return cmp.Compare(a.Name(), b.Name())
	})
	return slices.Values(list)
}

// Failed returns a deterministic iterator over all plugins currently in [proteus.StateFailed], sorted by name.
func (m *Manager) Failed() iter.Seq[*proteus.Plugin] {
	m.mu.RLock()
	list := make([]*proteus.Plugin, 0, len(m.failed))
	for _, p := range m.failed {
		list = append(list, p)
	}
	m.mu.RUnlock()
	slices.SortFunc(list, func(a, b *proteus.Plugin) int {
		return cmp.Compare(a.Name(), b.Name())
	})
	return slices.Values(list)
}

// LookupAll yields each ready plugin that exports symbol along with the resolved symbol value.
func (m *Manager) LookupAll(symbol string) iter.Seq2[*proteus.Plugin, any] {
	return func(yield func(*proteus.Plugin, any) bool) {
		for p := range m.All() {
			if sym, ok := p.Lookup(symbol); ok {
				if !yield(p, sym) {
					return
				}
			}
		}
	}
}

// Quarantined returns a sorted snapshot of all currently quarantined binary hashes.
func (m *Manager) Quarantined() []proteus.QuarantineEntry {
	return m.quarantine.snapshot()
}

// ClearQuarantine removes a single SHA-256 digest from the quarantine set, or clears the entire
// quarantine set when sha256 is empty.
func (m *Manager) ClearQuarantine(sha256 string) {
	m.mu.Lock()
	if sha256 == "" {
		m.quarantine.clear()
	} else {
		m.quarantine.remove(strings.ToLower(strings.TrimSpace(sha256)))
	}
	stats := m.statsLocked()
	m.mu.Unlock()
	m.observer.RegistryChanged(stats)
}

// Health evaluates the health of all ready and failed plugins and returns an aggregate [proteus.HealthReport].
func (m *Manager) Health(ctx context.Context) proteus.HealthReport {
	m.mu.RLock()
	if m.closed {
		qCount := m.quarantine.len()
		m.mu.RUnlock()
		return proteus.HealthReport{
			Status:      proteus.StatusNotServing,
			Quarantined: qCount,
		}
	}
	readyList := make([]readyPlugin, 0, len(m.ready))
	for _, entry := range m.ready {
		readyList = append(readyList, entry)
	}
	failedList := make([]*proteus.Plugin, 0, len(m.failed))
	for _, p := range m.failed {
		failedList = append(failedList, p)
	}
	qCount := m.quarantine.len()
	discoveryErr := m.discoveryErr
	m.mu.RUnlock()

	var (
		readyCount  int
		failedCount int
		plugins     = make([]proteus.PluginHealth, 0, len(readyList)+len(failedList))
	)

	for _, entry := range readyList {
		p := entry.plugin
		var probeErr error
		// Admission to a probe and removal from the registry are mutually exclusive.
		m.mu.RLock()
		current, active := m.ready[p.Name()]
		active = active && current.plugin == p
		if active && entry.healthFn != nil {
			entry.probes.Add(1)
		}
		m.mu.RUnlock()
		if active && entry.healthFn != nil {
			probeErr = runWatchdog(ctx, m.healthTimeout, p.Name(), "HealthCheck", nil, m.logger, func(ctx context.Context) error {
				defer entry.probes.Done()
				return entry.healthFn(ctx)
			})
		}
		state := p.State()
		if probeErr != nil || state != proteus.StateReady {
			failedCount++
			plugins = append(plugins, proteus.PluginHealth{
				Name:   p.Name(),
				State:  state,
				Status: proteus.StatusNotServing,
				Err:    probeErr,
			})
		} else {
			readyCount++
			plugins = append(plugins, proteus.PluginHealth{
				Name:   p.Name(),
				State:  state,
				Status: proteus.StatusServing,
			})
		}
	}

	for _, fp := range failedList {
		failedCount++
		plugins = append(plugins, proteus.PluginHealth{
			Name:   fp.Name(),
			State:  proteus.StateFailed,
			Status: proteus.StatusNotServing,
			Err:    fp.Err(),
		})
	}

	slices.SortFunc(plugins, func(a, b proteus.PluginHealth) int {
		return cmp.Compare(a.Name, b.Name)
	})

	status := proteus.StatusServing
	if failedCount > 0 || discoveryErr != nil {
		if readyCount == 0 {
			status = proteus.StatusNotServing
		} else {
			status = proteus.StatusDegraded
		}
	}

	return proteus.HealthReport{
		Status:       status,
		DiscoveryErr: discoveryErr,
		Ready:        readyCount,
		Failed:       failedCount,
		Quarantined:  qCount,
		Plugins:      plugins,
	}
}

func (m *Manager) isNameAllowed(name string) bool {
	if _, denied := m.deny[name]; denied {
		return false
	}
	if len(m.allow) > 0 {
		_, allowed := m.allow[name]
		return allowed
	}
	return true
}

func (m *Manager) isNameLoaded(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.ready[name]
	return ok
}

func (m *Manager) isHashLoadedOrUnloaded(hash string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !proteus.IsValidSHA256Hex(hash) {
		return false
	}
	if _, loaded := m.loadedHashes[hash]; loaded {
		return true
	}
	if _, unloaded := m.unloadedHashes[hash]; unloaded {
		return true
	}
	return false
}

func (m *Manager) statsLocked() proteus.Stats {
	return proteus.Stats{
		Ready:       len(m.ready),
		Failed:      len(m.failed),
		Quarantined: m.quarantine.len(),
	}
}
