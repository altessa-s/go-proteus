// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package host

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/sdk"
)

func (m *Manager) admitCandidate(ctx context.Context, cand proteus.Candidate, report *proteus.LoadReport) {
	if cand.Err != nil {
		report.Failed = append(report.Failed, proteus.CandidateReport{Source: cand.ID, Err: cand.Err})
		m.observer.Admitted(proteus.AdmissionEvent{Source: cand.ID, Outcome: proteus.OutcomeRejected, Err: cand.Err})
		return
	}
	if len(cand.Signature) > 0 && m.verifier != nil {
		m.admitSigned(ctx, cand, report)
		return
	}
	if len(cand.Signature) == 0 {
		if m.unsigned != proteus.UnsignedWarn && m.unsigned != proteus.UnsignedAllow {
			err := fmt.Errorf("%w: %s has no detached .sig envelope", proteus.ErrSignatureMissing, cand.ID)
			report.Failed = append(report.Failed, proteus.CandidateReport{
				Source:   cand.ID,
				Unsigned: true,
				Err:      err,
			})
			m.observer.Admitted(proteus.AdmissionEvent{
				Source:   cand.ID,
				Unsigned: true,
				Outcome:  proteus.OutcomeRejected,
				Err:      err,
			})
			return
		}
		m.admitUnsigned(ctx, cand, report)
		return
	}
	// Candidate has a signature file, but no verifier was configured in unsigned dev mode.
	m.admitUnsigned(ctx, cand, report)
}

func (m *Manager) admitSigned(ctx context.Context, cand proteus.Candidate, report *proteus.LoadReport) {
	verified, err := m.verifier.Verify(ctx, cand.Signature)
	if err != nil {
		// Defect 16: Signature/manifest failure before hashing does not know a trustworthy binary SHA-256;
		// never insert an empty hash into quarantine.
		report.Failed = append(report.Failed, proteus.CandidateReport{
			Source: cand.ID,
			Err:    err,
		})
		m.observer.Admitted(proteus.AdmissionEvent{
			Source:  cand.ID,
			Outcome: proteus.OutcomeRejected,
			Err:     err,
		})
		return
	}

	manifest := verified.Manifest
	keyID := verified.KeyID
	hash := manifest.SHA256
	name := manifest.Name
	ver := manifest.PluginVer

	// Skip if this exact content hash is already loaded or was explicitly unloaded in this process (Defect 10).
	if m.isHashLoadedOrUnloaded(hash) {
		m.clearActiveSourceFailure(cand.ID, hash)
		skipErr := fmt.Errorf("%w: %s (%s)", proteus.ErrAlreadyLoaded, name, hash)
		report.Skipped = append(report.Skipped, proteus.CandidateReport{
			Source: cand.ID,
			Name:   name,
			SHA256: hash,
			Err:    skipErr,
		})
		m.observer.Admitted(proteus.AdmissionEvent{
			Source:  cand.ID,
			Name:    name,
			Version: ver,
			SHA256:  hash,
			KeyID:   keyID,
			Outcome: proteus.OutcomeSkipped,
			Err:     skipErr,
		})
		return
	}

	// Skip if hash is already quarantined.
	if m.quarantine.isQuarantined(hash) {
		qErr := fmt.Errorf("%w: %s (%s)", proteus.ErrQuarantined, name, hash)
		report.Skipped = append(report.Skipped, proteus.CandidateReport{
			Source: cand.ID,
			Name:   name,
			SHA256: hash,
			Err:    qErr,
		})
		m.observer.Admitted(proteus.AdmissionEvent{
			Source:  cand.ID,
			Name:    name,
			Version: ver,
			SHA256:  hash,
			KeyID:   keyID,
			Outcome: proteus.OutcomeSkipped,
			Err:     qErr,
		})
		return
	}

	// Check revocation list before opening.
	if _, revoked := m.revoked[hash]; revoked {
		revErr := fmt.Errorf("%w: %s (%s)", proteus.ErrRevoked, name, hash)
		m.quarantineAndFail(cand.ID, name, ver, hash, keyID, false, revErr, report)
		return
	}

	// Check platform match before opening.
	if manifest.GOOS != m.goos || manifest.GOARCH != m.goarch {
		platErr := fmt.Errorf(
			"%w: manifest targets %s/%s, host is %s/%s",
			proteus.ErrPlatformMismatch,
			manifest.GOOS,
			manifest.GOARCH,
			m.goos,
			m.goarch,
		)
		m.quarantineAndFail(cand.ID, name, ver, hash, keyID, false, platErr, report)
		return
	}

	// Check allow/deny policy on manifest name before opening (decisions Q8).
	if !m.isNameAllowed(name) {
		disErr := fmt.Errorf("%w: %s", proteus.ErrDisabled, name)
		report.Skipped = append(report.Skipped, proteus.CandidateReport{
			Source: cand.ID,
			Name:   name,
			SHA256: hash,
			Err:    disErr,
		})
		m.observer.Admitted(proteus.AdmissionEvent{
			Source:  cand.ID,
			Name:    name,
			Version: ver,
			SHA256:  hash,
			KeyID:   keyID,
			Outcome: proteus.OutcomeSkipped,
			Err:     disErr,
		})
		return
	}

	// Defect 11: Check duplicate plugin name collision before opening or running Init.
	if m.isNameLoaded(name) {
		dupErr := fmt.Errorf("%w: %s", proteus.ErrAlreadyLoaded, name)
		report.Failed = append(report.Failed, proteus.CandidateReport{
			Source: cand.ID,
			Name:   name,
			SHA256: hash,
			Err:    dupErr,
		})
		m.observer.Admitted(proteus.AdmissionEvent{
			Source:  cand.ID,
			Name:    name,
			Version: ver,
			SHA256:  hash,
			KeyID:   keyID,
			Outcome: proteus.OutcomeRejected,
			Err:     dupErr,
		})
		return
	}

	// Check host major version constraint before opening.
	if hostErr := m.checkHostMajor(name, manifest.HostMajor); hostErr != nil {
		m.quarantineAndFail(cand.ID, name, ver, hash, keyID, false, hostErr, report)
		return
	}

	// Check minimum plugin version floor before opening.
	if minErr := m.checkMinVersion(name, ver); minErr != nil {
		m.quarantineAndFail(cand.ID, name, ver, hash, keyID, false, minErr, report)
		return
	}

	// Open the candidate via Opener.
	opened, err := m.opener.Open(ctx, cand, hash, manifest.Size)
	if err != nil {
		if !opened.ContentFailure {
			report.Failed = append(report.Failed, proteus.CandidateReport{
				Source: cand.ID,
				Name:   name,
				SHA256: hash,
				Err:    err,
			})
			m.observer.Admitted(proteus.AdmissionEvent{
				Source:  cand.ID,
				Name:    name,
				Version: ver,
				SHA256:  hash,
				KeyID:   keyID,
				Outcome: proteus.OutcomeRejected,
				Err:     err,
			})
			return
		}
		qHash := hash
		if proteus.IsValidSHA256Hex(opened.SHA256) {
			qHash = opened.SHA256
		}
		m.quarantineAndFail(cand.ID, name, ver, qHash, keyID, false, err, report)
		return
	}

	if opened.SHA256 != hash || opened.Size != manifest.Size {
		mmErr := fmt.Errorf(
			"%w: binary sha256/size (%s, %d) does not match manifest (%s, %d)",
			proteus.ErrManifestMismatch,
			opened.SHA256,
			opened.Size,
			hash,
			manifest.Size,
		)
		qHash := hash
		if proteus.IsValidSHA256Hex(opened.SHA256) {
			qHash = opened.SHA256
		}
		m.quarantineAndFail(cand.ID, name, ver, qHash, keyID, false, mmErr, report)
		return
	}

	resolved, err := resolvePluginSymbols(opened.Symbols)
	if err != nil {
		m.recordFailedPlugin(sdk.Descriptor{Name: name, Version: ver}, manifest, cand.ID, hash, err)
		m.quarantineAndFail(cand.ID, name, ver, hash, keyID, false, err, report)
		return
	}

	if resolved.descriptor.Name != name || resolved.descriptor.Version != ver {
		mmErr := fmt.Errorf(
			"%w: Descriptor (%s@%s) does not match Manifest (%s@%s)",
			proteus.ErrManifestMismatch,
			resolved.descriptor.Name,
			resolved.descriptor.Version,
			name,
			ver,
		)
		m.recordFailedPlugin(sdk.Descriptor{Name: name, Version: ver}, manifest, cand.ID, hash, mmErr)
		m.quarantineAndFail(cand.ID, name, ver, hash, keyID, false, mmErr, report)
		return
	}

	m.finalizeAdmission(ctx, cand.ID, manifest, keyID, false, opened, resolved, report)
}

func (m *Manager) admitUnsigned(ctx context.Context, cand proteus.Candidate, report *proteus.LoadReport) {
	if m.unsigned == proteus.UnsignedWarn {
		m.logger.Warn("admitting unsigned plugin candidate in development mode",
			slog.String("source", cand.ID),
		)
	}

	opened, err := m.opener.Open(ctx, cand, "", 0)
	if err != nil {
		// Defect 16: Only quarantine when a valid content hash was computed and the failure is not snapshot storage tamper.
		if proteus.IsValidSHA256Hex(opened.SHA256) && opened.ContentFailure {
			m.quarantineAndFail(cand.ID, "", "", opened.SHA256, "", true, err, report)
			return
		}
		report.Failed = append(report.Failed, proteus.CandidateReport{
			Source:   cand.ID,
			SHA256:   opened.SHA256,
			Unsigned: true,
			Err:      err,
		})
		m.observer.Admitted(proteus.AdmissionEvent{
			Source:   cand.ID,
			SHA256:   opened.SHA256,
			Unsigned: true,
			Outcome:  proteus.OutcomeRejected,
			Err:      err,
		})
		return
	}

	hash := opened.SHA256

	if m.isHashLoadedOrUnloaded(hash) {
		m.clearActiveSourceFailure(cand.ID, hash)
		skipErr := fmt.Errorf("%w: %s (%s)", proteus.ErrAlreadyLoaded, cand.ID, hash)
		report.Skipped = append(report.Skipped, proteus.CandidateReport{
			Source:   cand.ID,
			SHA256:   hash,
			Unsigned: true,
			Err:      skipErr,
		})
		m.observer.Admitted(proteus.AdmissionEvent{
			Source:   cand.ID,
			SHA256:   hash,
			Unsigned: true,
			Outcome:  proteus.OutcomeSkipped,
			Err:      skipErr,
		})
		return
	}

	if m.quarantine.isQuarantined(hash) {
		qErr := fmt.Errorf("%w: %s (%s)", proteus.ErrQuarantined, cand.ID, hash)
		report.Skipped = append(report.Skipped, proteus.CandidateReport{
			Source:   cand.ID,
			SHA256:   hash,
			Unsigned: true,
			Err:      qErr,
		})
		m.observer.Admitted(proteus.AdmissionEvent{
			Source:   cand.ID,
			SHA256:   hash,
			Unsigned: true,
			Outcome:  proteus.OutcomeSkipped,
			Err:      qErr,
		})
		return
	}

	if _, revoked := m.revoked[hash]; revoked {
		revErr := fmt.Errorf("%w: %s (%s)", proteus.ErrRevoked, cand.ID, hash)
		m.quarantineAndFail(cand.ID, "", "", hash, "", true, revErr, report)
		return
	}

	resolved, err := resolvePluginSymbols(opened.Symbols)
	if err != nil {
		m.quarantineAndFail(cand.ID, "", "", hash, "", true, err, report)
		return
	}

	name := resolved.descriptor.Name
	ver := resolved.descriptor.Version

	// Evaluate allow/deny on Descriptor.Name after open for unsigned dev mode (decisions Q8).
	if !m.isNameAllowed(name) {
		disErr := fmt.Errorf("%w: %s", proteus.ErrDisabled, name)
		report.Skipped = append(report.Skipped, proteus.CandidateReport{
			Source:   cand.ID,
			Name:     name,
			SHA256:   hash,
			Unsigned: true,
			Err:      disErr,
		})
		m.observer.Admitted(proteus.AdmissionEvent{
			Source:   cand.ID,
			Name:     name,
			Version:  ver,
			SHA256:   hash,
			Unsigned: true,
			Outcome:  proteus.OutcomeSkipped,
			Err:      disErr,
		})
		return
	}

	// Defect 11: Check duplicate plugin name collision before running Init.
	if m.isNameLoaded(name) {
		dupErr := fmt.Errorf("%w: %s", proteus.ErrAlreadyLoaded, name)
		report.Failed = append(report.Failed, proteus.CandidateReport{
			Source:   cand.ID,
			Name:     name,
			SHA256:   hash,
			Unsigned: true,
			Err:      dupErr,
		})
		m.observer.Admitted(proteus.AdmissionEvent{
			Source:   cand.ID,
			Name:     name,
			Version:  ver,
			SHA256:   hash,
			Unsigned: true,
			Outcome:  proteus.OutcomeRejected,
			Err:      dupErr,
		})
		return
	}

	if err := m.checkMinVersion(name, ver); err != nil {
		m.recordFailedPlugin(resolved.descriptor, proteus.Manifest{}, cand.ID, hash, err)
		m.quarantineAndFail(cand.ID, name, ver, hash, "", true, err, report)
		return
	}

	m.finalizeAdmission(ctx, cand.ID, proteus.Manifest{}, "", true, opened, resolved, report)
}

func (m *Manager) finalizeAdmission(
	ctx context.Context,
	sourceID string,
	manifest proteus.Manifest,
	keyID string,
	unsigned bool,
	opened proteus.Opened,
	resolved resolvedSymbols,
	report *proteus.LoadReport,
) {
	desc := resolved.descriptor
	hash := opened.SHA256

	checkDepSkew(m.logger, desc.Name, resolved.depInfo, m.hostBuildInfo)

	m.observer.Admitted(proteus.AdmissionEvent{
		Source:   sourceID,
		Name:     desc.Name,
		Version:  desc.Version,
		SHA256:   hash,
		KeyID:    keyID,
		Unsigned: unsigned,
		Outcome:  proteus.OutcomeAdmitted,
	})

	start := m.now()
	release, contentFailure, initErr := acquireImage(ctx, m.initTimeout, opened, func() error {
		return runWatchdog(ctx, m.initTimeout, desc.Name, sdk.SymbolInit, proteus.ErrInitFailed, m.logger, resolved.initFn)
	}, resolved.closeFn)
	initDuration := m.now().Sub(start)

	m.observer.Initialized(proteus.InitEvent{
		Name:     desc.Name,
		Version:  desc.Version,
		Duration: initDuration,
		Err:      initErr,
	})

	now := m.now().UTC()
	if initErr != nil {
		m.recordFailedPlugin(desc, manifest, sourceID, hash, initErr)
		if contentFailure {
			if qEntry, added := m.quarantine.add(sourceID, hash, initErr, now); added {
				m.observer.Quarantined(qEntry)
			}
		}
		report.Failed = append(report.Failed, proteus.CandidateReport{
			Source:   sourceID,
			Name:     desc.Name,
			SHA256:   hash,
			Unsigned: unsigned,
			Err:      initErr,
		})
		return
	}

	plugin, setState := proteus.NewManagedPlugin(desc, manifest, sourceID, hash, now, opened.Symbols)
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, failed := range m.failed {
		if failed.Source() == sourceID {
			delete(m.failed, key)
		}
	}
	delete(m.failed, desc.Name)
	probes := new(sync.WaitGroup)
	m.ready[desc.Name] = readyPlugin{
		plugin: plugin,
		probes: probes,
		release: func(closeCtx context.Context) error {
			return runWatchdog(closeCtx, m.closeTimeout, desc.Name, sdk.SymbolClose, nil, m.logger, func(context.Context) error {
				// A timed-out health worker still owns plugin resources until it exits.
				probes.Wait()
				// Cleanup gets its own budget even if the caller has already stopped waiting.
				cleanupCtx := context.WithoutCancel(closeCtx)
				if m.closeTimeout > 0 {
					var cancel context.CancelFunc
					cleanupCtx, cancel = context.WithTimeout(cleanupCtx, m.closeTimeout)
					defer cancel()
				}
				return release(cleanupCtx)
			})
		},
		setState: setState,
		healthFn: resolved.healthFn,
	}
	m.loadedHashes[hash] = desc.Name
	report.Loaded = append(report.Loaded, plugin)
}

func (m *Manager) quarantineAndFail(
	sourceID, name, ver, hash, keyID string,
	unsigned bool,
	err error,
	report *proteus.LoadReport,
) {
	now := m.now().UTC()
	outcome := proteus.OutcomeRejected
	if qEntry, added := m.quarantine.add(sourceID, hash, err, now); added {
		outcome = proteus.OutcomeQuarantined
		m.observer.Quarantined(qEntry)
	}
	report.Failed = append(report.Failed, proteus.CandidateReport{
		Source:   sourceID,
		Name:     name,
		SHA256:   hash,
		Unsigned: unsigned,
		Err:      err,
	})
	m.observer.Admitted(proteus.AdmissionEvent{
		Source:   sourceID,
		Name:     name,
		Version:  ver,
		SHA256:   hash,
		KeyID:    keyID,
		Unsigned: unsigned,
		Outcome:  outcome,
		Err:      err,
	})
}

func (m *Manager) recordFailedPlugin(
	desc sdk.Descriptor,
	manifest proteus.Manifest,
	sourceID string,
	hash string,
	err error,
) {
	now := m.now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	if desc.Name == "" {
		desc.Name = "source:" + sourceID
	}
	// Do not overwrite an already-ready plugin if a duplicate candidate failed.
	if _, active := m.ready[desc.Name]; active {
		return
	}
	for key, previous := range m.failed {
		if previous.Source() != sourceID {
			continue
		}
		if key == desc.Name && desc.Version == "" {
			desc = previous.Descriptor()
			manifest, _ = previous.Manifest()
		}
		delete(m.failed, key)
	}
	m.failed[desc.Name] = proteus.NewFailedPlugin(desc, manifest, sourceID, hash, now, err)
}

func (m *Manager) checkHostMajor(pluginName string, pluginHostMajor int) error {
	if !m.hasHostMajor || pluginHostMajor <= 0 || m.hostVersionPolicy == proteus.VersionIgnore {
		return nil
	}
	if pluginHostMajor == m.hostMajor {
		return nil
	}
	err := fmt.Errorf(
		"%w: plugin %q requires host major %d, running host major is %d",
		proteus.ErrHostVersionMismatch,
		pluginName,
		pluginHostMajor,
		m.hostMajor,
	)
	if m.hostVersionPolicy == proteus.VersionWarn {
		m.logger.Warn("plugin host major version mismatch (allowed by policy)",
			slog.String("plugin", pluginName),
			slog.Int("plugin_host_major", pluginHostMajor),
			slog.Int("host_major", m.hostMajor),
		)
		return nil
	}
	return err
}

func (m *Manager) checkMinVersion(pluginName, rawPluginVer string) error {
	if len(m.minVersions) == 0 || m.minVersionPolicy == proteus.VersionIgnore {
		return nil
	}
	minVer, hasFloor := m.minVersions[pluginName]
	if !hasFloor {
		return nil
	}
	parsedPluginVer, err := parseSemver(rawPluginVer)
	if err != nil {
		vErr := fmt.Errorf("%w: plugin %q has non-semver version %q: %w", proteus.ErrBelowMinVersion, pluginName, rawPluginVer, err)
		if m.minVersionPolicy == proteus.VersionWarn {
			m.logger.Warn("plugin version could not be compared against minimum floor",
				slog.String("plugin", pluginName),
				slog.String("version", rawPluginVer),
			)
			return nil
		}
		return vErr
	}
	if parsedPluginVer.compare(minVer) >= 0 {
		return nil
	}
	vErr := fmt.Errorf(
		"%w: plugin %q version %s is below minimum %d.%d.%d",
		proteus.ErrBelowMinVersion,
		pluginName,
		rawPluginVer,
		minVer.major,
		minVer.minor,
		minVer.patch,
	)
	if m.minVersionPolicy == proteus.VersionWarn {
		m.logger.Warn("plugin version is below configured minimum floor (allowed by policy)",
			slog.String("plugin", pluginName),
			slog.String("version", rawPluginVer),
		)
		return nil
	}
	return vErr
}
