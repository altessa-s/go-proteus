// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package proteus

import "time"

// AdmissionOutcome classifies the result of evaluating a plugin candidate.
type AdmissionOutcome string

const (
	// OutcomeAdmitted indicates that the candidate passed admission and opened cleanly.
	OutcomeAdmitted AdmissionOutcome = "admitted"

	// OutcomeSkipped indicates that the candidate was skipped (already loaded, unloaded, disabled, or quarantined).
	OutcomeSkipped AdmissionOutcome = "skipped"

	// OutcomeQuarantined indicates that the candidate failed verification, opening, or initialization and was quarantined.
	OutcomeQuarantined AdmissionOutcome = "quarantined"

	// OutcomeRejected indicates that the candidate was rejected before quarantine (for example, missing signature or name collision).
	OutcomeRejected AdmissionOutcome = "rejected"
)

// AdmissionEvent describes the admission result for a single plugin candidate.
type AdmissionEvent struct {
	// Source is the candidate identifier (for example, "greeter.so").
	Source string

	// Name is the plugin name from its Manifest or Descriptor, if resolved.
	Name string

	// Version is the plugin semantic version, if resolved.
	Version string

	// SHA256 is the 64-character lowercase hex SHA-256 digest of the candidate, if resolved.
	SHA256 string

	// KeyID is the signing key identifier that verified the manifest, or empty when unsigned.
	KeyID string

	// Unsigned is true when the candidate was evaluated without a detached signature.
	Unsigned bool

	// Outcome is the classification of the admission decision.
	Outcome AdmissionOutcome

	// Err is the associated failure or skip reason, or nil when Outcome is [OutcomeAdmitted].
	Err error
}

// InitEvent describes the execution of a plugin's Init hook.
type InitEvent struct {
	// Name is the unique plugin name.
	Name string

	// Version is the plugin semantic version.
	Version string

	// Duration is the wall-clock time spent waiting for Init.
	Duration time.Duration

	// Err is the initialization error (or timeout/panic error), or nil on success.
	Err error
}

// Stats holds point-in-time counts of plugins tracked by the manager.
type Stats struct {
	// Ready is the number of active plugins in [StateReady].
	Ready int

	// Failed is the number of failed plugins in [StateFailed].
	Failed int

	// Quarantined is the number of binary hashes in the quarantine set.
	Quarantined int
}

// Observer receives structured lifecycle telemetry events from [host.Manager].
// Implementations must be safe for concurrent calls and should not block.
type Observer interface {
	// Admitted is called once for every candidate evaluated during Load or Reload.
	Admitted(event AdmissionEvent)

	// Initialized is called after a plugin's Init hook completes (or immediately if Init is absent).
	Initialized(event InitEvent)

	// Quarantined is called whenever a binary hash is added to or updated in the quarantine set.
	Quarantined(entry QuarantineEntry)

	// RegistryChanged is called at the end of Load, Reload, Unload, Close, ClearQuarantine, or health failure transitions.
	RegistryChanged(stats Stats)
}

// NoopObserver is an [Observer] implementation that discards all events.
type NoopObserver struct{}

// Admitted implements [Observer].
func (NoopObserver) Admitted(AdmissionEvent) {}

// Initialized implements [Observer].
func (NoopObserver) Initialized(InitEvent) {}

// Quarantined implements [Observer].
func (NoopObserver) Quarantined(QuarantineEntry) {}

// RegistryChanged implements [Observer].
func (NoopObserver) RegistryChanged(Stats) {}
