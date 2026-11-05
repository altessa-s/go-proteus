// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package proteus

import (
	"errors"
	"time"
)

// CandidateReport describes the outcome for a single candidate inspected during Load or Reload.
type CandidateReport struct {
	// Source is the candidate identifier (for example, "greeter.so").
	Source string

	// Name is the resolved plugin name from its Manifest or Descriptor, if known.
	Name string

	// SHA256 is the 64-character lowercase hex SHA-256 digest of the candidate, if known.
	SHA256 string

	// Unsigned is true when the candidate was processed without a detached signature.
	Unsigned bool

	// Err is the reason the candidate was skipped or failed.
	Err error
}

// QuarantineEntry records a quarantined plugin binary hash and the failure that triggered quarantine.
type QuarantineEntry struct {
	// Source is the candidate identifier that produced the failure.
	Source string

	// SHA256 is the 64-character lowercase hex SHA-256 digest of the quarantined binary.
	SHA256 string

	// Reason is the error that caused the candidate to be quarantined.
	Reason error

	// Since is the timestamp when the binary hash entered quarantine.
	Since time.Time
}

// LoadReport summarizes the results of a [host.Manager.Load] or [host.Manager.Reload] pass.
type LoadReport struct {
	// Loaded lists the plugins newly admitted and initialized to [StateReady] during this pass.
	Loaded []*Plugin

	// Skipped lists candidates that were intentionally bypassed (already loaded, unloaded in this
	// process, disabled by allow/deny policy, or already quarantined).
	Skipped []CandidateReport

	// Failed lists candidates that failed admission, opening, or initialization during this pass.
	Failed []CandidateReport

	// Quarantine is a snapshot of all currently quarantined binary hashes after the pass completes.
	Quarantine []QuarantineEntry
}

// Err returns a joined error across all [LoadReport.Failed] entries, or nil when Failed is empty.
func (r LoadReport) Err() error {
	if len(r.Failed) == 0 {
		return nil
	}

	errs := make([]error, 0, len(r.Failed))
	for _, f := range r.Failed {
		if f.Err != nil {
			errs = append(errs, f.Err)
		}
	}

	return errors.Join(errs...)
}
