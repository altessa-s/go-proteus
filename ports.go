// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package proteus

import (
	"context"
	"io"
)

// Source discovers plugin candidates available for admission.
type Source interface {
	// Candidates returns the current set of plugin candidates in deterministic order.
	Candidates(ctx context.Context) ([]Candidate, error)
}

// Candidate represents a single unverified plugin artifact and its optional detached signature bytes.
type Candidate struct {
	// ID is a stable source identifier for logging and reporting (typically the base filename).
	ID string

	// Open opens a fresh stream to the candidate's .so bytes.
	// The host calls Open only after pre-open manifest and policy checks pass.
	Open func() (Artifact, error)

	// Signature holds the raw detached DSSE .so.sig bytes, or nil if no signature file is present.
	Signature []byte
}

// Artifact wraps a readable stream of a plugin binary along with its reported byte size.
type Artifact struct {
	// Reader streams the raw .so bytes. The caller is responsible for closing Reader.
	Reader io.ReadCloser

	// Size is the byte length of the artifact reported by the underlying storage.
	Size int64
}

// Symbols abstracts symbol resolution on an opened plugin handle.
type Symbols interface {
	// Lookup resolves a package-level symbol by name.
	Lookup(name string) (any, error)
}

// Opened holds the resolved symbol table and content digest returned by [Opener.Open].
type Opened struct {
	// Symbols provides access to exported symbols in the loaded shared object.
	Symbols Symbols

	// SHA256 is the verified 64-character lowercase hex SHA-256 digest of the opened snapshot.
	SHA256 string

	// Size is the verified byte size of the opened snapshot.
	Size int64
}

// Opener materializes a [Candidate] into an in-process [Opened] symbol table.
type Opener interface {
	// Open streams the candidate binary, verifies its digest against verifiedSHA256 when non-empty,
	// and opens the shared object.
	Open(ctx context.Context, c Candidate, verifiedSHA256 string) (Opened, error)
}

// VerifiedManifest pairs a cryptographically verified [Manifest] with the signing key identifier.
type VerifiedManifest struct {
	// Manifest is the decoded and validated plugin manifest.
	Manifest Manifest

	// KeyID is the lowercase hex SHA-256 key identifier that verified the envelope signature.
	KeyID string
}

// Verifier verifies a detached DSSE signature envelope and extracts its [VerifiedManifest].
type Verifier interface {
	// Verify checks the cryptographic signature(s) and manifest validity of envelope.
	Verify(ctx context.Context, envelope []byte) (VerifiedManifest, error)
}
