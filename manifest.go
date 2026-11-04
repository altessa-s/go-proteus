// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package proteus

import (
	"fmt"
	"time"
)

// Manifest constants for DSSE signing and verification.
const (
	// ManifestVersion is the schema version required in [Manifest.Version].
	ManifestVersion = 1

	// ManifestPayloadType is the DSSE payloadType identifier for signed plugin manifests.
	ManifestPayloadType = "application/vnd.altessa.proteus.manifest+json"

	sha256HexLen = 64
)

// Manifest is the signed metadata document embedded inside a detached DSSE .so.sig envelope.
//
// It binds the plugin's identity (Name, PluginVer), target platform (GOOS, GOARCH), and content
// digest (SHA256, Size) so the host can evaluate admission policies before calling dlopen.
type Manifest struct {
	// Version is the manifest schema version; must equal [ManifestVersion] (1).
	Version int `json:"v"`

	// Name is the unique plugin identifier expected to match [sdk.Descriptor.Name].
	Name string `json:"name"`

	// PluginVer is the semantic version expected to match [sdk.Descriptor.Version].
	PluginVer string `json:"version"`

	// SHA256 is the 64-character lowercase hexadecimal SHA-256 digest of the .so binary.
	SHA256 string `json:"sha256"`

	// Size is the exact byte length of the .so binary.
	Size int64 `json:"size"`

	// GOOS is the target operating system (for example, "linux" or "darwin").
	GOOS string `json:"goos"`

	// GOARCH is the target CPU architecture (for example, "amd64" or "arm64").
	GOARCH string `json:"goarch"`

	// HostMajor is the optional required host major version (0 means unconstrained).
	HostMajor int `json:"hostMajor,omitzero"`

	// IssuedAt is the UTC timestamp when the manifest was signed.
	IssuedAt time.Time `json:"issuedAt"`

	// NotAfter is the optional UTC expiration timestamp after which the manifest is rejected.
	NotAfter time.Time `json:"notAfter,omitzero"`
}

// Validate checks that all required fields in m are well-formed and consistent.
func (m Manifest) Validate() error {
	if m.Version != ManifestVersion {
		return fmt.Errorf("%w: unsupported schema version %d", ErrManifestInvalid, m.Version)
	}

	if m.Name == "" {
		return fmt.Errorf("%w: name is required", ErrManifestInvalid)
	}

	if m.PluginVer == "" {
		return fmt.Errorf("%w: version is required", ErrManifestInvalid)
	}

	if !IsValidSHA256Hex(m.SHA256) {
		return fmt.Errorf("%w: sha256 must be 64 lowercase hex characters", ErrManifestInvalid)
	}

	if m.Size <= 0 {
		return fmt.Errorf("%w: size must be positive", ErrManifestInvalid)
	}

	if m.GOOS == "" || m.GOARCH == "" {
		return fmt.Errorf("%w: goos and goarch are required", ErrManifestInvalid)
	}

	if m.HostMajor < 0 {
		return fmt.Errorf("%w: hostMajor must be non-negative", ErrManifestInvalid)
	}

	if m.IssuedAt.IsZero() {
		return fmt.Errorf("%w: issuedAt is required", ErrManifestInvalid)
	}

	if !m.NotAfter.IsZero() && !m.NotAfter.After(m.IssuedAt) {
		return fmt.Errorf("%w: notAfter must be after issuedAt", ErrManifestInvalid)
	}

	return nil
}

// IsExpired reports whether m has a non-zero NotAfter timestamp that precedes now.
func (m Manifest) IsExpired(now time.Time) bool {
	return !m.NotAfter.IsZero() && now.After(m.NotAfter)
}

// IsValidSHA256Hex reports whether s is a 64-character lowercase hexadecimal SHA-256 digest.
func IsValidSHA256Hex(s string) bool {
	if len(s) != sha256HexLen {
		return false
	}

	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}

	return true
}
