// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package dirsource

//go:generate optgen generate --type=options

// Default discovery limits and file suffixes for [Source].
const (
	// DefaultMaxSignatureBytes is the default maximum size (64 KiB) of a detached .so.sig file.
	DefaultMaxSignatureBytes int64 = 64 << 10

	// DefaultMaxArtifactBytes is the default maximum size (256 MiB) of a plugin .so binary.
	DefaultMaxArtifactBytes int64 = 256 << 20

	// DefaultExtension is the default filename suffix for plugin shared objects.
	DefaultExtension = ".so"

	// DefaultSignatureSuffix is the default suffix appended to a plugin filename for its signature.
	DefaultSignatureSuffix = ".sig"
)

type options struct {
	skipPermissionChecks bool
	followSymlinks       bool
	maxSignatureBytes    int64  `optgen:"default=DefaultMaxSignatureBytes"`
	maxArtifactBytes     int64  `optgen:"default=DefaultMaxArtifactBytes"`
	extension            string `optgen:"default=DefaultExtension"`
	signatureSuffix      string `optgen:"default=DefaultSignatureSuffix"`
}
