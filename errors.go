// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package proteus

import "errors"

// Sentinel errors returned across go-proteus packages.
var (
	// ErrNotFound indicates that the requested plugin is not registered in the active manager.
	ErrNotFound = errors.New("proteus: plugin not found")

	// ErrAlreadyLoaded indicates that a plugin with the same name is already loaded.
	ErrAlreadyLoaded = errors.New("proteus: plugin already loaded")

	// ErrClosed indicates that an operation was attempted on a closed manager or watcher.
	ErrClosed = errors.New("proteus: manager is closed")

	// ErrQuarantined indicates that a candidate's content SHA-256 is in the quarantine set.
	ErrQuarantined = errors.New("proteus: plugin quarantined")

	// ErrRevoked indicates that a candidate's content SHA-256 is on the configured revocation list.
	ErrRevoked = errors.New("proteus: plugin hash revoked")

	// ErrDisabled indicates that a candidate's name is rejected by the configured allow or deny list.
	ErrDisabled = errors.New("proteus: plugin disabled by policy")

	// ErrSignatureMissing indicates that a detached signature is required by policy but missing.
	ErrSignatureMissing = errors.New("proteus: plugin signature missing")

	// ErrSignatureInvalid indicates that a detached DSSE envelope or cryptographic signature is invalid.
	ErrSignatureInvalid = errors.New("proteus: plugin signature invalid")

	// ErrManifestInvalid indicates that a signed manifest payload is malformed, expired, or fails validation.
	ErrManifestInvalid = errors.New("proteus: plugin manifest invalid")

	// ErrManifestMismatch indicates that the opened binary's content, size, or Descriptor disagrees with its signed Manifest.
	ErrManifestMismatch = errors.New("proteus: plugin binary does not match signed manifest")

	// ErrPlatformMismatch indicates that the manifest's GOOS or GOARCH does not match the running host platform.
	ErrPlatformMismatch = errors.New("proteus: plugin platform mismatch")

	// ErrHostVersionMismatch indicates that the plugin's required host major version does not match the host.
	ErrHostVersionMismatch = errors.New("proteus: plugin host major version mismatch")

	// ErrBelowMinVersion indicates that the plugin's version is below the host's configured minimum version floor.
	ErrBelowMinVersion = errors.New("proteus: plugin version below minimum required")

	// ErrSnapshotModified indicates that the private snapshot file on disk changed between streaming write and re-hash.
	ErrSnapshotModified = errors.New("proteus: plugin snapshot modified before open")

	// ErrInsecurePermissions indicates that a plugin directory, artifact, or signature has world- or group-writable permissions.
	ErrInsecurePermissions = errors.New("proteus: insecure file or directory permissions")

	// ErrNoDescriptor indicates that a loaded .so binary does not export the required Descriptor symbol.
	ErrNoDescriptor = errors.New("proteus: plugin missing Descriptor symbol")

	// ErrInvalidDescriptor indicates that the exported Descriptor symbol has an invalid type or empty Name/Version.
	ErrInvalidDescriptor = errors.New("proteus: plugin Descriptor is invalid")

	// ErrInvalidSymbol indicates that an optional lifecycle symbol (Init, Close, HealthCheck, DepInfo) has an unexpected type.
	ErrInvalidSymbol = errors.New("proteus: plugin symbol has invalid signature")

	// ErrInitFailed indicates that a plugin's Init hook returned an error or exceeded its timeout.
	ErrInitFailed = errors.New("proteus: plugin initialization failed")

	// ErrPanicked indicates that plugin code panicked during open, initialization, shutdown, health check, or SPI execution.
	ErrPanicked = errors.New("proteus: plugin panicked")

	// ErrSPIVersionMismatch indicates that a plugin's exported SPIVersion does not satisfy the host's version constraint.
	ErrSPIVersionMismatch = errors.New("proteus: plugin SPI version mismatch")

	// ErrUnsupportedPlatform indicates that dynamic Go plugins are not supported on the current operating system or build mode.
	ErrUnsupportedPlatform = errors.New("proteus: dynamic plugins not supported on this platform")
)
