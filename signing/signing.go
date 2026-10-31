// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package signing

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/altessa-s/go-atlas-core/encoding/hash"
	"github.com/altessa-s/go-atlas-core/io/files"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/signature"
)

// HashFile streams the regular file at path and returns its 64-character lowercase hex SHA-256
// digest and byte size.
func HashFile(path string) (string, int64, error) {
	f, err := files.OpenRegular(path)
	if err != nil {
		return "", 0, fmt.Errorf("signing: open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	hasher := hash.NewSHA256Hasher()
	n, err := io.Copy(hasher, f)
	if err != nil {
		return "", 0, fmt.Errorf("signing: hash %q: %w", path, err)
	}
	return hasher.SumHex(), n, nil
}

// BuildManifest hashes artifactPath and constructs a validated [proteus.Manifest] for name and version.
func BuildManifest(artifactPath, name, version string, opts ...Option) (proteus.Manifest, error) {
	sha256Hex, size, err := HashFile(artifactPath)
	if err != nil {
		return proteus.Manifest{}, err
	}

	cfg := newOptions(opts...)
	goos := cfg.goos
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch := cfg.goarch
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	nowFn := cfg.now
	if nowFn == nil {
		nowFn = time.Now
	}
	issuedAt := cfg.issuedAt.UTC()
	if issuedAt.IsZero() {
		issuedAt = nowFn().UTC()
	}
	notAfter := cfg.notAfter.UTC()
	if notAfter.IsZero() && cfg.ttl > 0 {
		notAfter = issuedAt.Add(cfg.ttl)
	}

	m := proteus.Manifest{
		Version:   proteus.ManifestVersion,
		Name:      name,
		PluginVer: version,
		SHA256:    sha256Hex,
		Size:      size,
		GOOS:      goos,
		GOARCH:    goarch,
		HostMajor: cfg.hostMajor,
		IssuedAt:  issuedAt,
		NotAfter:  notAfter,
	}
	if err := m.Validate(); err != nil {
		return proteus.Manifest{}, err
	}
	return m, nil
}

// SignManifest serializes m, signs its DSSE v1 PAE using signer (Ed25519 or ECDSA P-256), and
// returns the serialized DSSE JSON envelope.
func SignManifest(m proteus.Manifest, signer crypto.Signer) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("signing: signer is required")
	}
	key, err := signature.NewKey(signer.Public())
	if err != nil {
		return nil, err
	}
	payload, err := signature.MarshalManifest(m)
	if err != nil {
		return nil, err
	}

	pae := signature.PAE(proteus.ManifestPayloadType, payload)
	var sigBytes []byte
	switch key.Algorithm() {
	case signature.AlgEd25519:
		sigBytes, err = signer.Sign(rand.Reader, pae, crypto.Hash(0))
	case signature.AlgECDSAP256:
		digest := sha256.Sum256(pae)
		sigBytes, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	default:
		return nil, fmt.Errorf("%w: unsupported algorithm %q", signature.ErrKeyPolicy, key.Algorithm())
	}
	if err != nil {
		return nil, fmt.Errorf("signing: sign DSSE PAE: %w", err)
	}

	env := signature.Envelope{
		PayloadType: proteus.ManifestPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []signature.Entry{
			{
				KeyID: key.ID(),
				Sig:   base64.StdEncoding.EncodeToString(sigBytes),
			},
		},
	}
	return signature.MarshalEnvelope(env)
}

// SignFile builds a [proteus.Manifest] for artifactPath and signs it with signer.
func SignFile(artifactPath, name, version string, signer crypto.Signer, opts ...Option) ([]byte, proteus.Manifest, error) {
	m, err := BuildManifest(artifactPath, name, version, opts...)
	if err != nil {
		return nil, proteus.Manifest{}, err
	}
	envBytes, err := SignManifest(m, signer)
	if err != nil {
		return nil, proteus.Manifest{}, err
	}
	return envBytes, m, nil
}

// WriteFileAtomic writes data to a temporary file in the same directory as path, syncs it, sets
// perm, and atomically renames it over path (Defect 22).
func WriteFileAtomic(path string, data []byte, perm fs.FileMode) error {
	const (
		defaultFilePerm = 0o600
		defaultDirPerm  = 0o700
	)
	if perm == 0 {
		perm = defaultFilePerm
	}
	cleaned := filepath.Clean(path)
	dir := filepath.Dir(cleaned)
	if err := os.MkdirAll(dir, defaultDirPerm); err != nil {
		return fmt.Errorf("signing: create parent directory %q: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".proteus-atomic-*")
	if err != nil {
		return fmt.Errorf("signing: create temp file in %q: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("signing: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("signing: write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("signing: sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("signing: close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, cleaned); err != nil {
		return fmt.Errorf("signing: rename temp file to %q: %w", cleaned, err)
	}
	cleanup = false
	return nil
}
