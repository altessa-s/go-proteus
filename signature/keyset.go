// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package signature

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Sentinel errors returned by key set construction and signature verification.
var (
	// ErrEmptyKeySet indicates that [NewKeySet] was called with zero keys or that a nil KeySet was supplied.
	ErrEmptyKeySet = errors.New("signature: key set is empty")

	// ErrDuplicateKeyID indicates that two keys in [NewKeySet] share the same SHA-256 PKIX key identifier.
	ErrDuplicateKeyID = errors.New("signature: duplicate key id")

	// ErrUnknownKeyID indicates that none of the key IDs in a DSSE envelope exist in the configured [KeySet].
	ErrUnknownKeyID = errors.New("signature: no matching key id in key set")

	// ErrKeyPolicy indicates that a key uses a disallowed algorithm, curve, or malformed key material.
	ErrKeyPolicy = errors.New("signature: key violates cryptographic policy")

	// ErrKeyExpired indicates that the matching signing key is outside its [Key.NotBefore]/[Key.NotAfter] validity window.
	ErrKeyExpired = errors.New("signature: signing key is outside its validity window")
)

// Algorithm identifies a permitted public-key signature algorithm.
type Algorithm string

const (
	// AlgEd25519 is pure Ed25519 (RFC 8032), the default signing algorithm.
	AlgEd25519 Algorithm = "ed25519"

	// AlgECDSAP256 is ECDSA over NIST P-256 (secp256r1) with SHA-256 and ASN.1 DER signatures.
	AlgECDSAP256 Algorithm = "ecdsa-p256"
)

// Key wraps a policy-validated public key along with its computed key identifier and optional validity window.
type Key struct {
	id        string
	alg       Algorithm
	pub       crypto.PublicKey
	notBefore time.Time
	notAfter  time.Time
}

// NewKey validates pub against the go-proteus cryptographic policy (Ed25519 or ECDSA P-256 only)
// and computes its key identifier: the first 16 bytes of SHA-256(SPKI DER), lowercase hex.
func NewKey(pub crypto.PublicKey) (Key, error) {
	alg, normalizedPub, err := validatePublicKey(pub)
	if err != nil {
		return Key{}, err
	}

	der, err := x509.MarshalPKIXPublicKey(normalizedPub)
	if err != nil {
		return Key{}, fmt.Errorf("%w: marshal PKIX public key: %w", ErrKeyPolicy, err)
	}

	sum := sha256.Sum256(der)

	return Key{
		id:  hex.EncodeToString(sum[:16]),
		alg: alg,
		pub: normalizedPub,
	}, nil
}

func validatePublicKey(pub crypto.PublicKey) (Algorithm, crypto.PublicKey, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return "", nil, fmt.Errorf("%w: ed25519 public key must be %d bytes, got %d", ErrKeyPolicy, ed25519.PublicKeySize, len(k))
		}

		cloned := slices.Clone(k)

		return AlgEd25519, cloned, nil
	case *ecdsa.PublicKey:
		if k == nil {
			return "", nil, fmt.Errorf("%w: nil ecdsa public key", ErrKeyPolicy)
		}

		if k.Curve != elliptic.P256() {
			return "", nil, fmt.Errorf("%w: unsupported ecdsa curve (only P-256 is allowed)", ErrKeyPolicy)
		}

		encoded, err := k.Bytes()
		if err != nil {
			return "", nil, fmt.Errorf("%w: invalid P-256 public key point: %w", ErrKeyPolicy, err)
		}

		cloned, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
		if err != nil {
			return "", nil, fmt.Errorf("%w: copy P-256 public key: %w", ErrKeyPolicy, err)
		}

		return AlgECDSAP256, cloned, nil
	default:
		return "", nil, fmt.Errorf("%w: unsupported public key type %T (only Ed25519 and ECDSA P-256 are allowed)", ErrKeyPolicy, pub)
	}
}

// ParsePublicKeyPEM parses a single PEM-encoded PKIX PUBLIC KEY block and validates it via [NewKey].
// Trailing PEM blocks or non-PUBLIC KEY blocks are rejected.
func ParsePublicKeyPEM(pemBytes []byte) (Key, error) {
	keys, err := ParsePublicKeysPEM(pemBytes)
	if err != nil {
		return Key{}, err
	}

	if len(keys) != 1 {
		return Key{}, fmt.Errorf("%w: expected exactly 1 PEM public key block, got %d", ErrKeyPolicy, len(keys))
	}

	return keys[0], nil
}

// ParsePublicKeysPEM parses one or more PEM-encoded PKIX PUBLIC KEY blocks.
// Only ASCII space, tab, CR and LF are permitted before, between, or after blocks.
func ParsePublicKeysPEM(pemBytes []byte) ([]Key, error) {
	rest := pemBytes

	var keys []Key

	for {
		// Only ASCII space, tab, CR and LF may separate trust anchors.
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}

		const (
			begin = "-----BEGIN PUBLIC KEY-----"
			end   = "-----END PUBLIC KEY-----"
		)

		if !bytes.HasPrefix(rest, []byte(begin)) {
			return nil, fmt.Errorf("%w: expected PUBLIC KEY block", ErrKeyPolicy)
		}

		endIndex := bytes.Index(rest, []byte(end))
		if endIndex < 0 {
			return nil, fmt.Errorf("%w: incomplete PUBLIC KEY block", ErrKeyPolicy)
		}

		endIndex += len(end)
		encoded := rest[:endIndex]
		// Decode only the first block: pem.Decode otherwise skips malformed blocks.
		if bytes.Contains(encoded[len(begin):], []byte("-----BEGIN")) {
			return nil, fmt.Errorf("%w: nested PEM block", ErrKeyPolicy)
		}

		block, remainder := pem.Decode(encoded)
		if block == nil || len(remainder) != 0 {
			return nil, fmt.Errorf("%w: malformed PUBLIC KEY block", ErrKeyPolicy)
		}

		rest = rest[endIndex:]

		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parse PKIX public key: %w", ErrKeyPolicy, err)
		}

		key, err := NewKey(pub)
		if err != nil {
			return nil, err
		}

		keys = append(keys, key)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no PEM public key blocks found", ErrKeyPolicy)
	}

	return keys, nil
}

// WithValidity returns a copy of k restricted to the inclusive time window [notBefore, notAfter].
// Either bound may be zero to leave that side unbounded. When both bounds are non-zero, notAfter
// must be after notBefore.
func (k Key) WithValidity(notBefore, notAfter time.Time) (Key, error) {
	if !notBefore.IsZero() && !notAfter.IsZero() && !notAfter.After(notBefore) {
		return Key{}, fmt.Errorf("%w: key notAfter must be after notBefore", ErrKeyPolicy)
	}

	k.notBefore = notBefore.UTC()
	k.notAfter = notAfter.UTC()

	return k, nil
}

// ID returns the 32-character lowercase hex SHA-256 PKIX key identifier.
func (k Key) ID() string { return k.id }

// Algorithm returns the key's [Algorithm].
func (k Key) Algorithm() Algorithm { return k.alg }

// PublicKey returns a defensive copy of the [crypto.PublicKey].
func (k Key) PublicKey() crypto.PublicKey {
	_, pub, _ := validatePublicKey(k.pub)
	return pub
}

// NotBefore returns the optional start of the key's validity window (zero if unbounded).
func (k Key) NotBefore() time.Time { return k.notBefore }

// NotAfter returns the optional end of the key's validity window (zero if unbounded).
func (k Key) NotAfter() time.Time { return k.notAfter }

// ValidAt reports whether t falls within the key's [NotBefore, NotAfter] validity window.
func (k Key) ValidAt(t time.Time) bool {
	if !k.notBefore.IsZero() && t.Before(k.notBefore) {
		return false
	}

	if !k.notAfter.IsZero() && t.After(k.notAfter) {
		return false
	}

	return true
}

// KeySet is an immutable, policy-validated collection of public signing keys indexed by key ID.
type KeySet struct {
	byID map[string]Key
	keys []Key
}

// NewKeySet constructs a [KeySet] from one or more [Key] values.
// It fails if keys is empty, if any key was not constructed via [NewKey] (or violates policy),
// or if two keys have the same key ID.
func NewKeySet(keys ...Key) (*KeySet, error) {
	if len(keys) == 0 {
		return nil, ErrEmptyKeySet
	}

	byID := make(map[string]Key, len(keys))

	ordered := make([]Key, 0, len(keys))
	for _, k := range keys {
		validated, err := NewKey(k.pub)
		if err != nil {
			return nil, err
		}

		if k.id != validated.id || k.alg != validated.alg {
			return nil, fmt.Errorf("%w: key metadata does not match public key", ErrKeyPolicy)
		}

		validated, err = validated.WithValidity(k.notBefore, k.notAfter)
		if err != nil {
			return nil, err
		}

		if _, exists := byID[validated.id]; exists {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateKeyID, validated.id)
		}

		byID[validated.id] = validated
		ordered = append(ordered, validated)
	}

	return &KeySet{
		byID: byID,
		keys: ordered,
	}, nil
}

// Lookup retrieves a [Key] by its 32-character lowercase hex key identifier.
func (ks *KeySet) Lookup(keyID string) (Key, bool) {
	if ks == nil {
		return Key{}, false
	}

	k, ok := ks.byID[keyID]

	return k, ok
}

// Keys returns a copy of all keys in the set in insertion order.
func (ks *KeySet) Keys() []Key {
	if ks == nil {
		return nil
	}

	return slices.Clone(ks.keys)
}

// Len returns the number of keys in the set.
func (ks *KeySet) Len() int {
	if ks == nil {
		return 0
	}

	return len(ks.keys)
}
