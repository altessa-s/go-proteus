// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package signature

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/altessa-s/go-proteus"
)

// Verifier implements [proteus.Verifier] over a policy-validated [KeySet].
type Verifier struct {
	keys             *KeySet
	now              func() time.Time
	maxEnvelopeBytes int64
}

// NewVerifier constructs a [Verifier] backed by keys and configured with opts.
func NewVerifier(keys *KeySet, opts ...Option) (*Verifier, error) {
	if keys == nil || keys.Len() == 0 {
		return nil, ErrEmptyKeySet
	}
	cfg := newOptions(opts...)
	maxBytes := cfg.maxEnvelopeBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxEnvelopeBytes
	}
	nowFn := cfg.now
	if nowFn == nil {
		nowFn = time.Now
	}
	return &Verifier{
		keys:             keys,
		now:              nowFn,
		maxEnvelopeBytes: maxBytes,
	}, nil
}

// Verify checks a detached DSSE envelope against the verifier's [KeySet], validates key and
// manifest expiration timestamps, and returns the decoded [proteus.VerifiedManifest].
func (v *Verifier) Verify(ctx context.Context, raw []byte) (proteus.VerifiedManifest, error) {
	if err := ctx.Err(); err != nil {
		return proteus.VerifiedManifest{}, err
	}
	if v == nil || v.keys == nil || v.keys.Len() == 0 {
		return proteus.VerifiedManifest{}, ErrEmptyKeySet
	}
	if int64(len(raw)) > v.maxEnvelopeBytes {
		return proteus.VerifiedManifest{}, fmt.Errorf(
			"%w: envelope size %d exceeds maximum %d",
			proteus.ErrSignatureInvalid,
			len(raw),
			v.maxEnvelopeBytes,
		)
	}

	env, err := UnmarshalEnvelope(raw)
	if err != nil {
		return proteus.VerifiedManifest{}, err
	}

	payloadBytes, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if err != nil {
		return proteus.VerifiedManifest{}, fmt.Errorf("%w: decode base64 payload: %w", proteus.ErrSignatureInvalid, err)
	}

	pae := PAE(env.PayloadType, payloadBytes)
	now := v.now().UTC()

	var (
		matchedKeyID string
		sawKnownKey  bool
		sawExpired   bool
	)

	for _, entry := range env.Signatures {
		key, ok := v.keys.Lookup(entry.KeyID)
		if !ok {
			continue
		}
		sawKnownKey = true

		sigBytes, decErr := base64.StdEncoding.Strict().DecodeString(entry.Sig)
		if decErr != nil {
			continue
		}
		if !verifySignatureBytes(key, pae, sigBytes) {
			continue
		}
		if !key.ValidAt(now) {
			sawExpired = true
			continue
		}
		matchedKeyID = key.ID()
		break
	}

	if matchedKeyID == "" {
		if sawExpired {
			return proteus.VerifiedManifest{}, fmt.Errorf("%w: %w", proteus.ErrSignatureInvalid, ErrKeyExpired)
		}
		if !sawKnownKey {
			return proteus.VerifiedManifest{}, fmt.Errorf("%w: %w", proteus.ErrSignatureInvalid, ErrUnknownKeyID)
		}
		return proteus.VerifiedManifest{}, fmt.Errorf("%w: cryptographic signature verification failed", proteus.ErrSignatureInvalid)
	}

	manifest, err := UnmarshalManifest(payloadBytes)
	if err != nil {
		return proteus.VerifiedManifest{}, err
	}
	if manifest.IsExpired(now) {
		return proteus.VerifiedManifest{}, fmt.Errorf(
			"%w: manifest expired at %s",
			proteus.ErrManifestInvalid,
			manifest.NotAfter.Format(time.RFC3339),
		)
	}

	return proteus.VerifiedManifest{
		Manifest: manifest,
		KeyID:    matchedKeyID,
	}, nil
}

func verifySignatureBytes(key Key, pae, sig []byte) bool {
	switch key.Algorithm() {
	case AlgEd25519:
		pub, ok := key.PublicKey().(ed25519.PublicKey)
		if !ok || len(sig) != ed25519.SignatureSize {
			return false
		}
		return ed25519.Verify(pub, pae, sig)
	case AlgECDSAP256:
		pub, ok := key.PublicKey().(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		digest := sha256.Sum256(pae)
		return ecdsa.VerifyASN1(pub, digest[:], sig)
	default:
		return false
	}
}
