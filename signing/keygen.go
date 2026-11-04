// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/altessa-s/go-tlsutils"

	"github.com/altessa-s/go-proteus/signature"
)

// KeyPair holds a generated private signing key, its validated public [signature.Key], and their
// PEM encodings.
type KeyPair struct {
	// PrivateKey is the generated [crypto.Signer] (ed25519.PrivateKey or *ecdsa.PrivateKey).
	PrivateKey crypto.Signer

	// PrivateKeyPEM is the PKCS#8 PRIVATE KEY PEM encoding.
	PrivateKeyPEM []byte

	// PublicKey is the policy-validated public [signature.Key] including its computed key ID.
	PublicKey signature.Key

	// PublicKeyPEM is the PKIX PUBLIC KEY PEM encoding.
	PublicKeyPEM []byte
}

// GenerateKey generates a new signing key pair for alg ([signature.AlgEd25519] or [signature.AlgECDSAP256]).
// An empty alg defaults to [signature.AlgEd25519].
func GenerateKey(alg signature.Algorithm) (KeyPair, error) {
	if alg == "" {
		alg = signature.AlgEd25519
	}

	var signer crypto.Signer

	switch alg {
	case signature.AlgEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return KeyPair{}, fmt.Errorf("signing: generate ed25519 key: %w", err)
		}

		signer = priv
	case signature.AlgECDSAP256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return KeyPair{}, fmt.Errorf("signing: generate ecdsa-p256 key: %w", err)
		}

		signer = priv
	default:
		return KeyPair{}, fmt.Errorf("%w: unsupported key generation algorithm %q", signature.ErrKeyPolicy, alg)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return KeyPair{}, fmt.Errorf("signing: marshal PKCS#8 private key: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	pubDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return KeyPair{}, fmt.Errorf("signing: marshal PKIX public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	pubKey, err := signature.NewKey(signer.Public())
	if err != nil {
		return KeyPair{}, err
	}

	return KeyPair{
		PrivateKey:    signer,
		PrivateKeyPEM: privPEM,
		PublicKey:     pubKey,
		PublicKeyPEM:  pubPEM,
	}, nil
}

// ParsePrivateKeyPEM parses an encrypted or unencrypted PEM private key using [tlsutils.ParsePrivateKeyPEM]
// and validates its public key against the go-proteus cryptographic policy (Ed25519 or ECDSA P-256 only).
func ParsePrivateKeyPEM(pemData []byte, password string) (crypto.Signer, signature.Key, error) {
	signer, err := tlsutils.ParsePrivateKeyPEM(pemData, password)
	if err != nil {
		return nil, signature.Key{}, fmt.Errorf("signing: parse private key PEM: %w", err)
	}

	pubKey, err := signature.NewKey(signer.Public())
	if err != nil {
		return nil, signature.Key{}, err
	}

	return signer, pubKey, nil
}
