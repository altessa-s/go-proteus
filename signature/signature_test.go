// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package signature_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/signature"
)

func signEnvelope(t *testing.T, signer crypto.Signer, key signature.Key, m proteus.Manifest) []byte {
	t.Helper()

	payload, err := signature.MarshalManifest(m)
	if err != nil {
		t.Fatalf("MarshalManifest: %v", err)
	}

	pae := signature.PAE(proteus.ManifestPayloadType, payload)

	var sig []byte

	switch key.Algorithm() {
	case signature.AlgEd25519:
		sig, err = signer.Sign(rand.Reader, pae, crypto.Hash(0))
	case signature.AlgECDSAP256:
		digest := sha256.Sum256(pae)
		sig, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	default:
		t.Fatalf("unsupported algorithm %s", key.Algorithm())
	}

	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	env := signature.Envelope{
		PayloadType: proteus.ManifestPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []signature.Entry{
			{
				KeyID: key.ID(),
				Sig:   base64.StdEncoding.EncodeToString(sig),
			},
		},
	}

	raw, err := signature.MarshalEnvelope(env)
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}

	return raw
}

func sampleManifest(now time.Time) proteus.Manifest {
	return proteus.Manifest{
		Version:   proteus.ManifestVersion,
		Name:      "greeter",
		PluginVer: "1.0.0",
		SHA256:    strings.Repeat("a", 64),
		Size:      2048,
		GOOS:      "linux",
		GOARCH:    "arm64",
		HostMajor: 1,
		IssuedAt:  now,
		NotAfter:  now.Add(24 * time.Hour),
	}
}

func TestKeyPolicy_D6(t *testing.T) {
	t.Parallel()

	// Ed25519 accepted.
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	edKey, err := signature.NewKey(edPub)
	if err != nil {
		t.Fatalf("expected Ed25519 key accepted, got %v", err)
	}

	if edKey.Algorithm() != signature.AlgEd25519 || len(edKey.ID()) != 32 || edKey.PublicKey() == nil {
		t.Fatalf("unexpected Ed25519 key metadata: alg=%s id=%s", edKey.Algorithm(), edKey.ID())
	}

	// ECDSA P-256 accepted.
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ecKey, err := signature.NewKey(&ecPriv.PublicKey)
	if err != nil {
		t.Fatalf("expected ECDSA P-256 key accepted, got %v", err)
	}

	if ecKey.Algorithm() != signature.AlgECDSAP256 || len(ecKey.ID()) != 32 {
		t.Fatalf("unexpected ECDSA P-256 key metadata: alg=%s id=%s", ecKey.Algorithm(), ecKey.ID())
	}

	// RSA rejected (decisions Q1 / Defect 6).
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := signature.NewKey(&rsaPriv.PublicKey); !errors.Is(err, signature.ErrKeyPolicy) {
		t.Fatalf("expected RSA key rejected with ErrKeyPolicy, got %v", err)
	}

	// ECDSA P-384 rejected.
	p384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := signature.NewKey(&p384Priv.PublicKey); !errors.Is(err, signature.ErrKeyPolicy) {
		t.Fatalf("expected P-384 rejected with ErrKeyPolicy, got %v", err)
	}

	// Nil and invalid ECDSA points rejected.
	var nilEC *ecdsa.PublicKey
	if _, err := signature.NewKey(nilEC); !errors.Is(err, signature.ErrKeyPolicy) {
		t.Fatalf("expected nil ECDSA key rejected, got %v", err)
	}

	offCurve := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(1),
		Y:     big.NewInt(2),
	}
	if _, err := signature.NewKey(offCurve); !errors.Is(err, signature.ErrKeyPolicy) {
		t.Fatalf("expected off-curve P-256 point rejected, got %v", err)
	}

	// Short Ed25519 key rejected.
	if _, err := signature.NewKey(ed25519.PublicKey("short")); !errors.Is(err, signature.ErrKeyPolicy) {
		t.Fatalf("expected short Ed25519 key rejected, got %v", err)
	}

	// PEM parsing.
	edDER, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}

	edPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: edDER})

	parsedKey, err := signature.ParsePublicKeyPEM(edPEM)
	if err != nil || parsedKey.ID() != edKey.ID() {
		t.Fatalf("ParsePublicKeyPEM mismatch: %v", err)
	}

	ecDER, err := x509.MarshalPKIXPublicKey(&ecPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER})

	multiKeys, err := signature.ParsePublicKeysPEM(append(append([]byte{}, edPEM...), ecPEM...))
	if err != nil || len(multiKeys) != 2 {
		t.Fatalf("expected 2 parsed keys, got %d (%v)", len(multiKeys), err)
	}

	if _, err := signature.ParsePublicKeyPEM(append(append([]byte{}, edPEM...), ecPEM...)); !errors.Is(err, signature.ErrKeyPolicy) {
		t.Fatalf("expected ParsePublicKeyPEM to reject multiple PEM blocks, got %v", err)
	}

	if _, err := signature.ParsePublicKeysPEM([]byte("not pem")); !errors.Is(err, signature.ErrKeyPolicy) {
		t.Fatalf("expected non-PEM rejected, got %v", err)
	}

	badTypePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: edDER})
	if _, err := signature.ParsePublicKeyPEM(badTypePEM); !errors.Is(err, signature.ErrKeyPolicy) {
		t.Fatalf("expected non-PUBLIC KEY block rejected, got %v", err)
	}

	badBytesPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("corrupt")})
	if _, err := signature.ParsePublicKeyPEM(badBytesPEM); !errors.Is(err, signature.ErrKeyPolicy) {
		t.Fatalf("expected corrupt DER rejected, got %v", err)
	}

	rsaDER, err := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaDER})
	if _, err := signature.ParsePublicKeyPEM(rsaPEM); !errors.Is(err, signature.ErrKeyPolicy) {
		t.Fatalf("expected RSA PEM rejected, got %v", err)
	}
}

func TestKeySetAndValidity_D7(t *testing.T) {
	t.Parallel()

	if _, err := signature.NewKeySet(); !errors.Is(err, signature.ErrEmptyKeySet) {
		t.Fatalf("expected ErrEmptyKeySet, got %v", err)
	}

	if _, err := signature.NewKeySet(signature.Key{}); !errors.Is(err, signature.ErrKeyPolicy) {
		t.Fatalf("expected ErrKeyPolicy for zero Key, got %v", err)
	}

	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	k, err := signature.NewKey(edPub)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := signature.NewKeySet(k, k); !errors.Is(err, signature.ErrDuplicateKeyID) {
		t.Fatalf("expected ErrDuplicateKeyID, got %v", err)
	}

	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	t1 := t0.Add(time.Hour)
	if _, err := k.WithValidity(t1, t0); !errors.Is(err, signature.ErrKeyPolicy) {
		t.Fatalf("expected invalid validity window rejected, got %v", err)
	}

	kBounded, err := k.WithValidity(t0, t1)
	if err != nil {
		t.Fatal(err)
	}

	if !kBounded.NotBefore().Equal(t0) || !kBounded.NotAfter().Equal(t1) {
		t.Fatal("unexpected NotBefore/NotAfter")
	}

	if kBounded.ValidAt(t0.Add(-time.Second)) || kBounded.ValidAt(t1.Add(time.Second)) || !kBounded.ValidAt(t0.Add(30*time.Minute)) {
		t.Fatal("unexpected ValidAt results")
	}

	ks, err := signature.NewKeySet(kBounded)
	if err != nil {
		t.Fatal(err)
	}

	if ks.Len() != 1 || len(ks.Keys()) != 1 {
		t.Fatalf("expected 1 key in KeySet, got %d", ks.Len())
	}

	if _, ok := ks.Lookup(kBounded.ID()); !ok {
		t.Fatal("expected key lookup to succeed")
	}

	if _, ok := ks.Lookup("missing"); ok {
		t.Fatal("expected missing key lookup to return false")
	}

	var nilKS *signature.KeySet
	if nilKS.Len() != 0 || nilKS.Keys() != nil {
		t.Fatal("expected zero values from nil KeySet")
	}

	if _, ok := nilKS.Lookup("any"); ok {
		t.Fatal("expected false from nil KeySet.Lookup")
	}
}

func TestVerifierAndDSSE_D5(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	edKey, err := signature.NewKey(edPub)
	if err != nil {
		t.Fatal(err)
	}

	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ecKey, err := signature.NewKey(&ecPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	ks, err := signature.NewKeySet(edKey, ecKey)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := signature.NewVerifier(ks, signature.WithNow(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}

	m := sampleManifest(now)

	// Verify Ed25519 envelope.
	edRaw := signEnvelope(t, edPriv, edKey, m)

	res, err := verifier.Verify(context.Background(), edRaw)
	if err != nil {
		t.Fatalf("Ed25519 Verify failed: %v", err)
	}

	if res.KeyID != edKey.ID() || res.Manifest.Name != "greeter" {
		t.Fatalf("unexpected Verify result: %+v", res)
	}

	// Verify ECDSA P-256 envelope.
	ecRaw := signEnvelope(t, ecPriv, ecKey, m)

	resEC, err := verifier.Verify(context.Background(), ecRaw)
	if err != nil {
		t.Fatalf("ECDSA P-256 Verify failed: %v", err)
	}

	if resEC.KeyID != ecKey.ID() {
		t.Fatalf("unexpected ECDSA KeyID: %s", resEC.KeyID)
	}

	// Reject legacy raw .sig bytes (not DSSE JSON).
	rawLegacySig := ed25519.Sign(edPriv, []byte("raw binary bytes"))
	if _, err := verifier.Verify(context.Background(), rawLegacySig); !errors.Is(err, proteus.ErrSignatureInvalid) {
		t.Fatalf("expected legacy raw .sig rejected with ErrSignatureInvalid, got %v", err)
	}

	// Reject unknown key ID.
	otherPub, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	otherKey, err := signature.NewKey(otherPub)
	if err != nil {
		t.Fatal(err)
	}

	unknownRaw := signEnvelope(t, otherPriv, otherKey, m)

	_, err = verifier.Verify(context.Background(), unknownRaw)
	if !errors.Is(err, proteus.ErrSignatureInvalid) || !errors.Is(err, signature.ErrUnknownKeyID) {
		t.Fatalf("expected ErrSignatureInvalid + ErrUnknownKeyID, got %v", err)
	}

	// Reject expired signing key.
	expiredKey, err := edKey.WithValidity(now.Add(-2*time.Hour), now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	expiredKS, err := signature.NewKeySet(expiredKey)
	if err != nil {
		t.Fatal(err)
	}

	expiredVerifier, err := signature.NewVerifier(expiredKS, signature.WithNow(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}

	_, err = expiredVerifier.Verify(context.Background(), edRaw)
	if !errors.Is(err, proteus.ErrSignatureInvalid) || !errors.Is(err, signature.ErrKeyExpired) {
		t.Fatalf("expected ErrSignatureInvalid + ErrKeyExpired, got %v", err)
	}

	// Reject expired manifest (NotAfter < now).
	futureVerifier, err := signature.NewVerifier(ks, signature.WithNow(func() time.Time { return now.Add(48 * time.Hour) }))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := futureVerifier.Verify(context.Background(), edRaw); !errors.Is(err, proteus.ErrManifestInvalid) {
		t.Fatalf("expected ErrManifestInvalid for expired manifest, got %v", err)
	}

	// Reject oversized envelope.
	tinyVerifier, err := signature.NewVerifier(ks, signature.WithMaxEnvelopeBytes(16))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tinyVerifier.Verify(context.Background(), edRaw); !errors.Is(err, proteus.ErrSignatureInvalid) {
		t.Fatalf("expected oversized envelope rejected, got %v", err)
	}

	// Reject duplicate JSON member names and unknown fields in envelope and manifest.
	dupEnv := `{"payloadType":"application/vnd.altessa.proteus.manifest+json","payloadType":"evil","payload":"e30=","signatures":[{"keyid":"k","sig":"c2ln"}]}`
	if _, err := signature.UnmarshalEnvelope([]byte(dupEnv)); !errors.Is(err, proteus.ErrSignatureInvalid) {
		t.Fatalf("expected duplicate field in envelope rejected, got %v", err)
	}

	unknownEnv := `{"payloadType":"application/vnd.altessa.proteus.manifest+json","payload":"e30=","signatures":[{"keyid":"k","sig":"c2ln"}],"extra":1}`
	if _, err := signature.UnmarshalEnvelope([]byte(unknownEnv)); !errors.Is(err, proteus.ErrSignatureInvalid) {
		t.Fatalf("expected unknown field in envelope rejected, got %v", err)
	}

	dupManifest := `{"v":1,"name":"a","name":"b","version":"1.0.0","sha256":"` + strings.Repeat("a", 64) + `","size":10,"goos":"linux","goarch":"arm64","issuedAt":"2026-06-01T12:00:00Z"}`
	if _, err := signature.UnmarshalManifest([]byte(dupManifest)); !errors.Is(err, proteus.ErrManifestInvalid) {
		t.Fatalf("expected duplicate field in manifest rejected, got %v", err)
	}

	unknownManifest := `{"v":1,"name":"a","version":"1.0.0","sha256":"` + strings.Repeat("a", 64) + `","size":10,"goos":"linux","goarch":"arm64","issuedAt":"2026-06-01T12:00:00Z","unknown":true}`
	if _, err := signature.UnmarshalManifest([]byte(unknownManifest)); !errors.Is(err, proteus.ErrManifestInvalid) {
		t.Fatalf("expected unknown field in manifest rejected, got %v", err)
	}

	// Reject tampered signature.
	tamperedEnv := signature.Envelope{
		PayloadType: proteus.ManifestPayloadType,
		Payload:     base64.StdEncoding.EncodeToString([]byte(`{"v":1}`)),
		Signatures: []signature.Entry{
			{
				KeyID: edKey.ID(),
				Sig:   base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
			},
		},
	}

	tamperedBytes, err := signature.MarshalEnvelope(tamperedEnv)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := verifier.Verify(context.Background(), tamperedBytes); !errors.Is(err, proteus.ErrSignatureInvalid) {
		t.Fatalf("expected tampered signature rejected, got %v", err)
	}

	// Canceled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := verifier.Verify(ctx, edRaw); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	// Nil KeySet in NewVerifier.
	if _, err := signature.NewVerifier(nil); !errors.Is(err, signature.ErrEmptyKeySet) {
		t.Fatalf("expected ErrEmptyKeySet from NewVerifier(nil), got %v", err)
	}
}

func TestKeyMaterialIsImmutableAndIDMatchesProtocol(t *testing.T) {
	t.Parallel()

	for _, alg := range []signature.Algorithm{signature.AlgEd25519, signature.AlgECDSAP256} {
		t.Run(string(alg), func(t *testing.T) {
			var signer crypto.Signer

			if alg == signature.AlgEd25519 {
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}

				signer = key
			} else {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}

				signer = key
			}

			original := signer.Public()

			der, err := x509.MarshalPKIXPublicKey(original)
			if err != nil {
				t.Fatal(err)
			}

			digest := sha256.Sum256(der)

			key, err := signature.NewKey(original)
			if err != nil {
				t.Fatal(err)
			}

			if key.ID() != fmt.Sprintf("%x", digest[:16]) {
				t.Fatalf("nonconforming key ID: %s", key.ID())
			}

			ks, err := signature.NewKeySet(key)
			if err != nil {
				t.Fatal(err)
			}

			now := time.Now().UTC()
			envelope := signEnvelope(t, signer, key, sampleManifest(now))
			mutate := func(pub crypto.PublicKey) {
				switch k := pub.(type) {
				case ed25519.PublicKey:
					clear(k)
				case *ecdsa.PublicKey:
					k.X.SetInt64(0)
					k.Y.SetInt64(0)
				}
			}
			mutate(original)
			mutate(key.PublicKey())

			found, ok := ks.Lookup(key.ID())
			if !ok {
				t.Fatal("missing key")
			}

			mutate(found.PublicKey())
			mutate(ks.Keys()[0].PublicKey())

			verifier, err := signature.NewVerifier(ks)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := verifier.Verify(t.Context(), envelope); err != nil {
				t.Fatalf("mutation changed verification: %v", err)
			}
		})
	}
}
