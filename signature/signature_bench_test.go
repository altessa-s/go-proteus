// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package signature_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/signature"
)

func BenchmarkVerifyEd25519(b *testing.B) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	key, err := signature.NewKey(pub)
	if err != nil {
		b.Fatal(err)
	}
	ks, err := signature.NewKeySet(key)
	if err != nil {
		b.Fatal(err)
	}
	verifier, err := signature.NewVerifier(ks, signature.WithNow(func() time.Time { return now }))
	if err != nil {
		b.Fatal(err)
	}
	m := proteus.Manifest{
		Version:   proteus.ManifestVersion,
		Name:      "bench",
		PluginVer: "1.0.0",
		SHA256:    strings.Repeat("a", 64),
		Size:      1024,
		GOOS:      "linux",
		GOARCH:    "arm64",
		IssuedAt:  now,
	}
	payload, err := signature.MarshalManifest(m)
	if err != nil {
		b.Fatal(err)
	}
	pae := signature.PAE(proteus.ManifestPayloadType, payload)
	sig := ed25519.Sign(priv, pae)
	raw, err := signature.MarshalEnvelope(signature.Envelope{
		PayloadType: proteus.ManifestPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []signature.Entry{{KeyID: key.ID(), Sig: base64.StdEncoding.EncodeToString(sig)}},
	})
	if err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := verifier.Verify(ctx, raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyECDSAP256(b *testing.B) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	key, err := signature.NewKey(&priv.PublicKey)
	if err != nil {
		b.Fatal(err)
	}
	ks, err := signature.NewKeySet(key)
	if err != nil {
		b.Fatal(err)
	}
	verifier, err := signature.NewVerifier(ks, signature.WithNow(func() time.Time { return now }))
	if err != nil {
		b.Fatal(err)
	}
	m := proteus.Manifest{
		Version:   proteus.ManifestVersion,
		Name:      "bench",
		PluginVer: "1.0.0",
		SHA256:    strings.Repeat("b", 64),
		Size:      1024,
		GOOS:      "linux",
		GOARCH:    "arm64",
		IssuedAt:  now,
	}
	payload, err := signature.MarshalManifest(m)
	if err != nil {
		b.Fatal(err)
	}
	pae := signature.PAE(proteus.ManifestPayloadType, payload)
	digest := sha256.Sum256(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		b.Fatal(err)
	}
	raw, err := signature.MarshalEnvelope(signature.Envelope{
		PayloadType: proteus.ManifestPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []signature.Entry{{KeyID: key.ID(), Sig: base64.StdEncoding.EncodeToString(sig)}},
	})
	if err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := verifier.Verify(ctx, raw); err != nil {
			b.Fatal(err)
		}
	}
}
