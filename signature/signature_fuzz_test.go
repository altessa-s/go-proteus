// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package signature_test

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/altessa-s/go-proteus/signature"
)

func FuzzUnmarshalEnvelopeAndVerify(f *testing.F) {
	seed := make([]byte, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	key, err := signature.NewKey(pub)
	if err != nil {
		f.Fatal(err)
	}

	ks, err := signature.NewKeySet(key)
	if err != nil {
		f.Fatal(err)
	}

	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	verifier, err := signature.NewVerifier(ks, signature.WithNow(func() time.Time { return now }))
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte(`{"payloadType":"application/vnd.altessa.proteus.manifest+json","payload":"e30=","signatures":[{"keyid":"abc","sig":"def"}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not-json`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = signature.UnmarshalEnvelope(raw)
		_, _ = verifier.Verify(context.Background(), raw)
	})
}

func FuzzUnmarshalManifest(f *testing.F) {
	validJSON := `{"v":1,"name":"p","version":"1.0.0","sha256":"` + strings.Repeat("0", 64) + `","size":128,"goos":"linux","goarch":"arm64","issuedAt":"2026-06-01T00:00:00Z"}`
	f.Add([]byte(validJSON))
	f.Add([]byte(`{"v":2}`))
	f.Add([]byte(`[]`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := signature.UnmarshalManifest(raw)
		if err == nil {
			if vErr := m.Validate(); vErr != nil {
				t.Fatalf("UnmarshalManifest returned invalid manifest: %v", vErr)
			}

			_, _ = signature.MarshalManifest(m)
		}
	})
}

func FuzzParsePublicKeysPEM(f *testing.F) {
	f.Add([]byte("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=\n-----END PUBLIC KEY-----\n"))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"))
	f.Add([]byte("garbage"))

	f.Fuzz(func(t *testing.T, pemBytes []byte) {
		keys, err := signature.ParsePublicKeysPEM(pemBytes)
		if err == nil && len(keys) == 0 {
			t.Fatal("ParsePublicKeysPEM returned nil error with empty keys")
		}
	})
}
