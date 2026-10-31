// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package signing_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/signature"
	"github.com/altessa-s/go-proteus/signing"
)

func TestGenerateParseSignAndVerify_D6_D22(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	for _, alg := range []signature.Algorithm{"", signature.AlgEd25519, signature.AlgECDSAP256} {
		kp, err := signing.GenerateKey(alg)
		if err != nil {
			t.Fatalf("GenerateKey(%q): %v", alg, err)
		}
		if kp.PrivateKey == nil || len(kp.PrivateKeyPEM) == 0 || len(kp.PublicKeyPEM) == 0 || kp.PublicKey.ID() == "" {
			t.Fatalf("incomplete KeyPair for %q", alg)
		}

		// Round-trip private key PEM via ParsePrivateKeyPEM (go-tlsutils).
		signer, pubKey, err := signing.ParsePrivateKeyPEM(kp.PrivateKeyPEM, "")
		if err != nil {
			t.Fatalf("ParsePrivateKeyPEM: %v", err)
		}
		if pubKey.ID() != kp.PublicKey.ID() {
			t.Fatalf("KeyID mismatch after PEM round-trip: %s != %s", pubKey.ID(), kp.PublicKey.ID())
		}

		// Sign a file and verify with signature.Verifier.
		dir := t.TempDir()
		soPath := filepath.Join(dir, "plugin.so")
		if err := signing.WriteFileAtomic(soPath, []byte("compiled-plugin-bytes"), 0o600); err != nil {
			t.Fatalf("WriteFileAtomic: %v", err)
		}
		info, err := os.Stat(soPath)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("unexpected file mode from WriteFileAtomic: %v (%v)", info.Mode(), err)
		}

		goos := "linux"
		goarch := "arm64"
		envBytes, manifest, err := signing.SignFile(
			soPath,
			"greeter",
			"1.2.3",
			signer,
			signing.WithGoos(&goos),
			signing.WithGoarch(&goarch),
			signing.WithHostMajor(2),
			signing.WithIssuedAt(now),
			signing.WithTTL(24*time.Hour),
			signing.WithNow(func() time.Time { return now }),
		)
		if err != nil {
			t.Fatalf("SignFile: %v", err)
		}
		if manifest.NotAfter.Sub(manifest.IssuedAt) != 24*time.Hour {
			t.Fatalf("expected 24h TTL on manifest, got %v", manifest.NotAfter.Sub(manifest.IssuedAt))
		}

		sigPath := soPath + ".sig"
		if err := signing.WriteFileAtomic(sigPath, envBytes, 0o600); err != nil {
			t.Fatalf("WriteFileAtomic sig: %v", err)
		}

		ks, err := signature.NewKeySet(pubKey)
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := signature.NewVerifier(ks, signature.WithNow(func() time.Time { return now }))
		if err != nil {
			t.Fatal(err)
		}
		verified, err := verifier.Verify(context.Background(), envBytes)
		if err != nil {
			t.Fatalf("Verifier.Verify failed: %v", err)
		}
		if verified.KeyID != pubKey.ID() || verified.Manifest.SHA256 != manifest.SHA256 {
			t.Fatalf("unexpected verified manifest: %+v", verified)
		}
	}

	// Defect 6: Reject unsupported algorithm and RSA keys in GenerateKey, ParsePrivateKeyPEM, and SignManifest.
	if _, err := signing.GenerateKey("rsa"); !errors.Is(err, signature.ErrKeyPolicy) {
		t.Fatalf("expected ErrKeyPolicy for GenerateKey(rsa), got %v", err)
	}

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaPriv)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER})
	if _, _, err := signing.ParsePrivateKeyPEM(rsaPEM, ""); !errors.Is(err, signature.ErrKeyPolicy) {
		t.Fatalf("expected RSA private key PEM rejected with ErrKeyPolicy, got %v", err)
	}
	if _, err := signing.SignManifest(proteus.Manifest{}, rsaPriv); !errors.Is(err, signature.ErrKeyPolicy) {
		t.Fatalf("expected RSA signer rejected in SignManifest with ErrKeyPolicy, got %v", err)
	}
	if _, err := signing.SignManifest(proteus.Manifest{}, nil); err == nil {
		t.Fatal("expected error for nil signer in SignManifest")
	}
	if _, _, err := signing.ParsePrivateKeyPEM([]byte("not-pem"), ""); err == nil {
		t.Fatal("expected error for invalid PEM in ParsePrivateKeyPEM")
	}

	// BuildManifest and SignFile errors on missing file or empty name.
	if _, err := signing.BuildManifest("/nonexistent/file.so", "p", "1.0.0"); err == nil {
		t.Fatal("expected error on nonexistent artifact")
	}
	dir := t.TempDir()
	validSO := filepath.Join(dir, "valid.so")
	if err := signing.WriteFileAtomic(validSO, []byte("abc"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := signing.BuildManifest(
		validSO,
		"p",
		"1.0.0",
		signing.WithGoos("linux"),
		signing.WithGoarch("arm64"),
		signing.WithGoos((*string)(nil)),
		signing.WithGoarch((*string)(nil)),
		signing.WithGoos(""),
		signing.WithGoarch(""),
		signing.WithTTL(-time.Second),
		signing.WithNotAfter(time.Now().Add(time.Hour)),
	); err != nil {
		t.Fatalf("BuildManifest defaults: %v", err)
	}
	if err := signing.WriteFileAtomic(filepath.Join(validSO, "out.sig"), []byte("x"), 0o600); err == nil {
		t.Fatal("expected WriteFileAtomic error when parent path is a file")
	}
	roDir := filepath.Join(dir, "ro")
	if err := os.MkdirAll(roDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) })
	if err := signing.WriteFileAtomic(filepath.Join(roDir, "out.sig"), []byte("x"), 0o600); err == nil {
		t.Fatal("expected WriteFileAtomic error on read-only directory")
	}
	if _, _, err := signing.SignFile(validSO, "", "1.0.0", nil, signing.WithNotAfter(time.Now().Add(time.Hour))); !errors.Is(err, proteus.ErrManifestInvalid) {
		t.Fatalf("expected ErrManifestInvalid for empty plugin name, got %v", err)
	}
}
