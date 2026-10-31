// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func execCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestCLIKeygenSignVerifyInspect_D21_D22(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	for _, alg := range []string{"ed25519", "ecdsa-p256"} {
		privPath := filepath.Join(dir, alg+".key")
		pubPath := filepath.Join(dir, alg+".pub")

		out, err := execCLI(t, "keygen", "--alg", alg, "--private-out", privPath, "--public-out", pubPath)
		if err != nil {
			t.Fatalf("keygen (%s) failed: %v\n%s", alg, err, out)
		}
		if !strings.Contains(out, "keyid: ") {
			t.Fatalf("expected keyid in keygen output, got %q", out)
		}

		soPath := filepath.Join(dir, "plugin-"+alg+".so")
		if err := os.WriteFile(soPath, []byte("shared-object-"+alg), 0o600); err != nil {
			t.Fatal(err)
		}

		notAfter := time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339)
		pwFile := filepath.Join(dir, "pw.txt")
		if err := os.WriteFile(pwFile, []byte("\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		signOut, err := execCLI(t,
			"sign",
			"--key", privPath,
			"--password-file", pwFile,
			"--name", "greeter",
			"--version", "1.2.3",
			"--host-major", "1",
			"--ttl", "24h",
			"--not-after", notAfter,
			soPath,
		)
		if err != nil {
			t.Fatalf("sign (%s) failed: %v\n%s", alg, err, signOut)
		}

		nowRFC := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
		verifyOut, err := execCLI(t, "verify", "--key", pubPath, "--now", nowRFC, soPath)
		if err != nil {
			t.Fatalf("verify (%s) failed: %v\n%s", alg, err, verifyOut)
		}
		if !strings.Contains(verifyOut, "verified:") {
			t.Fatalf("unexpected verify output: %q", verifyOut)
		}

		inspectSigOut, err := execCLI(t, "inspect", soPath+".sig")
		if err != nil {
			t.Fatalf("inspect .sig failed: %v\n%s", err, inspectSigOut)
		}
		if !strings.Contains(inspectSigOut, `"name": "greeter"`) {
			t.Fatalf("unexpected inspect .sig output: %s", inspectSigOut)
		}

		inspectSOOut, err := execCLI(t, "inspect", soPath)
		if err != nil {
			t.Fatalf("inspect .so failed: %v\n%s", err, inspectSOOut)
		}
		if !strings.Contains(inspectSOOut, `"sha256":`) {
			t.Fatalf("unexpected inspect .so output: %s", inspectSOOut)
		}

		// Tamper with the .so binary after signing -> verify must fail with ErrManifestMismatch.
		if err := os.WriteFile(soPath, []byte("tampered-binary"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := execCLI(t, "verify", "--key", pubPath, soPath); err == nil {
			t.Fatalf("expected verify to fail on tampered .so (%s)", alg)
		}
	}
}

func TestCLIErrorCases(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// keygen errors: missing flags, RSA algorithm rejected.
	if _, err := execCLI(t, "keygen"); err == nil {
		t.Fatal("expected error when keygen output flags are missing")
	}
	if _, err := execCLI(t, "keygen", "--alg", "rsa", "--private-out", filepath.Join(dir, "k"), "--public-out", filepath.Join(dir, "p")); err == nil {
		t.Fatal("expected error for unsupported RSA algorithm")
	}

	// sign errors: missing --key, missing --name/--version, conflicting password flags.
	soPath := filepath.Join(dir, "p.so")
	_ = os.WriteFile(soPath, []byte("abc"), 0o600)
	if _, err := execCLI(t, "sign", soPath); err == nil {
		t.Fatal("expected error when --key is missing")
	}
	if _, err := execCLI(t, "sign", "--key", "k", soPath); err == nil {
		t.Fatal("expected error when --name/--version are missing")
	}
	if _, err := execCLI(t, "sign", "--key", "k", "--name", "p", "--version", "1.0.0", "--password-env", "A", "--password-file", "B", soPath); err == nil {
		t.Fatal("expected error when both --password-env and --password-file are set")
	}

	// verify errors: missing --key, missing file.
	if _, err := execCLI(t, "verify", soPath); err == nil {
		t.Fatal("expected error when verify --key is missing")
	}
	if _, err := execCLI(t, "verify", "--key", filepath.Join(dir, "missing.pub"), soPath); err == nil {
		t.Fatal("expected error when public key file does not exist")
	}

	// inspect errors: missing .sig or .so, or invalid .sig JSON.
	if _, err := execCLI(t, "inspect", filepath.Join(dir, "missing.so.sig")); err == nil {
		t.Fatal("expected error on missing .sig")
	}
	badSig := filepath.Join(dir, "bad.so.sig")
	_ = os.WriteFile(badSig, []byte("not-json"), 0o600)
	if _, err := execCLI(t, "inspect", badSig); err == nil {
		t.Fatal("expected error on invalid .sig JSON")
	}
	if _, err := execCLI(t, "inspect", filepath.Join(dir, "missing.so")); err == nil {
		t.Fatal("expected error on missing .so")
	}
	if _, err := resolvePassword("PROTEUS_TEST_EMPTY_PW", ""); err != nil {
		t.Fatalf("resolvePassword env: %v", err)
	}
}
