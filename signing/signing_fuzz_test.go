// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package signing_test

import (
	"testing"

	"github.com/altessa-s/go-proteus/signing"
)

func FuzzParsePrivateKeyPEM(f *testing.F) {
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PRIVATE KEY-----\n"), "")
	f.Add([]byte("not-pem"), "secret")

	f.Fuzz(func(t *testing.T, pemBytes []byte, password string) {
		signer, key, err := signing.ParsePrivateKeyPEM(pemBytes, password)
		if err == nil && (signer == nil || key.ID() == "") {
			t.Fatal("ParsePrivateKeyPEM returned nil error with invalid signer or key")
		}
	})
}
