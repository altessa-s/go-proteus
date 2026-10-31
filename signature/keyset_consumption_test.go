// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package signature_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/altessa-s/go-proteus/signature"
)

func TestPEMParsersRejectIncompleteBundles(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	valid := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	for _, malformed := range []string{
		"-----BEGIN PUBLIC KEY-----\nAAAA\n",
		"-----BEGIN PUBLIC KEY-----\n!invalid!\n-----END PUBLIC KEY-----\n",
		"garbage\n",
		"\u00a0",
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	} {
		for _, bundle := range []string{malformed + valid, valid + malformed + valid, valid + malformed} {
			keys, err := signature.ParsePublicKeysPEM([]byte(bundle))
			require.ErrorIs(t, err, signature.ErrKeyPolicy)
			require.Nil(t, keys)
			_, err = signature.ParsePublicKeyPEM([]byte(bundle))
			require.ErrorIs(t, err, signature.ErrKeyPolicy)
		}
	}
	whitespace := " \t\r\n"
	_, err = signature.ParsePublicKeyPEM([]byte(whitespace + valid + whitespace))
	require.NoError(t, err)
	keys, err := signature.ParsePublicKeysPEM([]byte(whitespace + valid + whitespace + valid + whitespace))
	require.NoError(t, err)
	require.Len(t, keys, 2)
}
