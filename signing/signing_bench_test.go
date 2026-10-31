// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package signing_test

import (
	"strings"
	"testing"
	"time"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/signature"
	"github.com/altessa-s/go-proteus/signing"
)

func BenchmarkSignManifestEd25519(b *testing.B) {
	kp, err := signing.GenerateKey(signature.AlgEd25519)
	if err != nil {
		b.Fatal(err)
	}
	m := proteus.Manifest{
		Version:   proteus.ManifestVersion,
		Name:      "bench",
		PluginVer: "1.0.0",
		SHA256:    strings.Repeat("a", 64),
		Size:      4096,
		GOOS:      "linux",
		GOARCH:    "arm64",
		IssuedAt:  time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := signing.SignManifest(m, kp.PrivateKey); err != nil {
			b.Fatal(err)
		}
	}
}
