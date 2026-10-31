// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package signing_test

import (
	"fmt"

	"github.com/altessa-s/go-proteus/signature"
	"github.com/altessa-s/go-proteus/signing"
)

func ExampleGenerateKey() {
	kp, err := signing.GenerateKey(signature.AlgEd25519)
	if err != nil {
		panic(err)
	}
	fmt.Println(kp.PublicKey.Algorithm(), len(kp.PublicKey.ID()))
	// Output:
	// ed25519 32
}
