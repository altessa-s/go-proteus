// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package signature_test

import (
	"fmt"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/signature"
)

func ExamplePAE() {
	pae := signature.PAE(proteus.ManifestPayloadType, []byte(`{"v":1}`))
	fmt.Println(string(pae))
	// Output:
	// DSSEv1 45 application/vnd.altessa.proteus.manifest+json 7 {"v":1}
}
