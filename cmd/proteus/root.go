// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import (
	"github.com/spf13/cobra"

	"github.com/altessa-s/go-atlas-core/io/files"

	"github.com/altessa-s/go-proteus/signature"

	coreio "github.com/altessa-s/go-atlas-core/io"
)

const outputPerm = 0o600

func readRegularFile(path string) ([]byte, error) {
	f, err := files.OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	// Metadata inputs share the verifier envelope limit; artifacts are streamed separately.
	return coreio.ReadAllLimited(f, signature.DefaultMaxEnvelopeBytes)
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "proteus",
		Short:         "Sign, verify, and inspect Go plugin artifacts and DSSE manifests",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(
		newKeygenCmd(),
		newSignCmd(),
		newVerifyCmd(),
		newInspectCmd(),
	)
	return root
}
