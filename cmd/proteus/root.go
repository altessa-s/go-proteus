// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import (
	"io"

	"github.com/spf13/cobra"

	"github.com/altessa-s/go-atlas-core/io/files"
)

const outputPerm = 0o600

func readRegularFile(path string) ([]byte, error) {
	f, err := files.OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
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
