// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/altessa-s/go-proteus/signature"
	"github.com/altessa-s/go-proteus/signing"
)

func newKeygenCmd() *cobra.Command {
	var (
		alg     string
		privOut string
		pubOut  string
	)
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 or ECDSA P-256 signing key pair",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if privOut == "" || pubOut == "" {
				return errors.New("both --private-out and --public-out are required")
			}
			pair, err := signing.GenerateKey(signature.Algorithm(alg))
			if err != nil {
				return err
			}
			if err := signing.WriteFileAtomic(privOut, pair.PrivateKeyPEM, outputPerm); err != nil {
				return fmt.Errorf("write private key: %w", err)
			}
			if err := signing.WriteFileAtomic(pubOut, pair.PublicKeyPEM, outputPerm); err != nil {
				return fmt.Errorf("write public key: %w", err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "keyid: %s\nalgorithm: %s\n",
				pair.PublicKey.ID(), pair.PublicKey.Algorithm())
			return nil
		},
	}
	cmd.Flags().StringVar(&alg, "alg", string(signature.AlgEd25519), "Signing algorithm (ed25519 | ecdsa-p256)")
	cmd.Flags().StringVar(&privOut, "private-out", "", "Output path for PKCS#8 private key PEM (required)")
	cmd.Flags().StringVar(&pubOut, "public-out", "", "Output path for PKIX public key PEM (required)")
	return cmd
}
