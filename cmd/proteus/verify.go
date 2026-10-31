// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/altessa-s/go-proteus/signature"
	"github.com/altessa-s/go-proteus/signing"

	proteus "github.com/altessa-s/go-proteus"
)

func newVerifyCmd() *cobra.Command {
	var (
		keyPaths []string
		sigPath  string
		nowStr   string
	)
	cmd := &cobra.Command{
		Use:   "verify <plugin.so>",
		Short: "Verify a plugin shared object and its detached DSSE .so.sig envelope",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			soPath := args[0]
			if len(keyPaths) == 0 {
				return errors.New("at least one --key public key PEM file is required")
			}
			keys := make([]signature.Key, 0, len(keyPaths))
			for _, kp := range keyPaths {
				pemBytes, err := readRegularFile(kp)
				if err != nil {
					return fmt.Errorf("read public key %q: %w", kp, err)
				}
				k, err := signature.ParsePublicKeyPEM(pemBytes)
				if err != nil {
					return fmt.Errorf("parse public key %q: %w", kp, err)
				}
				keys = append(keys, k)
			}
			ks, err := signature.NewKeySet(keys...)
			if err != nil {
				return err
			}

			var vOpts []signature.Option
			if nowStr != "" {
				ts, parseErr := time.Parse(time.RFC3339, nowStr)
				if parseErr != nil {
					return fmt.Errorf("parse --now %q: %w", nowStr, parseErr)
				}
				vOpts = append(vOpts, signature.WithNow(func() time.Time { return ts }))
			}
			verifier, err := signature.NewVerifier(ks, vOpts...)
			if err != nil {
				return err
			}

			targetSig := sigPath
			if targetSig == "" {
				targetSig = soPath + ".sig"
			}
			envBytes, err := readRegularFile(targetSig)
			if err != nil {
				return fmt.Errorf("read signature %q: %w", targetSig, err)
			}
			verified, err := verifier.Verify(cmd.Context(), envBytes)
			if err != nil {
				return err
			}

			digest, size, err := signing.HashFile(soPath)
			if err != nil {
				return err
			}
			if digest != verified.Manifest.SHA256 || size != verified.Manifest.Size {
				return fmt.Errorf("%w: artifact digest/size (%s, %d) != manifest (%s, %d)",
					proteus.ErrManifestMismatch, digest, size, verified.Manifest.SHA256, verified.Manifest.Size)
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "verified: %s (name=%s version=%s keyid=%s sha256=%s)\n",
				soPath, verified.Manifest.Name, verified.Manifest.PluginVer, verified.KeyID, verified.Manifest.SHA256)
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&keyPaths, "key", nil, "Path(s) to trusted public key PEM file(s) (required)")
	cmd.Flags().StringVar(&sigPath, "sig", "", "Detached signature file path (defaults to <plugin.so>.sig)")
	cmd.Flags().StringVar(&nowStr, "now", "", "Optional RFC3339 evaluation timestamp override")
	return cmd
}
