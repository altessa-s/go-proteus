// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/altessa-s/go-proteus/signature"
	"github.com/altessa-s/go-proteus/signing"

	proteus "github.com/altessa-s/go-proteus"
)

type envelopeInspection struct {
	PayloadType string           `json:"payloadType"`
	KeyIDs      []string         `json:"keyIds"`
	Manifest    proteus.Manifest `json:"manifest"`
}

type binaryInspection struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func newInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect <file.so|file.so.sig>",
		Short: "Inspect a DSSE .so.sig envelope or compute the SHA-256 digest of a .so artifact",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			if strings.HasSuffix(path, ".sig") {
				data, err := readRegularFile(path)
				if err != nil {
					return fmt.Errorf("read %q: %w", path, err)
				}

				env, err := signature.UnmarshalEnvelope(data)
				if err != nil {
					return err
				}

				rawManifest, err := base64.StdEncoding.DecodeString(env.Payload)
				if err != nil {
					return fmt.Errorf("decode envelope payload: %w", err)
				}

				manifest, err := signature.UnmarshalManifest(rawManifest)
				if err != nil {
					return err
				}

				keyIDs := make([]string, 0, len(env.Signatures))
				for _, sig := range env.Signatures {
					keyIDs = append(keyIDs, sig.KeyID)
				}

				out, err := json.Marshal(
					envelopeInspection{
						PayloadType: env.PayloadType,
						KeyIDs:      keyIDs,
						Manifest:    manifest,
					},
					jsontext.WithIndent("  "),
				)
				if err != nil {
					return err
				}

				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", out)

				return nil
			}

			digest, size, err := signing.HashFile(path)
			if err != nil {
				return err
			}

			out, err := json.Marshal(
				binaryInspection{
					Path:   path,
					SHA256: digest,
					Size:   size,
				},
				jsontext.WithIndent("  "),
			)
			if err != nil {
				return err
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", out)

			return nil
		},
	}

	return cmd
}
