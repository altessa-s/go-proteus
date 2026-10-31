// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/altessa-s/go-proteus/signing"
)

func newSignCmd() *cobra.Command {
	var (
		keyPath      string
		passwordEnv  string
		passwordFile string
		name         string
		version      string
		goos         string
		goarch       string
		hostMajor    int
		ttl          time.Duration
		notAfterStr  string
		outPath      string
	)
	cmd := &cobra.Command{
		Use:   "sign <plugin.so>",
		Short: "Sign a plugin shared object and write a detached DSSE .so.sig envelope",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			soPath := args[0]
			if keyPath == "" {
				return errors.New("--key is required")
			}
			if name == "" || version == "" {
				return errors.New("--name and --version are required")
			}
			password, err := resolvePassword(passwordEnv, passwordFile)
			if err != nil {
				return err
			}
			keyBytes, err := readRegularFile(keyPath)
			if err != nil {
				return fmt.Errorf("read private key %q: %w", keyPath, err)
			}
			signer, pubKey, err := signing.ParsePrivateKeyPEM(keyBytes, password)
			if err != nil {
				return err
			}

			opts := []signing.Option{
				signing.WithGoos(&goos),
				signing.WithGoarch(&goarch),
				signing.WithHostMajor(hostMajor),
			}
			if ttl > 0 {
				opts = append(opts, signing.WithTTL(ttl))
			}
			if notAfterStr != "" {
				ts, parseErr := time.Parse(time.RFC3339, notAfterStr)
				if parseErr != nil {
					return fmt.Errorf("parse --not-after %q: %w", notAfterStr, parseErr)
				}
				opts = append(opts, signing.WithNotAfter(ts))
			}

			envBytes, manifest, err := signing.SignFile(soPath, name, version, signer, opts...)
			if err != nil {
				return err
			}
			targetSig := outPath
			if targetSig == "" {
				targetSig = soPath + ".sig"
			}
			if err := signing.WriteFileAtomic(targetSig, envBytes, outputPerm); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "signed: %s (keyid=%s sha256=%s)\n",
				targetSig, pubKey.ID(), manifest.SHA256)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "Path to private key PEM file (required)")
	cmd.Flags().StringVar(&passwordEnv, "password-env", "", "Environment variable holding private key passphrase")
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "File holding private key passphrase")
	cmd.Flags().StringVar(&name, "name", "", "Plugin manifest name (required)")
	cmd.Flags().StringVar(&version, "version", "", "Plugin semantic version (required)")
	cmd.Flags().StringVar(&goos, "goos", runtime.GOOS, "Target GOOS")
	cmd.Flags().StringVar(&goarch, "goarch", runtime.GOARCH, "Target GOARCH")
	cmd.Flags().IntVar(&hostMajor, "host-major", 0, "Optional required host major version")
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "Optional manifest validity duration from issuedAt")
	cmd.Flags().StringVar(&notAfterStr, "not-after", "", "Optional RFC3339 expiration timestamp")
	cmd.Flags().StringVar(&outPath, "out", "", "Output signature path (defaults to <plugin.so>.sig)")
	return cmd
}

func resolvePassword(envName, filePath string) (string, error) {
	if envName != "" && filePath != "" {
		return "", errors.New("specify at most one of --password-env or --password-file")
	}
	if envName != "" {
		return os.Getenv(envName), nil
	}
	if filePath != "" {
		data, err := readRegularFile(filePath)
		if err != nil {
			return "", fmt.Errorf("read password file %q: %w", filePath, err)
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	return "", nil
}
