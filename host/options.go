// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package host

import (
	"log/slog"
	"runtime/debug"
	"time"

	proteus "github.com/altessa-s/go-proteus"
)

//go:generate optgen generate --type=options

// Default lifecycle timeouts for [Manager].
const (
	// DefaultInitTimeout is the default maximum duration allowed for a plugin's Init hook.
	DefaultInitTimeout = 10 * time.Second

	// DefaultCloseTimeout is the default maximum duration allowed for a plugin's Close hook.
	DefaultCloseTimeout = 5 * time.Second

	// DefaultHealthTimeout is the default maximum duration allowed for a plugin's HealthCheck probe.
	DefaultHealthTimeout = 3 * time.Second
)

type options struct {
	verifier          proteus.Verifier
	unsigned          proteus.UnsignedPolicy `optgen:"default=proteus.UnsignedReject"`
	allow             []string
	deny              []string
	revoked           []string
	hostVersion       string
	hostVersionPolicy proteus.VersionPolicy `optgen:"default=proteus.VersionEnforce"`
	minVersions       map[string]string
	minVersionPolicy  proteus.VersionPolicy `optgen:"default=proteus.VersionEnforce"`
	initTimeout       time.Duration         `optgen:"default=DefaultInitTimeout"`
	closeTimeout      time.Duration         `optgen:"default=DefaultCloseTimeout"`
	healthTimeout     time.Duration         `optgen:"default=DefaultHealthTimeout"`
	logger            *slog.Logger
	observer          proteus.Observer
	now               func() time.Time `optgen:"default=time.Now"`
	goos              string
	goarch            string
	hostBuildInfo     func() (*debug.BuildInfo, bool) `optgen:"default=debug.ReadBuildInfo"`
}
