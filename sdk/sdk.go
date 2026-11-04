// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package sdk

import (
	"errors"
	"runtime/debug"
)

// Standard symbol names recognized by the host loader.
const (
	// SymbolDescriptor is the required package-level symbol holding [Descriptor] or [*Descriptor].
	SymbolDescriptor = "Descriptor"

	// SymbolInit is the optional initialization hook with signature func(context.Context) error.
	SymbolInit = "Init"

	// SymbolClose is the optional shutdown hook with signature func(context.Context) error.
	SymbolClose = "Close"

	// SymbolHealth is the optional health probe with signature func(context.Context) error.
	SymbolHealth = "HealthCheck"

	// SymbolSPIVersion is the suffix or symbol name for [SPIVersion] metadata.
	SymbolSPIVersion = "SPIVersion"

	// SymbolDepInfo is the optional symbol holding [DepInfo] or [*DepInfo].
	SymbolDepInfo = "DepInfo"
)

// Descriptor carries the identity and build metadata that every plugin must export.
type Descriptor struct {
	// Name is the unique plugin identifier (for example, "auth-oidc").
	Name string

	// Version is the semantic version of the plugin (for example, "1.2.0").
	Version string

	// Description is optional human-readable summary text.
	Description string

	// Build is an optional build identifier or commit revision.
	Build string

	// Custom holds optional plugin-defined metadata key-value pairs.
	Custom map[string]any
}

// SPIVersion declares the Service Provider Interface contract version implemented by a plugin symbol.
type SPIVersion struct {
	// Contract is the SPI contract or symbol name (for example, "Greeter").
	Contract string

	// Major is the major version number; incremented on breaking changes.
	Major int

	// Minor is the minor version number; incremented on backward-compatible additions.
	Minor int
}

// ModDep represents a single Go module dependency and version at plugin build time.
type ModDep struct {
	// Path is the module import path.
	Path string

	// Version is the module semantic version.
	Version string
}

// DepInfo captures the Go toolchain and module dependencies embedded in a plugin binary.
type DepInfo struct {
	// GoVersion is the Go toolchain version used to build the plugin.
	GoVersion string

	// MainPath is the main module path of the plugin binary.
	MainPath string

	// Deps lists the module dependencies recorded in build info.
	Deps []ModDep
}

// NewDepInfoFromBuild constructs a [DepInfo] from the running binary's embedded [debug.ReadBuildInfo].
// If build metadata is unavailable, it returns a zero [DepInfo].
func NewDepInfoFromBuild() DepInfo {
	bi, ok := debug.ReadBuildInfo()
	return depInfoFromBuildInfo(bi, ok)
}

func depInfoFromBuildInfo(bi *debug.BuildInfo, ok bool) DepInfo {
	if !ok || bi == nil {
		return DepInfo{}
	}

	deps := make([]ModDep, 0, len(bi.Deps))
	for _, d := range bi.Deps {
		if d == nil {
			continue
		}

		mod := d
		if mod.Replace != nil {
			mod = mod.Replace
		}

		deps = append(deps, ModDep{
			Path:    mod.Path,
			Version: mod.Version,
		})
	}

	return DepInfo{
		GoVersion: bi.GoVersion,
		MainPath:  bi.Main.Path,
		Deps:      deps,
	}
}

// Map returns a map of module path to module version for all dependencies in d.
func (d DepInfo) Map() map[string]string {
	m := make(map[string]string, len(d.Deps))
	for _, dep := range d.Deps {
		m[dep.Path] = dep.Version
	}

	return m
}

// UnwrapAll performs a pre-order traversal of err's unwrap tree and returns all visited non-nil errors.
// Both single-child (Unwrap() error) and multi-child (Unwrap() []error) wrappers are expanded.
func UnwrapAll(err error) []error {
	if err == nil {
		return nil
	}

	var out []error
	unwrapInto(err, &out)

	return out
}

func unwrapInto(err error, out *[]error) {
	for err != nil {
		*out = append(*out, err)
		switch u := err.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range u.Unwrap() {
				if child != nil {
					unwrapInto(child, out)
				}
			}

			return
		case interface{ Unwrap() error }:
			err = u.Unwrap()
		default:
			return
		}
	}
}

// AsViaUnwrapAll searches the flattened error tree of err for the first error assignable to T or
// matching [errors.AsType].
func AsViaUnwrapAll[T error](err error) (T, bool) {
	for _, candidate := range UnwrapAll(err) {
		if target, ok := candidate.(T); ok {
			return target, true
		}

		if target, ok := errors.AsType[T](candidate); ok {
			return target, true
		}
	}

	var zero T

	return zero, false
}
