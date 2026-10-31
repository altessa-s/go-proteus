// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package spi

import (
	"fmt"
	"iter"
	"reflect"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/sdk"
)

// Registry is the symbol lookup port satisfied by [*github.com/altessa-s/go-proteus/host.Manager].
type Registry interface {
	// LookupAll yields each ready plugin that exports symbol along with its raw symbol value.
	LookupAll(symbol string) iter.Seq2[*proteus.Plugin, any]
}

// SkipReason classifies why a plugin candidate was skipped during [Providers] iteration.
type SkipReason string

const (
	// SkipInvalidVersionSymbol indicates that the plugin exported a malformed SPIVersion symbol.
	SkipInvalidVersionSymbol SkipReason = "invalid_version_symbol"

	// SkipVersionMismatch indicates that the plugin's SPIVersion did not satisfy the host's constraint.
	SkipVersionMismatch SkipReason = "version_mismatch"

	// SkipTypeMismatch indicates that the exported symbol could not be asserted to T.
	SkipTypeMismatch SkipReason = "type_mismatch"
)

// SkipEvent describes a plugin skipped during [Providers] negotiation.
type SkipEvent struct {
	// Plugin is the ready plugin that was skipped.
	Plugin *proteus.Plugin

	// Contract is the SPI contract name requested by the caller.
	Contract string

	// Symbol is the symbol name looked up on the plugin.
	Symbol string

	// Reason classifies why the plugin was skipped.
	Reason SkipReason

	// Err holds the structured diagnostic error ([proteus.ErrSPIVersionMismatch] or [proteus.ErrInvalidSymbol]).
	Err error
}

// Providers iterates over all ready plugins in reg that export contract (or the symbol configured
// via [WithSymbol]), satisfy any configured [sdk.SPIVersion] constraint ([WithMajor], [WithMinMinor],
// [WithRequireVersion]), and implement T.
func Providers[T any](reg Registry, contract string, opts ...Option) iter.Seq2[T, *proteus.Plugin] {
	cfg := newOptions(opts...)
	symName := cfg.symbol
	if symName == "" {
		symName = contract
	}
	verSymName := symName + sdk.SymbolSPIVersion

	return func(yield func(T, *proteus.Plugin) bool) {
		if reg == nil {
			return
		}
		for p, rawSym := range reg.LookupAll(symName) {
			if !checkVersion(p, contract, symName, verSymName, cfg) {
				continue
			}
			provider, ok := unwrapSymbol[T](rawSym)
			if !ok {
				emitSkip(cfg, SkipEvent{
					Plugin:   p,
					Contract: contract,
					Symbol:   symName,
					Reason:   SkipTypeMismatch,
					Err: fmt.Errorf(
						"%w: plugin %q symbol %q does not implement %T",
						proteus.ErrInvalidSymbol,
						p.Name(),
						symName,
						*new(T),
					),
				})
				continue
			}
			if !yield(provider, p) {
				return
			}
		}
	}
}

func checkVersion(p *proteus.Plugin, contract, symName, verSymName string, cfg *options) bool {
	if cfg.major < 0 && cfg.minMinor < 0 && !cfg.requireVersion {
		return true
	}
	rawVer, ok := p.Lookup(verSymName)
	if !ok {
		rawVer, ok = p.Lookup(sdk.SymbolSPIVersion)
	}
	if !ok {
		if cfg.requireVersion {
			emitSkip(cfg, SkipEvent{
				Plugin:   p,
				Contract: contract,
				Symbol:   symName,
				Reason:   SkipVersionMismatch,
				Err: fmt.Errorf(
					"%w: plugin %q is missing %s symbol",
					proteus.ErrSPIVersionMismatch,
					p.Name(),
					verSymName,
				),
			})
			return false
		}
		return true
	}

	ver, valid := unwrapSPIVersion(rawVer)
	if !valid {
		emitSkip(cfg, SkipEvent{
			Plugin:   p,
			Contract: contract,
			Symbol:   verSymName,
			Reason:   SkipInvalidVersionSymbol,
			Err: fmt.Errorf(
				"%w: plugin %q exports malformed %s symbol",
				proteus.ErrInvalidSymbol,
				p.Name(),
				verSymName,
			),
		})
		return false
	}

	if ver.Contract != "" && ver.Contract != contract && ver.Contract != symName {
		emitSkip(cfg, SkipEvent{
			Plugin:   p,
			Contract: contract,
			Symbol:   symName,
			Reason:   SkipVersionMismatch,
			Err: fmt.Errorf(
				"%w: plugin %q SPIVersion contract %q does not match %q",
				proteus.ErrSPIVersionMismatch,
				p.Name(),
				ver.Contract,
				contract,
			),
		})
		return false
	}

	if (cfg.major >= 0 && ver.Major != cfg.major) || ver.Minor < cfg.minMinor {
		emitSkip(cfg, SkipEvent{
			Plugin:   p,
			Contract: contract,
			Symbol:   symName,
			Reason:   SkipVersionMismatch,
			Err: fmt.Errorf(
				"%w: plugin %q exports %s v%d.%d, host requires v%d.%d+",
				proteus.ErrSPIVersionMismatch,
				p.Name(),
				contract,
				ver.Major,
				ver.Minor,
				cfg.major,
				cfg.minMinor,
			),
		})
		return false
	}
	return true
}

func emitSkip(cfg *options, ev SkipEvent) {
	if cfg.onSkip != nil {
		cfg.onSkip(ev)
	}
}

func unwrapSPIVersion(raw any) (sdk.SPIVersion, bool) {
	switch v := raw.(type) {
	case sdk.SPIVersion:
		return v, true
	case *sdk.SPIVersion:
		if v == nil {
			return sdk.SPIVersion{}, false
		}
		return *v, true
	case **sdk.SPIVersion:
		if v == nil || *v == nil {
			return sdk.SPIVersion{}, false
		}
		return **v, true
	default:
		return sdk.SPIVersion{}, false
	}
}

func unwrapSymbol[T any](raw any) (T, bool) {
	if v, ok := raw.(T); ok && !nilProvider(v) {
		return v, true
	}
	// plugin.Lookup returns a pointer to an exported variable, including **Impl
	// for a variable whose value is *Impl. Dereference exactly one variable pointer.
	value := reflect.ValueOf(raw)
	if value.IsValid() && value.Kind() == reflect.Pointer && !value.IsNil() {
		if v, ok := reflect.TypeAssert[T](value.Elem()); ok && !nilProvider(v) {
			return v, true
		}
	}
	var zero T
	return zero, false
}

func nilProvider(v any) bool {
	value := reflect.ValueOf(v)
	if !value.IsValid() {
		return true
	}
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
