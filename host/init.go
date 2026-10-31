// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package host

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/altessa-s/go-proteus"
	"github.com/altessa-s/go-proteus/sdk"
)

type lifecycleHook func(context.Context) error

type resolvedSymbols struct {
	descriptor sdk.Descriptor
	depInfo    *sdk.DepInfo
	initFn     lifecycleHook
	closeFn    lifecycleHook
	healthFn   lifecycleHook
}

func resolvePluginSymbols(syms proteus.Symbols) (resolvedSymbols, error) {
	if syms == nil {
		return resolvedSymbols{}, fmt.Errorf("%w: nil symbol table", proteus.ErrNoDescriptor)
	}
	rawDesc, err := syms.Lookup(sdk.SymbolDescriptor)
	if err != nil {
		return resolvedSymbols{}, fmt.Errorf("%w: %w", proteus.ErrNoDescriptor, err)
	}
	desc, ok := unwrapDescriptor(rawDesc)
	if !ok {
		return resolvedSymbols{}, fmt.Errorf(
			"%w: %s has unexpected type %T",
			proteus.ErrInvalidDescriptor,
			sdk.SymbolDescriptor,
			rawDesc,
		)
	}
	if desc.Name == "" {
		return resolvedSymbols{}, fmt.Errorf("%w: Descriptor.Name is empty", proteus.ErrInvalidDescriptor)
	}
	if desc.Version == "" {
		return resolvedSymbols{}, fmt.Errorf("%w: Descriptor.Version is empty", proteus.ErrInvalidDescriptor)
	}

	var out resolvedSymbols
	out.descriptor = desc

	if rawDep, depErr := syms.Lookup(sdk.SymbolDepInfo); depErr == nil {
		dep, valid := unwrapDepInfo(rawDep)
		if !valid {
			return resolvedSymbols{}, fmt.Errorf(
				"%w: %s has unexpected type %T",
				proteus.ErrInvalidSymbol,
				sdk.SymbolDepInfo,
				rawDep,
			)
		}
		out.depInfo = dep
	}

	if rawInit, initErr := syms.Lookup(sdk.SymbolInit); initErr == nil {
		fn, valid := unwrapHook(rawInit)
		if !valid {
			return resolvedSymbols{}, fmt.Errorf(
				"%w: %s has unexpected type %T (want func(context.Context) error)",
				proteus.ErrInvalidSymbol,
				sdk.SymbolInit,
				rawInit,
			)
		}
		out.initFn = fn
	}

	if rawClose, closeErr := syms.Lookup(sdk.SymbolClose); closeErr == nil {
		fn, valid := unwrapHook(rawClose)
		if !valid {
			return resolvedSymbols{}, fmt.Errorf(
				"%w: %s has unexpected type %T (want func(context.Context) error)",
				proteus.ErrInvalidSymbol,
				sdk.SymbolClose,
				rawClose,
			)
		}
		out.closeFn = fn
	}

	if rawHealth, healthErr := syms.Lookup(sdk.SymbolHealth); healthErr == nil {
		fn, valid := unwrapHook(rawHealth)
		if !valid {
			return resolvedSymbols{}, fmt.Errorf(
				"%w: %s has unexpected type %T (want func(context.Context) error)",
				proteus.ErrInvalidSymbol,
				sdk.SymbolHealth,
				rawHealth,
			)
		}
		out.healthFn = fn
	}

	return out, nil
}

func unwrapDescriptor(raw any) (sdk.Descriptor, bool) {
	switch v := raw.(type) {
	case sdk.Descriptor:
		return v, true
	case *sdk.Descriptor:
		if v == nil {
			return sdk.Descriptor{}, false
		}
		return *v, true
	case **sdk.Descriptor:
		if v == nil || *v == nil {
			return sdk.Descriptor{}, false
		}
		return **v, true
	default:
		return sdk.Descriptor{}, false
	}
}

func unwrapDepInfo(raw any) (*sdk.DepInfo, bool) {
	switch v := raw.(type) {
	case sdk.DepInfo:
		cp := v
		return &cp, true
	case *sdk.DepInfo:
		if v == nil {
			return nil, true
		}
		cp := *v
		return &cp, true
	case **sdk.DepInfo:
		if v == nil {
			return nil, false
		}
		if *v == nil {
			return nil, true
		}
		cp := **v
		return &cp, true
	default:
		return nil, false
	}
}

func unwrapHook(raw any) (lifecycleHook, bool) {
	switch v := raw.(type) {
	case func(context.Context) error:
		if v == nil {
			return nil, true
		}
		return v, true
	case *func(context.Context) error:
		if v == nil {
			return nil, false
		}
		if *v == nil {
			return nil, true
		}
		return *v, true
	default:
		return nil, false
	}
}

// runWatchdog executes hook on a supervised goroutine bounded by timeout.
// If the hook panics, it returns an error wrapping both sentinel (when non-nil) and [proteus.ErrPanicked].
// If the timeout expires before hook returns, runWatchdog returns immediately and logs that the
// plugin goroutine was abandoned (Defect 2).
func runWatchdog(
	ctx context.Context,
	timeout time.Duration,
	pluginName string,
	hookName string,
	sentinel error,
	logger *slog.Logger,
	hook lifecycleHook,
) error {
	if hook == nil {
		return nil
	}
	callCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		callCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	done := make(chan error, 1)
	go func() {
		var err error
		returned := false
		defer func() {
			if r := recover(); r != nil {
				logger.Error("plugin hook panicked",
					slog.String("plugin", pluginName),
					slog.String("hook", hookName),
					slog.String("panic_type", fmt.Sprintf("%T", r)),
				)
				if sentinel != nil {
					err = fmt.Errorf("%w: %w: plugin %q %s panicked (%T)", sentinel, proteus.ErrPanicked, pluginName, hookName, r)
				} else {
					err = fmt.Errorf("%w: plugin %q %s panicked (%T)", proteus.ErrPanicked, pluginName, hookName, r)
				}
			} else if !returned {
				err = fmt.Errorf("%w: plugin %q %s exited without returning", proteus.ErrHookExited, pluginName, hookName)
			}
			done <- err
		}()
		err = hook(callCtx)
		returned = true
	}()

	select {
	case err := <-done:
		if err == nil {
			return nil
		}
		if sentinel != nil {
			return fmt.Errorf("%w: %w", sentinel, err)
		}
		return err
	case <-callCtx.Done():
		ctxErr := callCtx.Err()
		logger.Warn("plugin hook exceeded timeout; abandoning blocked plugin goroutine",
			slog.String("plugin", pluginName),
			slog.String("hook", hookName),
			slog.Duration("timeout", timeout),
			slog.Any("err", ctxErr),
		)
		if sentinel != nil {
			return fmt.Errorf("%w: plugin %q %s timed out: %w", sentinel, pluginName, hookName, ctxErr)
		}
		return fmt.Errorf("plugin %q %s timed out: %w", pluginName, hookName, ctxErr)
	}
}

func checkDepSkew(logger *slog.Logger, pluginName string, depInfo *sdk.DepInfo, hostBIFn func() (*debug.BuildInfo, bool)) {
	if depInfo == nil || hostBIFn == nil {
		return
	}
	bi, ok := hostBIFn()
	if !ok || bi == nil {
		return
	}
	if depInfo.GoVersion != "" && bi.GoVersion != "" && depInfo.GoVersion != bi.GoVersion {
		logger.Warn("plugin Go toolchain version differs from host",
			slog.String("plugin", pluginName),
			slog.String("plugin_go", depInfo.GoVersion),
			slog.String("host_go", bi.GoVersion),
		)
	}
	hostDeps := make(map[string]string, len(bi.Deps))
	for _, d := range bi.Deps {
		if d == nil {
			continue
		}
		mod := d
		if mod.Replace != nil {
			mod = mod.Replace
		}
		hostDeps[mod.Path] = mod.Version
	}
	var mismatches []string
	for _, pd := range depInfo.Deps {
		if hostVer, exists := hostDeps[pd.Path]; exists && hostVer != pd.Version {
			mismatches = append(mismatches, fmt.Sprintf("%s: plugin=%s host=%s", pd.Path, pd.Version, hostVer))
		}
	}
	if len(mismatches) > 0 {
		logger.Warn("plugin shared dependencies differ from host build info",
			slog.String("plugin", pluginName),
			slog.Int("mismatch_count", len(mismatches)),
			slog.Any("mismatches", mismatches),
		)
	}
}
