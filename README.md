# go-proteus

`github.com/altessa-s/go-proteus` is a standalone Go library and CLI for admitting, verifying, loading, and supervising dynamic Go `.so`
plugins.

## Features

- **Fail-Closed Admission Pipeline**: Verifies detached Dead Simple Signing Envelope (DSSE) v1 signatures over a strict JSON v2 manifest
  *before* calling `dlopen` (`plugin.Open`).
- **Modern Cryptography Policy**: Supports Ed25519 (default) and ECDSA P-256 keys with 32-character key IDs (first 16 bytes of SHA-256 of SPKI DER), key validity windows, and
  optional manifest expiration (`notAfter`). Rejects RSA and legacy raw `.sig` files.
- **Confined Filesystem Discovery**: `dirsource` uses `os.Root` (`files.OpenRootDir` and `files.OpenRegularIn`) to prevent symlink escapes,
  FIFO stalls (`O_NONBLOCK`), and group/world-writable plugin files.
- **Streaming Snapshot Isolation**: `goloader` streams `.so` bytes to a private `0o600` snapshot, re-hashes from disk to close TOCTOU
  windows, caches handles by SHA-256, and contains panics in package `init()` functions.
- **Bounded Initialization & Quarantine**: `host.Manager` supervises `Init(ctx)` with a watchdog timer so a hung plugin cannot block the
  host, isolates failed plugins from the active registry, and quarantines failing content hashes.
- **Typed SPI Negotiation**: `spi.Providers[T]` resolves and version-checks exported plugin symbols, while `spi.Guard` isolates panics in
  post-load plugin calls.
- **Quiet Settle Watcher**: `watch.Watcher` coalesces `.so` and `.so.sig` filesystem events over a configurable quiet window before
  triggering `Reload`.

## Packages

| Package | Description |
|---|---|
| `proteus` (`.`) | Core entities (`Plugin`, `Manifest`, `State`), reports, health types, sentinel errors, and ports (`Source`, `Opener`, `Verifier`, `Observer`). |
| `sdk` | Minimal zero-dependency contract imported by plugin authors (`Descriptor`, `SPIVersion`, `DepInfo`, `UnwrapAll`). |
| `signature` | DSSE v1 PAE codec, strict JSON v2 manifest codec, `KeySet`, and `Verifier`. |
| `host` | `Manager` orchestrating admission, lifecycle, quarantine, health, and reload. |
| `spi` | Generic `Providers[T]` negotiation and `Guard` panic wrapper. |
| `dirsource` | `os.Root`-confined directory `Source` adapter. |
| `goloader` | Snapshot-isolating `Opener` adapter over stdlib `plugin`. |
| `watch` | `fsnotify` watcher with quiet settle window triggering `Reloader.Reload`. |
| `signing` | Manifest builder, DSSE signer, and Ed25519 / ECDSA P-256 key generator. |
| `proteustest` | In-memory fakes (`Source`, `Opener`, `Symbols`, `Observer`), signing helpers, and `BuildPlugin`. |
| `cmd/proteus` | Cobra CLI (`keygen`, `sign`, `verify`, `inspect`). |

## Quick Start

```go
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/altessa-s/go-proteus/dirsource"
	"github.com/altessa-s/go-proteus/goloader"
	"github.com/altessa-s/go-proteus/host"
	"github.com/altessa-s/go-proteus/signature"
)

func run(ctx context.Context, pubKeyPEM []byte) error {
	key, err := signature.ParsePublicKeyPEM(pubKeyPEM)
	if err != nil {
		return err
	}
	keys, err := signature.NewKeySet(key)
	if err != nil {
		return err
	}
	verifier, err := signature.NewVerifier(keys)
	if err != nil {
		return err
	}
	src, err := dirsource.New("/var/lib/myapp/plugins")
	if err != nil {
		return err
	}
	opener, err := goloader.New("/var/run/myapp/plugin-snapshots")
	if err != nil {
		return err
	}
	mgr, err := host.New(src, opener,
		host.WithVerifier(verifier),
		host.WithLogger(slog.New(slog.NewJSONHandler(os.Stderr, nil))),
	)
	if err != nil {
		return err
	}
	defer mgr.Close(ctx)

	report, err := mgr.Load(ctx)
	if err != nil {
		return err
	}
	_ = report
	return nil
}
```

## Process Hardening at Service Startup

Because Go `.so` plugins execute in-process, kernel-level process hardening (`PR_SET_NO_NEW_PRIVS`, resource limits, and seccomp filters)
is a process-wide startup concern rather than a lazy side effect of loading a plugin. Host services should apply hardening at the beginning
of `main()` using `github.com/altessa-s/go-atlas-core` before starting worker goroutines or calling `mgr.Load(ctx)`:

1. `nonewprivs.Set()` (`github.com/altessa-s/go-atlas-core/runtime/nonewprivs`) — prevent privilege escalation across `execve`.
2. `rlimits.Apply(...)` (`github.com/altessa-s/go-atlas-core/runtime/rlimits`) — bound core dumps, open file descriptors, and address space.
3. `seccomp.BlockDangerousSyscalls()` (`github.com/altessa-s/go-atlas-core/runtime/seccomp`) — install the seccomp-bpf filter on Linux.

See [ADR 0005](docs/adr/0005-process-hardening-at-startup.md) for rationale.

## CLI (`cmd/proteus`)

```bash
# Generate an Ed25519 signing key pair
proteus keygen --alg ed25519 --out-private signing.key --out-public signing.pub

# Sign a compiled plugin .so and write <plugin>.so.sig atomically
proteus sign --key signing.key --name greeter --version 1.0.0 ./greeter.so

# Verify a .so and .so.sig pair against one or more public keys
proteus verify --key signing.pub ./greeter.so

# Inspect a .so.sig envelope or .so binary
proteus inspect ./greeter.so.sig
```
