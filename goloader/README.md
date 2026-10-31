# goloader

Package `goloader` implements `proteus.Opener` over the Go standard library `plugin` package (`linux` and `darwin` with `cgo`; returns
`proteus.ErrUnsupportedPlatform` elsewhere).

## Features

- **Streaming Snapshot Isolation**: Streams `.so` bytes directly to a temporary `0o600` snapshot file while hashing with
  `hash.NewSHA256Hasher()`, then re-hashes the snapshot file from disk (`proteus.ErrSnapshotModified` on mismatch) without buffering the
  entire binary in memory (fixes Defect 14).
- **Package `init()` Panic Containment**: Wraps `plugin.Open` in local recovery so a panic inside a plugin's package `init()`
  is recovered, converted into `proteus.ErrPanicked`, and cached as an error result rather than crashing the host or re-panicking on
  subsequent attempts (fixes Defect 1).
- **Content-Addressed Handle Cache**: Caches opened plugin handles by SHA-256 so updated plugin binaries with new content hashes open from
  distinct snapshot paths.

All real openers share one process-wide cache by digest, including terminal package-init failures.
The registry lock only reserves and publishes per-digest entries; package initializers run outside it.
Different digests can open concurrently (including nested opens), and same-digest waiters can cancel
without changing the shared result. Injected `WithOpenFunc` loaders have isolated caches. Both the signed digest and positive signed size
are checked before the low-level loader executes. Temporary snapshot/storage failures are retryable;
`Opened.ContentFailure` identifies terminal loader failures attributable to verified bytes.
Each load attempt retains its exclusively created snapshot pathname until cleanup; independent openers and processes can share a workDir
without replacing or removing one another’s snapshots. Snapshots are unlinked after the loader returns on success or failure;
cached handles remain mapped.

Panic diagnostics include the recovered type, never its value. Recovery does not invoke process-wide panic handlers.
