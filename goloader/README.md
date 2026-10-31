# goloader

Package `goloader` implements `proteus.Opener` over the Go standard library `plugin` package (`linux` and `darwin` with `cgo`; returns
`proteus.ErrUnsupportedPlatform` elsewhere).

## Features

- **Streaming Snapshot Isolation**: Streams `.so` bytes directly to a temporary `0o600` snapshot file while hashing with
  `hash.NewSHA256Hasher()`, then re-hashes the snapshot file from disk (`proteus.ErrSnapshotModified` on mismatch) without buffering the
  entire binary in memory (fixes Defect 14).
- **Package `init()` Panic Containment**: Wraps `plugin.Open` in `panics.HandleWithOpts` so a panic inside a plugin's package `init()`
  is recovered, converted into `proteus.ErrPanicked`, and cached as an error result rather than crashing the host or re-panicking on
  subsequent attempts (fixes Defect 1).
- **Content-Addressed Handle Cache**: Caches opened plugin handles by SHA-256 so updated plugin binaries with new content hashes open from
  distinct snapshot paths.
