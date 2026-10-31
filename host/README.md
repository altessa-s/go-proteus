# host

Package `host` provides `Manager`, the application-layer orchestrator for admitting, initializing, supervising, and unloading dynamic Go
plugins.

## Admission Pipeline

1. **Candidate discovery**: Queries `proteus.Source.Candidates(ctx)`.
2. **Pre-open signature & policy checks**: In the default fail-closed mode (`proteus.UnsignedReject`), verifies the detached DSSE signature
   via `proteus.Verifier` and checks `Manifest` platform (`GOOS`/`GOARCH`), revocation list, quarantine set, allow/deny list, duplicate
   plugin names, host major version, and minimum plugin version *before* calling `Opener.Open`.
3. **Binary open & descriptor verification**: Opens the artifact via `proteus.Opener.Open`, resolves `sdk.Descriptor`, and verifies that
   `Descriptor.Name` and `Descriptor.Version` match the signed `Manifest`.
4. **Bounded `Init`**: Runs optional `Init(ctx)` on a supervised goroutine with `WithInitTimeout` so a blocked plugin cannot stall the host.
5. **Registry & Quarantine**: Ready plugins enter the active registry (`Get`, `All`, `LookupAll`); failed plugins enter `Failed()` and their
   content SHA-256 is added to quarantine (`Quarantined()`).
