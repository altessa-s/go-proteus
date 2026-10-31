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

## Lifecycle ownership and callbacks

For `Opened.Mapped` images, managers acquire process-wide references keyed by digest. `Init` runs once;
`Close` runs when the last owner releases. A failed Init or last release is terminal for that image.
A new manager cannot initialize it again and receives an `ErrAlreadyLoaded`-style admission failure
after unload. Each waiting manager applies its own `WithInitTimeout` and caller context to shared
initialization. Abandoning that wait reports cancellation or timeout without quarantining the digest
or canceling the owning manager’s Init; the waiter can retry while the owner retains the image.
Non-mapped test loaders retain isolated lifecycle behavior.

Discovery and admission are serialized separately from registry reads. Observers and Init hooks may
call `Get`, `All`, and `Failed`; callbacks must not synchronously initiate another Load, Close, Unload,
or Quarantine on the same manager, since those operations share admission serialization.

`Quarantine(name)` atomically removes an active entry, records the failed entity and its digest,
releases ownership, and emits quarantine and registry telemetry. Plugin values expose no lifecycle
mutators; only their manager retains the mutation capability. Clearing quarantine does not reset a
terminal mapped image. Admission failures without a trustworthy name use `source:<candidate ID>`.
Failures remain diagnostic records until a successful admission replaces that source (or name).
Temporary storage failures appear in `Failed()` and health but do not quarantine the signed digest.
Minimum versions use semantic-version prerelease precedence; build metadata has no precedence.
