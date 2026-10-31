# proteustest

```go
import "github.com/altessa-s/go-proteus/proteustest"
```

Package `proteustest` provides in-memory test doubles (`MemSource`, `MemOpener`, `MapSymbols`, `RecordingObserver`), signing helpers (`MustGenerateKey`, `SignedCandidate`), fixture `.so` builders (`BuildPlugin`), and goroutine leak checks (`GoroutineLeaks`).

`BuildPlugin` builds into fresh per-test output paths and relies on the Go build cache to track all dependencies. Native build tests require `integration && cgo`; race and coverage flags mirror the test binary, and cgo is never forced on.
