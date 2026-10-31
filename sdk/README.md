# sdk

Package `sdk` defines the minimal ABI and metadata types imported by Go `.so` plugins managed by `go-proteus`.

## Exported Symbols

Every plugin must export a `Descriptor` variable of type `sdk.Descriptor` or `*sdk.Descriptor`:

```go
package main

import (
	"context"

	"github.com/altessa-s/go-proteus/sdk"
)

var Descriptor = sdk.Descriptor{
	Name:        "my-plugin",
	Version:     "1.2.0",
	Description: "Example plugin",
}

var DepInfo = sdk.NewDepInfoFromBuild()

func Init(ctx context.Context) error {
	return nil
}

func Close(ctx context.Context) error {
	return nil
}
```

## Features

- **Zero external dependencies**: Imports only standard library packages (`errors`, `runtime/debug`).
- **SPI versioning**: `sdk.SPIVersion` declares contract major and minor versions for negotiation via `spi.Providers[T]`.
- **Dependency snapshots**: `sdk.NewDepInfoFromBuild()` captures embedded module versions so the host can warn on shared-dependency skew.
- **Error unwrapping**: `sdk.UnwrapAll` and `sdk.AsViaUnwrapAll[T]` flatten single and multi-error trees across plugin boundaries.
