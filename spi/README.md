# spi

Package `spi` provides typed Service Provider Interface (SPI) negotiation (`Providers[T]`) and panic-isolated plugin invocation (`Guard`).

## Usage

```go
for greeter, p := range spi.Providers[Greeter](mgr, "Greeter", spi.WithMajor(1), spi.WithMinMinor(0)) {
	err := spi.Guard(ctx, p.Name(), func(ctx context.Context) error {
		return greeter.Greet(ctx, "world")
	})
	if err != nil {
		// Handle error or proteus.ErrPanicked
	}
}
```

`WithMajor(0)` explicitly requires major zero. `WithMinMinor(n)` works independently of a major constraint. Internally, -1 denotes an omitted constraint; valid version components are nonnegative.
