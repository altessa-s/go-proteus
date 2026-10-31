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

Providers accept direct symbols and dereference one exported-variable pointer, including `var Greeter = &greeterImpl{}`.
Nil interfaces and typed nil provider values are skipped with `proteus.ErrInvalidSymbol`.

`Guard` errors report the panic type without its value. An explicitly configured `WithOnPanic` callback receives the raw value and stack; callers control how that sensitive diagnostic data is handled.
