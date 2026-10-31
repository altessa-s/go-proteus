# watch

Package `watch` provides an `fsnotify` directory watcher (`Watcher`) that triggers `Reloader.Reload(ctx)` after a quiet settle window
(`WithSettle`, default `200ms`).

## Settle Protocol

Copying a `.so` file and its `.so.sig` companion into a watched directory produces multiple `Create`, `Write`, and `Rename` events.
`Watcher` resets its settle timer on every `.so` or `.so.sig` event and calls `Reload` only after the directory has remained quiet for the
full settle duration, preventing mid-copy hash or missing-signature errors (fixes Defect 15).
