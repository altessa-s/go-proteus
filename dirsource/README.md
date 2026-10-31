# dirsource

Package `dirsource` implements `proteus.Source` over a filesystem directory confined with `os.Root` (`go-atlas-core/io/files`).

## Security Properties

- **Confined Root**: Uses `files.OpenRootDir` and `files.OpenRegularIn` (`O_NONBLOCK` on Unix to prevent FIFO stalls).
- **Symlink Refusal**: Refuses symlinks for the directory, `.so` files, and `.so.sig` files unless `WithFollowSymlinks()` is explicitly set
  (even then, `os.Root` prevents escaping the directory root).
- **Permission Checks**: Rejects directories, `.so` files, or `.so.sig` files writable by group or others (`mode & 0o022 != 0`) unless
  `WithSkipPermissionChecks()` is set.
- **Bounded Reads**: Enforces `WithMaxSignatureBytes` (default 64 KiB) and `WithMaxArtifactBytes` (default 256 MiB).
