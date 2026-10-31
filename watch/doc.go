// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Package watch implements an [fsnotify]-backed directory watcher that coalesces .so and .so.sig
// filesystem events over a quiet settle window before triggering [Reloader.Reload].
package watch
