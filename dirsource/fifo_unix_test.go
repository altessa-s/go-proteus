// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

//go:build linux || darwin

package dirsource_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/altessa-s/go-proteus/dirsource"
)

func TestFollowSymlinksRejectsFIFO(t *testing.T) {
	t.Parallel()
	for _, signature := range []bool{false, true} {
		for _, link := range []bool{false, true} {
			dir := createSecureDir(t)
			name := "p.so"
			if signature {
				writeSecureFile(t, filepath.Join(dir, name), []byte("plugin"))
				name += ".sig"
			}
			fifo := name
			if link {
				fifo = "pipe"
			}
			if err := syscall.Mkfifo(filepath.Join(dir, fifo), 0o600); err != nil {
				t.Fatal(err)
			}
			if link {
				if err := os.Symlink(fifo, filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			}
			source, err := dirsource.New(dir, dirsource.WithFollowSymlinks())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := source.Candidates(t.Context()); err == nil {
				t.Fatalf("accepted FIFO signature=%v link=%v", signature, link)
			}
		}
	}
}
