// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

//go:build integration && cgo

package proteustest_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/altessa-s/go-proteus/proteustest"
)

func TestBuildPluginFreshArtifact(t *testing.T) {
	t.Parallel()

	pkgDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pkgDir, "go.mod"), []byte("module example.com/testplugin\n\ngo 1.27\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	src := `package main

import "example.com/testplugin/helper"
var Exported = helper.Value
`
	if err := os.WriteFile(filepath.Join(pkgDir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	helper := filepath.Join(pkgDir, "helper")
	if err := os.Mkdir(helper, 0o700); err != nil {
		t.Fatal(err)
	}

	helperFile := filepath.Join(helper, "value.go")
	if err := os.WriteFile(helperFile, []byte("package helper; const Value = \"before\""), 0o600); err != nil {
		t.Fatal(err)
	}

	so1 := proteustest.BuildPlugin(t, pkgDir)
	if err := os.WriteFile(helperFile, []byte("package helper; const Value = \"after\""), 0o600); err != nil {
		t.Fatal(err)
	}

	so2 := proteustest.BuildPlugin(t, pkgDir)
	if so1 == so2 {
		t.Fatalf("expected distinct isolated paths per call, got %q", so1)
	}

	first, err := os.ReadFile(so1)
	if err != nil {
		t.Fatal(err)
	}

	second, err := os.ReadFile(so2)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(first, second) {
		t.Fatal("reused stale dependency")
	}

	info1, err := os.Stat(so1)
	if err != nil || info1.Size() == 0 {
		t.Fatalf("invalid built plugin %q: %v", so1, err)
	}
}
