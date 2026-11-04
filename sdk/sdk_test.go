// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package sdk

import (
	"errors"
	"fmt"
	"runtime/debug"
	"testing"
)

type customErr struct {
	code int
	msg  string
}

func (e *customErr) Error() string { return e.msg }

type asResponderErr struct {
	target *customErr
}

func (e *asResponderErr) Error() string { return "responder" }

func (e *asResponderErr) As(target any) bool {
	if p, ok := target.(**customErr); ok && e.target != nil {
		*p = e.target
		return true
	}

	return false
}

type multiUnwrapWithNil struct {
	children []error
}

func (e *multiUnwrapWithNil) Error() string   { return "multi" }
func (e *multiUnwrapWithNil) Unwrap() []error { return e.children }

func TestNewDepInfoFromBuild(t *testing.T) {
	t.Parallel()

	info := NewDepInfoFromBuild()
	if info.GoVersion == "" {
		t.Fatal("expected non-empty GoVersion from NewDepInfoFromBuild")
	}

	empty := depInfoFromBuildInfo(nil, false)
	if empty.GoVersion != "" || len(empty.Deps) != 0 {
		t.Fatalf("expected empty DepInfo when ReadBuildInfo fails, got %+v", empty)
	}

	bi := &debug.BuildInfo{
		GoVersion: "go1.27.3",
		Main:      debug.Module{Path: "example.com/plugin"},
		Deps: []*debug.Module{
			nil,
			{Path: "example.com/a", Version: "v1.0.0"},
			{
				Path:    "example.com/b",
				Version: "v1.0.0",
				Replace: &debug.Module{Path: "example.com/b-fork", Version: "v1.0.1"},
			},
		},
	}

	fromBI := depInfoFromBuildInfo(bi, true)
	if fromBI.GoVersion != "go1.27.3" || fromBI.MainPath != "example.com/plugin" {
		t.Fatalf("unexpected DepInfo header: %+v", fromBI)
	}

	m := fromBI.Map()
	if len(m) != 2 || m["example.com/a"] != "v1.0.0" || m["example.com/b-fork"] != "v1.0.1" {
		t.Fatalf("unexpected DepInfo.Map(): %v", m)
	}
}

func TestUnwrapAllAndAsViaUnwrapAll(t *testing.T) {
	t.Parallel()

	if got := UnwrapAll(nil); got != nil {
		t.Fatalf("expected nil for UnwrapAll(nil), got %v", got)
	}

	leaf1 := &customErr{code: 42, msg: "leaf1"}
	leaf2 := errors.New("leaf2")
	wrapped1 := fmt.Errorf("wrap1: %w", leaf1)
	joined := errors.Join(wrapped1, leaf2)
	withNil := &multiUnwrapWithNil{children: []error{nil, joined}}
	top := fmt.Errorf("top: %w", withNil)

	all := UnwrapAll(top)
	if len(all) != 6 {
		t.Fatalf("expected 6 errors in UnwrapAll, got %d: %v", len(all), all)
	}

	found, ok := AsViaUnwrapAll[*customErr](top)
	if !ok || found == nil || found.code != 42 {
		t.Fatalf("expected customErr{code:42}, got %v, %v", found, ok)
	}

	responder := fmt.Errorf("outer: %w", &asResponderErr{target: &customErr{code: 99, msg: "via-as"}})

	foundViaAs, ok := AsViaUnwrapAll[*customErr](responder)
	if !ok || foundViaAs == nil || foundViaAs.code != 99 {
		t.Fatalf("expected customErr{code:99} via As, got %v, %v", foundViaAs, ok)
	}

	if _, ok := AsViaUnwrapAll[*customErr](leaf2); ok {
		t.Fatal("expected false when target type is absent")
	}

	if _, ok := AsViaUnwrapAll[*customErr](nil); ok {
		t.Fatal("expected false for nil error")
	}
}
