// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package host

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/altessa-s/go-atlas-core/semver"
)

type version struct {
	semver.Version
	major int
}

func parseSemver(raw string) (version, error) {
	v, err := semver.Parse(strings.TrimSpace(raw))
	if err != nil {
		return version{}, err
	}

	// Proteus accepts only core version components that fit in an int.
	major, err := strconv.Atoi(v.Major)
	if err != nil {
		return version{}, fmt.Errorf("%w: invalid major version in %q", semver.ErrInvalid, raw)
	}

	if _, err := strconv.Atoi(v.Minor); err != nil {
		return version{}, fmt.Errorf("%w: invalid minor version in %q", semver.ErrInvalid, raw)
	}

	if _, err := strconv.Atoi(v.Patch); err != nil {
		return version{}, fmt.Errorf("%w: invalid patch version in %q", semver.ErrInvalid, raw)
	}

	return version{Version: v, major: major}, nil
}
