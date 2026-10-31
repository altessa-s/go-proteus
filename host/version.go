// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package host

import (
	"fmt"
	"strconv"
	"strings"
)

type semver struct {
	major int
	minor int
	patch int
}

func parseSemver(raw string) (semver, error) {
	s := strings.TrimPrefix(strings.TrimSpace(raw), "v")
	if s == "" {
		return semver{}, fmt.Errorf("empty version string")
	}
	// Strip build metadata (+...) and pre-release (-...) suffixes for numeric comparison.
	if idx := strings.IndexByte(s, '+'); idx >= 0 {
		s = s[:idx]
	}
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		s = s[:idx]
	}
	const (
		semverMinParts = 2
		semverMaxParts = 3
	)
	parts := strings.Split(s, ".")
	if len(parts) < semverMinParts || len(parts) > semverMaxParts {
		return semver{}, fmt.Errorf("invalid semantic version %q", raw)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil || major < 0 {
		return semver{}, fmt.Errorf("invalid major version in %q", raw)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil || minor < 0 {
		return semver{}, fmt.Errorf("invalid minor version in %q", raw)
	}
	patch := 0
	if len(parts) == semverMaxParts {
		patch, err = strconv.Atoi(parts[2])
		if err != nil || patch < 0 {
			return semver{}, fmt.Errorf("invalid patch version in %q", raw)
		}
	}
	return semver{major: major, minor: minor, patch: patch}, nil
}

func (v semver) compare(other semver) int {
	if v.major != other.major {
		if v.major < other.major {
			return -1
		}
		return 1
	}
	if v.minor != other.minor {
		if v.minor < other.minor {
			return -1
		}
		return 1
	}
	if v.patch != other.patch {
		if v.patch < other.patch {
			return -1
		}
		return 1
	}
	return 0
}
