// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package host

import (
	"cmp"
	"fmt"
	"strconv"
	"strings"
)

type semver struct {
	major int
	minor int
	patch int
	pre   []string
}

func parseSemver(raw string) (semver, error) {
	s := strings.TrimPrefix(strings.TrimSpace(raw), "v")
	if s == "" {
		return semver{}, fmt.Errorf("empty version string")
	}

	base, build, hasBuild := strings.Cut(s, "+")
	if hasBuild && !validIdentifiers(build, false) {
		return semver{}, fmt.Errorf("invalid build metadata %q", raw)
	}

	s, prerelease, hasPre := strings.Cut(base, "-")

	var pre []string

	if hasPre {
		if !validIdentifiers(prerelease, true) {
			return semver{}, fmt.Errorf("invalid prerelease %q", raw)
		}

		pre = strings.Split(prerelease, ".")
	}

	const (
		semverMinParts = 3
		semverMaxParts = 3
	)

	parts := strings.Split(s, ".")
	for _, part := range parts {
		if !numericIdentifier(part) || (len(part) > 1 && part[0] == '0') {
			return semver{}, fmt.Errorf("invalid version %q", raw)
		}
	}

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

	return semver{major: major, minor: minor, patch: patch, pre: pre}, nil
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

	if len(v.pre) == 0 && len(other.pre) != 0 {
		return 1
	}

	if len(other.pre) == 0 && len(v.pre) != 0 {
		return -1
	}

	for i := 0; i < len(v.pre) && i < len(other.pre); i++ {
		a, b := v.pre[i], other.pre[i]
		if a == b {
			continue
		}

		an, bn := numericIdentifier(a), numericIdentifier(b)
		if an && !bn {
			return -1
		}

		if !an && bn {
			return 1
		}

		if an && bn && len(a) != len(b) {
			return cmp.Compare(len(a), len(b))
		}

		return cmp.Compare(a, b)
	}

	return cmp.Compare(len(v.pre), len(other.pre))
}

func numericIdentifier(s string) bool {
	if s == "" {
		return false
	}

	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}

	return true
}

func validIdentifiers(s string, prerelease bool) bool {
	for part := range strings.SplitSeq(s, ".") {
		if part == "" {
			return false
		}

		for _, c := range part {
			valid := c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-'
			if !valid {
				return false
			}
		}

		if prerelease && numericIdentifier(part) && len(part) > 1 && part[0] == '0' {
			return false
		}
	}

	return true
}
