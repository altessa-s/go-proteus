// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package signature

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"

	"github.com/altessa-s/go-proteus"
)

// MarshalManifest validates m and serializes it to deterministic JSON v2 bytes.
func MarshalManifest(m proteus.Manifest) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}

	data, err := json.Marshal(m, json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("%w: marshal manifest: %w", proteus.ErrManifestInvalid, err)
	}

	return data, nil
}

// UnmarshalManifest parses raw JSON bytes into a [proteus.Manifest] using strict JSON v2 rules
// (rejecting unknown members and duplicate member names) and validates all manifest fields.
func UnmarshalManifest(raw []byte) (proteus.Manifest, error) {
	var m proteus.Manifest

	err := json.Unmarshal(
		raw,
		&m,
		json.RejectUnknownMembers(true),
		jsontext.AllowDuplicateNames(false),
	)
	if err != nil {
		return proteus.Manifest{}, fmt.Errorf("%w: decode manifest: %w", proteus.ErrManifestInvalid, err)
	}

	if err := m.Validate(); err != nil {
		return proteus.Manifest{}, err
	}

	return m, nil
}
