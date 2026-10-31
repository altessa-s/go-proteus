// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package signature

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"strconv"

	"github.com/altessa-s/go-proteus"
)

// Envelope is a Dead Simple Signing Envelope (DSSE) v1 JSON container.
type Envelope struct {
	// PayloadType identifies the format of Payload; must equal [proteus.ManifestPayloadType].
	PayloadType string `json:"payloadType"`

	// Payload is the standard base64 encoding of the serialized [proteus.Manifest] JSON.
	Payload string `json:"payload"`

	// Signatures holds one or more key-attributed signatures over the DSSE PAE.
	Signatures []Entry `json:"signatures"`
}

// Entry is a single signature inside a DSSE [Envelope].
type Entry struct {
	// KeyID is the 64-character lowercase hex SHA-256 PKIX identifier of the signing key.
	KeyID string `json:"keyid"`

	// Sig is the standard base64 encoding of the raw Ed25519 or ASN.1 DER ECDSA P-256 signature.
	Sig string `json:"sig"`
}

// PAE computes the DSSE v1 Pre-Authentication Encoding for payloadType and decoded payload bytes:
//
//	"DSSEv1 " + len(payloadType) + " " + payloadType + " " + len(payload) + " " + payload
//
// Lengths are decimal ASCII byte counts.
func PAE(payloadType string, payload []byte) []byte {
	ptLen := strconv.Itoa(len(payloadType))
	pLen := strconv.Itoa(len(payload))
	total := len("DSSEv1 ") + len(ptLen) + 1 + len(payloadType) + 1 + len(pLen) + 1 + len(payload)
	buf := make([]byte, 0, total)
	buf = append(buf, "DSSEv1 "...)
	buf = append(buf, ptLen...)
	buf = append(buf, ' ')
	buf = append(buf, payloadType...)
	buf = append(buf, ' ')
	buf = append(buf, pLen...)
	buf = append(buf, ' ')
	buf = append(buf, payload...)
	return buf
}

// MarshalEnvelope serializes env to deterministic JSON v2 bytes after validating its structure.
func MarshalEnvelope(env Envelope) ([]byte, error) {
	if err := validateEnvelope(env); err != nil {
		return nil, err
	}
	data, err := json.Marshal(env, json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("%w: marshal envelope: %w", proteus.ErrSignatureInvalid, err)
	}
	return data, nil
}

// UnmarshalEnvelope parses and validates a DSSE v1 JSON envelope using strict JSON v2 rules
// (rejecting unknown members and duplicate member names).
func UnmarshalEnvelope(raw []byte) (Envelope, error) {
	var env Envelope
	err := json.Unmarshal(
		raw,
		&env,
		json.RejectUnknownMembers(true),
		jsontext.AllowDuplicateNames(false),
	)
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: decode DSSE envelope: %w", proteus.ErrSignatureInvalid, err)
	}
	if err := validateEnvelope(env); err != nil {
		return Envelope{}, err
	}
	return env, nil
}

func validateEnvelope(env Envelope) error {
	if env.PayloadType != proteus.ManifestPayloadType {
		return fmt.Errorf("%w: unexpected payloadType %q", proteus.ErrSignatureInvalid, env.PayloadType)
	}
	if env.Payload == "" {
		return fmt.Errorf("%w: empty DSSE payload", proteus.ErrSignatureInvalid)
	}
	if len(env.Signatures) == 0 {
		return fmt.Errorf("%w: DSSE envelope contains no signatures", proteus.ErrSignatureInvalid)
	}
	for i, s := range env.Signatures {
		if s.KeyID == "" {
			return fmt.Errorf("%w: signature[%d] has empty keyid", proteus.ErrSignatureInvalid, i)
		}
		if s.Sig == "" {
			return fmt.Errorf("%w: signature[%d] has empty sig", proteus.ErrSignatureInvalid, i)
		}
	}
	return nil
}
