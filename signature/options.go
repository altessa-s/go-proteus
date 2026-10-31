// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package signature

import "time"

//go:generate optgen generate --type=options

// DefaultMaxEnvelopeBytes is the default upper bound (64 KiB) for a detached .so.sig DSSE envelope.
const DefaultMaxEnvelopeBytes int64 = 64 << 10

type options struct {
	now              func() time.Time `optgen:"default=time.Now"`
	maxEnvelopeBytes int64            `optgen:"default=DefaultMaxEnvelopeBytes"`
}
