// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package signing

import "time"

//go:generate optgen generate --type=options

type options struct {
	goos      string
	goarch    string
	hostMajor int
	issuedAt  time.Time
	notAfter  time.Time
	ttl       time.Duration
	now       func() time.Time `optgen:"default=time.Now"`
}
