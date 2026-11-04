// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package host

import (
	"context"
	"fmt"

	"github.com/altessa-s/go-proteus"
)

// Quarantine removes name from the active registry and releases this manager's ownership.
// The failed entity and digest remain visible for diagnosis. Clearing quarantine does not
// permit a terminal mapped image to be initialized again.
func (m *Manager) Quarantine(name string) error {
	m.loadMu.Lock()
	defer m.loadMu.Unlock()

	now := m.now()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return proteus.ErrClosed
	}

	entry, ok := m.ready[name]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("%w: %s", proteus.ErrNotFound, name)
	}

	reason := fmt.Errorf("%w: runtime failure in %s", proteus.ErrQuarantined, name)
	delete(m.ready, name)
	delete(m.loadedHashes, entry.plugin.SHA256())
	entry.setState(proteus.StateFailed, reason)
	m.failed[name] = entry.plugin
	q, _ := m.quarantine.add(entry.plugin.Source(), entry.plugin.SHA256(), reason, now)
	stats := m.statsLocked()
	m.mu.Unlock()

	err := entry.release(context.Background())

	m.observer.Quarantined(q)
	m.observer.RegistryChanged(stats)

	return err
}
