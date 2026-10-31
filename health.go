// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package proteus

// HealthStatus represents the aggregate or per-plugin operational status.
type HealthStatus int32

const (
	// StatusServing indicates that all plugins are operational and no failures are present.
	StatusServing HealthStatus = iota + 1

	// StatusDegraded indicates that at least one plugin is ready, but one or more plugins have failed.
	StatusDegraded

	// StatusNotServing indicates that no plugins are ready and at least one plugin has failed, or the manager is closed.
	StatusNotServing
)

// String returns the lowercase name of the health status.
func (s HealthStatus) String() string {
	switch s {
	case StatusServing:
		return "serving"
	case StatusDegraded:
		return "degraded"
	case StatusNotServing:
		return "not_serving"
	default:
		return "unknown"
	}
}

// PluginHealth describes the health of an individual plugin tracked by the manager.
type PluginHealth struct {
	// Name is the unique plugin name (or source identifier if the plugin failed before name resolution).
	Name string

	// State is the lifecycle state ([StateReady] or [StateFailed]).
	State State

	// Status is the health status derived from State and the optional HealthCheck probe.
	Status HealthStatus

	// Err is the initialization or HealthCheck error when Status is not [StatusServing].
	Err error
}

// HealthReport summarizes the operational health of the plugin manager.
type HealthReport struct {
	// Status is the aggregate health status of the manager.
	Status HealthStatus

	// Ready is the count of operational plugins in [StateReady] whose health probe succeeded.
	Ready int

	// Failed is the count of plugins in [StateFailed] or failing their health probe.
	Failed int

	// Quarantined is the count of binary hashes currently held in quarantine.
	Quarantined int

	// Plugins contains per-plugin health details sorted by Name.
	Plugins []PluginHealth
}
