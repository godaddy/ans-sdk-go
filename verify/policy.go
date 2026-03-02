package verify

import "time"

// Default failure policy configuration values.
const defaultMaxStalenessMinutes = 10

// FailurePolicy defines behavior when DNS or transparency log is unavailable.
type FailurePolicy int

const (
	// FailClosed rejects on any failure (most secure, default).
	FailClosed FailurePolicy = iota
	// FailOpenWithCache uses cached badge if available, otherwise rejects.
	FailOpenWithCache
	// FailOpen accepts without verification (not recommended).
	FailOpen
)

// FailurePolicyConfig holds configuration for FailOpenWithCache policy.
type FailurePolicyConfig struct {
	// MaxStaleness is the maximum age of a cached badge to accept.
	MaxStaleness time.Duration
}

// DefaultFailurePolicyConfig returns the default failure policy configuration.
func DefaultFailurePolicyConfig() FailurePolicyConfig {
	return FailurePolicyConfig{
		MaxStaleness: defaultMaxStalenessMinutes * time.Minute,
	}
}
