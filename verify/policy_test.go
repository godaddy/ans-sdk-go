package verify

import (
	"testing"
	"time"
)

func TestDefaultFailurePolicyConfig(t *testing.T) {
	cfg := DefaultFailurePolicyConfig()

	expectedStaleness := 10 * time.Minute
	if cfg.MaxStaleness != expectedStaleness {
		t.Errorf("MaxStaleness = %v, want %v", cfg.MaxStaleness, expectedStaleness)
	}
}

func TestFailurePolicy_Constants(t *testing.T) {
	tests := []struct {
		name   string
		policy FailurePolicy
		want   int
	}{
		{"FailClosed", FailClosed, 0},
		{"FailOpenWithCache", FailOpenWithCache, 1},
		{"FailOpen", FailOpen, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if int(tt.policy) != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.policy, tt.want)
			}
		})
	}
}
