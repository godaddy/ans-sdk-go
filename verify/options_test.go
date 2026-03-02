package verify

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := defaultConfig()

	if cfg.dnsResolver == nil {
		t.Error("expected non-nil dnsResolver")
	}
	if cfg.tlogClient == nil {
		t.Error("expected non-nil tlogClient")
	}
	if cfg.cache != nil {
		t.Error("expected nil cache by default")
	}
	if cfg.failurePolicy != FailClosed {
		t.Errorf("expected FailClosed, got %v", cfg.failurePolicy)
	}
	if cfg.urlValidator == nil {
		t.Error("expected non-nil urlValidator by default")
	}
	if cfg.daneResolver != nil {
		t.Error("expected nil daneResolver by default")
	}
}

func TestWithDNSResolver(t *testing.T) {
	mock := NewMockDNSResolver()
	cfg := defaultConfig()
	WithDNSResolver(mock)(cfg)
	if cfg.dnsResolver != mock {
		t.Error("expected custom DNS resolver to be set")
	}
}

func TestWithTlogClient(t *testing.T) {
	mock := NewMockTransparencyLogClient()
	cfg := defaultConfig()
	WithTlogClient(mock)(cfg)
	if cfg.tlogClient != mock {
		t.Error("expected custom tlog client to be set")
	}
}

func TestWithCache(t *testing.T) {
	cache := NewBadgeCache(DefaultCacheConfig())
	cfg := defaultConfig()
	WithCache(cache)(cfg)
	if cfg.cache != cache {
		t.Error("expected cache to be set")
	}
}

func TestWithCacheConfig(t *testing.T) {
	cfg := defaultConfig()
	WithCacheConfig(DefaultCacheConfig())(cfg)
	if cfg.cache == nil {
		t.Error("expected cache to be created from config")
	}
}

func TestWithFailurePolicy(t *testing.T) {
	cfg := defaultConfig()
	WithFailurePolicy(FailOpen)(cfg)
	if cfg.failurePolicy != FailOpen {
		t.Errorf("expected FailOpen, got %v", cfg.failurePolicy)
	}
}

func TestWithFailurePolicyConfig(t *testing.T) {
	cfg := defaultConfig()
	policyCfg := FailurePolicyConfig{MaxStaleness: 30 * time.Minute}
	WithFailurePolicyConfig(policyCfg)(cfg)
	if cfg.failurePolicyConfig.MaxStaleness != 30*time.Minute {
		t.Errorf("expected MaxStaleness 30m, got %v", cfg.failurePolicyConfig.MaxStaleness)
	}
}

func TestWithTrustedRADomains(t *testing.T) {
	cfg := defaultConfig()
	WithTrustedRADomains([]string{"example.com", "test.com"})(cfg)
	if cfg.urlValidator == nil {
		t.Error("expected urlValidator to be set")
	}
}

func TestWithoutURLValidation(t *testing.T) {
	cfg := defaultConfig()
	WithoutURLValidation()(cfg)
	if cfg.urlValidator != nil {
		t.Error("expected urlValidator to be nil")
	}
}

func TestWithDANEResolver_Option(t *testing.T) {
	mock := NewMockDANEResolver()
	cfg := defaultConfig()
	WithDANEResolver(mock)(cfg)
	if cfg.daneResolver != mock {
		t.Error("expected DANE resolver to be set")
	}
}
