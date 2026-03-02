package verify

// Option configures a verifier.
type Option func(*verifierConfig)

// verifierConfig holds the configuration for verifiers.
type verifierConfig struct {
	dnsResolver         DNSResolver
	tlogClient          TransparencyLogClient
	cache               *BadgeCache
	failurePolicy       FailurePolicy
	failurePolicyConfig FailurePolicyConfig
	urlValidator        *URLValidator
	daneResolver        DANEResolver
}

// defaultConfig returns the default verifier configuration.
func defaultConfig() *verifierConfig {
	return &verifierConfig{
		dnsResolver:         NewStandardDNSResolver(),
		tlogClient:          NewHTTPTransparencyLogClient(),
		cache:               nil,
		failurePolicy:       FailClosed,
		failurePolicyConfig: DefaultFailurePolicyConfig(),
		urlValidator:        NewDefaultURLValidator(),
	}
}

// WithDNSResolver sets a custom DNS resolver.
func WithDNSResolver(r DNSResolver) Option {
	return func(c *verifierConfig) {
		c.dnsResolver = r
	}
}

// WithTlogClient sets a custom transparency log client.
func WithTlogClient(t TransparencyLogClient) Option {
	return func(c *verifierConfig) {
		c.tlogClient = t
	}
}

// WithCache sets a badge cache.
func WithCache(cache *BadgeCache) Option {
	return func(c *verifierConfig) {
		c.cache = cache
	}
}

// WithCacheConfig creates and sets a badge cache with the given configuration.
func WithCacheConfig(cfg CacheConfig) Option {
	return func(c *verifierConfig) {
		c.cache = NewBadgeCache(cfg)
	}
}

// WithFailurePolicy sets the failure policy for DNS/TLog errors.
func WithFailurePolicy(policy FailurePolicy) Option {
	return func(c *verifierConfig) {
		c.failurePolicy = policy
	}
}

// WithFailurePolicyConfig sets the failure policy configuration.
func WithFailurePolicyConfig(cfg FailurePolicyConfig) Option {
	return func(c *verifierConfig) {
		c.failurePolicyConfig = cfg
	}
}

// WithTrustedRADomains sets custom trusted RA domains for URL validation.
func WithTrustedRADomains(domains []string) Option {
	return func(c *verifierConfig) {
		c.urlValidator = NewURLValidator(domains)
	}
}

// WithoutURLValidation disables badge URL domain validation.
func WithoutURLValidation() Option {
	return func(c *verifierConfig) {
		c.urlValidator = nil
	}
}

// WithDANEResolver enables DANE/TLSA verification using the given resolver.
// When set, the verifier performs an additional DANE check after badge verification.
// DANE rejection (fingerprint mismatch or DNSSEC failure) overrides a successful badge check.
func WithDANEResolver(d DANEResolver) Option {
	return func(c *verifierConfig) {
		c.daneResolver = d
	}
}
