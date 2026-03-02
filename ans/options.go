package ans

import (
	"net/http"
	"time"
)

const (
	// DefaultTimeout is the default HTTP client timeout
	DefaultTimeout = 120 * time.Second
)

// Option is a functional option for configuring ANS clients
type Option func(*clientConfig) error

// clientConfig holds the configuration for ANS clients
type clientConfig struct {
	baseURL    string
	httpClient *http.Client
	authHeader string // Can be "sso-jwt <token>" or "sso-key <key>:<secret>"
	verbose    bool
	timeout    time.Duration
}

// defaultConfig returns the default client configuration
func defaultConfig() *clientConfig {
	return &clientConfig{
		baseURL: "https://api.godaddy.com",
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		verbose: false,
		timeout: DefaultTimeout,
	}
}

// WithBaseURL sets the base URL for the API
func WithBaseURL(baseURL string) Option {
	return func(c *clientConfig) error {
		c.baseURL = baseURL
		return nil
	}
}

// WithJWT sets JWT authentication (for internal endpoints)
func WithJWT(jwt string) Option {
	return func(c *clientConfig) error {
		c.authHeader = "sso-jwt " + jwt
		return nil
	}
}

// WithAPIKey sets API key authentication (for public gateway endpoints)
func WithAPIKey(key, secret string) Option {
	return func(c *clientConfig) error {
		c.authHeader = "sso-key " + key + ":" + secret
		return nil
	}
}

// WithTimeout sets the HTTP client timeout
func WithTimeout(timeout time.Duration) Option {
	return func(c *clientConfig) error {
		c.timeout = timeout
		if c.httpClient != nil {
			c.httpClient.Timeout = timeout
		}
		return nil
	}
}

// WithVerbose enables verbose logging
func WithVerbose(verbose bool) Option {
	return func(c *clientConfig) error {
		c.verbose = verbose
		return nil
	}
}

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(client *http.Client) Option {
	return func(c *clientConfig) error {
		c.httpClient = client
		return nil
	}
}
