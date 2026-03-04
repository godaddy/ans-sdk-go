package verify

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// DefaultTrustedRADomains returns the default trusted Registration Authority domains.
func DefaultTrustedRADomains() []string {
	return []string{
		"transparency.ans.godaddy.com",
		"transparency.ans.ote-godaddy.com",
	}
}

// URLErrorType represents the type of URL validation failure.
type URLErrorType int

const (
	// URLErrorHTTPScheme indicates the URL uses HTTP instead of HTTPS.
	URLErrorHTTPScheme URLErrorType = iota
	// URLErrorUntrustedDomain indicates the URL domain is not a trusted RA.
	URLErrorUntrustedDomain
	// URLErrorNonStandardPort indicates the URL uses a non-standard port.
	URLErrorNonStandardPort
	// URLErrorPathTraversal indicates the URL contains path traversal or query injection.
	URLErrorPathTraversal
)

// URLValidationError represents a badge URL validation failure.
type URLValidationError struct {
	Type   URLErrorType
	URL    string
	Reason string
}

// Error implements the error interface.
func (e *URLValidationError) Error() string {
	switch e.Type {
	case URLErrorHTTPScheme:
		return fmt.Sprintf("badge URL must use HTTPS: %s", e.URL)
	case URLErrorUntrustedDomain:
		return fmt.Sprintf("badge URL domain not trusted: %s", e.URL)
	case URLErrorNonStandardPort:
		return fmt.Sprintf("badge URL uses non-standard port: %s", e.URL)
	case URLErrorPathTraversal:
		return fmt.Sprintf("badge URL contains path traversal or query params: %s", e.URL)
	default:
		return fmt.Sprintf("badge URL validation error: %s", e.URL)
	}
}

// URLValidator validates badge URLs against trusted RA domains.
type URLValidator struct {
	trustedDomains []string
}

// NewURLValidator creates a new URLValidator with the given trusted domains.
func NewURLValidator(trustedDomains []string) *URLValidator {
	lower := make([]string, len(trustedDomains))
	for i, d := range trustedDomains {
		lower[i] = strings.ToLower(d)
	}
	return &URLValidator{trustedDomains: lower}
}

// NewDefaultURLValidator creates a URLValidator with default trusted RA domains.
func NewDefaultURLValidator() *URLValidator {
	return NewURLValidator(DefaultTrustedRADomains())
}

// Validate checks a badge URL against security requirements:
// 1. HTTPS required
// 2. Domain must be in trusted list (case-insensitive)
// 3. No non-standard port (only 443 or empty)
// 4. No path traversal (..) or query params
func (v *URLValidator) Validate(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return &URLValidationError{
			Type:   URLErrorHTTPScheme,
			URL:    rawURL,
			Reason: err.Error(),
		}
	}

	// 1. HTTPS required
	if parsed.Scheme != "https" {
		return &URLValidationError{
			Type: URLErrorHTTPScheme,
			URL:  rawURL,
		}
	}

	// 2. Trusted domain check (case-insensitive)
	hostname := strings.ToLower(parsed.Hostname())
	if !v.isDomainTrusted(hostname) {
		return &URLValidationError{
			Type: URLErrorUntrustedDomain,
			URL:  rawURL,
		}
	}

	// 3. No non-standard port
	port := parsed.Port()
	if port != "" && port != "443" {
		return &URLValidationError{
			Type: URLErrorNonStandardPort,
			URL:  rawURL,
		}
	}

	// 4. No path traversal or query injection
	if strings.Contains(parsed.Path, "..") {
		return &URLValidationError{
			Type: URLErrorPathTraversal,
			URL:  rawURL,
		}
	}
	if parsed.RawQuery != "" {
		return &URLValidationError{
			Type: URLErrorPathTraversal,
			URL:  rawURL,
		}
	}

	return nil
}

// isDomainTrusted checks if the hostname matches any trusted domain.
func (v *URLValidator) isDomainTrusted(hostname string) bool {
	return slices.Contains(v.trustedDomains, hostname)
}
