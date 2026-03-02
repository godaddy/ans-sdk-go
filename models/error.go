package models

import "errors"

// Sentinel errors for common API error conditions
var (
	// ErrNotFound indicates a resource was not found (404)
	ErrNotFound = errors.New("resource not found")

	// ErrUnauthorized indicates authentication failed (401)
	ErrUnauthorized = errors.New("unauthorized")

	// ErrForbidden indicates insufficient permissions (403)
	ErrForbidden = errors.New("forbidden")

	// ErrBadRequest indicates invalid request parameters (400)
	ErrBadRequest = errors.New("bad request")

	// ErrConflict indicates a resource conflict (409)
	ErrConflict = errors.New("conflict")

	// ErrTooManyRequests indicates rate limiting (429)
	ErrTooManyRequests = errors.New("too many requests")

	// ErrInternalServer indicates a server error (500)
	ErrInternalServer = errors.New("internal server error")
)

// APIError represents an API error response
type APIError struct {
	Status  string         `json:"status"`
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// Error implements the error interface
func (e *APIError) Error() string {
	return e.Message
}
