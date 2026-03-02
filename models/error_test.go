package models

import (
	"testing"
)

func TestAPIError_Error(t *testing.T) {
	tests := []struct {
		name    string
		err     *APIError
		wantMsg string
	}{
		{
			name:    "simple error message",
			err:     &APIError{Status: "400", Code: "BAD_REQUEST", Message: "invalid input"},
			wantMsg: "invalid input",
		},
		{
			name:    "empty message",
			err:     &APIError{Status: "500", Code: "INTERNAL", Message: ""},
			wantMsg: "",
		},
		{
			name:    "with details",
			err:     &APIError{Status: "422", Code: "VALIDATION", Message: "validation failed", Details: map[string]any{"field": "name"}},
			wantMsg: "validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("Error() = %q, want %q", got, tt.wantMsg)
			}
		})
	}
}
