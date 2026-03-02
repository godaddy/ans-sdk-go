package models

import (
	"testing"
)

func TestFqdn(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		want    string
	}{
		{
			name:    "valid fqdn",
			input:   "agent.example.com",
			wantErr: false,
			want:    "agent.example.com",
		},
		{
			name:    "valid fqdn with trailing dot",
			input:   "agent.example.com.",
			wantErr: false,
			want:    "agent.example.com",
		},
		{
			name:    "valid fqdn lowercased",
			input:   "Agent.Example.COM",
			wantErr: false,
			want:    "agent.example.com",
		},
		{
			name:    "valid subdomain",
			input:   "ote.agent.cs3p.com",
			wantErr: false,
			want:    "ote.agent.cs3p.com",
		},
		{
			name:    "valid with hyphen",
			input:   "my-agent.example.com",
			wantErr: false,
			want:    "my-agent.example.com",
		},
		{
			name:    "invalid empty",
			input:   "",
			wantErr: true,
			want:    "",
		},
		{
			name:    "invalid empty label",
			input:   "agent..example.com",
			wantErr: true,
			want:    "",
		},
		{
			name:    "invalid underscore",
			input:   "agent_test.example.com",
			wantErr: true,
			want:    "",
		},
		{
			name:    "invalid label starts with hyphen",
			input:   "-agent.example.com",
			wantErr: true,
			want:    "",
		},
		{
			name:    "invalid label ends with hyphen",
			input:   "agent-.example.com",
			wantErr: true,
			want:    "",
		},
		{
			name:    "invalid label too long",
			input:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
			wantErr: true,
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fqdn, err := NewFqdn(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewFqdn(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("NewFqdn(%q) unexpected error: %v", tt.input, err)
				return
			}
			if fqdn.String() != tt.want {
				t.Errorf("NewFqdn(%q).String() = %q, want %q", tt.input, fqdn.String(), tt.want)
			}
		})
	}
}

func TestFqdn_AnsBadgeName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple fqdn",
			input: "agent.example.com",
			want:  "_ans-badge.agent.example.com",
		},
		{
			name:  "subdomain fqdn",
			input: "ote.agent.cs3p.com",
			want:  "_ans-badge.ote.agent.cs3p.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fqdn, err := NewFqdn(tt.input)
			if err != nil {
				t.Fatalf("NewFqdn(%q) unexpected error: %v", tt.input, err)
			}
			got := fqdn.AnsBadgeName()
			if got != tt.want {
				t.Errorf("AnsBadgeName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFqdn_RaBadgeName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple fqdn",
			input: "agent.example.com",
			want:  "_ra-badge.agent.example.com",
		},
		{
			name:  "subdomain fqdn",
			input: "ote.agent.cs3p.com",
			want:  "_ra-badge.ote.agent.cs3p.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fqdn, err := NewFqdn(tt.input)
			if err != nil {
				t.Fatalf("NewFqdn(%q) unexpected error: %v", tt.input, err)
			}
			got := fqdn.RaBadgeName()
			if got != tt.want {
				t.Errorf("RaBadgeName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFqdn_TlsaName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		port  uint16
		want  string
	}{
		{
			name:  "default https port",
			input: "agent.example.com",
			port:  443,
			want:  "_443._tcp.agent.example.com",
		},
		{
			name:  "custom port",
			input: "agent.example.com",
			port:  8443,
			want:  "_8443._tcp.agent.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fqdn, err := NewFqdn(tt.input)
			if err != nil {
				t.Fatalf("NewFqdn(%q) unexpected error: %v", tt.input, err)
			}
			got := fqdn.TlsaName(tt.port)
			if got != tt.want {
				t.Errorf("TlsaName(%d) = %q, want %q", tt.port, got, tt.want)
			}
		})
	}
}

func TestFqdn_IsZero(t *testing.T) {
	tests := []struct {
		name string
		fqdn Fqdn
		want bool
	}{
		{"zero fqdn", Fqdn{}, true},
		{"non-zero fqdn", func() Fqdn { f, _ := NewFqdn("example.com"); return f }(), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fqdn.IsZero(); got != tt.want {
				t.Errorf("IsZero() = %v, want %v", got, tt.want)
			}
		})
	}
}
