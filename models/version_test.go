package models

import (
	"testing"
)

func TestVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		want    Version
	}{
		{
			name:    "valid with v prefix",
			input:   "v1.2.3",
			wantErr: false,
			want:    Version{Major: 1, Minor: 2, Patch: 3},
		},
		{
			name:    "valid without v prefix",
			input:   "1.2.3",
			wantErr: false,
			want:    Version{Major: 1, Minor: 2, Patch: 3},
		},
		{
			name:    "valid zeros",
			input:   "v0.0.0",
			wantErr: false,
			want:    Version{Major: 0, Minor: 0, Patch: 0},
		},
		{
			name:    "valid large numbers",
			input:   "v100.200.300",
			wantErr: false,
			want:    Version{Major: 100, Minor: 200, Patch: 300},
		},
		{
			name:    "invalid too few parts",
			input:   "v1.2",
			wantErr: true,
		},
		{
			name:    "invalid too many parts",
			input:   "v1.2.3.4",
			wantErr: true,
		},
		{
			name:    "invalid non-numeric major",
			input:   "va.2.3",
			wantErr: true,
		},
		{
			name:    "invalid non-numeric minor",
			input:   "v1.b.3",
			wantErr: true,
		},
		{
			name:    "invalid non-numeric patch",
			input:   "v1.2.c",
			wantErr: true,
		},
		{
			name:    "invalid empty",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid negative",
			input:   "v-1.2.3",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, err := ParseVersion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseVersion(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseVersion(%q) unexpected error: %v", tt.input, err)
				return
			}
			if version.Major != tt.want.Major || version.Minor != tt.want.Minor || version.Patch != tt.want.Patch {
				t.Errorf("ParseVersion(%q) = %+v, want %+v", tt.input, version, tt.want)
			}
		})
	}
}

func TestVersion_String(t *testing.T) {
	tests := []struct {
		name    string
		version Version
		want    string
	}{
		{
			name:    "simple version",
			version: Version{Major: 1, Minor: 2, Patch: 3},
			want:    "v1.2.3",
		},
		{
			name:    "zero version",
			version: Version{Major: 0, Minor: 0, Patch: 0},
			want:    "v0.0.0",
		},
		{
			name:    "large version",
			version: Version{Major: 100, Minor: 200, Patch: 300},
			want:    "v100.200.300",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.version.String()
			if got != tt.want {
				t.Errorf("Version.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVersion_Compare(t *testing.T) {
	tests := []struct {
		name string
		a    Version
		b    Version
		want int
	}{
		{
			name: "equal",
			a:    Version{Major: 1, Minor: 2, Patch: 3},
			b:    Version{Major: 1, Minor: 2, Patch: 3},
			want: 0,
		},
		{
			name: "a major less than b",
			a:    Version{Major: 1, Minor: 0, Patch: 0},
			b:    Version{Major: 2, Minor: 0, Patch: 0},
			want: -1,
		},
		{
			name: "a major greater than b",
			a:    Version{Major: 2, Minor: 0, Patch: 0},
			b:    Version{Major: 1, Minor: 0, Patch: 0},
			want: 1,
		},
		{
			name: "a minor less than b",
			a:    Version{Major: 1, Minor: 0, Patch: 0},
			b:    Version{Major: 1, Minor: 1, Patch: 0},
			want: -1,
		},
		{
			name: "a minor greater than b",
			a:    Version{Major: 1, Minor: 1, Patch: 0},
			b:    Version{Major: 1, Minor: 0, Patch: 0},
			want: 1,
		},
		{
			name: "a patch less than b",
			a:    Version{Major: 1, Minor: 0, Patch: 0},
			b:    Version{Major: 1, Minor: 0, Patch: 1},
			want: -1,
		},
		{
			name: "a patch greater than b",
			a:    Version{Major: 1, Minor: 0, Patch: 1},
			b:    Version{Major: 1, Minor: 0, Patch: 0},
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.a.Compare(tt.b)
			if got != tt.want {
				t.Errorf("Version.Compare() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestVersion_New(t *testing.T) {
	v := NewVersion(1, 2, 3)
	if v.Major != 1 || v.Minor != 2 || v.Patch != 3 {
		t.Errorf("NewVersion(1, 2, 3) = %+v, want {Major:1 Minor:2 Patch:3}", v)
	}
}

func TestVersion_IsZero(t *testing.T) {
	tests := []struct {
		name string
		v    Version
		want bool
	}{
		{"zero version", Version{0, 0, 0}, true},
		{"non-zero major", Version{1, 0, 0}, false},
		{"non-zero minor", Version{0, 1, 0}, false},
		{"non-zero patch", Version{0, 0, 1}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.v.IsZero(); got != tt.want {
				t.Errorf("IsZero() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVersion_Equal(t *testing.T) {
	tests := []struct {
		name  string
		a, b  Version
		equal bool
	}{
		{"equal versions", Version{1, 2, 3}, Version{1, 2, 3}, true},
		{"different major", Version{1, 2, 3}, Version{2, 2, 3}, false},
		{"different minor", Version{1, 2, 3}, Version{1, 3, 3}, false},
		{"different patch", Version{1, 2, 3}, Version{1, 2, 4}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.Equal(tt.b); got != tt.equal {
				t.Errorf("Equal() = %v, want %v", got, tt.equal)
			}
		})
	}
}

func TestVersion_Less(t *testing.T) {
	tests := []struct {
		name string
		a, b Version
		want bool
	}{
		{"less major", Version{1, 0, 0}, Version{2, 0, 0}, true},
		{"less minor", Version{1, 1, 0}, Version{1, 2, 0}, true},
		{"less patch", Version{1, 1, 1}, Version{1, 1, 2}, true},
		{"equal", Version{1, 1, 1}, Version{1, 1, 1}, false},
		{"greater major", Version{2, 0, 0}, Version{1, 0, 0}, false},
		{"greater minor", Version{1, 2, 0}, Version{1, 1, 0}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.Less(tt.b); got != tt.want {
				t.Errorf("Less() = %v, want %v", got, tt.want)
			}
		})
	}
}
