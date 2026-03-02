package models

import (
	"testing"
)

func TestTransparencyLog_GetV1Payload(t *testing.T) {
	v1 := &TransparencyLogV1{Producer: ProducerV1{KeyID: "test-key"}}
	tests := []struct {
		name      string
		log       *TransparencyLog
		wantNil   bool
		wantKeyID string
	}{
		{
			name:      "V1 parsed payload",
			log:       &TransparencyLog{ParsedPayload: v1},
			wantNil:   false,
			wantKeyID: "test-key",
		},
		{
			name:    "nil parsed payload",
			log:     &TransparencyLog{},
			wantNil: true,
		},
		{
			name:    "V0 parsed payload",
			log:     &TransparencyLog{ParsedPayload: &TransparencyLogV0{}},
			wantNil: true,
		},
		{
			name:    "non-payload type",
			log:     &TransparencyLog{ParsedPayload: "not a payload"},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.log.GetV1Payload()
			if tt.wantNil && got != nil {
				t.Errorf("GetV1Payload() = %v, want nil", got)
			}
			if !tt.wantNil {
				if got == nil {
					t.Fatal("GetV1Payload() = nil, want non-nil")
				}
				if got.Producer.KeyID != tt.wantKeyID {
					t.Errorf("GetV1Payload().Producer.KeyID = %q, want %q", got.Producer.KeyID, tt.wantKeyID)
				}
			}
		})
	}
}

func TestTransparencyLog_GetV0Payload(t *testing.T) {
	v0 := &TransparencyLogV0{LogID: "test-log"}
	tests := []struct {
		name      string
		log       *TransparencyLog
		wantNil   bool
		wantLogID string
	}{
		{
			name:      "V0 parsed payload",
			log:       &TransparencyLog{ParsedPayload: v0},
			wantNil:   false,
			wantLogID: "test-log",
		},
		{
			name:    "nil parsed payload",
			log:     &TransparencyLog{},
			wantNil: true,
		},
		{
			name:    "V1 parsed payload",
			log:     &TransparencyLog{ParsedPayload: &TransparencyLogV1{}},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.log.GetV0Payload()
			if tt.wantNil && got != nil {
				t.Errorf("GetV0Payload() = %v, want nil", got)
			}
			if !tt.wantNil {
				if got == nil {
					t.Fatal("GetV0Payload() = nil, want non-nil")
				}
				if got.LogID != tt.wantLogID {
					t.Errorf("GetV0Payload().LogID = %q, want %q", got.LogID, tt.wantLogID)
				}
			}
		})
	}
}

func TestTransparencyLog_IsV1(t *testing.T) {
	tests := []struct {
		name string
		log  *TransparencyLog
		want bool
	}{
		{
			name: "schema version V1",
			log:  &TransparencyLog{SchemaVersion: string(SchemaVersionV1)},
			want: true,
		},
		{
			name: "parsed V1 payload",
			log:  &TransparencyLog{ParsedPayload: &TransparencyLogV1{}},
			want: true,
		},
		{
			name: "schema version V0",
			log:  &TransparencyLog{SchemaVersion: string(SchemaVersionV0)},
			want: false,
		},
		{
			name: "empty schema version",
			log:  &TransparencyLog{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.log.IsV1(); got != tt.want {
				t.Errorf("IsV1() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTransparencyLog_IsV0(t *testing.T) {
	tests := []struct {
		name string
		log  *TransparencyLog
		want bool
	}{
		{
			name: "schema version V0",
			log:  &TransparencyLog{SchemaVersion: string(SchemaVersionV0)},
			want: true,
		},
		{
			name: "empty schema version defaults to V0",
			log:  &TransparencyLog{SchemaVersion: ""},
			want: true,
		},
		{
			name: "parsed V0 payload",
			log:  &TransparencyLog{ParsedPayload: &TransparencyLogV0{}},
			want: true,
		},
		{
			name: "schema version V1 only",
			log:  &TransparencyLog{SchemaVersion: string(SchemaVersionV1)},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.log.IsV0(); got != tt.want {
				t.Errorf("IsV0() = %v, want %v", got, tt.want)
			}
		})
	}
}
