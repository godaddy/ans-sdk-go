package models

import (
	"encoding/json"
	"testing"
)

func TestAgentCapabilityRequest_JSON(t *testing.T) {
	tests := []struct {
		name     string
		request  AgentCapabilityRequest
		wantJSON string
	}{
		{
			name: "full request",
			request: AgentCapabilityRequest{
				AgentHost: "myagent.example.com",
				Version:   "^1.0.0",
			},
			wantJSON: `{"agentHost":"myagent.example.com","version":"^1.0.0"}`,
		},
		{
			name: "any version",
			request: AgentCapabilityRequest{
				AgentHost: "agent.test.com",
				Version:   "*",
			},
			wantJSON: `{"agentHost":"agent.test.com","version":"*"}`,
		},
		{
			name: "exact version",
			request: AgentCapabilityRequest{
				AgentHost: "agent.test.com",
				Version:   "2.1.0",
			},
			wantJSON: `{"agentHost":"agent.test.com","version":"2.1.0"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData, err := json.Marshal(tt.request)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			if string(jsonData) != tt.wantJSON {
				t.Errorf("JSON mismatch:\ngot:  %s\nwant: %s", string(jsonData), tt.wantJSON)
			}
		})
	}
}

func TestAgentCapabilityResponse_JSON(t *testing.T) {
	tests := []struct {
		name    string
		jsonStr string
		want    AgentCapabilityResponse
	}{
		{
			name:    "basic response",
			jsonStr: `{"ansName":"ans://v1.0.0.myagent.example.com"}`,
			want: AgentCapabilityResponse{
				AnsName: "ans://v1.0.0.myagent.example.com",
			},
		},
		{
			name:    "response with links",
			jsonStr: `{"ansName":"ans://v2.0.0.agent.test.com","links":[{"href":"https://api.example.com/v1/agents/123","rel":"self"}]}`,
			want: AgentCapabilityResponse{
				AnsName: "ans://v2.0.0.agent.test.com",
				Links: []Link{
					{Href: "https://api.example.com/v1/agents/123", Rel: "self"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got AgentCapabilityResponse
			if err := json.Unmarshal([]byte(tt.jsonStr), &got); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			if got.AnsName != tt.want.AnsName {
				t.Errorf("AnsName mismatch: got %q, want %q", got.AnsName, tt.want.AnsName)
			}

			if len(got.Links) != len(tt.want.Links) {
				t.Errorf("Links count mismatch: got %d, want %d", len(got.Links), len(tt.want.Links))
			}
		})
	}
}
