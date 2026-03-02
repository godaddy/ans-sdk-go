package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/godaddy/ans-sdk-go/models"
)

func TestBuildSearchCmd(t *testing.T) {
	tests := []struct {
		name      string
		checkUse  string
		flagNames []string
	}{
		{
			name:      "command properties and flags",
			checkUse:  "search",
			flagNames: []string{"name", "host", "version", "limit", "offset"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := buildSearchCmd()
			if cmd == nil {
				t.Fatal("buildSearchCmd() returned nil")
			}
			if cmd.Use != tt.checkUse {
				t.Errorf("Use = %q, want %q", cmd.Use, tt.checkUse)
			}
			for _, flagName := range tt.flagNames {
				if cmd.Flags().Lookup(flagName) == nil {
					t.Errorf("missing flag %q", flagName)
				}
			}
		})
	}
}

func TestPrintSearchResults(t *testing.T) {
	tests := []struct {
		name   string
		result *models.AgentSearchResponse
		checks []string
	}{
		{
			name: "empty results",
			result: &models.AgentSearchResponse{
				Agents: []models.AgentSearchResult{},
			},
			checks: []string{"No agents found"},
		},
		{
			name: "with agents and details",
			result: &models.AgentSearchResponse{
				TotalCount:    2,
				ReturnedCount: 2,
				Limit:         20,
				Offset:        0,
				HasMore:       false,
				Agents: []models.AgentSearchResult{
					{
						AgentDisplayName:      "Agent One",
						ANSName:               "ans://v1.0.0.agent1.example.com",
						AgentHost:             "agent1.example.com",
						Version:               "v1.0.0",
						AgentDescription:      "First agent",
						RegistrationTimestamp: time.Now(),
						Endpoints: []models.AgentEndpoint{
							{Protocol: "MCP"},
							{Protocol: "A2A"},
						},
						Links: []models.Link{
							{Rel: "self", Href: "https://api.example.com/agents/1"},
						},
					},
					{
						AgentDisplayName: "Agent Two",
						ANSName:          "ans://v2.0.0.agent2.example.com",
						AgentHost:        "agent2.example.com",
						Version:          "v2.0.0",
					},
				},
			},
			checks: []string{
				"Search Results", "Total matches: 2",
				"Agent One", "agent1.example.com", "v1.0.0", "First agent",
				"Endpoints: 2", "MCP", "A2A",
				"Agent Two", "agent2.example.com", "v2.0.0",
			},
		},
		{
			name: "has more results with pagination hint",
			result: &models.AgentSearchResponse{
				TotalCount:    50,
				ReturnedCount: 20,
				Limit:         20,
				Offset:        0,
				HasMore:       true,
				Agents: []models.AgentSearchResult{
					{AgentDisplayName: "Agent One"},
				},
			},
			checks: []string{"More results available", "--offset 20"},
		},
		{
			name: "last page",
			result: &models.AgentSearchResponse{
				Agents: []models.AgentSearchResult{
					{
						AgentDisplayName: "Agent",
						AgentHost:        "agent.com",
						ANSName:          "a.ans.godaddy",
						Version:          "1.0.0",
					},
				},
				TotalCount:    1,
				ReturnedCount: 1,
				Limit:         20,
				Offset:        0,
				HasMore:       false,
			},
			checks: []string{"Agent"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(func() {
				printSearchResults(tt.result)
			})
			for _, check := range tt.checks {
				if !strings.Contains(output, check) {
					t.Errorf("printSearchResults() output missing %q", check)
				}
			}
		})
	}
}

func TestPrintPaginationHint(t *testing.T) {
	tests := []struct {
		name   string
		result *models.AgentSearchResponse
		expect string
	}{
		{
			name:   "no more results produces no hint",
			result: &models.AgentSearchResponse{HasMore: false},
			expect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(func() {
				printPaginationHint(tt.result)
			})
			if tt.expect == "" && strings.Contains(output, "More results") {
				t.Error("printPaginationHint() should not show hint when HasMore is false")
			}
		})
	}
}
