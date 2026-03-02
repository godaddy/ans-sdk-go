package models

import "time"

// EventItem represents an individual ANS event
type EventItem struct {
	LogID            string          `json:"logId"`
	EventType        string          `json:"eventType"`
	CreatedAt        time.Time       `json:"createdAt"`
	ExpiresAt        *time.Time      `json:"expiresAt,omitempty"`
	AgentID          string          `json:"agentId"`
	AnsName          string          `json:"ansName"`
	AgentHost        string          `json:"agentHost"`
	AgentDisplayName *string         `json:"agentDisplayName,omitempty"`
	AgentDescription *string         `json:"agentDescription,omitempty"`
	Version          string          `json:"version"`
	ProviderID       *string         `json:"providerId,omitempty"`
	Endpoints        []AgentEndpoint `json:"endpoints,omitempty"`
}

// EventPageResponse represents a paginated events response
type EventPageResponse struct {
	Items     []EventItem `json:"items"`
	LastLogID *string     `json:"lastLogId,omitempty"`
}
