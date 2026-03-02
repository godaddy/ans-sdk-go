package models

import "time"

// IsValidRevocationReason checks if the revocation reason is a valid enum value
func IsValidRevocationReason(r RevocationReason) bool {
	switch r {
	case RevocationReasonKeyCompromise, RevocationReasonCessationOfOperation,
		RevocationReasonAffiliationChanged, RevocationReasonSuperseded,
		RevocationReasonCertificateHold, RevocationReasonPrivilegeWithdrawn,
		RevocationReasonAACompromise, RevocationReasonCACompromise,
		RevocationReasonExpiredCert, RevocationReasonRemoveFromCRL,
		RevocationReasonUnspecified:
		return true
	default:
		return false
	}
}

// AgentRevocationRequest represents a request to revoke an agent
type AgentRevocationRequest struct {
	// Reason is the revocation reason (required)
	Reason RevocationReason `json:"reason"`
	// Comments provides additional context for the revocation (optional)
	Comments string `json:"comments,omitempty"`
}

// AgentRevocationResponse represents the response from a revocation request
type AgentRevocationResponse struct {
	// AgentID is the unique identifier of the revoked agent
	AgentID string `json:"agentId"`
	// AnsName is the ANS name of the revoked agent
	AnsName string `json:"ansName"`
	// Status is the new status of the agent (typically "REVOKED")
	Status string `json:"status"`
	// RevokedAt is the timestamp when the agent was revoked
	RevokedAt time.Time `json:"revokedAt"`
	// Reason is the revocation reason
	Reason RevocationReason `json:"reason"`
}
