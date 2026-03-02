package models

import "time"

// CertificateResponse represents a certificate returned from the API
type CertificateResponse struct {
	CertificatePEM                string    `json:"certificatePEM"`
	CertificateIssuer             *string   `json:"certificateIssuer,omitempty"`
	CertificateSubject            *string   `json:"certificateSubject,omitempty"`
	CertificateSerialNumber       *string   `json:"certificateSerialNumber,omitempty"`
	CertificatePublicKeyAlgorithm *string   `json:"certificatePublicKeyAlgorithm,omitempty"`
	CertificateSignatureAlgorithm *string   `json:"certificateSignatureAlgorithm,omitempty"`
	CertificateValidFrom          time.Time `json:"certificateValidFrom"`
	CertificateValidTo            time.Time `json:"certificateValidTo"`
	CsrID                         string    `json:"csrId"`
}

// CsrSubmissionRequest represents the request body for CSR submission
type CsrSubmissionRequest struct {
	CsrPEM string `json:"csrPEM"`
}

// CsrSubmissionResponse represents the response from CSR submission (202 Accepted)
type CsrSubmissionResponse struct {
	CsrID   string  `json:"csrId"`
	Message *string `json:"message,omitempty"`
}

// CsrStatusResponse represents CSR processing status
type CsrStatusResponse struct {
	CsrID         string    `json:"csrId"`
	Type          string    `json:"type"`   // SERVER or IDENTITY
	Status        string    `json:"status"` // PENDING, SIGNED, REJECTED
	SubmittedAt   time.Time `json:"submittedAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
	FailureReason *string   `json:"failureReason,omitempty"`
}

// CertAttestation represents certificate validation information for badges
type CertAttestation struct {
	SerialNumber    string    `json:"serialNumber,omitempty"`
	Issuer          string    `json:"issuer,omitempty"`
	Subject         string    `json:"subject,omitempty"`
	ValidFrom       time.Time `json:"validFrom,omitempty"`
	ValidTo         time.Time `json:"validTo,omitempty"`
	PublicKeyHash   string    `json:"publicKeyHash,omitempty"`
	SignatureHash   string    `json:"signatureHash,omitempty"`
	ValidationProof string    `json:"validationProof,omitempty"`
}
