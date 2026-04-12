package medical

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type RedactionRequest struct {
	RecordID    string `json:"record_id"`
	PatientID   string `json:"patient_id"`
	Reason      string `json:"reason"`
	RequestedAt int64  `json:"requested_at"`
	Signature   string `json:"signature"`
}

type RedactionApproval struct {
	RecordID    string `json:"record_id"`
	PatientID   string `json:"patient_id"`
	AuthorityID string `json:"authority_id"`
	ApprovedAt  int64  `json:"approved_at"`
	Signature   string `json:"signature"`
}

type signableRedactionRequest struct {
	RecordID    string `json:"record_id"`
	PatientID   string `json:"patient_id"`
	Reason      string `json:"reason"`
	RequestedAt int64  `json:"requested_at"`
}

type signableRedactionApproval struct {
	RecordID    string `json:"record_id"`
	PatientID   string `json:"patient_id"`
	AuthorityID string `json:"authority_id"`
	ApprovedAt  int64  `json:"approved_at"`
}

func NewRedactionRequest(recordID, patientID, reason string) RedactionRequest {
	return RedactionRequest{
		RecordID:    recordID,
		PatientID:   patientID,
		Reason:      reason,
		RequestedAt: time.Now().Unix(),
	}
}

func NewRedactionApproval(recordID, patientID, authorityID string) RedactionApproval {
	return RedactionApproval{
		RecordID:    recordID,
		PatientID:   patientID,
		AuthorityID: authorityID,
		ApprovedAt:  time.Now().Unix(),
	}
}

func (r RedactionRequest) Validate() error {
	if strings.TrimSpace(r.RecordID) == "" {
		return fmt.Errorf("redaction request record ID is required")
	}
	if _, err := ParseSequentialRecordID(r.RecordID); err != nil {
		return err
	}
	if err := ValidatePatientID(r.PatientID); err != nil {
		return err
	}
	if strings.TrimSpace(r.Reason) == "" {
		return fmt.Errorf("redaction request reason is required")
	}
	if r.RequestedAt <= 0 {
		return fmt.Errorf("redaction request timestamp is required")
	}
	if strings.TrimSpace(r.Signature) == "" {
		return fmt.Errorf("redaction request signature is required")
	}

	return nil
}

func (r RedactionApproval) Validate() error {
	if strings.TrimSpace(r.RecordID) == "" {
		return fmt.Errorf("redaction approval record ID is required")
	}
	if _, err := ParseSequentialRecordID(r.RecordID); err != nil {
		return err
	}
	if err := ValidatePatientID(r.PatientID); err != nil {
		return err
	}
	if err := ValidateAuthorityID(r.AuthorityID); err != nil {
		return err
	}
	if r.ApprovedAt <= 0 {
		return fmt.Errorf("redaction approval timestamp is required")
	}
	if strings.TrimSpace(r.Signature) == "" {
		return fmt.Errorf("redaction approval signature is required")
	}

	return nil
}

func (r RedactionRequest) SignableBytes() ([]byte, error) {
	payload := signableRedactionRequest{
		RecordID:    r.RecordID,
		PatientID:   r.PatientID,
		Reason:      r.Reason,
		RequestedAt: r.RequestedAt,
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal redaction request payload: %w", err)
	}

	return encoded, nil
}

func (r RedactionApproval) SignableBytes() ([]byte, error) {
	payload := signableRedactionApproval{
		RecordID:    r.RecordID,
		PatientID:   r.PatientID,
		AuthorityID: r.AuthorityID,
		ApprovedAt:  r.ApprovedAt,
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal redaction approval payload: %w", err)
	}

	return encoded, nil
}
