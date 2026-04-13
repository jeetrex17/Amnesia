package medical

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jeetraj/amnesia/actors"
)

type RecordPayload struct {
	PatientID string `json:"patient_id"`
	Title     string `json:"title"`
	Content   string `json:"content"`
}

type WrappedKey struct {
	ActorID            string `json:"actor_id"`
	ActorRole          string `json:"actor_role"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Ciphertext         string `json:"ciphertext"`
	Nonce              string `json:"nonce"`
}

type EncryptedRecord struct {
	RecordID          string             `json:"record_id"`
	DoctorID          string             `json:"doctor_id"`
	RecordType        string             `json:"record_type"`
	CreatedAt         int64              `json:"created_at"`
	Ciphertext        string             `json:"ciphertext"`
	Nonce             string             `json:"nonce"`
	WrappedKeys       []WrappedKey       `json:"wrapped_keys"`
	PendingRedaction  bool               `json:"pending_redaction"`
	Redacted          bool               `json:"redacted"`
	RedactedAt        int64              `json:"redacted_at,omitempty"`
	RedactionRequest  *RedactionRequest  `json:"redaction_request,omitempty"`
	RedactionApproval *RedactionApproval `json:"redaction_approval,omitempty"`
}

type encryptedRecordSignablePayload struct {
	RecordID    string       `json:"record_id"`
	DoctorID    string       `json:"doctor_id"`
	RecordType  string       `json:"record_type"`
	CreatedAt   int64        `json:"created_at"`
	Ciphertext  string       `json:"ciphertext"`
	Nonce       string       `json:"nonce"`
	WrappedKeys []WrappedKey `json:"wrapped_keys"`
}

func NewRecordPayload(patientID, title, content string) RecordPayload {
	return RecordPayload{
		PatientID: patientID,
		Title:     title,
		Content:   content,
	}
}

func NewGenesisEncryptedRecord() EncryptedRecord {
	return EncryptedRecord{
		RecordID:   "GENESIS",
		DoctorID:   "SYSTEM",
		RecordType: "genesis",
		CreatedAt:  time.Now().Unix(),
	}
}

func NewEncryptedRecord(recordID, doctorID, recordType string, createdAt int64, ciphertext, nonce string, wrappedKeys []WrappedKey) EncryptedRecord {
	return EncryptedRecord{
		RecordID:    recordID,
		DoctorID:    doctorID,
		RecordType:  recordType,
		CreatedAt:   createdAt,
		Ciphertext:  ciphertext,
		Nonce:       nonce,
		WrappedKeys: append([]WrappedKey(nil), wrappedKeys...),
	}
}

func (p RecordPayload) Validate() error {
	if err := ValidatePatientID(p.PatientID); err != nil {
		return err
	}
	if strings.TrimSpace(p.Title) == "" {
		return fmt.Errorf("title is required")
	}
	if strings.TrimSpace(p.Content) == "" {
		return fmt.Errorf("content is required")
	}

	return nil
}

func (p RecordPayload) Bytes() ([]byte, error) {
	encoded, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal record payload: %w", err)
	}

	return encoded, nil
}

func (r EncryptedRecord) IsGenesis() bool {
	return r.RecordID == "GENESIS" && r.RecordType == "genesis"
}

func (r EncryptedRecord) IsRedacted() bool {
	return r.Redacted
}

func (r EncryptedRecord) ValidateStored() error {
	if r.IsGenesis() {
		return nil
	}

	if strings.TrimSpace(r.RecordID) == "" {
		return fmt.Errorf("record ID is required")
	}
	if _, err := ParseSequentialRecordID(r.RecordID); err != nil {
		return err
	}
	if err := ValidateDoctorID(r.DoctorID); err != nil {
		return err
	}
	if err := ValidateRecordType(r.RecordType); err != nil {
		return err
	}
	if r.CreatedAt <= 0 {
		return fmt.Errorf("created_at must be set")
	}

	if err := r.validateRedactionMetadata(); err != nil {
		return err
	}

	if r.Redacted {
		if r.PendingRedaction {
			return fmt.Errorf("redacted record cannot still be pending redaction")
		}
		if r.RedactedAt <= 0 {
			return fmt.Errorf("redacted_at must be set for redacted records")
		}
		if strings.TrimSpace(r.Ciphertext) != "" {
			return fmt.Errorf("redacted record must not retain ciphertext")
		}
		if strings.TrimSpace(r.Nonce) != "" {
			return fmt.Errorf("redacted record must not retain nonce")
		}
		if len(r.WrappedKeys) != 0 {
			return fmt.Errorf("redacted record must not retain wrapped keys")
		}
		return nil
	}

	if r.RedactedAt != 0 {
		return fmt.Errorf("non-redacted record must not set redacted_at")
	}
	if strings.TrimSpace(r.Ciphertext) == "" {
		return fmt.Errorf("ciphertext is required")
	}
	if strings.TrimSpace(r.Nonce) == "" {
		return fmt.Errorf("nonce is required")
	}
	if len(r.WrappedKeys) == 0 {
		return fmt.Errorf("wrapped keys are required")
	}

	seenActors := make(map[string]struct{})
	for _, wrappedKey := range r.WrappedKeys {
		if err := wrappedKey.Validate(); err != nil {
			return err
		}
		if _, exists := seenActors[wrappedKey.ActorID]; exists {
			return fmt.Errorf("duplicate wrapped key for actor ID: %s", wrappedKey.ActorID)
		}
		seenActors[wrappedKey.ActorID] = struct{}{}
	}

	return nil
}

func (r EncryptedRecord) WrappedKeyForActor(actorID string) (WrappedKey, error) {
	for _, wrappedKey := range r.WrappedKeys {
		if wrappedKey.ActorID == actorID {
			return wrappedKey, nil
		}
	}

	return WrappedKey{}, fmt.Errorf("wrapped key not found for actor ID: %s", actorID)
}

func (r EncryptedRecord) SignableBytes() ([]byte, error) {
	sortedWrappedKeys := append([]WrappedKey(nil), r.WrappedKeys...)
	sort.Slice(sortedWrappedKeys, func(i, j int) bool {
		if sortedWrappedKeys[i].ActorID == sortedWrappedKeys[j].ActorID {
			return sortedWrappedKeys[i].ActorRole < sortedWrappedKeys[j].ActorRole
		}
		return sortedWrappedKeys[i].ActorID < sortedWrappedKeys[j].ActorID
	})

	payload := encryptedRecordSignablePayload{
		RecordID:    r.RecordID,
		DoctorID:    r.DoctorID,
		RecordType:  r.RecordType,
		CreatedAt:   r.CreatedAt,
		Ciphertext:  r.Ciphertext,
		Nonce:       r.Nonce,
		WrappedKeys: sortedWrappedKeys,
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal signable encrypted record payload: %w", err)
	}

	return encoded, nil
}

func (w WrappedKey) Validate() error {
	if strings.TrimSpace(w.ActorID) == "" {
		return fmt.Errorf("wrapped key actor ID is required")
	}
	if err := actors.ValidateRole(w.ActorRole); err != nil {
		return fmt.Errorf("invalid wrapped key role for %s: %w", w.ActorID, err)
	}
	if strings.TrimSpace(w.EphemeralPublicKey) == "" {
		return fmt.Errorf("wrapped key ephemeral public key is required for %s", w.ActorID)
	}
	if strings.TrimSpace(w.Ciphertext) == "" {
		return fmt.Errorf("wrapped key ciphertext is required for %s", w.ActorID)
	}
	if strings.TrimSpace(w.Nonce) == "" {
		return fmt.Errorf("wrapped key nonce is required for %s", w.ActorID)
	}

	return nil
}

func (r EncryptedRecord) validateRedactionMetadata() error {
	if r.RedactionRequest == nil && r.RedactionApproval == nil {
		if r.PendingRedaction {
			return fmt.Errorf("pending redaction requires both request and approval")
		}
		return nil
	}
	if r.RedactionRequest == nil || r.RedactionApproval == nil {
		return fmt.Errorf("redaction metadata requires both request and approval")
	}
	if err := r.RedactionRequest.Validate(); err != nil {
		return fmt.Errorf("invalid redaction request: %w", err)
	}
	if err := r.RedactionApproval.Validate(); err != nil {
		return fmt.Errorf("invalid redaction approval: %w", err)
	}
	if r.RedactionRequest.RecordID != r.RecordID {
		return fmt.Errorf("redaction request record ID mismatch: %s", r.RedactionRequest.RecordID)
	}
	if r.RedactionApproval.RecordID != r.RecordID {
		return fmt.Errorf("redaction approval record ID mismatch: %s", r.RedactionApproval.RecordID)
	}
	if r.RedactionRequest.PatientID != r.RedactionApproval.PatientID {
		return fmt.Errorf("redaction patient mismatch between request and approval")
	}

	return nil
}
