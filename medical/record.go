package medical

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type MedicalRecord struct {
	RecordID   string `json:"record_id"`
	PatientID  string `json:"patient_id"`
	DoctorID   string `json:"doctor_id"`
	RecordType string `json:"record_type"`
	Title      string `json:"title"`
	Content    string `json:"content"`
	CreatedAt  int64  `json:"created_at"`
}

var (
	recordIDPattern  = regexp.MustCompile(`^R([0-9]+)$`)
	patientIDPattern = regexp.MustCompile(`^P[0-9]+$`)
	doctorIDPattern  = regexp.MustCompile(`^D[0-9]+$`)
	allowedTypes     = map[string]struct{}{
		"diagnosis":          {},
		"prescription":       {},
		"lab_result":         {},
		"vaccination":        {},
		"visit_note":         {},
		"infectious_disease": {},
	}
)

func ValidatePatientID(patientID string) error {
	if strings.TrimSpace(patientID) == "" {
		return fmt.Errorf("patient ID is required")
	}
	if !patientIDPattern.MatchString(patientID) {
		return fmt.Errorf("invalid patient ID format: %s", patientID)
	}

	return nil
}

func ValidateDoctorID(doctorID string) error {
	if strings.TrimSpace(doctorID) == "" {
		return fmt.Errorf("doctor ID is required")
	}
	if !doctorIDPattern.MatchString(doctorID) {
		return fmt.Errorf("invalid doctor ID format: %s", doctorID)
	}

	return nil
}

func ValidateRecordType(recordType string) error {
	if strings.TrimSpace(recordType) == "" {
		return fmt.Errorf("record type is required")
	}
	if _, ok := allowedTypes[recordType]; !ok {
		return fmt.Errorf("unsupported record type: %s", recordType)
	}

	return nil
}

func NewRecord(patientID, doctorID, recordType, title, content string) MedicalRecord {
	return NewRecordWithID("", patientID, doctorID, recordType, title, content)
}

func NewRecordWithID(recordID, patientID, doctorID, recordType, title, content string) MedicalRecord {
	return MedicalRecord{
		RecordID:   recordID,
		PatientID:  patientID,
		DoctorID:   doctorID,
		RecordType: recordType,
		Title:      title,
		Content:    content,
		CreatedAt:  time.Now().Unix(),
	}
}

func NewGenesisRecord() MedicalRecord {
	return MedicalRecord{
		RecordID:   "GENESIS",
		PatientID:  "",
		DoctorID:   "SYSTEM",
		RecordType: "genesis",
		Title:      "Genesis Block",
		Content:    "Genesis Block",
		CreatedAt:  time.Now().Unix(),
	}
}

func (r MedicalRecord) IsGenesis() bool {
	return r.RecordID == "GENESIS" && r.RecordType == "genesis"
}

func (r MedicalRecord) ValidateFields() error {
	if r.IsGenesis() {
		return nil
	}

	if err := ValidatePatientID(r.PatientID); err != nil {
		return err
	}

	if err := ValidateDoctorID(r.DoctorID); err != nil {
		return err
	}
	if err := ValidateRecordType(r.RecordType); err != nil {
		return err
	}

	if strings.TrimSpace(r.Title) == "" {
		return fmt.Errorf("title is required")
	}
	if strings.TrimSpace(r.Content) == "" {
		return fmt.Errorf("content is required")
	}
	if r.CreatedAt <= 0 {
		return fmt.Errorf("created_at must be set")
	}

	return nil
}

func (r MedicalRecord) ValidateStored() error {
	if r.IsGenesis() {
		return nil
	}

	if err := r.ValidateFields(); err != nil {
		return err
	}

	if strings.TrimSpace(r.RecordID) == "" {
		return fmt.Errorf("record ID is required")
	}

	if _, err := ParseSequentialRecordID(r.RecordID); err != nil {
		return err
	}

	return nil
}

func ParseSequentialRecordID(recordID string) (int, error) {
	matches := recordIDPattern.FindStringSubmatch(recordID)
	if len(matches) != 2 {
		return 0, fmt.Errorf("invalid record ID format: %s", recordID)
	}

	var n int
	if _, err := fmt.Sscanf(matches[1], "%d", &n); err != nil {
		return 0, fmt.Errorf("parse record ID: %w", err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("record ID must be positive: %s", recordID)
	}

	return n, nil
}

type signableRecordPayload struct {
	RecordID   string `json:"record_id"`
	PatientID  string `json:"patient_id"`
	DoctorID   string `json:"doctor_id"`
	RecordType string `json:"record_type"`
	Title      string `json:"title"`
	Content    string `json:"content"`
	CreatedAt  int64  `json:"created_at"`
}

func (r MedicalRecord) SignableBytes() ([]byte, error) {
	payload := signableRecordPayload{
		RecordID:   r.RecordID,
		PatientID:  r.PatientID,
		DoctorID:   r.DoctorID,
		RecordType: r.RecordType,
		Title:      r.Title,
		Content:    r.Content,
		CreatedAt:  r.CreatedAt,
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal signable record payload: %w", err)
	}

	return encoded, nil
}
