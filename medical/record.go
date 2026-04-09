package medical

import (
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

	if strings.TrimSpace(r.PatientID) == "" {
		return fmt.Errorf("patient ID is required")
	}
	if !patientIDPattern.MatchString(r.PatientID) {
		return fmt.Errorf("invalid patient ID format: %s", r.PatientID)
	}

	if strings.TrimSpace(r.DoctorID) == "" {
		return fmt.Errorf("doctor ID is required")
	}
	if !doctorIDPattern.MatchString(r.DoctorID) {
		return fmt.Errorf("invalid doctor ID format: %s", r.DoctorID)
	}

	if strings.TrimSpace(r.RecordType) == "" {
		return fmt.Errorf("record type is required")
	}
	if _, ok := allowedTypes[r.RecordType]; !ok {
		return fmt.Errorf("unsupported record type: %s", r.RecordType)
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
