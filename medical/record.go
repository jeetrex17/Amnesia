package medical

import "time"

type MedicalRecord struct {
	RecordID   string `json:"record_id"`
	PatientID  string `json:"patient_id"`
	DoctorID   string `json:"doctor_id"`
	RecordType string `json:"record_type"`
	Title      string `json:"title"`
	Content    string `json:"content"`
	CreatedAt  int64  `json:"created_at"`
}

func NewRecord(recordID, patientID, doctorID, recordType, title, content string) MedicalRecord {
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
