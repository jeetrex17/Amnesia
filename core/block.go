package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jeetraj/amnesia/medical"
)

type Block struct {
	Index           int                   `json:"index"`
	Timestamp       int64                 `json:"timestamp"`
	Record          medical.MedicalRecord `json:"record"`
	DoctorSignature string                `json:"doctor_signature"`
	PrevHash        string                `json:"prev_hash"`
	Hash            string                `json:"hash"`
}

type blockHashPayload struct {
	Index           int                   `json:"index"`
	Timestamp       int64                 `json:"timestamp"`
	Record          medical.MedicalRecord `json:"record"`
	DoctorSignature string                `json:"doctor_signature"`
	PrevHash        string                `json:"prev_hash"`
}

func NewBlock(index int, record medical.MedicalRecord, doctorSignature, prevHash string) Block {
	block := Block{
		Index:           index,
		Timestamp:       time.Now().Unix(),
		Record:          record,
		DoctorSignature: doctorSignature,
		PrevHash:        prevHash,
	}
	block.Hash = block.CalculateHash()
	return block
}

func NewGenesisBlock() Block {
	return NewBlock(0, medical.NewGenesisRecord(), "", "")
}

func (b Block) CalculateHash() string {
	payload := blockHashPayload{
		Index:           b.Index,
		Timestamp:       b.Timestamp,
		Record:          b.Record,
		DoctorSignature: b.DoctorSignature,
		PrevHash:        b.PrevHash,
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		panic(fmt.Errorf("marshal block payload: %w", err))
	}

	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
