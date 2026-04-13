package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jeetraj/amnesia/chameleon"
	"github.com/jeetraj/amnesia/medical"
)

type Block struct {
	Index           int                     `json:"index"`
	Timestamp       int64                   `json:"timestamp"`
	Record          medical.EncryptedRecord `json:"record"`
	DoctorSignature string                  `json:"doctor_signature"`
	ContentHash     string                  `json:"content_hash"`
	PrevLinkHash    string                  `json:"prev_link_hash"`
	LinkRandomness  string                  `json:"link_randomness"`
	LinkHash        string                  `json:"link_hash"`
}

type blockContentPayload struct {
	Record          medical.EncryptedRecord `json:"record"`
	DoctorSignature string                  `json:"doctor_signature"`
}

type blockLinkPayload struct {
	Index           int    `json:"index"`
	Timestamp       int64  `json:"timestamp"`
	ContentHash     string `json:"content_hash"`
	DoctorSignature string `json:"doctor_signature"`
	PrevLinkHash    string `json:"prev_link_hash"`
}

func NewBlock(index int, record medical.EncryptedRecord, doctorSignature, prevLinkHash string, publicKey *chameleon.PublicKey) (Block, error) {
	block := Block{
		Index:           index,
		Timestamp:       time.Now().Unix(),
		Record:          record,
		DoctorSignature: doctorSignature,
		PrevLinkHash:    prevLinkHash,
	}

	if err := block.InitializeLink(publicKey); err != nil {
		return Block{}, err
	}

	return block, nil
}

func NewGenesisBlock(publicKey *chameleon.PublicKey) (Block, error) {
	return NewBlock(0, medical.NewGenesisEncryptedRecord(), "", "", publicKey)
}

func (b Block) CalculateContentHash() string {
	payload := blockContentPayload{
		Record:          b.Record,
		DoctorSignature: b.DoctorSignature,
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		panic(fmt.Errorf("marshal block content payload: %w", err))
	}

	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func (b Block) LinkMessage() ([]byte, error) {
	payload := blockLinkPayload{
		Index:           b.Index,
		Timestamp:       b.Timestamp,
		ContentHash:     b.ContentHash,
		DoctorSignature: b.DoctorSignature,
		PrevLinkHash:    b.PrevLinkHash,
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal block link payload: %w", err)
	}

	return encoded, nil
}

func (b *Block) UpdateContentHash() {
	b.ContentHash = b.CalculateContentHash()
}

func (b *Block) InitializeLink(publicKey *chameleon.PublicKey) error {
	if publicKey == nil {
		return fmt.Errorf("chameleon public key is required")
	}

	b.UpdateContentHash()
	randomness, err := chameleon.GenerateRandomness()
	if err != nil {
		return err
	}
	message, err := b.LinkMessage()
	if err != nil {
		return err
	}
	linkHash, err := publicKey.Hash(message, randomness)
	if err != nil {
		return err
	}

	b.LinkRandomness = randomness
	b.LinkHash = linkHash
	return nil
}

func (b Block) VerifyLink(publicKey *chameleon.PublicKey) error {
	if publicKey == nil {
		return fmt.Errorf("chameleon public key is required")
	}

	message, err := b.LinkMessage()
	if err != nil {
		return err
	}

	return publicKey.Verify(message, b.LinkRandomness, b.LinkHash)
}
