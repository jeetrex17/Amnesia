package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type Block struct {
	Index     int    `json:"index"`
	Timestamp int64  `json:"timestamp"`
	Data      string `json:"data"`
	PrevHash  string `json:"prev_hash"`
	Hash      string `json:"hash"`
}

type blockHashPayload struct {
	Index     int    `json:"index"`
	Timestamp int64  `json:"timestamp"`
	Data      string `json:"data"`
	PrevHash  string `json:"prev_hash"`
}

func NewBlock(index int, data string, prevHash string) Block {
	block := Block{
		Index:     index,
		Timestamp: time.Now().Unix(),
		Data:      data,
		PrevHash:  prevHash,
	}
	block.Hash = block.CalculateHash()
	return block
}

func NewGenesisBlock() Block {
	return NewBlock(0, "Genesis Block", "")
}

func (b Block) CalculateHash() string {
	payload := blockHashPayload{
		Index:     b.Index,
		Timestamp: b.Timestamp,
		Data:      b.Data,
		PrevHash:  b.PrevHash,
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		panic(fmt.Errorf("marshal block payload: %w", err))
	}

	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
