package core

import (
	"fmt"

	"github.com/jeetraj/amnesia/medical"
)

type Blockchain struct {
	Blocks []Block `json:"blocks"`
}

func NewBlockchain() *Blockchain {
	return &Blockchain{
		Blocks: []Block{NewGenesisBlock()},
	}
}

func (bc *Blockchain) AddBlock(record medical.MedicalRecord) (Block, error) {
	if err := record.ValidateFields(); err != nil {
		return Block{}, err
	}

	if record.RecordID == "" {
		nextID, err := bc.NextRecordID()
		if err != nil {
			return Block{}, err
		}
		record.RecordID = nextID
	}

	if !record.IsGenesis() {
		if _, err := medical.ParseSequentialRecordID(record.RecordID); err != nil {
			return Block{}, err
		}
	}

	if bc.HasRecordID(record.RecordID) {
		return Block{}, fmt.Errorf("duplicate record ID: %s", record.RecordID)
	}

	prev := bc.Blocks[len(bc.Blocks)-1]
	block := NewBlock(prev.Index+1, record, prev.Hash)
	bc.Blocks = append(bc.Blocks, block)
	return block, nil
}

func (bc *Blockchain) HasRecordID(recordID string) bool {
	for _, block := range bc.Blocks {
		if block.Record.RecordID == recordID {
			return true
		}
	}

	return false
}

func (bc *Blockchain) NextRecordID() (string, error) {
	maxID := 0

	for i, block := range bc.Blocks {
		if block.Record.IsGenesis() {
			continue
		}

		n, err := medical.ParseSequentialRecordID(block.Record.RecordID)
		if err != nil {
			return "", fmt.Errorf("invalid record ID at block %d: %w", i, err)
		}
		if n > maxID {
			maxID = n
		}
	}

	return fmt.Sprintf("R%03d", maxID+1), nil
}

func (bc *Blockchain) ValidateChain() error {
	if len(bc.Blocks) == 0 {
		return fmt.Errorf("blockchain is empty")
	}

	genesis := bc.Blocks[0]
	if genesis.Index != 0 {
		return fmt.Errorf("invalid genesis index: got %d", genesis.Index)
	}
	if genesis.PrevHash != "" {
		return fmt.Errorf("invalid genesis prev hash: expected empty")
	}
	if genesis.Hash != genesis.CalculateHash() {
		return fmt.Errorf("invalid genesis hash")
	}
	if !genesis.Record.IsGenesis() {
		return fmt.Errorf("invalid genesis record")
	}

	seenRecordIDs := make(map[string]struct{})

	for i := 1; i < len(bc.Blocks); i++ {
		prev := bc.Blocks[i-1]
		curr := bc.Blocks[i]

		if curr.Index != prev.Index+1 {
			return fmt.Errorf("invalid index at block %d", i)
		}
		if curr.PrevHash != prev.Hash {
			return fmt.Errorf("broken link at block %d", i)
		}
		if curr.Hash != curr.CalculateHash() {
			return fmt.Errorf("invalid hash at block %d", i)
		}
		if err := curr.Record.ValidateStored(); err != nil {
			return fmt.Errorf("invalid record at block %d: %w", i, err)
		}
		if _, exists := seenRecordIDs[curr.Record.RecordID]; exists {
			return fmt.Errorf("duplicate record ID at block %d: %s", i, curr.Record.RecordID)
		}
		seenRecordIDs[curr.Record.RecordID] = struct{}{}
	}

	return nil
}
