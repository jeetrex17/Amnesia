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

func (bc *Blockchain) AddBlock(record medical.MedicalRecord) Block {
	prev := bc.Blocks[len(bc.Blocks)-1]
	block := NewBlock(prev.Index+1, record, prev.Hash)
	bc.Blocks = append(bc.Blocks, block)
	return block
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
	}

	return nil
}
