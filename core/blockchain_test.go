package core

import (
	"testing"

	"github.com/jeetraj/amnesia/medical"
)

func TestValidateChainDetectsTampering(t *testing.T) {
	chain := NewBlockchain()
	chain.AddBlock(medical.NewRecord("R001", "P001", "D001", "visit_note", "Visit Note", "Patient A: record 1"))
	chain.AddBlock(medical.NewRecord("R002", "P002", "D002", "diagnosis", "Diagnosis", "Patient B: record 2"))

	if err := chain.ValidateChain(); err != nil {
		t.Fatalf("expected valid chain, got error: %v", err)
	}

	chain.Blocks[1].Record.Content = "tampered data"

	if err := chain.ValidateChain(); err == nil {
		t.Fatalf("expected tampering to be detected")
	}
}
