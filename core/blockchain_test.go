package core

import (
	"testing"

	"github.com/jeetraj/amnesia/medical"
)

func TestValidateChainDetectsTampering(t *testing.T) {
	chain := NewBlockchain()
	if _, err := chain.AddBlock(medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "Patient A: record 1")); err != nil {
		t.Fatalf("add block failed: %v", err)
	}
	if _, err := chain.AddBlock(medical.NewRecord("P002", "D002", "diagnosis", "Diagnosis", "Patient B: record 2")); err != nil {
		t.Fatalf("add block failed: %v", err)
	}

	if err := chain.ValidateChain(); err != nil {
		t.Fatalf("expected valid chain, got error: %v", err)
	}

	chain.Blocks[1].Record.Content = "tampered data"

	if err := chain.ValidateChain(); err == nil {
		t.Fatalf("expected tampering to be detected")
	}
}

func TestAddBlockGeneratesSequentialRecordIDs(t *testing.T) {
	chain := NewBlockchain()

	first, err := chain.AddBlock(medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "First"))
	if err != nil {
		t.Fatalf("add first block failed: %v", err)
	}

	second, err := chain.AddBlock(medical.NewRecord("P002", "D002", "diagnosis", "Diagnosis", "Second"))
	if err != nil {
		t.Fatalf("add second block failed: %v", err)
	}

	if first.Record.RecordID != "R001" {
		t.Fatalf("unexpected first record ID: got %s", first.Record.RecordID)
	}
	if second.Record.RecordID != "R002" {
		t.Fatalf("unexpected second record ID: got %s", second.Record.RecordID)
	}
}

func TestAddBlockRejectsInvalidRecord(t *testing.T) {
	chain := NewBlockchain()

	if _, err := chain.AddBlock(medical.NewRecord("bad-patient", "D001", "visit_note", "Visit Note", "content")); err == nil {
		t.Fatalf("expected invalid patient ID to be rejected")
	}
}

func TestAddBlockRejectsDuplicateRecordID(t *testing.T) {
	chain := NewBlockchain()

	if _, err := chain.AddBlock(medical.NewRecordWithID("R001", "P001", "D001", "visit_note", "Visit Note", "first")); err != nil {
		t.Fatalf("first add failed: %v", err)
	}
	if _, err := chain.AddBlock(medical.NewRecordWithID("R001", "P002", "D002", "diagnosis", "Diagnosis", "second")); err == nil {
		t.Fatalf("expected duplicate record ID to be rejected")
	}
}
