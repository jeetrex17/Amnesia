package core

import (
	"testing"

	"github.com/jeetraj/amnesia/actors"
	"github.com/jeetraj/amnesia/auth"
	"github.com/jeetraj/amnesia/medical"
)

func TestValidateChainDetectsTampering(t *testing.T) {
	chain := NewBlockchain()
	store := newTestKeystore(t)
	addSignedBlock(t, chain, store, medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "Patient A: record 1"))
	addSignedBlock(t, chain, store, medical.NewRecord("P002", "D002", "diagnosis", "Diagnosis", "Patient B: record 2"))

	if err := chain.ValidateChain(store); err != nil {
		t.Fatalf("expected valid chain, got error: %v", err)
	}

	chain.Blocks[1].Record.Content = "tampered data"

	if err := chain.ValidateChain(store); err == nil {
		t.Fatalf("expected tampering to be detected")
	}
}

func TestAddBlockGeneratesSequentialRecordIDs(t *testing.T) {
	chain := NewBlockchain()
	store := newTestKeystore(t)

	first := addSignedBlock(t, chain, store, medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "First"))
	second := addSignedBlock(t, chain, store, medical.NewRecord("P002", "D002", "diagnosis", "Diagnosis", "Second"))

	if first.Record.RecordID != "R001" {
		t.Fatalf("unexpected first record ID: got %s", first.Record.RecordID)
	}
	if second.Record.RecordID != "R002" {
		t.Fatalf("unexpected second record ID: got %s", second.Record.RecordID)
	}
}

func TestAddBlockRejectsInvalidRecord(t *testing.T) {
	chain := NewBlockchain()
	store := newTestKeystore(t)
	record := medical.NewRecord("bad-patient", "D001", "visit_note", "Visit Note", "content")
	record.RecordID = "R001"
	signature, err := store.SignRecordAsDoctor("D001", record)
	if err != nil {
		t.Fatalf("sign record failed: %v", err)
	}

	if _, err := chain.AddBlock(record, signature); err == nil {
		t.Fatalf("expected invalid patient ID to be rejected")
	}
}

func TestAddBlockRejectsDuplicateRecordID(t *testing.T) {
	chain := NewBlockchain()
	store := newTestKeystore(t)

	firstRecord := medical.NewRecordWithID("R001", "P001", "D001", "visit_note", "Visit Note", "first")
	firstSignature, err := store.SignRecordAsDoctor("D001", firstRecord)
	if err != nil {
		t.Fatalf("sign first record failed: %v", err)
	}
	if _, err := chain.AddBlock(firstRecord, firstSignature); err != nil {
		t.Fatalf("first add failed: %v", err)
	}

	secondRecord := medical.NewRecordWithID("R001", "P002", "D002", "diagnosis", "Diagnosis", "second")
	secondSignature, err := store.SignRecordAsDoctor("D002", secondRecord)
	if err != nil {
		t.Fatalf("sign second record failed: %v", err)
	}
	if _, err := chain.AddBlock(secondRecord, secondSignature); err == nil {
		t.Fatalf("expected duplicate record ID to be rejected")
	}
}

func TestValidateChainRejectsInvalidDoctorSignature(t *testing.T) {
	chain := NewBlockchain()
	store := newTestKeystore(t)
	addSignedBlock(t, chain, store, medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "Signed"))

	chain.Blocks[1].DoctorSignature = "not-a-valid-signature"

	if err := chain.ValidateChain(store); err == nil {
		t.Fatalf("expected invalid signature to be rejected")
	}
}

func newTestKeystore(t *testing.T) *auth.Keystore {
	t.Helper()

	store, err := auth.NewDemoKeystore(actors.NewDemoRegistry())
	if err != nil {
		t.Fatalf("create demo keystore: %v", err)
	}

	return store
}

func addSignedBlock(t *testing.T, chain *Blockchain, store *auth.Keystore, record medical.MedicalRecord) Block {
	t.Helper()

	recordID, err := chain.NextRecordID()
	if err != nil {
		t.Fatalf("next record ID: %v", err)
	}
	record.RecordID = recordID

	signature, err := store.SignRecordAsDoctor(record.DoctorID, record)
	if err != nil {
		t.Fatalf("sign record: %v", err)
	}

	block, err := chain.AddBlock(record, signature)
	if err != nil {
		t.Fatalf("add block failed: %v", err)
	}

	return block
}
