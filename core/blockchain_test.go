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

	chain.Blocks[1].Record.Ciphertext = "tampered-data"

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
	record := medical.NewEncryptedRecord("R001", "D001", "visit_note", 1, "", "nonce", []medical.WrappedKey{
		{
			ActorID:            "D001",
			ActorRole:          actors.RoleDoctor,
			EphemeralPublicKey: "ephemeral",
			Ciphertext:         "ciphertext",
			Nonce:              "nonce",
		},
	})

	if _, err := chain.AddBlock(record, "signature"); err == nil {
		t.Fatalf("expected invalid encrypted record to be rejected")
	}
}

func TestAddBlockRejectsDuplicateRecordID(t *testing.T) {
	chain := NewBlockchain()
	store := newTestKeystore(t)

	firstRecord := medical.NewRecordWithID("R001", "P001", "D001", "visit_note", "Visit Note", "first")
	firstEncryptedRecord, err := encryptRecordForTest(store, firstRecord)
	if err != nil {
		t.Fatalf("encrypt first record failed: %v", err)
	}
	firstSignature, err := store.SignRecordAsDoctor("D001", firstEncryptedRecord)
	if err != nil {
		t.Fatalf("sign first record failed: %v", err)
	}
	if _, err := chain.AddBlock(firstEncryptedRecord, firstSignature); err != nil {
		t.Fatalf("first add failed: %v", err)
	}

	secondRecord := medical.NewRecordWithID("R001", "P002", "D002", "diagnosis", "Diagnosis", "second")
	secondEncryptedRecord, err := encryptRecordForTest(store, secondRecord)
	if err != nil {
		t.Fatalf("encrypt second record failed: %v", err)
	}
	secondSignature, err := store.SignRecordAsDoctor("D002", secondEncryptedRecord)
	if err != nil {
		t.Fatalf("sign second record failed: %v", err)
	}
	if _, err := chain.AddBlock(secondEncryptedRecord, secondSignature); err == nil {
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

func TestAuthorizeRedactionAddsSignedMetadata(t *testing.T) {
	chain := NewBlockchain()
	store := newTestKeystore(t)
	block := addSignedBlock(t, chain, store, medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "Signed"))

	request := medical.NewRedactionRequest(block.Record.RecordID, "P001", "patient requested deletion")
	requestSignature, err := store.SignRedactionRequestAsPatient("P001", request)
	if err != nil {
		t.Fatalf("sign redaction request failed: %v", err)
	}
	request.Signature = requestSignature

	approval := medical.NewRedactionApproval(block.Record.RecordID, "P001", "A001")
	approvalSignature, err := store.SignRedactionApprovalAsAuthority("A001", approval)
	if err != nil {
		t.Fatalf("sign redaction approval failed: %v", err)
	}
	approval.Signature = approvalSignature

	if err := chain.AuthorizeRedaction(block.Record.RecordID, request, approval); err != nil {
		t.Fatalf("authorize redaction failed: %v", err)
	}
	if !chain.Blocks[1].Record.PendingRedaction {
		t.Fatalf("expected record to be marked pending redaction")
	}
	if err := chain.ValidateChain(store); err != nil {
		t.Fatalf("expected valid chain after redaction authorization, got: %v", err)
	}
}

func TestValidateChainRejectsTamperedRedactionRequest(t *testing.T) {
	chain := NewBlockchain()
	store := newTestKeystore(t)
	block := addSignedBlock(t, chain, store, medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "Signed"))

	request := medical.NewRedactionRequest(block.Record.RecordID, "P001", "patient requested deletion")
	requestSignature, err := store.SignRedactionRequestAsPatient("P001", request)
	if err != nil {
		t.Fatalf("sign redaction request failed: %v", err)
	}
	request.Signature = requestSignature

	approval := medical.NewRedactionApproval(block.Record.RecordID, "P001", "A001")
	approvalSignature, err := store.SignRedactionApprovalAsAuthority("A001", approval)
	if err != nil {
		t.Fatalf("sign redaction approval failed: %v", err)
	}
	approval.Signature = approvalSignature

	if err := chain.AuthorizeRedaction(block.Record.RecordID, request, approval); err != nil {
		t.Fatalf("authorize redaction failed: %v", err)
	}

	chain.Blocks[1].Record.RedactionRequest.Reason = "tampered"
	chain.Blocks[1].Hash = chain.Blocks[1].CalculateHash()

	if err := chain.ValidateChain(store); err == nil {
		t.Fatalf("expected tampered redaction request to be rejected")
	}
}

func TestRedactRecordRemovesEncryptedPayloadAndPreservesValidation(t *testing.T) {
	chain := NewBlockchain()
	store := newTestKeystore(t)
	block := addSignedBlock(t, chain, store, medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "Signed"))

	request := medical.NewRedactionRequest(block.Record.RecordID, "P001", "patient requested deletion")
	requestSignature, err := store.SignRedactionRequestAsPatient("P001", request)
	if err != nil {
		t.Fatalf("sign redaction request failed: %v", err)
	}
	request.Signature = requestSignature

	approval := medical.NewRedactionApproval(block.Record.RecordID, "P001", "A001")
	approvalSignature, err := store.SignRedactionApprovalAsAuthority("A001", approval)
	if err != nil {
		t.Fatalf("sign redaction approval failed: %v", err)
	}
	approval.Signature = approvalSignature

	if err := chain.AuthorizeRedaction(block.Record.RecordID, request, approval); err != nil {
		t.Fatalf("authorize redaction failed: %v", err)
	}
	if err := chain.RedactRecord(block.Record.RecordID); err != nil {
		t.Fatalf("redact record failed: %v", err)
	}

	redacted := chain.Blocks[1].Record
	if !redacted.IsRedacted() {
		t.Fatalf("expected record to be marked redacted")
	}
	if redacted.PendingRedaction {
		t.Fatalf("expected pending_redaction to be false after execution")
	}
	if redacted.Ciphertext != "" || redacted.Nonce != "" {
		t.Fatalf("expected encrypted payload to be cleared")
	}
	if len(redacted.WrappedKeys) != 0 {
		t.Fatalf("expected wrapped keys to be cleared")
	}
	if redacted.RedactedAt <= 0 {
		t.Fatalf("expected redacted_at to be set")
	}
	if err := chain.ValidateChain(store); err != nil {
		t.Fatalf("expected valid chain after redaction, got: %v", err)
	}
}

func TestValidateChainRejectsRedactedRecordWithCiphertext(t *testing.T) {
	chain := NewBlockchain()
	store := newTestKeystore(t)
	block := addSignedBlock(t, chain, store, medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "Signed"))

	request := medical.NewRedactionRequest(block.Record.RecordID, "P001", "patient requested deletion")
	requestSignature, err := store.SignRedactionRequestAsPatient("P001", request)
	if err != nil {
		t.Fatalf("sign redaction request failed: %v", err)
	}
	request.Signature = requestSignature

	approval := medical.NewRedactionApproval(block.Record.RecordID, "P001", "A001")
	approvalSignature, err := store.SignRedactionApprovalAsAuthority("A001", approval)
	if err != nil {
		t.Fatalf("sign redaction approval failed: %v", err)
	}
	approval.Signature = approvalSignature

	if err := chain.AuthorizeRedaction(block.Record.RecordID, request, approval); err != nil {
		t.Fatalf("authorize redaction failed: %v", err)
	}
	if err := chain.RedactRecord(block.Record.RecordID); err != nil {
		t.Fatalf("redact record failed: %v", err)
	}

	chain.Blocks[1].Record.Ciphertext = "should-not-be-here"
	chain.Blocks[1].Hash = chain.Blocks[1].CalculateHash()

	if err := chain.ValidateChain(store); err == nil {
		t.Fatalf("expected redacted record with ciphertext to be rejected")
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

	encryptedRecord, err := encryptRecordForTest(store, record)
	if err != nil {
		t.Fatalf("encrypt record: %v", err)
	}
	signature, err := store.SignRecordAsDoctor(record.DoctorID, encryptedRecord)
	if err != nil {
		t.Fatalf("sign record: %v", err)
	}

	block, err := chain.AddBlock(encryptedRecord, signature)
	if err != nil {
		t.Fatalf("add block failed: %v", err)
	}

	return block
}

func encryptRecordForTest(store *auth.Keystore, record medical.MedicalRecord) (medical.EncryptedRecord, error) {
	return store.EncryptRecord(record, []actors.ActorInfo{
		{ID: "A001", Role: actors.RoleAuthority, Active: true},
	})
}
