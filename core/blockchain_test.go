package core

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/jeetraj/amnesia/actors"
	"github.com/jeetraj/amnesia/auth"
	"github.com/jeetraj/amnesia/chameleon"
	"github.com/jeetraj/amnesia/medical"
	"github.com/jeetraj/amnesia/zk"
)

type allowAllProofVerifier struct{}

func (allowAllProofVerifier) VerifyRecordProof(record medical.EncryptedRecord) error {
	return nil
}

type failProofVerifier struct{}

func (failProofVerifier) VerifyRecordProof(record medical.EncryptedRecord) error {
	return fmt.Errorf("proof rejected")
}

func TestValidateChainDetectsTampering(t *testing.T) {
	chain, _, publicKey := newTestBlockchain(t)
	store := newTestKeystore(t)
	addSignedBlock(t, chain, store, publicKey, medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "Patient A: record 1"))
	addSignedBlock(t, chain, store, publicKey, medical.NewRecord("P002", "D002", "diagnosis", "Diagnosis", "Patient B: record 2"))

	if err := chain.ValidateChain(store, publicKey, nil); err != nil {
		t.Fatalf("expected valid chain, got error: %v", err)
	}

	chain.Blocks[1].Record.Ciphertext = "tampered-data"

	if err := chain.ValidateChain(store, publicKey, nil); err == nil {
		t.Fatalf("expected tampering to be detected")
	}
}

func TestAddBlockGeneratesSequentialRecordIDs(t *testing.T) {
	chain, _, publicKey := newTestBlockchain(t)
	store := newTestKeystore(t)

	first := addSignedBlock(t, chain, store, publicKey, medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "First"))
	second := addSignedBlock(t, chain, store, publicKey, medical.NewRecord("P002", "D002", "diagnosis", "Diagnosis", "Second"))

	if first.Record.RecordID != "R001" {
		t.Fatalf("unexpected first record ID: got %s", first.Record.RecordID)
	}
	if second.Record.RecordID != "R002" {
		t.Fatalf("unexpected second record ID: got %s", second.Record.RecordID)
	}
}

func TestAddBlockRejectsInvalidRecord(t *testing.T) {
	chain, _, publicKey := newTestBlockchain(t)
	record := medical.NewEncryptedRecord("R001", "D001", "visit_note", 1, "", "", "nonce", []medical.WrappedKey{
		{
			ActorID:            "D001",
			ActorRole:          actors.RoleDoctor,
			EphemeralPublicKey: "ephemeral",
			Ciphertext:         "ciphertext",
			Nonce:              "nonce",
		},
	})

	if _, err := chain.AddBlock(record, "signature", publicKey); err == nil {
		t.Fatalf("expected invalid encrypted record to be rejected")
	}
}

func TestAddBlockRejectsDuplicateRecordID(t *testing.T) {
	chain, _, publicKey := newTestBlockchain(t)
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
	if _, err := chain.AddBlock(firstEncryptedRecord, firstSignature, publicKey); err != nil {
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
	if _, err := chain.AddBlock(secondEncryptedRecord, secondSignature, publicKey); err == nil {
		t.Fatalf("expected duplicate record ID to be rejected")
	}
}

func TestValidateChainRejectsInvalidDoctorSignature(t *testing.T) {
	chain, _, publicKey := newTestBlockchain(t)
	store := newTestKeystore(t)
	addSignedBlock(t, chain, store, publicKey, medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "Signed"))

	chain.Blocks[1].DoctorSignature = "not-a-valid-signature"

	if err := chain.ValidateChain(store, publicKey, nil); err == nil {
		t.Fatalf("expected invalid signature to be rejected")
	}
}

func TestAuthorizeRedactionAddsSignedMetadataWithoutChangingLaterLinkHashes(t *testing.T) {
	chain, chameleonStore, publicKey := newTestBlockchain(t)
	store := newTestKeystore(t)
	blockOne := addSignedBlock(t, chain, store, publicKey, medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "Signed"))
	addSignedBlock(t, chain, store, publicKey, medical.NewRecord("P002", "D002", "diagnosis", "Diagnosis", "Second block"))

	nextPrevLink := chain.Blocks[2].PrevLinkHash
	nextLinkHash := chain.Blocks[2].LinkHash

	request := signTestRedactionRequest(t, store, blockOne.Record.RecordID, "P001", "patient requested deletion")
	approval := signTestRedactionApproval(t, store, blockOne.Record.RecordID, "P001", "A001")

	if err := chain.AuthorizeRedaction(blockOne.Record.RecordID, request, approval, chameleonStore); err != nil {
		t.Fatalf("authorize redaction failed: %v", err)
	}
	if !chain.Blocks[1].Record.PendingRedaction {
		t.Fatalf("expected record to be marked pending redaction")
	}
	if chain.Blocks[2].PrevLinkHash != nextPrevLink {
		t.Fatalf("expected downstream prev link hash to remain unchanged")
	}
	if chain.Blocks[2].LinkHash != nextLinkHash {
		t.Fatalf("expected downstream link hash to remain unchanged")
	}
	if err := chain.ValidateChain(store, publicKey, nil); err != nil {
		t.Fatalf("expected valid chain after redaction authorization, got: %v", err)
	}
}

func TestValidateChainRejectsTamperedRedactionRequest(t *testing.T) {
	chain, chameleonStore, publicKey := newTestBlockchain(t)
	store := newTestKeystore(t)
	block := addSignedBlock(t, chain, store, publicKey, medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "Signed"))

	request := signTestRedactionRequest(t, store, block.Record.RecordID, "P001", "patient requested deletion")
	approval := signTestRedactionApproval(t, store, block.Record.RecordID, "P001", "A001")

	if err := chain.AuthorizeRedaction(block.Record.RecordID, request, approval, chameleonStore); err != nil {
		t.Fatalf("authorize redaction failed: %v", err)
	}

	chain.Blocks[1].Record.RedactionRequest.Reason = "tampered"

	if err := chain.ValidateChain(store, publicKey, nil); err == nil {
		t.Fatalf("expected tampered redaction request to be rejected")
	}
}

func TestRedactRecordRemovesEncryptedPayloadWithoutChangingLaterLinkHashes(t *testing.T) {
	chain, chameleonStore, publicKey := newTestBlockchain(t)
	store := newTestKeystore(t)
	blockOne := addSignedBlock(t, chain, store, publicKey, medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "Signed"))
	addSignedBlock(t, chain, store, publicKey, medical.NewRecord("P002", "D002", "diagnosis", "Diagnosis", "Second block"))

	request := signTestRedactionRequest(t, store, blockOne.Record.RecordID, "P001", "patient requested deletion")
	approval := signTestRedactionApproval(t, store, blockOne.Record.RecordID, "P001", "A001")
	if err := chain.AuthorizeRedaction(blockOne.Record.RecordID, request, approval, chameleonStore); err != nil {
		t.Fatalf("authorize redaction failed: %v", err)
	}

	nextPrevLink := chain.Blocks[2].PrevLinkHash
	nextLinkHash := chain.Blocks[2].LinkHash

	proof := newTestRedactionProof(t, blockOne.Record.RecordID, "P001", blockOne.Record.PatientCommitment)
	if err := chain.RedactRecord(blockOne.Record.RecordID, proof, chameleonStore); err != nil {
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
	if chain.Blocks[2].PrevLinkHash != nextPrevLink {
		t.Fatalf("expected downstream prev link hash to remain unchanged")
	}
	if chain.Blocks[2].LinkHash != nextLinkHash {
		t.Fatalf("expected downstream link hash to remain unchanged")
	}
	if err := chain.ValidateChain(store, publicKey, allowAllProofVerifier{}); err != nil {
		t.Fatalf("expected valid chain after redaction, got: %v", err)
	}
}

func TestValidateChainRejectsRedactedRecordWithCiphertext(t *testing.T) {
	chain, chameleonStore, publicKey := newTestBlockchain(t)
	store := newTestKeystore(t)
	block := addSignedBlock(t, chain, store, publicKey, medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "Signed"))

	request := signTestRedactionRequest(t, store, block.Record.RecordID, "P001", "patient requested deletion")
	approval := signTestRedactionApproval(t, store, block.Record.RecordID, "P001", "A001")

	if err := chain.AuthorizeRedaction(block.Record.RecordID, request, approval, chameleonStore); err != nil {
		t.Fatalf("authorize redaction failed: %v", err)
	}
	proof := newTestRedactionProof(t, block.Record.RecordID, "P001", block.Record.PatientCommitment)
	if err := chain.RedactRecord(block.Record.RecordID, proof, chameleonStore); err != nil {
		t.Fatalf("redact record failed: %v", err)
	}

	chain.Blocks[1].Record.Ciphertext = "should-not-be-here"

	if err := chain.ValidateChain(store, publicKey, allowAllProofVerifier{}); err == nil {
		t.Fatalf("expected redacted record with ciphertext to be rejected")
	}
}

func newTestBlockchain(t *testing.T) (*Blockchain, *chameleon.Store, *chameleon.PublicKey) {
	t.Helper()

	chameleonStore, err := chameleon.Generate()
	if err != nil {
		t.Fatalf("generate chameleon store: %v", err)
	}
	publicKey, err := chameleonStore.Public()
	if err != nil {
		t.Fatalf("load chameleon public key: %v", err)
	}
	chain, err := NewBlockchain(publicKey)
	if err != nil {
		t.Fatalf("create blockchain: %v", err)
	}

	return chain, chameleonStore, publicKey
}

func newTestKeystore(t *testing.T) *auth.Keystore {
	t.Helper()

	store, err := auth.NewDemoKeystore(actors.NewDemoRegistry())
	if err != nil {
		t.Fatalf("create demo keystore: %v", err)
	}

	return store
}

func addSignedBlock(t *testing.T, chain *Blockchain, store *auth.Keystore, publicKey *chameleon.PublicKey, record medical.MedicalRecord) Block {
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

	block, err := chain.AddBlock(encryptedRecord, signature, publicKey)
	if err != nil {
		t.Fatalf("add block failed: %v", err)
	}

	return block
}

func encryptRecordForTest(store *auth.Keystore, record medical.MedicalRecord) (medical.EncryptedRecord, error) {
	salt, err := zk.GeneratePatientCommitmentSalt()
	if err != nil {
		return medical.EncryptedRecord{}, err
	}
	if err := store.SetRecordCommitmentSalt(record.RecordID, salt); err != nil {
		return medical.EncryptedRecord{}, err
	}
	patientCommitment, err := zk.ComputePatientCommitment(record.RecordID, record.PatientID, salt)
	if err != nil {
		return medical.EncryptedRecord{}, err
	}

	return store.EncryptRecord(record, patientCommitment, []actors.ActorInfo{
		{ID: "A001", Role: actors.RoleAuthority, Active: true},
	})
}

func signTestRedactionRequest(t *testing.T, store *auth.Keystore, recordID, patientID, reason string) medical.RedactionRequest {
	t.Helper()

	request := medical.NewRedactionRequest(recordID, patientID, reason)
	signature, err := store.SignRedactionRequestAsPatient(patientID, request)
	if err != nil {
		t.Fatalf("sign redaction request failed: %v", err)
	}
	request.Signature = signature
	return request
}

func signTestRedactionApproval(t *testing.T, store *auth.Keystore, recordID, patientID, authorityID string) medical.RedactionApproval {
	t.Helper()

	approval := medical.NewRedactionApproval(recordID, patientID, authorityID)
	signature, err := store.SignRedactionApprovalAsAuthority(authorityID, approval)
	if err != nil {
		t.Fatalf("sign redaction approval failed: %v", err)
	}
	approval.Signature = signature
	return approval
}

func newTestRedactionProof(t *testing.T, recordID, patientID, patientCommitment string) medical.RedactionProof {
	t.Helper()

	recordField, err := zk.EncodeIDFieldString(recordID)
	if err != nil {
		t.Fatalf("encode record ID field: %v", err)
	}
	patientField, err := zk.EncodeIDFieldString(patientID)
	if err != nil {
		t.Fatalf("encode patient ID field: %v", err)
	}

	return medical.RedactionProof{
		Scheme:            medical.RedactionProofScheme,
		PatientCommitment: patientCommitment,
		RecordIDField:     recordField,
		PatientIDField:    patientField,
		Proof:             base64.StdEncoding.EncodeToString([]byte("proof")),
	}
}
