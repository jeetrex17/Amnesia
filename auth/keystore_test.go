package auth

import (
	"testing"

	"github.com/jeetraj/amnesia/actors"
	"github.com/jeetraj/amnesia/medical"
)

func TestAddActorCreatesActiveKeyEntry(t *testing.T) {
	store, err := NewDemoKeystore(actors.NewDemoRegistry())
	if err != nil {
		t.Fatalf("create keystore failed: %v", err)
	}

	entry, err := store.AddActor("D003", actors.RoleDoctor)
	if err != nil {
		t.Fatalf("add keystore actor failed: %v", err)
	}

	if !entry.Active {
		t.Fatalf("expected new key entry to be active")
	}
	if _, err := store.EntryForActiveActor("D003"); err != nil {
		t.Fatalf("expected active entry lookup to succeed: %v", err)
	}
	if entry.EncryptionPublicKey == "" || entry.EncryptionPrivateKey == "" {
		t.Fatalf("expected encryption keypair to be created")
	}
}

func TestDeactivateActorMarksKeyInactive(t *testing.T) {
	store, err := NewDemoKeystore(actors.NewDemoRegistry())
	if err != nil {
		t.Fatalf("create keystore failed: %v", err)
	}

	if err := store.DeactivateActor("D001"); err != nil {
		t.Fatalf("deactivate key entry failed: %v", err)
	}
	if _, err := store.EntryForActiveActor("D001"); err == nil {
		t.Fatalf("expected inactive actor lookup to fail")
	}
}

func TestSignRecordAsDoctorRejectsInactiveDoctor(t *testing.T) {
	store, err := NewDemoKeystore(actors.NewDemoRegistry())
	if err != nil {
		t.Fatalf("create keystore failed: %v", err)
	}
	record := medical.NewRecordWithID("R001", "P001", "D001", "visit_note", "Visit Note", "content")
	encryptedRecord, err := store.EncryptRecord(record, []actors.ActorInfo{{ID: "A001", Role: actors.RoleAuthority, Active: true}})
	if err != nil {
		t.Fatalf("encrypt record failed: %v", err)
	}
	if err := store.DeactivateActor("D001"); err != nil {
		t.Fatalf("deactivate key entry failed: %v", err)
	}
	if _, err := store.SignRecordAsDoctor("D001", encryptedRecord); err == nil {
		t.Fatalf("expected inactive doctor signing to fail")
	}
}

func TestVerifyDoctorSignatureStillWorksForInactiveDoctor(t *testing.T) {
	store, err := NewDemoKeystore(actors.NewDemoRegistry())
	if err != nil {
		t.Fatalf("create keystore failed: %v", err)
	}

	record := medical.NewRecordWithID("R001", "P001", "D001", "visit_note", "Visit Note", "content")
	encryptedRecord, err := store.EncryptRecord(record, []actors.ActorInfo{{ID: "A001", Role: actors.RoleAuthority, Active: true}})
	if err != nil {
		t.Fatalf("encrypt record failed: %v", err)
	}
	signature, err := store.SignRecordAsDoctor("D001", encryptedRecord)
	if err != nil {
		t.Fatalf("sign record failed: %v", err)
	}
	if err := store.DeactivateActor("D001"); err != nil {
		t.Fatalf("deactivate key entry failed: %v", err)
	}
	if err := store.VerifyDoctorRecordSignature(encryptedRecord, signature); err != nil {
		t.Fatalf("expected historical signature verification to succeed: %v", err)
	}
}

func TestEncryptRecordAndDecryptForAllowedActors(t *testing.T) {
	store, err := NewDemoKeystore(actors.NewDemoRegistry())
	if err != nil {
		t.Fatalf("create keystore failed: %v", err)
	}

	record := medical.NewRecordWithID("R001", "P001", "D001", "diagnosis", "Diagnosis", "Patient content")
	encryptedRecord, err := store.EncryptRecord(record, []actors.ActorInfo{{ID: "A001", Role: actors.RoleAuthority, Active: true}})
	if err != nil {
		t.Fatalf("encrypt record failed: %v", err)
	}

	doctorPayload, err := store.DecryptRecordForActor(encryptedRecord, "D001")
	if err != nil {
		t.Fatalf("doctor decrypt failed: %v", err)
	}
	if doctorPayload.Content != "Patient content" {
		t.Fatalf("unexpected doctor payload content: %s", doctorPayload.Content)
	}

	patientPayload, err := store.DecryptRecordForActor(encryptedRecord, "P001")
	if err != nil {
		t.Fatalf("patient decrypt failed: %v", err)
	}
	if patientPayload.PatientID != "P001" {
		t.Fatalf("unexpected patient payload ID: %s", patientPayload.PatientID)
	}

	authorityPayload, err := store.DecryptRecordForActor(encryptedRecord, "A001")
	if err != nil {
		t.Fatalf("authority decrypt failed: %v", err)
	}
	if authorityPayload.Title != "Diagnosis" {
		t.Fatalf("unexpected authority payload title: %s", authorityPayload.Title)
	}
}

func TestDecryptRecordRejectsUnrelatedOrInactiveActor(t *testing.T) {
	store, err := NewDemoKeystore(actors.NewDemoRegistry())
	if err != nil {
		t.Fatalf("create keystore failed: %v", err)
	}

	if _, err := store.AddActor("D003", actors.RoleDoctor); err != nil {
		t.Fatalf("add unrelated doctor failed: %v", err)
	}
	record := medical.NewRecordWithID("R001", "P001", "D001", "visit_note", "Visit Note", "content")
	encryptedRecord, err := store.EncryptRecord(record, []actors.ActorInfo{{ID: "A001", Role: actors.RoleAuthority, Active: true}})
	if err != nil {
		t.Fatalf("encrypt record failed: %v", err)
	}

	if _, err := store.DecryptRecordForActor(encryptedRecord, "D003"); err == nil {
		t.Fatalf("expected unrelated actor decryption to fail")
	}

	if err := store.DeactivateActor("D001"); err != nil {
		t.Fatalf("deactivate doctor failed: %v", err)
	}
	if _, err := store.DecryptRecordForActor(encryptedRecord, "D001"); err == nil {
		t.Fatalf("expected inactive actor decryption to fail")
	}
}

func TestSignAndVerifyRedactionRequest(t *testing.T) {
	store, err := NewDemoKeystore(actors.NewDemoRegistry())
	if err != nil {
		t.Fatalf("create keystore failed: %v", err)
	}

	request := medical.NewRedactionRequest("R001", "P001", "patient requested deletion")
	signature, err := store.SignRedactionRequestAsPatient("P001", request)
	if err != nil {
		t.Fatalf("sign redaction request failed: %v", err)
	}
	request.Signature = signature

	if err := store.VerifyRedactionRequestSignature(request); err != nil {
		t.Fatalf("verify redaction request failed: %v", err)
	}
}

func TestSignAndVerifyRedactionApproval(t *testing.T) {
	store, err := NewDemoKeystore(actors.NewDemoRegistry())
	if err != nil {
		t.Fatalf("create keystore failed: %v", err)
	}

	approval := medical.NewRedactionApproval("R001", "P001", "A001")
	signature, err := store.SignRedactionApprovalAsAuthority("A001", approval)
	if err != nil {
		t.Fatalf("sign redaction approval failed: %v", err)
	}
	approval.Signature = signature

	if err := store.VerifyRedactionApprovalSignature(approval); err != nil {
		t.Fatalf("verify redaction approval failed: %v", err)
	}
}
