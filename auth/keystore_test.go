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
	if err := store.DeactivateActor("D001"); err != nil {
		t.Fatalf("deactivate key entry failed: %v", err)
	}

	record := medical.NewRecordWithID("R001", "P001", "D001", "visit_note", "Visit Note", "content")
	if _, err := store.SignRecordAsDoctor("D001", record); err == nil {
		t.Fatalf("expected inactive doctor signing to fail")
	}
}

func TestVerifyDoctorSignatureStillWorksForInactiveDoctor(t *testing.T) {
	store, err := NewDemoKeystore(actors.NewDemoRegistry())
	if err != nil {
		t.Fatalf("create keystore failed: %v", err)
	}

	record := medical.NewRecordWithID("R001", "P001", "D001", "visit_note", "Visit Note", "content")
	signature, err := store.SignRecordAsDoctor("D001", record)
	if err != nil {
		t.Fatalf("sign record failed: %v", err)
	}
	if err := store.DeactivateActor("D001"); err != nil {
		t.Fatalf("deactivate key entry failed: %v", err)
	}
	if err := store.VerifyDoctorRecordSignature(record, signature); err != nil {
		t.Fatalf("expected historical signature verification to succeed: %v", err)
	}
}
