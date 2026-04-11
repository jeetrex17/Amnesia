package actors

import "testing"

func TestAddActorGeneratesNextIDByRole(t *testing.T) {
	registry := NewDemoRegistry()

	doctor, err := registry.AddActor(RoleDoctor, "Dr. Kapoor")
	if err != nil {
		t.Fatalf("add doctor failed: %v", err)
	}
	patient, err := registry.AddActor(RolePatient, "Neha Joshi")
	if err != nil {
		t.Fatalf("add patient failed: %v", err)
	}
	authority, err := registry.AddActor(RoleAuthority, "State Review Board")
	if err != nil {
		t.Fatalf("add authority failed: %v", err)
	}

	if doctor.ID != "D003" {
		t.Fatalf("unexpected doctor ID: got %s", doctor.ID)
	}
	if patient.ID != "P008" {
		t.Fatalf("unexpected patient ID: got %s", patient.ID)
	}
	if authority.ID != "A002" {
		t.Fatalf("unexpected authority ID: got %s", authority.ID)
	}
}

func TestDeactivateActorMarksActorInactive(t *testing.T) {
	registry := NewDemoRegistry()

	actor, err := registry.DeactivateActor("D001")
	if err != nil {
		t.Fatalf("deactivate actor failed: %v", err)
	}
	if actor.Active {
		t.Fatalf("expected returned actor to be inactive")
	}
	if registry.HasActiveDoctor("D001") {
		t.Fatalf("expected doctor to be inactive in registry")
	}
}
