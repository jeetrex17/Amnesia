package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeetraj/amnesia/actors"
)

func TestSaveAndLoadActorsRoundTrip(t *testing.T) {
	registry := actors.NewDemoRegistry()

	path := filepath.Join(t.TempDir(), "actors.json")
	if err := SaveActors(path, registry); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	loaded, err := LoadActors(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if !loaded.HasPatient("P001") {
		t.Fatalf("expected seeded patient to exist")
	}
	if !loaded.HasDoctor("D001") {
		t.Fatalf("expected seeded doctor to exist")
	}
	if !loaded.HasAuthority("A001") {
		t.Fatalf("expected seeded authority to exist")
	}
	if !loaded.HasActiveDoctor("D001") {
		t.Fatalf("expected seeded doctor to be active")
	}
}

func TestLoadActorsRejectsTamperedFile(t *testing.T) {
	registry := actors.NewDemoRegistry()

	path := filepath.Join(t.TempDir(), "actors.json")
	if err := SaveActors(path, registry); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	tampered := strings.Replace(string(data), `"id": "A001"`, `"id": ""`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if _, err := LoadActors(path); err == nil {
		t.Fatalf("expected tampered actor file to fail validation")
	}
}
