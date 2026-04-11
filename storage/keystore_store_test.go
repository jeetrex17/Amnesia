package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeetraj/amnesia/actors"
	"github.com/jeetraj/amnesia/auth"
)

func TestSaveAndLoadKeystoreRoundTrip(t *testing.T) {
	store, err := auth.NewDemoKeystore(actors.NewDemoRegistry())
	if err != nil {
		t.Fatalf("create keystore failed: %v", err)
	}

	path := filepath.Join(t.TempDir(), "keystore.json")
	if err := SaveKeystore(path, store); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	loaded, err := LoadKeystore(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if _, err := loaded.EntryForActor("D001"); err != nil {
		t.Fatalf("expected doctor key to exist: %v", err)
	}
	if _, err := loaded.EntryForActor("A001"); err != nil {
		t.Fatalf("expected authority key to exist: %v", err)
	}
}

func TestLoadKeystoreRejectsTamperedFile(t *testing.T) {
	store, err := auth.NewDemoKeystore(actors.NewDemoRegistry())
	if err != nil {
		t.Fatalf("create keystore failed: %v", err)
	}

	path := filepath.Join(t.TempDir(), "keystore.json")
	if err := SaveKeystore(path, store); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	tampered := strings.Replace(string(data), `"role": "doctor"`, `"role": "invalid"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if _, err := LoadKeystore(path); err == nil {
		t.Fatalf("expected tampered keystore to fail validation")
	}
}
