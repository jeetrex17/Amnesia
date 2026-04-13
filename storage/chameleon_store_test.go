package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jeetraj/amnesia/chameleon"
)

func TestSaveAndLoadChameleonStoreRoundTrip(t *testing.T) {
	store, err := chameleon.Generate()
	if err != nil {
		t.Fatalf("generate chameleon store failed: %v", err)
	}

	path := filepath.Join(t.TempDir(), "chameleon.json")
	if err := SaveChameleonStore(path, store); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	loaded, err := LoadChameleonStore(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if loaded.PublicKey != store.PublicKey {
		t.Fatalf("unexpected public key after round trip")
	}
	if loaded.Trapdoor != store.Trapdoor {
		t.Fatalf("unexpected trapdoor after round trip")
	}
}

func TestLoadChameleonStoreRejectsTamperedFile(t *testing.T) {
	store, err := chameleon.Generate()
	if err != nil {
		t.Fatalf("generate chameleon store failed: %v", err)
	}

	path := filepath.Join(t.TempDir(), "chameleon.json")
	if err := SaveChameleonStore(path, store); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	if err := os.WriteFile(path, []byte(`{"public_key":"00","trapdoor":"00"}`), 0644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if _, err := LoadChameleonStore(path); err == nil {
		t.Fatalf("expected tampered chameleon store to fail validation")
	}
}
