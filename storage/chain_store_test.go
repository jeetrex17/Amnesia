package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeetraj/amnesia/core"
	"github.com/jeetraj/amnesia/medical"
)

func TestSaveAndLoadChainRoundTrip(t *testing.T) {
	chain := core.NewBlockchain()
	if _, err := chain.AddBlock(medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "Original content")); err != nil {
		t.Fatalf("add block failed: %v", err)
	}

	path := filepath.Join(t.TempDir(), "chain.json")
	if err := SaveChain(path, chain); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	loaded, err := LoadChain(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if got, want := len(loaded.Blocks), len(chain.Blocks); got != want {
		t.Fatalf("unexpected block count: got %d want %d", got, want)
	}

	if loaded.Blocks[1].Record.RecordID != "R001" {
		t.Fatalf("unexpected record ID: got %s", loaded.Blocks[1].Record.RecordID)
	}
}

func TestLoadChainRejectsTamperedFile(t *testing.T) {
	chain := core.NewBlockchain()
	if _, err := chain.AddBlock(medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "Original content")); err != nil {
		t.Fatalf("add block failed: %v", err)
	}

	path := filepath.Join(t.TempDir(), "chain.json")
	if err := SaveChain(path, chain); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	tampered := strings.Replace(string(data), "Original content", "Tampered content", 1)
	if err := os.WriteFile(path, []byte(tampered), 0644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if _, err := LoadChain(path); err == nil {
		t.Fatalf("expected tampered chain to fail validation")
	}
}
