package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeetraj/amnesia/actors"
	"github.com/jeetraj/amnesia/auth"
	"github.com/jeetraj/amnesia/core"
	"github.com/jeetraj/amnesia/medical"
)

func TestSaveAndLoadChainRoundTrip(t *testing.T) {
	chain := core.NewBlockchain()
	store, err := auth.NewDemoKeystore(actors.NewDemoRegistry())
	if err != nil {
		t.Fatalf("create keystore failed: %v", err)
	}

	record := medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "Original content")
	record.RecordID = "R001"
	encryptedRecord, err := store.EncryptRecord(record, []actors.ActorInfo{
		{ID: "A001", Role: actors.RoleAuthority, Active: true},
	})
	if err != nil {
		t.Fatalf("encrypt record failed: %v", err)
	}
	signature, err := store.SignRecordAsDoctor("D001", encryptedRecord)
	if err != nil {
		t.Fatalf("sign record failed: %v", err)
	}

	if _, err := chain.AddBlock(encryptedRecord, signature); err != nil {
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
	if loaded.Blocks[1].Record.Ciphertext == "" {
		t.Fatalf("expected encrypted ciphertext to be stored")
	}
}

func TestLoadChainRejectsTamperedFile(t *testing.T) {
	chain := core.NewBlockchain()
	store, err := auth.NewDemoKeystore(actors.NewDemoRegistry())
	if err != nil {
		t.Fatalf("create keystore failed: %v", err)
	}

	record := medical.NewRecord("P001", "D001", "visit_note", "Visit Note", "Original content")
	record.RecordID = "R001"
	encryptedRecord, err := store.EncryptRecord(record, []actors.ActorInfo{
		{ID: "A001", Role: actors.RoleAuthority, Active: true},
	})
	if err != nil {
		t.Fatalf("encrypt record failed: %v", err)
	}
	signature, err := store.SignRecordAsDoctor("D001", encryptedRecord)
	if err != nil {
		t.Fatalf("sign record failed: %v", err)
	}

	if _, err := chain.AddBlock(encryptedRecord, signature); err != nil {
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

	tampered := strings.Replace(string(data), loadedEncryptedCiphertext(t, string(data)), "tampered-ciphertext", 1)
	if err := os.WriteFile(path, []byte(tampered), 0644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if _, err := LoadChain(path); err == nil {
		t.Fatalf("expected tampered chain to fail validation")
	}
}

func loadedEncryptedCiphertext(t *testing.T, data string) string {
	t.Helper()

	type chainFile struct {
		Blocks []struct {
			Record struct {
				Ciphertext string `json:"ciphertext"`
			} `json:"record"`
		} `json:"blocks"`
	}

	var parsed chainFile
	if err := json.Unmarshal([]byte(data), &parsed); err != nil {
		t.Fatalf("unmarshal test chain file: %v", err)
	}
	if len(parsed.Blocks) < 2 || parsed.Blocks[1].Record.Ciphertext == "" {
		t.Fatalf("expected encrypted ciphertext in saved chain")
	}

	return parsed.Blocks[1].Record.Ciphertext
}
