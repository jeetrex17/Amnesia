package storage

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jeetraj/amnesia/auth"
)

func SaveKeystore(path string, store *auth.Keystore) error {
	if err := store.Validate(); err != nil {
		return fmt.Errorf("validate keystore: %w", err)
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal keystore: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write keystore file: %w", err)
	}

	return nil
}

func LoadKeystore(path string) (*auth.Keystore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read keystore file: %w", err)
	}

	var store auth.Keystore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("unmarshal keystore: %w", err)
	}
	store.ActivateLegacyDefaults()

	if err := store.Validate(); err != nil {
		return nil, fmt.Errorf("loaded keystore is invalid: %w", err)
	}

	return &store, nil
}
