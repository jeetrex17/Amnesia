package storage

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jeetraj/amnesia/chameleon"
)

func SaveChameleonStore(path string, store *chameleon.Store) error {
	if err := store.Validate(); err != nil {
		return fmt.Errorf("validate chameleon store: %w", err)
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal chameleon store: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write chameleon store file: %w", err)
	}

	return nil
}

func LoadChameleonStore(path string) (*chameleon.Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read chameleon store file: %w", err)
	}

	var store chameleon.Store
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("unmarshal chameleon store: %w", err)
	}
	if err := store.Validate(); err != nil {
		return nil, fmt.Errorf("loaded chameleon store is invalid: %w", err)
	}

	return &store, nil
}
