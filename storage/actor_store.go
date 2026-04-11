package storage

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jeetraj/amnesia/actors"
)

func SaveActors(path string, registry *actors.Registry) error {
	if err := registry.Validate(); err != nil {
		return fmt.Errorf("validate actor registry: %w", err)
	}

	data, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal actors: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write actor file: %w", err)
	}

	return nil
}

func LoadActors(path string) (*actors.Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read actor file: %w", err)
	}

	var registry actors.Registry
	if err := json.Unmarshal(data, &registry); err != nil {
		return nil, fmt.Errorf("unmarshal actors: %w", err)
	}
	registry.ActivateLegacyDefaults()

	if err := registry.Validate(); err != nil {
		return nil, fmt.Errorf("loaded actor registry is invalid: %w", err)
	}

	return &registry, nil
}
