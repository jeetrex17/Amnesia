package storage

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jeetraj/amnesia/chameleon"
	"github.com/jeetraj/amnesia/core"
)

func SaveChain(path string, chain *core.Blockchain) error {
	data, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal chain: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write chain file: %w", err)
	}

	return nil
}

func LoadChain(path string, publicKey *chameleon.PublicKey) (*core.Blockchain, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read chain file: %w", err)
	}

	var chain core.Blockchain
	if err := json.Unmarshal(data, &chain); err != nil {
		return nil, fmt.Errorf("unmarshal chain: %w", err)
	}

	if err := chain.ValidateIntegrity(publicKey); err != nil {
		return nil, fmt.Errorf("loaded chain is invalid: %w", err)
	}

	return &chain, nil
}
