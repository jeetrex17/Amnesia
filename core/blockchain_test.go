package core

import "testing"

func TestValidateChainDetectsTampering(t *testing.T) {
	chain := NewBlockchain()
	chain.AddBlock("patient A: record 1")
	chain.AddBlock("patient B: record 2")

	if err := chain.ValidateChain(); err != nil {
		t.Fatalf("expected valid chain, got error: %v", err)
	}

	chain.Blocks[1].Data = "tampered data"

	if err := chain.ValidateChain(); err == nil {
		t.Fatalf("expected tampering to be detected")
	}
}
