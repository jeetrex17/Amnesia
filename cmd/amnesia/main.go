package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/jeetraj/amnesia/core"
)

func main() {
	chain := core.NewBlockchain()
	chain.AddBlock("Patient P001 - visit note")
	chain.AddBlock("Patient P002 - diagnosis")

	if err := chain.ValidateChain(); err != nil {
		log.Fatalf("chain validation failed: %v", err)
	}

	output, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		log.Fatalf("marshal chain: %v", err)
	}

	fmt.Println(string(output))
}
