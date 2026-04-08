package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/jeetraj/amnesia/core"
	"github.com/jeetraj/amnesia/storage"
)

func main() {
	const chainPath = "chain.json"

	chain := core.NewBlockchain()
	chain.AddBlock("Patient P001 - visit note")
	chain.AddBlock("Patient P002 - diagnosis")

	if err := storage.SaveChain(chainPath, chain); err != nil {
		log.Fatalf("save failed: %v", err)
	}

	loadedChain, err := storage.LoadChain(chainPath)
	if err != nil {
		log.Fatalf("load failed: %v", err)
	}

	output, err := json.MarshalIndent(loadedChain, "", "  ")
	if err != nil {
		log.Fatalf("marshal loaded chain: %v", err)
	}

	fmt.Println(string(output))
}
