package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/jeetraj/amnesia/core"
	"github.com/jeetraj/amnesia/medical"
	"github.com/jeetraj/amnesia/storage"
)

func main() {
	const chainPath = "chain.json"

	chain := core.NewBlockchain()
	chain.AddBlock(medical.NewRecord(
		"R001",
		"P001",
		"D001",
		"visit_note",
		"Initial Consultation",
		"Patient reports mild fever and fatigue for three days.",
	))
	chain.AddBlock(medical.NewRecord(
		"R002",
		"P002",
		"D002",
		"diagnosis",
		"Respiratory Infection",
		"Clinical diagnosis indicates a non-severe respiratory infection.",
	))

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
