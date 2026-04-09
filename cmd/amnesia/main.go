package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/jeetraj/amnesia/core"
	"github.com/jeetraj/amnesia/medical"
	"github.com/jeetraj/amnesia/storage"
)

const chainPath = "chain.json"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		log.Fatal(err)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return fmt.Errorf("missing command")
	}

	switch args[0] {
	case "init":
		return runInit(stdout)
	case "add-record":
		return runAddRecord(args[1:], stdout, stderr)
	case "view-chain":
		return runViewChain(stdout)
	case "verify":
		return runVerify(stdout)
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func runInit(stdout io.Writer) error {
	chain := core.NewBlockchain()
	if err := storage.SaveChain(chainPath, chain); err != nil {
		return err
	}

	_, err := fmt.Fprintf(stdout, "initialized blockchain at %s\n", chainPath)
	return err
}

func runAddRecord(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("add-record", flag.ContinueOnError)
	fs.SetOutput(stderr)

	recordID := fs.String("record-id", "", "record identifier")
	patientID := fs.String("patient", "", "patient identifier")
	doctorID := fs.String("doctor", "", "doctor identifier")
	recordType := fs.String("type", "", "record type")
	title := fs.String("title", "", "record title")
	content := fs.String("content", "", "record content")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recordID == "" || *patientID == "" || *doctorID == "" || *recordType == "" || *title == "" || *content == "" {
		return fmt.Errorf("all add-record flags are required")
	}

	chain, err := loadExistingChain()
	if err != nil {
		return err
	}

	record := medical.NewRecord(*recordID, *patientID, *doctorID, *recordType, *title, *content)
	block := chain.AddBlock(record)

	if err := storage.SaveChain(chainPath, chain); err != nil {
		return err
	}

	_, err = fmt.Fprintf(stdout, "added record %s in block %d\n", record.RecordID, block.Index)
	return err
}

func runViewChain(stdout io.Writer) error {
	chain, err := loadExistingChain()
	if err != nil {
		return err
	}

	output, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal chain: %w", err)
	}

	_, err = fmt.Fprintln(stdout, string(output))
	return err
}

func runVerify(stdout io.Writer) error {
	chain, err := loadExistingChain()
	if err != nil {
		return err
	}

	if err := chain.ValidateChain(); err != nil {
		return fmt.Errorf("chain validation failed: %w", err)
	}

	_, err = fmt.Fprintln(stdout, "chain is valid")
	return err
}

func loadExistingChain() (*core.Blockchain, error) {
	chain, err := storage.LoadChain(chainPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s not found; run `amnesia init` first", chainPath)
		}
		return nil, err
	}

	return chain, nil
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: amnesia <command> [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  init")
	fmt.Fprintln(w, "  add-record --record-id <id> --patient <id> --doctor <id> --type <type> --title <title> --content <content>")
	fmt.Fprintln(w, "  view-chain")
	fmt.Fprintln(w, "  verify")
}
