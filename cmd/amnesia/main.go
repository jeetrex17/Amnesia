package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/jeetraj/amnesia/actors"
	"github.com/jeetraj/amnesia/auth"
	"github.com/jeetraj/amnesia/core"
	"github.com/jeetraj/amnesia/medical"
	"github.com/jeetraj/amnesia/storage"
)

const chainPath = "chain.json"
const actorsPath = "actors.json"
const keystorePath = "keystore.json"

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
	registry := actors.NewDemoRegistry()
	store, err := auth.NewDemoKeystore(registry)
	if err != nil {
		return err
	}

	if err := storage.SaveChain(chainPath, chain); err != nil {
		return err
	}
	if err := storage.SaveActors(actorsPath, registry); err != nil {
		return err
	}
	if err := storage.SaveKeystore(keystorePath, store); err != nil {
		return err
	}

	_, err = fmt.Fprintf(stdout, "initialized blockchain at %s, actors at %s, and keystore at %s\n", chainPath, actorsPath, keystorePath)
	return err
}

func runAddRecord(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("add-record", flag.ContinueOnError)
	fs.SetOutput(stderr)

	patientIDLong := fs.String("patient", "", "patient identifier")
	patientIDShort := fs.String("p", "", "patient identifier")
	doctorIDLong := fs.String("doctor", "", "doctor identifier")
	doctorIDShort := fs.String("d", "", "doctor identifier")
	recordTypeLong := fs.String("type", "", "record type")
	recordTypeShort := fs.String("r", "", "record type")
	titleLong := fs.String("title", "", "record title")
	titleShort := fs.String("t", "", "record title")
	contentLong := fs.String("content", "", "record content")
	contentShort := fs.String("c", "", "record content")

	if err := fs.Parse(args); err != nil {
		return err
	}

	patientID, err := resolveFlagValue("patient", *patientIDLong, "p", *patientIDShort)
	if err != nil {
		return err
	}
	doctorID, err := resolveFlagValue("doctor", *doctorIDLong, "d", *doctorIDShort)
	if err != nil {
		return err
	}
	recordType, err := resolveFlagValue("type", *recordTypeLong, "r", *recordTypeShort)
	if err != nil {
		return err
	}
	title, err := resolveFlagValue("title", *titleLong, "t", *titleShort)
	if err != nil {
		return err
	}
	content, err := resolveFlagValue("content", *contentLong, "c", *contentShort)
	if err != nil {
		return err
	}

	if patientID == "" || doctorID == "" || recordType == "" || title == "" || content == "" {
		return fmt.Errorf("all add-record flags are required")
	}

	chain, err := loadExistingChain()
	if err != nil {
		return err
	}
	registry, err := loadActorRegistry()
	if err != nil {
		return err
	}
	store, err := loadKeystore()
	if err != nil {
		return err
	}

	if !registry.HasPatient(patientID) {
		return fmt.Errorf("unknown patient ID: %s", patientID)
	}
	if !registry.HasDoctor(doctorID) {
		return fmt.Errorf("unknown doctor ID: %s", doctorID)
	}

	record := medical.NewRecord(patientID, doctorID, recordType, title, content)
	recordID, err := chain.NextRecordID()
	if err != nil {
		return err
	}
	record.RecordID = recordID

	signature, err := store.SignRecordAsDoctor(doctorID, record)
	if err != nil {
		return err
	}

	block, err := chain.AddBlock(record, signature)
	if err != nil {
		return err
	}
	if err := chain.ValidateChain(store); err != nil {
		return fmt.Errorf("post-add validation failed: %w", err)
	}

	if err := storage.SaveChain(chainPath, chain); err != nil {
		return err
	}

	_, err = fmt.Fprintf(stdout, "added record %s in block %d\n", block.Record.RecordID, block.Index)
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
	store, err := loadKeystore()
	if err != nil {
		return err
	}

	if err := chain.ValidateChain(store); err != nil {
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

func loadActorRegistry() (*actors.Registry, error) {
	registry, err := storage.LoadActors(actorsPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s not found; run `amnesia init` first", actorsPath)
		}
		return nil, err
	}

	return registry, nil
}

func loadKeystore() (*auth.Keystore, error) {
	store, err := storage.LoadKeystore(keystorePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s not found; run `amnesia init` first", keystorePath)
		}
		return nil, err
	}

	return store, nil
}

func resolveFlagValue(longName, longValue, shortName, shortValue string) (string, error) {
	if longValue != "" && shortValue != "" && longValue != shortValue {
		return "", fmt.Errorf("conflicting values for --%s and -%s", longName, shortName)
	}
	if longValue != "" {
		return longValue, nil
	}

	return shortValue, nil
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Amnesia")
	fmt.Fprintln(w, "A redactable zero-knowledge blockchain for medical records.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  amnesia <command> [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  init")
	fmt.Fprintln(w, "      Create a fresh blockchain and seed demo actors plus keys.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  add-record [--patient|-p] <id> [--doctor|-d] <id> [--type|-r] <type> [--title|-t] <title> [--content|-c] <content>")
	fmt.Fprintln(w, "      Add a new medical record to the blockchain.")
	fmt.Fprintln(w, "      Record IDs are generated automatically as R001, R002, ...")
	fmt.Fprintln(w, "      Short aliases: -p patient, -d doctor, -r type, -t title, -c content")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  view-chain")
	fmt.Fprintln(w, "      Print the full blockchain as formatted JSON.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  verify")
	fmt.Fprintln(w, "      Recalculate hashes and validate the stored chain plus doctor signatures.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Supported medical record types:")
	fmt.Fprintln(w, "  diagnosis           A diagnosis or confirmed condition")
	fmt.Fprintln(w, "  prescription        A prescribed medicine or treatment")
	fmt.Fprintln(w, "  lab_result          A lab report or test result")
	fmt.Fprintln(w, "  vaccination         A vaccination or immunization record")
	fmt.Fprintln(w, "  visit_note          A general visit or consultation note")
	fmt.Fprintln(w, "  infectious_disease  An infectious-disease record")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "ID format rules:")
	fmt.Fprintln(w, "  Patient IDs: P001, P002, ...")
	fmt.Fprintln(w, "  Doctor IDs : D001, D002, ...")
	fmt.Fprintln(w, "  Authority IDs: A001, A002, ...")
	fmt.Fprintln(w, "  Record IDs : generated automatically")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Seeded demo actors after init:")
	fmt.Fprintln(w, "  Patients   : P001, P002, P007")
	fmt.Fprintln(w, "  Doctors    : D001, D002")
	fmt.Fprintln(w, "  Authorities: A001")
	fmt.Fprintln(w, "  Keys       : stored in keystore.json")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Example:")
	fmt.Fprintln(w, `  amnesia add-record -p P007 -d D001 -r diagnosis -t "blood cancer" -c "3 months left"`)
}
