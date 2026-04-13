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
	"github.com/jeetraj/amnesia/chameleon"
	"github.com/jeetraj/amnesia/core"
	"github.com/jeetraj/amnesia/medical"
	"github.com/jeetraj/amnesia/storage"
	"github.com/jeetraj/amnesia/zk"
)

const chainPath = "chain.json"
const actorsPath = "actors.json"
const keystorePath = "keystore.json"
const chameleonPath = "chameleon.json"
const zkArtifactsPath = zk.ArtifactsDir

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
	case "setup-zk":
		return runSetupZK(stdout)
	case "add-actor":
		return runAddActor(args[1:], stdout, stderr)
	case "list-actors":
		return runListActors(stdout)
	case "deactivate-actor":
		return runDeactivateActor(args[1:], stdout, stderr)
	case "add-record":
		return runAddRecord(args[1:], stdout, stderr)
	case "view-chain":
		return runViewChain(stdout)
	case "view-record":
		return runViewRecord(args[1:], stdout, stderr)
	case "authorize-redaction":
		return runAuthorizeRedaction(args[1:], stdout, stderr)
	case "redact-record":
		return runRedactRecord(args[1:], stdout, stderr)
	case "verify-proof":
		return runVerifyProof(args[1:], stdout, stderr)
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
	chameleonStore, err := chameleon.Generate()
	if err != nil {
		return err
	}
	publicKey, err := chameleonStore.Public()
	if err != nil {
		return err
	}
	chain, err := core.NewBlockchain(publicKey)
	if err != nil {
		return err
	}
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
	if err := storage.SaveChameleonStore(chameleonPath, chameleonStore); err != nil {
		return err
	}

	_, err = fmt.Fprintf(stdout, "initialized blockchain at %s, actors at %s, keystore at %s, and chameleon keys at %s\n", chainPath, actorsPath, keystorePath, chameleonPath)
	return err
}

func runSetupZK(stdout io.Writer) error {
	if err := zk.Setup(zkArtifactsPath); err != nil {
		return err
	}

	_, err := fmt.Fprintf(stdout, "initialized zk artifacts at %s\n", zkArtifactsPath)
	return err
}

func runAddActor(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("add-actor", flag.ContinueOnError)
	fs.SetOutput(stderr)

	roleLong := fs.String("role", "", "actor role")
	roleShort := fs.String("r", "", "actor role")
	nameLong := fs.String("name", "", "actor name")
	nameShort := fs.String("n", "", "actor name")

	if err := fs.Parse(args); err != nil {
		return err
	}

	role, err := resolveFlagValue("role", *roleLong, "r", *roleShort)
	if err != nil {
		return err
	}
	name, err := resolveFlagValue("name", *nameLong, "n", *nameShort)
	if err != nil {
		return err
	}
	if role == "" || name == "" {
		return fmt.Errorf("both role and name are required")
	}

	registry, err := loadActorRegistry()
	if err != nil {
		return err
	}
	store, err := loadKeystore()
	if err != nil {
		return err
	}

	actor, err := registry.AddActor(role, name)
	if err != nil {
		return err
	}
	if _, err := store.AddActor(actor.ID, actor.Role); err != nil {
		return err
	}

	if err := storage.SaveKeystore(keystorePath, store); err != nil {
		return err
	}
	if err := storage.SaveActors(actorsPath, registry); err != nil {
		return err
	}

	_, err = fmt.Fprintf(stdout, "added %s %s (%s)\n", actor.Role, actor.ID, actor.Name)
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
	chameleonStore, err := loadChameleonStore()
	if err != nil {
		return err
	}
	chameleonPublicKey, err := chameleonStore.Public()
	if err != nil {
		return err
	}
	proofVerifier, err := loadOptionalProofVerifier()
	if err != nil {
		return err
	}

	patient, ok := registry.ActorByID(patientID)
	if !ok || patient.Role != actors.RolePatient {
		return fmt.Errorf("unknown patient ID: %s", patientID)
	}
	if !patient.Active {
		return fmt.Errorf("patient ID is inactive: %s", patientID)
	}

	doctor, ok := registry.ActorByID(doctorID)
	if !ok || doctor.Role != actors.RoleDoctor {
		return fmt.Errorf("unknown doctor ID: %s", doctorID)
	}
	if !doctor.Active {
		return fmt.Errorf("doctor ID is inactive: %s", doctorID)
	}

	record := medical.NewRecord(patientID, doctorID, recordType, title, content)
	recordID, err := chain.NextRecordID()
	if err != nil {
		return err
	}
	record.RecordID = recordID

	patientCommitmentSalt, err := zk.GeneratePatientCommitmentSalt()
	if err != nil {
		return err
	}
	patientCommitment, err := zk.ComputePatientCommitment(record.RecordID, record.PatientID, patientCommitmentSalt)
	if err != nil {
		return err
	}
	if err := store.SetRecordCommitmentSalt(record.RecordID, patientCommitmentSalt); err != nil {
		return err
	}

	encryptedRecord, err := store.EncryptRecord(record, patientCommitment, activeAuthorities(registry))
	if err != nil {
		return err
	}
	signature, err := store.SignRecordAsDoctor(doctorID, encryptedRecord)
	if err != nil {
		return err
	}

	block, err := chain.AddBlock(encryptedRecord, signature, chameleonPublicKey)
	if err != nil {
		return err
	}
	if err := chain.ValidateChain(store, chameleonPublicKey, proofVerifier); err != nil {
		return fmt.Errorf("post-add validation failed: %w", err)
	}

	if err := storage.SaveKeystore(keystorePath, store); err != nil {
		return err
	}
	if err := storage.SaveChain(chainPath, chain); err != nil {
		return err
	}

	_, err = fmt.Fprintf(stdout, "added record %s in block %d\n", block.Record.RecordID, block.Index)
	return err
}

func runListActors(stdout io.Writer) error {
	registry, err := loadActorRegistry()
	if err != nil {
		return err
	}
	store, err := loadKeystore()
	if err != nil {
		return err
	}

	fmt.Fprintln(stdout, "Patients:")
	for _, patient := range registry.Patients {
		fmt.Fprintf(stdout, "  %s  %s  %s  key:%s\n", patient.ID, patient.Name, actorStatus(patient.Active), keystoreStatus(store, patient.ID))
	}
	fmt.Fprintln(stdout)

	fmt.Fprintln(stdout, "Doctors:")
	for _, doctor := range registry.Doctors {
		fmt.Fprintf(stdout, "  %s  %s  %s  key:%s\n", doctor.ID, doctor.Name, actorStatus(doctor.Active), keystoreStatus(store, doctor.ID))
	}
	fmt.Fprintln(stdout)

	fmt.Fprintln(stdout, "Authorities:")
	for _, authority := range registry.Authorities {
		fmt.Fprintf(stdout, "  %s  %s  %s  key:%s\n", authority.ID, authority.Name, actorStatus(authority.Active), keystoreStatus(store, authority.ID))
	}

	return nil
}

func runDeactivateActor(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("deactivate-actor", flag.ContinueOnError)
	fs.SetOutput(stderr)

	idLong := fs.String("id", "", "actor identifier")
	idShort := fs.String("i", "", "actor identifier")

	if err := fs.Parse(args); err != nil {
		return err
	}

	actorID, err := resolveFlagValue("id", *idLong, "i", *idShort)
	if err != nil {
		return err
	}
	if actorID == "" {
		return fmt.Errorf("actor ID is required")
	}

	registry, err := loadActorRegistry()
	if err != nil {
		return err
	}
	store, err := loadKeystore()
	if err != nil {
		return err
	}

	actor, err := registry.DeactivateActor(actorID)
	if err != nil {
		return err
	}
	if err := store.DeactivateActor(actorID); err != nil {
		return err
	}

	if err := storage.SaveActors(actorsPath, registry); err != nil {
		return err
	}
	if err := storage.SaveKeystore(keystorePath, store); err != nil {
		return err
	}

	_, err = fmt.Fprintf(stdout, "deactivated %s %s (%s)\n", actor.Role, actor.ID, actor.Name)
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

func runViewRecord(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("view-record", flag.ContinueOnError)
	fs.SetOutput(stderr)

	recordIDLong := fs.String("record-id", "", "record identifier")
	recordIDShort := fs.String("i", "", "record identifier")
	actorIDLong := fs.String("actor", "", "actor identifier")
	actorIDShort := fs.String("a", "", "actor identifier")

	if err := fs.Parse(args); err != nil {
		return err
	}

	recordID, err := resolveFlagValue("record-id", *recordIDLong, "i", *recordIDShort)
	if err != nil {
		return err
	}
	actorID, err := resolveFlagValue("actor", *actorIDLong, "a", *actorIDShort)
	if err != nil {
		return err
	}
	if recordID == "" || actorID == "" {
		return fmt.Errorf("both record-id and actor are required")
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

	actor, ok := registry.ActorByID(actorID)
	if !ok {
		return fmt.Errorf("unknown actor ID: %s", actorID)
	}
	if !actor.Active {
		return fmt.Errorf("actor ID is inactive: %s", actorID)
	}

	record, err := chain.RecordByID(recordID)
	if err != nil {
		return err
	}
	if record.IsRedacted() {
		return fmt.Errorf("record is redacted: %s", recordID)
	}
	payload, err := store.DecryptRecordForActor(record, actorID)
	if err != nil {
		return err
	}

	view := struct {
		RecordID   string `json:"record_id"`
		DoctorID   string `json:"doctor_id"`
		RecordType string `json:"record_type"`
		CreatedAt  int64  `json:"created_at"`
		PatientID  string `json:"patient_id"`
		Title      string `json:"title"`
		Content    string `json:"content"`
	}{
		RecordID:   record.RecordID,
		DoctorID:   record.DoctorID,
		RecordType: record.RecordType,
		CreatedAt:  record.CreatedAt,
		PatientID:  payload.PatientID,
		Title:      payload.Title,
		Content:    payload.Content,
	}

	output, err := json.MarshalIndent(view, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal decrypted record: %w", err)
	}

	_, err = fmt.Fprintln(stdout, string(output))
	return err
}

func runAuthorizeRedaction(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("authorize-redaction", flag.ContinueOnError)
	fs.SetOutput(stderr)

	recordIDLong := fs.String("record-id", "", "record identifier")
	recordIDShort := fs.String("i", "", "record identifier")
	patientIDLong := fs.String("patient", "", "patient identifier")
	patientIDShort := fs.String("p", "", "patient identifier")
	authorityIDLong := fs.String("authority", "", "authority identifier")
	authorityIDShort := fs.String("a", "", "authority identifier")
	reasonLong := fs.String("reason", "", "redaction reason")
	reasonShort := fs.String("r", "", "redaction reason")

	if err := fs.Parse(args); err != nil {
		return err
	}

	recordID, err := resolveFlagValue("record-id", *recordIDLong, "i", *recordIDShort)
	if err != nil {
		return err
	}
	patientID, err := resolveFlagValue("patient", *patientIDLong, "p", *patientIDShort)
	if err != nil {
		return err
	}
	authorityID, err := resolveFlagValue("authority", *authorityIDLong, "a", *authorityIDShort)
	if err != nil {
		return err
	}
	reason, err := resolveFlagValue("reason", *reasonLong, "r", *reasonShort)
	if err != nil {
		return err
	}
	if recordID == "" || patientID == "" || authorityID == "" || reason == "" {
		return fmt.Errorf("record-id, patient, authority, and reason are required")
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
	chameleonStore, err := loadChameleonStore()
	if err != nil {
		return err
	}
	chameleonPublicKey, err := chameleonStore.Public()
	if err != nil {
		return err
	}
	proofVerifier, err := loadOptionalProofVerifier()
	if err != nil {
		return err
	}

	patient, ok := registry.ActorByID(patientID)
	if !ok || patient.Role != actors.RolePatient {
		return fmt.Errorf("unknown patient ID: %s", patientID)
	}
	if !patient.Active {
		return fmt.Errorf("patient ID is inactive: %s", patientID)
	}

	authority, ok := registry.ActorByID(authorityID)
	if !ok || authority.Role != actors.RoleAuthority {
		return fmt.Errorf("unknown authority ID: %s", authorityID)
	}
	if !authority.Active {
		return fmt.Errorf("authority ID is inactive: %s", authorityID)
	}

	record, err := chain.RecordByID(recordID)
	if err != nil {
		return err
	}
	if record.IsGenesis() {
		return fmt.Errorf("cannot authorize redaction for genesis record")
	}
	if record.IsRedacted() {
		return fmt.Errorf("record already redacted: %s", recordID)
	}
	if record.PendingRedaction || record.RedactionRequest != nil || record.RedactionApproval != nil {
		return fmt.Errorf("redaction authorization already exists for record ID: %s", recordID)
	}

	patientWrappedKey, err := record.WrappedKeyForActor(patientID)
	if err != nil {
		return fmt.Errorf("patient does not have access to record %s: %w", recordID, err)
	}
	if patientWrappedKey.ActorRole != actors.RolePatient {
		return fmt.Errorf("patient wrapped key role mismatch for record %s", recordID)
	}

	authorityWrappedKey, err := record.WrappedKeyForActor(authorityID)
	if err != nil {
		return fmt.Errorf("authority does not have access to record %s: %w", recordID, err)
	}
	if authorityWrappedKey.ActorRole != actors.RoleAuthority {
		return fmt.Errorf("authority wrapped key role mismatch for record %s", recordID)
	}

	payload, err := store.DecryptRecordForActor(record, authorityID)
	if err != nil {
		return err
	}
	if payload.PatientID != patientID {
		return fmt.Errorf("patient ID does not match decrypted record owner: expected %s got %s", payload.PatientID, patientID)
	}

	request := medical.NewRedactionRequest(recordID, patientID, reason)
	requestSignature, err := store.SignRedactionRequestAsPatient(patientID, request)
	if err != nil {
		return err
	}
	request.Signature = requestSignature

	approval := medical.NewRedactionApproval(recordID, patientID, authorityID)
	approvalSignature, err := store.SignRedactionApprovalAsAuthority(authorityID, approval)
	if err != nil {
		return err
	}
	approval.Signature = approvalSignature

	if err := chain.AuthorizeRedaction(recordID, request, approval, chameleonStore); err != nil {
		return err
	}
	if err := chain.ValidateChain(store, chameleonPublicKey, proofVerifier); err != nil {
		return fmt.Errorf("post-authorization validation failed: %w", err)
	}
	if err := storage.SaveChain(chainPath, chain); err != nil {
		return err
	}

	_, err = fmt.Fprintf(stdout, "authorized redaction for record %s by patient %s and authority %s\n", recordID, patientID, authorityID)
	return err
}

func runRedactRecord(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("redact-record", flag.ContinueOnError)
	fs.SetOutput(stderr)

	recordIDLong := fs.String("record-id", "", "record identifier")
	recordIDShort := fs.String("i", "", "record identifier")

	if err := fs.Parse(args); err != nil {
		return err
	}

	recordID, err := resolveFlagValue("record-id", *recordIDLong, "i", *recordIDShort)
	if err != nil {
		return err
	}
	if recordID == "" {
		return fmt.Errorf("record-id is required")
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
	chameleonStore, err := loadChameleonStore()
	if err != nil {
		return err
	}
	chameleonPublicKey, err := chameleonStore.Public()
	if err != nil {
		return err
	}
	proofSystem, err := loadRequiredProofProver()
	if err != nil {
		return err
	}

	record, err := chain.RecordByID(recordID)
	if err != nil {
		return err
	}
	if record.IsGenesis() {
		return fmt.Errorf("cannot redact genesis record")
	}
	if record.IsRedacted() {
		return fmt.Errorf("record already redacted: %s", recordID)
	}
	if !record.PendingRedaction || record.RedactionRequest == nil || record.RedactionApproval == nil {
		return fmt.Errorf("record is not authorized for redaction: %s", recordID)
	}
	if record.RedactionProof != nil {
		return fmt.Errorf("record already has redaction proof metadata: %s", recordID)
	}

	patient, ok := registry.ActorByID(record.RedactionRequest.PatientID)
	if !ok || patient.Role != actors.RolePatient {
		return fmt.Errorf("redaction patient no longer exists: %s", record.RedactionRequest.PatientID)
	}
	authority, ok := registry.ActorByID(record.RedactionApproval.AuthorityID)
	if !ok || authority.Role != actors.RoleAuthority {
		return fmt.Errorf("redaction authority no longer exists: %s", record.RedactionApproval.AuthorityID)
	}

	payload, err := store.DecryptRecordForActor(record, record.RedactionApproval.AuthorityID)
	if err != nil {
		return err
	}
	if payload.PatientID != record.RedactionRequest.PatientID {
		return fmt.Errorf("decrypted patient ID does not match redaction request patient: expected %s got %s", payload.PatientID, record.RedactionRequest.PatientID)
	}

	patientCommitmentSalt, err := store.RecordCommitmentSalt(recordID)
	if err != nil {
		return err
	}
	proof, err := proofSystem.GenerateRedactionProof(record.RecordID, record.RedactionRequest.PatientID, record.PatientCommitment, patientCommitmentSalt)
	if err != nil {
		return err
	}

	if err := chain.RedactRecord(recordID, proof, chameleonStore); err != nil {
		return err
	}
	if err := chain.ValidateChain(store, chameleonPublicKey, proofSystem); err != nil {
		return fmt.Errorf("post-redaction validation failed: %w", err)
	}
	if err := storage.SaveChain(chainPath, chain); err != nil {
		return err
	}
	store.DeleteRecordSecret(recordID)
	if err := storage.SaveKeystore(keystorePath, store); err != nil {
		return err
	}

	_, err = fmt.Fprintf(stdout, "redacted record %s\n", recordID)
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
	chameleonStore, err := loadChameleonStore()
	if err != nil {
		return err
	}
	chameleonPublicKey, err := chameleonStore.Public()
	if err != nil {
		return err
	}
	proofVerifier, err := loadOptionalProofVerifier()
	if err != nil {
		return err
	}

	if err := chain.ValidateChain(store, chameleonPublicKey, proofVerifier); err != nil {
		return fmt.Errorf("chain validation failed: %w", err)
	}

	_, err = fmt.Fprintln(stdout, "chain is valid")
	return err
}

func runVerifyProof(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("verify-proof", flag.ContinueOnError)
	fs.SetOutput(stderr)

	recordIDLong := fs.String("record-id", "", "record identifier")
	recordIDShort := fs.String("i", "", "record identifier")

	if err := fs.Parse(args); err != nil {
		return err
	}

	recordID, err := resolveFlagValue("record-id", *recordIDLong, "i", *recordIDShort)
	if err != nil {
		return err
	}
	if recordID == "" {
		return fmt.Errorf("record-id is required")
	}

	chain, err := loadExistingChain()
	if err != nil {
		return err
	}
	store, err := loadKeystore()
	if err != nil {
		return err
	}
	proofVerifier, err := loadRequiredProofVerifier()
	if err != nil {
		return err
	}

	record, err := chain.RecordByID(recordID)
	if err != nil {
		return err
	}
	if !record.IsRedacted() {
		return fmt.Errorf("record is not redacted: %s", recordID)
	}
	if record.RedactionRequest == nil || record.RedactionApproval == nil {
		return fmt.Errorf("record is missing redaction authorization metadata: %s", recordID)
	}
	if err := store.VerifyRedactionRequestSignature(*record.RedactionRequest); err != nil {
		return fmt.Errorf("invalid redaction request signature: %w", err)
	}
	if err := store.VerifyRedactionApprovalSignature(*record.RedactionApproval); err != nil {
		return fmt.Errorf("invalid redaction approval signature: %w", err)
	}
	if err := proofVerifier.VerifyRecordProof(record); err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	_, err = fmt.Fprintf(stdout, "proof is valid for record %s\n", recordID)
	return err
}

func loadExistingChain() (*core.Blockchain, error) {
	chameleonStore, err := loadChameleonStore()
	if err != nil {
		return nil, err
	}
	publicKey, err := chameleonStore.Public()
	if err != nil {
		return nil, err
	}
	chain, err := storage.LoadChain(chainPath, publicKey)
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

func loadChameleonStore() (*chameleon.Store, error) {
	store, err := storage.LoadChameleonStore(chameleonPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s not found; run `amnesia init` first", chameleonPath)
		}
		return nil, err
	}

	return store, nil
}

func loadOptionalProofVerifier() (*zk.System, error) {
	verifier, err := zk.LoadVerifier(zkArtifactsPath)
	if err != nil {
		if zk.IsArtifactsMissing(err) {
			return nil, nil
		}
		return nil, err
	}

	return verifier, nil
}

func loadRequiredProofVerifier() (*zk.System, error) {
	verifier, err := zk.LoadVerifier(zkArtifactsPath)
	if err != nil {
		if zk.IsArtifactsMissing(err) {
			return nil, fmt.Errorf("%s not found; run `amnesia setup-zk` first", zkArtifactsPath)
		}
		return nil, err
	}

	return verifier, nil
}

func loadRequiredProofProver() (*zk.System, error) {
	prover, err := zk.LoadProver(zkArtifactsPath)
	if err != nil {
		if zk.IsArtifactsMissing(err) {
			return nil, fmt.Errorf("%s not found; run `amnesia setup-zk` first", zkArtifactsPath)
		}
		return nil, err
	}

	return prover, nil
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

func actorStatus(active bool) string {
	if active {
		return "active"
	}

	return "inactive"
}

func keystoreStatus(store *auth.Keystore, actorID string) string {
	entry, err := store.EntryForActor(actorID)
	if err != nil {
		return "missing"
	}
	if entry.Active {
		return "active"
	}

	return "inactive"
}

func activeAuthorities(registry *actors.Registry) []actors.ActorInfo {
	authorities := make([]actors.ActorInfo, 0, len(registry.Authorities))
	for _, authority := range registry.Authorities {
		if !authority.Active {
			continue
		}
		authorities = append(authorities, actors.ActorInfo{
			ID:     authority.ID,
			Name:   authority.Name,
			Role:   actors.RoleAuthority,
			Active: true,
		})
	}

	return authorities
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
	fmt.Fprintln(w, "      Create a fresh blockchain and seed demo actors, keys, and chameleon-link material.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  setup-zk")
	fmt.Fprintln(w, "      Compile the patient-binding circuit and generate Groth16 artifacts in zk-artifacts/.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  add-actor [--role|-r] <patient|doctor|authority> [--name|-n] <name>")
	fmt.Fprintln(w, "      Add a new active actor and generate a matching keypair.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  list-actors")
	fmt.Fprintln(w, "      Show all actors, grouped by role, with actor/key active status.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  deactivate-actor [--id|-i] <actor-id>")
	fmt.Fprintln(w, "      Mark an actor and its key entry inactive without deleting history.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  add-record [--patient|-p] <id> [--doctor|-d] <id> [--type|-r] <type> [--title|-t] <title> [--content|-c] <content>")
	fmt.Fprintln(w, "      Add a new medical record to the blockchain.")
	fmt.Fprintln(w, "      Record IDs are generated automatically as R001, R002, ...")
	fmt.Fprintln(w, "      Short aliases: -p patient, -d doctor, -r type, -t title, -c content")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  view-chain")
	fmt.Fprintln(w, "      Print the full blockchain as formatted JSON. Record payloads stay encrypted.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  view-record [--record-id|-i] <record-id> [--actor|-a] <actor-id>")
	fmt.Fprintln(w, "      Decrypt and print one record as a specific active actor.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  authorize-redaction [--record-id|-i] <record-id> [--patient|-p] <patient-id> [--authority|-a] <authority-id> [--reason|-r] <reason>")
	fmt.Fprintln(w, "      Attach signed patient request and authority approval metadata to a record.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  redact-record [--record-id|-i] <record-id>")
	fmt.Fprintln(w, "      Generate the redaction proof and execute a full-record redaction for an already-authorized record.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  verify-proof [--record-id|-i] <record-id>")
	fmt.Fprintln(w, "      Verify the stored Groth16 proof for one redacted record.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  verify")
	fmt.Fprintln(w, "      Validate encrypted records, chameleon links, signatures, and stored redaction proofs.")
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
	fmt.Fprintln(w, "  Actor keys : stored in keystore.json")
	fmt.Fprintln(w, "  Link keys  : stored in chameleon.json")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Example:")
	fmt.Fprintln(w, `  amnesia add-record -p P007 -d D001 -r diagnosis -t "blood cancer" -c "3 months left"`)
	fmt.Fprintln(w, `  amnesia view-record -i R001 -a D001`)
	fmt.Fprintln(w, `  amnesia authorize-redaction -i R001 -p P007 -a A001 -r "patient requests deletion"`)
	fmt.Fprintln(w, `  amnesia redact-record -i R001`)
	fmt.Fprintln(w, `  amnesia verify-proof -i R001`)
	fmt.Fprintln(w, `  amnesia add-actor -r doctor -n "Dr. Kapoor"`)
}
