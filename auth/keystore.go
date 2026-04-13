package auth

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/jeetraj/amnesia/actors"
	"github.com/jeetraj/amnesia/medical"
)

type Entry struct {
	ActorID              string `json:"actor_id"`
	Role                 string `json:"role"`
	SigningPublicKey     string `json:"public_key"`
	SigningPrivateKey    string `json:"private_key"`
	EncryptionPublicKey  string `json:"encryption_public_key"`
	EncryptionPrivateKey string `json:"encryption_private_key"`
	Active               bool   `json:"active"`
}

type RecordSecret struct {
	PatientCommitmentSalt string `json:"patient_commitment_salt"`
}

type Keystore struct {
	Entries       []Entry                 `json:"entries"`
	RecordSecrets map[string]RecordSecret `json:"record_secrets,omitempty"`
}

func NewDemoKeystore(registry *actors.Registry) (*Keystore, error) {
	if err := registry.Validate(); err != nil {
		return nil, fmt.Errorf("validate actor registry: %w", err)
	}

	store := &Keystore{}

	for _, patient := range registry.Patients {
		entry, err := generateEntry(patient.ID, actors.RolePatient)
		if err != nil {
			return nil, err
		}
		store.Entries = append(store.Entries, entry)
	}

	for _, doctor := range registry.Doctors {
		entry, err := generateEntry(doctor.ID, actors.RoleDoctor)
		if err != nil {
			return nil, err
		}
		store.Entries = append(store.Entries, entry)
	}

	for _, authority := range registry.Authorities {
		entry, err := generateEntry(authority.ID, actors.RoleAuthority)
		if err != nil {
			return nil, err
		}
		store.Entries = append(store.Entries, entry)
	}

	if err := store.Validate(); err != nil {
		return nil, err
	}

	return store, nil
}

func generateEntry(actorID, role string) (Entry, error) {
	signingPublicKey, signingPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Entry{}, fmt.Errorf("generate signing keypair for %s: %w", actorID, err)
	}
	encryptionPublicKey, encryptionPrivateKey, err := generateEncryptionKeypair()
	if err != nil {
		return Entry{}, fmt.Errorf("generate encryption keypair for %s: %w", actorID, err)
	}

	return Entry{
		ActorID:              actorID,
		Role:                 role,
		SigningPublicKey:     base64.StdEncoding.EncodeToString(signingPublicKey),
		SigningPrivateKey:    base64.StdEncoding.EncodeToString(signingPrivateKey),
		EncryptionPublicKey:  base64.StdEncoding.EncodeToString(encryptionPublicKey.Bytes()),
		EncryptionPrivateKey: base64.StdEncoding.EncodeToString(encryptionPrivateKey.Bytes()),
		Active:               true,
	}, nil
}

func (k *Keystore) Validate() error {
	if k == nil {
		return fmt.Errorf("keystore is nil")
	}

	seen := make(map[string]struct{})
	for _, entry := range k.Entries {
		if entry.ActorID == "" {
			return fmt.Errorf("actor ID is required")
		}
		if err := actors.ValidateRole(entry.Role); err != nil {
			return fmt.Errorf("unsupported role for %s: %s", entry.ActorID, entry.Role)
		}
		if _, exists := seen[entry.ActorID]; exists {
			return fmt.Errorf("duplicate keystore entry for actor ID: %s", entry.ActorID)
		}
		seen[entry.ActorID] = struct{}{}

		publicKey, err := entry.SigningPublicKeyBytes()
		if err != nil {
			return fmt.Errorf("invalid signing public key for %s: %w", entry.ActorID, err)
		}
		privateKey, err := entry.SigningPrivateKeyBytes()
		if err != nil {
			return fmt.Errorf("invalid signing private key for %s: %w", entry.ActorID, err)
		}

		derivedPublicKey := privateKey.Public().(ed25519.PublicKey)
		if string(derivedPublicKey) != string(publicKey) {
			return fmt.Errorf("signing public/private key mismatch for %s", entry.ActorID)
		}

		encryptionPublicKey, err := entry.EncryptionPublicKeyBytes()
		if err != nil {
			return fmt.Errorf("invalid encryption public key for %s: %w", entry.ActorID, err)
		}
		encryptionPrivateKey, err := entry.EncryptionPrivateKeyBytes()
		if err != nil {
			return fmt.Errorf("invalid encryption private key for %s: %w", entry.ActorID, err)
		}

		derivedEncryptionPublicKey := encryptionPrivateKey.PublicKey()
		if string(derivedEncryptionPublicKey.Bytes()) != string(encryptionPublicKey.Bytes()) {
			return fmt.Errorf("encryption public/private key mismatch for %s", entry.ActorID)
		}
	}

	for recordID, secret := range k.RecordSecrets {
		if strings.TrimSpace(recordID) == "" {
			return fmt.Errorf("record secret record ID is required")
		}
		if _, err := medical.ParseSequentialRecordID(recordID); err != nil {
			return fmt.Errorf("invalid record secret ID %s: %w", recordID, err)
		}
		if strings.TrimSpace(secret.PatientCommitmentSalt) == "" {
			return fmt.Errorf("patient commitment salt is required for record ID: %s", recordID)
		}
		saltBytes, err := base64.StdEncoding.DecodeString(secret.PatientCommitmentSalt)
		if err != nil {
			return fmt.Errorf("decode patient commitment salt for %s: %w", recordID, err)
		}
		if len(saltBytes) != 32 {
			return fmt.Errorf("unexpected patient commitment salt length for %s: %d", recordID, len(saltBytes))
		}
	}

	return nil
}

func (k *Keystore) ActivateLegacyDefaults() {
	if len(k.Entries) == 0 {
		return
	}

	allInactive := true
	for _, entry := range k.Entries {
		if entry.Active {
			allInactive = false
			break
		}
	}
	if !allInactive {
		return
	}
	for i := range k.Entries {
		k.Entries[i].Active = true
	}
}

func (k *Keystore) PopulateMissingEncryptionKeys() error {
	k.ensureRecordSecretsMap()

	for i := range k.Entries {
		if k.Entries[i].EncryptionPublicKey != "" && k.Entries[i].EncryptionPrivateKey != "" {
			continue
		}

		publicKey, privateKey, err := generateEncryptionKeypair()
		if err != nil {
			return fmt.Errorf("generate encryption keypair for %s: %w", k.Entries[i].ActorID, err)
		}
		k.Entries[i].EncryptionPublicKey = base64.StdEncoding.EncodeToString(publicKey.Bytes())
		k.Entries[i].EncryptionPrivateKey = base64.StdEncoding.EncodeToString(privateKey.Bytes())
	}

	return nil
}

func (k *Keystore) RecordCommitmentSalt(recordID string) ([]byte, error) {
	if k == nil {
		return nil, fmt.Errorf("keystore is nil")
	}
	secret, ok := k.RecordSecrets[recordID]
	if !ok {
		return nil, fmt.Errorf("record secret not found for record ID: %s", recordID)
	}

	decoded, err := base64.StdEncoding.DecodeString(secret.PatientCommitmentSalt)
	if err != nil {
		return nil, fmt.Errorf("decode patient commitment salt for %s: %w", recordID, err)
	}

	return decoded, nil
}

func (k *Keystore) SetRecordCommitmentSalt(recordID string, salt []byte) error {
	if k == nil {
		return fmt.Errorf("keystore is nil")
	}
	if _, err := medical.ParseSequentialRecordID(recordID); err != nil {
		return err
	}
	if len(salt) != 32 {
		return fmt.Errorf("unexpected patient commitment salt length: %d", len(salt))
	}

	k.ensureRecordSecretsMap()
	k.RecordSecrets[recordID] = RecordSecret{
		PatientCommitmentSalt: base64.StdEncoding.EncodeToString(salt),
	}
	return nil
}

func (k *Keystore) DeleteRecordSecret(recordID string) {
	if k == nil || k.RecordSecrets == nil {
		return
	}
	delete(k.RecordSecrets, recordID)
}

func (k *Keystore) ensureRecordSecretsMap() {
	if k.RecordSecrets == nil {
		k.RecordSecrets = make(map[string]RecordSecret)
	}
}

func (k *Keystore) EntryForActor(actorID string) (Entry, error) {
	for _, entry := range k.Entries {
		if entry.ActorID == actorID {
			return entry, nil
		}
	}

	return Entry{}, fmt.Errorf("keystore entry not found for actor ID: %s", actorID)
}

func (k *Keystore) EntryForActiveActor(actorID string) (Entry, error) {
	entry, err := k.EntryForActor(actorID)
	if err != nil {
		return Entry{}, err
	}
	if !entry.Active {
		return Entry{}, fmt.Errorf("actor is inactive: %s", actorID)
	}

	return entry, nil
}

func (k *Keystore) AddActor(actorID, role string) (Entry, error) {
	if _, err := k.EntryForActor(actorID); err == nil {
		return Entry{}, fmt.Errorf("keystore entry already exists for actor ID: %s", actorID)
	}
	if err := actors.ValidateRole(role); err != nil {
		return Entry{}, err
	}

	entry, err := generateEntry(actorID, role)
	if err != nil {
		return Entry{}, err
	}

	k.Entries = append(k.Entries, entry)
	if err := k.Validate(); err != nil {
		return Entry{}, err
	}

	return entry, nil
}

func (k *Keystore) DeactivateActor(actorID string) error {
	for i := range k.Entries {
		if k.Entries[i].ActorID == actorID {
			if !k.Entries[i].Active {
				return fmt.Errorf("keystore entry already inactive for actor ID: %s", actorID)
			}
			k.Entries[i].Active = false
			return nil
		}
	}

	return fmt.Errorf("keystore entry not found for actor ID: %s", actorID)
}

func (e Entry) SigningPublicKeyBytes() (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(e.SigningPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode signing public key: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("unexpected signing public key length: %d", len(decoded))
	}

	return ed25519.PublicKey(decoded), nil
}

func (e Entry) SigningPrivateKeyBytes() (ed25519.PrivateKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(e.SigningPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode signing private key: %w", err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("unexpected signing private key length: %d", len(decoded))
	}

	return ed25519.PrivateKey(decoded), nil
}

func (e Entry) EncryptionPublicKeyBytes() (*ecdh.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(e.EncryptionPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode encryption public key: %w", err)
	}

	publicKey, err := ecdh.X25519().NewPublicKey(decoded)
	if err != nil {
		return nil, fmt.Errorf("build encryption public key: %w", err)
	}

	return publicKey, nil
}

func (e Entry) EncryptionPrivateKeyBytes() (*ecdh.PrivateKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(e.EncryptionPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode encryption private key: %w", err)
	}

	privateKey, err := ecdh.X25519().NewPrivateKey(decoded)
	if err != nil {
		return nil, fmt.Errorf("build encryption private key: %w", err)
	}

	return privateKey, nil
}

func (k *Keystore) SignRecordAsDoctor(doctorID string, record medical.EncryptedRecord) (string, error) {
	payload, err := record.SignableBytes()
	if err != nil {
		return "", err
	}

	return k.signPayloadAsActiveActor(doctorID, actors.RoleDoctor, payload)
}

func (k *Keystore) VerifyDoctorRecordSignature(record medical.EncryptedRecord, signature string) error {
	payload, err := record.SignableBytes()
	if err != nil {
		return err
	}

	return k.verifyPayloadSignature(record.DoctorID, actors.RoleDoctor, payload, signature, "doctor")
}

func (k *Keystore) SignRedactionRequestAsPatient(patientID string, request medical.RedactionRequest) (string, error) {
	payload, err := request.SignableBytes()
	if err != nil {
		return "", err
	}

	return k.signPayloadAsActiveActor(patientID, actors.RolePatient, payload)
}

func (k *Keystore) VerifyRedactionRequestSignature(request medical.RedactionRequest) error {
	payload, err := request.SignableBytes()
	if err != nil {
		return err
	}

	return k.verifyPayloadSignature(request.PatientID, actors.RolePatient, payload, request.Signature, "redaction request")
}

func (k *Keystore) SignRedactionApprovalAsAuthority(authorityID string, approval medical.RedactionApproval) (string, error) {
	payload, err := approval.SignableBytes()
	if err != nil {
		return "", err
	}

	return k.signPayloadAsActiveActor(authorityID, actors.RoleAuthority, payload)
}

func (k *Keystore) VerifyRedactionApprovalSignature(approval medical.RedactionApproval) error {
	payload, err := approval.SignableBytes()
	if err != nil {
		return err
	}

	return k.verifyPayloadSignature(approval.AuthorityID, actors.RoleAuthority, payload, approval.Signature, "redaction approval")
}

func (k *Keystore) signPayloadAsActiveActor(actorID, role string, payload []byte) (string, error) {
	entry, err := k.EntryForActiveActor(actorID)
	if err != nil {
		return "", err
	}
	if entry.Role != role {
		return "", fmt.Errorf("actor %s is not a %s", actorID, role)
	}

	privateKey, err := entry.SigningPrivateKeyBytes()
	if err != nil {
		return "", err
	}

	signature := ed25519.Sign(privateKey, payload)
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (k *Keystore) verifyPayloadSignature(actorID, role string, payload []byte, signature, label string) error {
	entry, err := k.EntryForActor(actorID)
	if err != nil {
		return err
	}
	if entry.Role != role {
		return fmt.Errorf("actor %s is not a %s", actorID, role)
	}

	publicKey, err := entry.SigningPublicKeyBytes()
	if err != nil {
		return err
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("decode %s signature: %w", label, err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return fmt.Errorf("unexpected signature length: %d", len(signatureBytes))
	}
	if !ed25519.Verify(publicKey, payload, signatureBytes) {
		return fmt.Errorf("invalid %s signature for actor ID: %s", label, actorID)
	}

	return nil
}
