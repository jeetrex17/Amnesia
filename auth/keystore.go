package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/jeetraj/amnesia/actors"
	"github.com/jeetraj/amnesia/medical"
)

type Entry struct {
	ActorID    string `json:"actor_id"`
	Role       string `json:"role"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
	Active     bool   `json:"active"`
}

type Keystore struct {
	Entries []Entry `json:"entries"`
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
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Entry{}, fmt.Errorf("generate keypair for %s: %w", actorID, err)
	}

	return Entry{
		ActorID:    actorID,
		Role:       role,
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey),
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey),
		Active:     true,
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

		publicKey, err := entry.PublicKeyBytes()
		if err != nil {
			return fmt.Errorf("invalid public key for %s: %w", entry.ActorID, err)
		}
		privateKey, err := entry.PrivateKeyBytes()
		if err != nil {
			return fmt.Errorf("invalid private key for %s: %w", entry.ActorID, err)
		}

		derivedPublicKey := privateKey.Public().(ed25519.PublicKey)
		if string(derivedPublicKey) != string(publicKey) {
			return fmt.Errorf("public/private key mismatch for %s", entry.ActorID)
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

func (e Entry) PublicKeyBytes() (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(e.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("unexpected public key length: %d", len(decoded))
	}

	return ed25519.PublicKey(decoded), nil
}

func (e Entry) PrivateKeyBytes() (ed25519.PrivateKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(e.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("unexpected private key length: %d", len(decoded))
	}

	return ed25519.PrivateKey(decoded), nil
}

func (k *Keystore) SignRecordAsDoctor(doctorID string, record medical.MedicalRecord) (string, error) {
	entry, err := k.EntryForActiveActor(doctorID)
	if err != nil {
		return "", err
	}
	if entry.Role != actors.RoleDoctor {
		return "", fmt.Errorf("actor %s is not a doctor", doctorID)
	}

	privateKey, err := entry.PrivateKeyBytes()
	if err != nil {
		return "", err
	}
	payload, err := record.SignableBytes()
	if err != nil {
		return "", err
	}

	signature := ed25519.Sign(privateKey, payload)
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (k *Keystore) VerifyDoctorRecordSignature(record medical.MedicalRecord, signature string) error {
	entry, err := k.EntryForActor(record.DoctorID)
	if err != nil {
		return err
	}
	if entry.Role != actors.RoleDoctor {
		return fmt.Errorf("actor %s is not a doctor", record.DoctorID)
	}

	publicKey, err := entry.PublicKeyBytes()
	if err != nil {
		return err
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("decode doctor signature: %w", err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return fmt.Errorf("unexpected signature length: %d", len(signatureBytes))
	}

	payload, err := record.SignableBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signatureBytes) {
		return fmt.Errorf("invalid doctor signature for doctor ID: %s", record.DoctorID)
	}

	return nil
}
