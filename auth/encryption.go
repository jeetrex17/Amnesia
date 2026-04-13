package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/jeetraj/amnesia/actors"
	"github.com/jeetraj/amnesia/medical"
)

const (
	aesKeySize   = 32
	gcmNonceSize = 12
)

func generateEncryptionKeypair() (*ecdh.PublicKey, *ecdh.PrivateKey, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	return privateKey.PublicKey(), privateKey, nil
}

func (k *Keystore) EncryptRecord(record medical.MedicalRecord, authorities []actors.ActorInfo) (medical.EncryptedRecord, error) {
	if err := record.ValidateFields(); err != nil {
		return medical.EncryptedRecord{}, err
	}
	if record.RecordID == "" {
		return medical.EncryptedRecord{}, fmt.Errorf("record ID is required before encryption")
	}

	payload := medical.NewRecordPayload(record.PatientID, record.Title, record.Content)
	payloadBytes, err := payload.Bytes()
	if err != nil {
		return medical.EncryptedRecord{}, err
	}

	recordKey, err := randomBytes(aesKeySize)
	if err != nil {
		return medical.EncryptedRecord{}, fmt.Errorf("generate record key: %w", err)
	}
	ciphertext, nonce, err := encryptBytes(payloadBytes, recordKey)
	if err != nil {
		return medical.EncryptedRecord{}, err
	}

	recipients := []actors.ActorInfo{
		{ID: record.PatientID, Role: actors.RolePatient, Active: true},
		{ID: record.DoctorID, Role: actors.RoleDoctor, Active: true},
	}
	recipients = append(recipients, authorities...)

	wrappedKeys := make([]medical.WrappedKey, 0, len(recipients))
	seenActors := make(map[string]struct{})
	for _, recipient := range recipients {
		if !recipient.Active {
			continue
		}
		if _, exists := seenActors[recipient.ID]; exists {
			continue
		}
		seenActors[recipient.ID] = struct{}{}

		wrappedKey, err := k.WrapRecordKeyForActor(recipient.ID, recipient.Role, recordKey)
		if err != nil {
			return medical.EncryptedRecord{}, err
		}
		wrappedKeys = append(wrappedKeys, wrappedKey)
	}

	sort.Slice(wrappedKeys, func(i, j int) bool {
		return wrappedKeys[i].ActorID < wrappedKeys[j].ActorID
	})

	return medical.NewEncryptedRecord(record.RecordID, record.DoctorID, record.RecordType, record.CreatedAt, ciphertext, nonce, wrappedKeys), nil
}

func (k *Keystore) DecryptRecordForActor(record medical.EncryptedRecord, actorID string) (medical.RecordPayload, error) {
	if record.IsRedacted() {
		return medical.RecordPayload{}, fmt.Errorf("record is redacted: %s", record.RecordID)
	}

	entry, err := k.EntryForActiveActor(actorID)
	if err != nil {
		return medical.RecordPayload{}, err
	}

	wrappedKey, err := record.WrappedKeyForActor(actorID)
	if err != nil {
		return medical.RecordPayload{}, err
	}
	if wrappedKey.ActorRole != entry.Role {
		return medical.RecordPayload{}, fmt.Errorf("wrapped key role mismatch for actor ID: %s", actorID)
	}

	recordKey, err := k.unwrapRecordKey(actorID, wrappedKey)
	if err != nil {
		return medical.RecordPayload{}, err
	}
	plaintext, err := decryptBytes(record.Ciphertext, record.Nonce, recordKey)
	if err != nil {
		return medical.RecordPayload{}, err
	}

	var payload medical.RecordPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return medical.RecordPayload{}, fmt.Errorf("unmarshal decrypted payload: %w", err)
	}
	if err := payload.Validate(); err != nil {
		return medical.RecordPayload{}, fmt.Errorf("validate decrypted payload: %w", err)
	}

	return payload, nil
}

func (k *Keystore) WrapRecordKeyForActor(actorID, role string, recordKey []byte) (medical.WrappedKey, error) {
	entry, err := k.EntryForActiveActor(actorID)
	if err != nil {
		return medical.WrappedKey{}, err
	}
	if entry.Role != role {
		return medical.WrappedKey{}, fmt.Errorf("actor role mismatch for %s: expected %s got %s", actorID, role, entry.Role)
	}
	recipientPublicKey, err := entry.EncryptionPublicKeyBytes()
	if err != nil {
		return medical.WrappedKey{}, err
	}

	ephemeralPublicKey, ephemeralPrivateKey, err := generateEncryptionKeypair()
	if err != nil {
		return medical.WrappedKey{}, fmt.Errorf("generate ephemeral encryption keypair: %w", err)
	}
	sharedSecret, err := ephemeralPrivateKey.ECDH(recipientPublicKey)
	if err != nil {
		return medical.WrappedKey{}, fmt.Errorf("derive shared secret for %s: %w", actorID, err)
	}
	wrappingKey := sha256.Sum256(sharedSecret)

	ciphertext, nonce, err := encryptBytes(recordKey, wrappingKey[:])
	if err != nil {
		return medical.WrappedKey{}, err
	}

	return medical.WrappedKey{
		ActorID:            actorID,
		ActorRole:          role,
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(ephemeralPublicKey.Bytes()),
		Ciphertext:         ciphertext,
		Nonce:              nonce,
	}, nil
}

func (k *Keystore) unwrapRecordKey(actorID string, wrappedKey medical.WrappedKey) ([]byte, error) {
	entry, err := k.EntryForActiveActor(actorID)
	if err != nil {
		return nil, err
	}

	privateKey, err := entry.EncryptionPrivateKeyBytes()
	if err != nil {
		return nil, err
	}
	ephemeralPublicKeyBytes, err := base64.StdEncoding.DecodeString(wrappedKey.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode ephemeral public key: %w", err)
	}
	ephemeralPublicKey, err := ecdh.X25519().NewPublicKey(ephemeralPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("build ephemeral public key: %w", err)
	}

	sharedSecret, err := privateKey.ECDH(ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("derive shared secret for %s: %w", actorID, err)
	}
	wrappingKey := sha256.Sum256(sharedSecret)

	recordKey, err := decryptBytes(wrappedKey.Ciphertext, wrappedKey.Nonce, wrappingKey[:])
	if err != nil {
		return nil, err
	}
	if len(recordKey) != aesKeySize {
		return nil, fmt.Errorf("unexpected record key length: %d", len(recordKey))
	}

	return recordKey, nil
}

func encryptBytes(plaintext, key []byte) (string, string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", fmt.Errorf("create aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", fmt.Errorf("create gcm: %w", err)
	}

	nonce, err := randomBytes(gcmNonceSize)
	if err != nil {
		return "", "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), base64.StdEncoding.EncodeToString(nonce), nil
}

func decryptBytes(ciphertextB64, nonceB64 string, key []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("unexpected nonce length: %d", len(nonce))
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}

	return plaintext, nil
}

func randomBytes(size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}

	return buf, nil
}
