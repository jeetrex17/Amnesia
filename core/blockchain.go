package core

import (
	"fmt"
	"strings"
	"time"

	"github.com/jeetraj/amnesia/actors"
	"github.com/jeetraj/amnesia/auth"
	"github.com/jeetraj/amnesia/chameleon"
	"github.com/jeetraj/amnesia/medical"
)

type Blockchain struct {
	Blocks []Block `json:"blocks"`
}

type RedactionProofVerifier interface {
	VerifyRecordProof(record medical.EncryptedRecord) error
}

func NewBlockchain(publicKey *chameleon.PublicKey) (*Blockchain, error) {
	genesis, err := NewGenesisBlock(publicKey)
	if err != nil {
		return nil, err
	}

	return &Blockchain{
		Blocks: []Block{genesis},
	}, nil
}

func (bc *Blockchain) AddBlock(record medical.EncryptedRecord, doctorSignature string, publicKey *chameleon.PublicKey) (Block, error) {
	if err := record.ValidateStored(); err != nil {
		return Block{}, err
	}
	if bc.HasRecordID(record.RecordID) {
		return Block{}, fmt.Errorf("duplicate record ID: %s", record.RecordID)
	}
	if strings.TrimSpace(doctorSignature) == "" {
		return Block{}, fmt.Errorf("doctor signature is required")
	}

	prev := bc.Blocks[len(bc.Blocks)-1]
	block, err := NewBlock(prev.Index+1, record, doctorSignature, prev.LinkHash, publicKey)
	if err != nil {
		return Block{}, err
	}
	bc.Blocks = append(bc.Blocks, block)
	return block, nil
}

func (bc *Blockchain) HasRecordID(recordID string) bool {
	for _, block := range bc.Blocks {
		if block.Record.RecordID == recordID {
			return true
		}
	}

	return false
}

func (bc *Blockchain) RecordByID(recordID string) (medical.EncryptedRecord, error) {
	for _, block := range bc.Blocks {
		if block.Record.RecordID == recordID {
			return block.Record, nil
		}
	}

	return medical.EncryptedRecord{}, fmt.Errorf("record not found: %s", recordID)
}

func (bc *Blockchain) NextRecordID() (string, error) {
	maxID := 0

	for i, block := range bc.Blocks {
		if block.Record.IsGenesis() {
			continue
		}

		n, err := medical.ParseSequentialRecordID(block.Record.RecordID)
		if err != nil {
			return "", fmt.Errorf("invalid record ID at block %d: %w", i, err)
		}
		if n > maxID {
			maxID = n
		}
	}

	return fmt.Sprintf("R%03d", maxID+1), nil
}

func (bc *Blockchain) AuthorizeRedaction(recordID string, request medical.RedactionRequest, approval medical.RedactionApproval, chameleonStore *chameleon.Store) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if err := approval.Validate(); err != nil {
		return err
	}
	if chameleonStore == nil {
		return fmt.Errorf("chameleon store is required")
	}

	for i := range bc.Blocks {
		if bc.Blocks[i].Record.RecordID != recordID {
			continue
		}
		if bc.Blocks[i].Record.IsGenesis() {
			return fmt.Errorf("cannot authorize redaction for genesis record")
		}
		if bc.Blocks[i].Record.PendingRedaction || bc.Blocks[i].Record.RedactionRequest != nil || bc.Blocks[i].Record.RedactionApproval != nil {
			return fmt.Errorf("redaction authorization already exists for record ID: %s", recordID)
		}
		if request.RecordID != recordID {
			return fmt.Errorf("redaction request record ID mismatch: %s", request.RecordID)
		}
		if approval.RecordID != recordID {
			return fmt.Errorf("redaction approval record ID mismatch: %s", approval.RecordID)
		}
		if request.PatientID != approval.PatientID {
			return fmt.Errorf("redaction patient mismatch between request and approval")
		}

		return bc.mutateBlockRecord(i, chameleonStore, func(record *medical.EncryptedRecord) error {
			record.PendingRedaction = true
			record.RedactionRequest = &request
			record.RedactionApproval = &approval
			return nil
		})
	}

	return fmt.Errorf("record not found: %s", recordID)
}

func (bc *Blockchain) RedactRecord(recordID string, proof medical.RedactionProof, chameleonStore *chameleon.Store) error {
	if chameleonStore == nil {
		return fmt.Errorf("chameleon store is required")
	}
	if err := proof.Validate(); err != nil {
		return fmt.Errorf("invalid redaction proof: %w", err)
	}

	for i := range bc.Blocks {
		if bc.Blocks[i].Record.RecordID != recordID {
			continue
		}

		record := bc.Blocks[i].Record
		if record.IsGenesis() {
			return fmt.Errorf("cannot redact genesis record")
		}
		if record.IsRedacted() {
			return fmt.Errorf("record already redacted: %s", recordID)
		}
		if !record.PendingRedaction || record.RedactionRequest == nil || record.RedactionApproval == nil {
			return fmt.Errorf("record is not authorized for redaction: %s", recordID)
		}

		return bc.mutateBlockRecord(i, chameleonStore, func(record *medical.EncryptedRecord) error {
			record.Redacted = true
			record.RedactedAt = time.Now().Unix()
			record.PendingRedaction = false
			record.Ciphertext = ""
			record.Nonce = ""
			record.WrappedKeys = nil
			record.RedactionProof = &proof
			return nil
		})
	}

	return fmt.Errorf("record not found: %s", recordID)
}

func (bc *Blockchain) ValidateIntegrity(publicKey *chameleon.PublicKey) error {
	if publicKey == nil {
		return fmt.Errorf("chameleon public key is required for integrity validation")
	}
	if len(bc.Blocks) == 0 {
		return fmt.Errorf("blockchain is empty")
	}

	genesis := bc.Blocks[0]
	if genesis.Index != 0 {
		return fmt.Errorf("invalid genesis index: got %d", genesis.Index)
	}
	if genesis.PrevLinkHash != "" {
		return fmt.Errorf("invalid genesis previous link hash: expected empty")
	}
	if genesis.ContentHash != genesis.CalculateContentHash() {
		return fmt.Errorf("invalid genesis content hash")
	}
	if err := genesis.VerifyLink(publicKey); err != nil {
		return fmt.Errorf("invalid genesis link hash: %w", err)
	}
	if !genesis.Record.IsGenesis() {
		return fmt.Errorf("invalid genesis record")
	}

	seenRecordIDs := make(map[string]struct{})

	for i := 1; i < len(bc.Blocks); i++ {
		prev := bc.Blocks[i-1]
		curr := bc.Blocks[i]

		if curr.Index != prev.Index+1 {
			return fmt.Errorf("invalid index at block %d", i)
		}
		if curr.PrevLinkHash != prev.LinkHash {
			return fmt.Errorf("broken link at block %d", i)
		}
		if curr.ContentHash != curr.CalculateContentHash() {
			return fmt.Errorf("invalid content hash at block %d", i)
		}
		if err := curr.VerifyLink(publicKey); err != nil {
			return fmt.Errorf("invalid link hash at block %d: %w", i, err)
		}
		if strings.TrimSpace(curr.DoctorSignature) == "" {
			return fmt.Errorf("missing doctor signature at block %d", i)
		}
		if err := curr.Record.ValidateStored(); err != nil {
			return fmt.Errorf("invalid record at block %d: %w", i, err)
		}
		if _, exists := seenRecordIDs[curr.Record.RecordID]; exists {
			return fmt.Errorf("duplicate record ID at block %d: %s", i, curr.Record.RecordID)
		}
		seenRecordIDs[curr.Record.RecordID] = struct{}{}
	}

	return nil
}

func (bc *Blockchain) ValidateChain(store *auth.Keystore, publicKey *chameleon.PublicKey, proofVerifier RedactionProofVerifier) error {
	if err := bc.ValidateIntegrity(publicKey); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("keystore is required for signature validation")
	}

	for i := 1; i < len(bc.Blocks); i++ {
		curr := bc.Blocks[i]
		if !curr.Record.IsRedacted() {
			if err := store.VerifyDoctorRecordSignature(curr.Record, curr.DoctorSignature); err != nil {
				return fmt.Errorf("invalid doctor signature at block %d: %w", i, err)
			}
		}
		if curr.Record.RedactionRequest != nil || curr.Record.RedactionApproval != nil {
			if err := store.VerifyRedactionRequestSignature(*curr.Record.RedactionRequest); err != nil {
				return fmt.Errorf("invalid redaction request signature at block %d: %w", i, err)
			}
			if err := store.VerifyRedactionApprovalSignature(*curr.Record.RedactionApproval); err != nil {
				return fmt.Errorf("invalid redaction approval signature at block %d: %w", i, err)
			}

			if !curr.Record.IsRedacted() {
				patientWrappedKey, err := curr.Record.WrappedKeyForActor(curr.Record.RedactionRequest.PatientID)
				if err != nil {
					return fmt.Errorf("missing patient wrapped key at block %d: %w", i, err)
				}
				if patientWrappedKey.ActorRole != actors.RolePatient {
					return fmt.Errorf("patient wrapped key role mismatch at block %d", i)
				}

				authorityWrappedKey, err := curr.Record.WrappedKeyForActor(curr.Record.RedactionApproval.AuthorityID)
				if err != nil {
					return fmt.Errorf("missing authority wrapped key at block %d: %w", i, err)
				}
				if authorityWrappedKey.ActorRole != actors.RoleAuthority {
					return fmt.Errorf("authority wrapped key role mismatch at block %d", i)
				}
			}
		}
		if curr.Record.IsRedacted() {
			if curr.Record.RedactionProof == nil {
				return fmt.Errorf("missing redaction proof at block %d", i)
			}
			if proofVerifier == nil {
				return fmt.Errorf("proof verifier is required for redacted record at block %d", i)
			}
			if err := proofVerifier.VerifyRecordProof(curr.Record); err != nil {
				return fmt.Errorf("invalid redaction proof at block %d: %w", i, err)
			}
		}
	}

	return nil
}

func (bc *Blockchain) mutateBlockRecord(index int, chameleonStore *chameleon.Store, mutate func(record *medical.EncryptedRecord) error) error {
	if index <= 0 || index >= len(bc.Blocks) {
		return fmt.Errorf("block index out of range: %d", index)
	}

	block := &bc.Blocks[index]
	oldMessage, err := block.LinkMessage()
	if err != nil {
		return err
	}
	oldRandomness := block.LinkRandomness
	oldLinkHash := block.LinkHash

	if err := mutate(&block.Record); err != nil {
		return err
	}

	block.UpdateContentHash()
	newMessage, err := block.LinkMessage()
	if err != nil {
		return err
	}

	newRandomness, err := chameleonStore.ForgeCollision(oldMessage, oldRandomness, newMessage)
	if err != nil {
		return err
	}

	publicKey, err := chameleonStore.Public()
	if err != nil {
		return err
	}
	if err := publicKey.Verify(newMessage, newRandomness, oldLinkHash); err != nil {
		return fmt.Errorf("preserve link hash after mutation: %w", err)
	}

	block.LinkRandomness = newRandomness
	block.LinkHash = oldLinkHash
	return nil
}
