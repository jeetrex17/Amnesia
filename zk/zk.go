package zk

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	gnarkecc "github.com/consensys/gnark-crypto/ecc"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254poseidon2 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stdhash "github.com/consensys/gnark/std/hash"
	stdpermposeidon2 "github.com/consensys/gnark/std/permutation/poseidon2"

	"github.com/jeetraj/amnesia/medical"
)

const (
	ArtifactsDir         = "zk-artifacts"
	constraintFilename   = "patient_redaction.r1cs"
	provingKeyFilename   = "patient_redaction.pk"
	verifyingKeyFilename = "patient_redaction.vk"
	idFieldByteLength    = 16
)

type patientBindingCircuit struct {
	PatientCommitment frontend.Variable `gnark:",public"`
	RecordIDField     frontend.Variable `gnark:",public"`
	PatientIDField    frontend.Variable `gnark:",public"`

	SecretRecordIDField  frontend.Variable
	SecretPatientIDField frontend.Variable
	Salt                 frontend.Variable
}

type System struct {
	ccs constraint.ConstraintSystem
	pk  groth16.ProvingKey
	vk  groth16.VerifyingKey
}

func (c *patientBindingCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.SecretRecordIDField, c.RecordIDField)
	api.AssertIsEqual(c.SecretPatientIDField, c.PatientIDField)

	params := bn254poseidon2.GetDefaultParameters()
	permutation, err := stdpermposeidon2.NewPoseidon2FromParameters(api, 2, params.NbFullRounds, params.NbPartialRounds)
	if err != nil {
		return fmt.Errorf("create poseidon2 permutation: %w", err)
	}
	hasher := stdhash.NewMerkleDamgardHasher(api, permutation, 0)
	hasher.Write(c.SecretRecordIDField, c.SecretPatientIDField, c.Salt)
	api.AssertIsEqual(hasher.Sum(), c.PatientCommitment)
	return nil
}

func Setup(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create zk artifacts directory: %w", err)
	}

	ccs, err := frontend.Compile(gnarkecc.BN254.ScalarField(), r1cs.NewBuilder, &patientBindingCircuit{})
	if err != nil {
		return fmt.Errorf("compile zk circuit: %w", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return fmt.Errorf("groth16 setup: %w", err)
	}

	if err := writeConstraintSystem(filepath.Join(dir, constraintFilename), ccs); err != nil {
		return err
	}
	if err := writeSerializable(filepath.Join(dir, provingKeyFilename), pk); err != nil {
		return err
	}
	if err := writeSerializable(filepath.Join(dir, verifyingKeyFilename), vk); err != nil {
		return err
	}

	return nil
}

func LoadProver(dir string) (*System, error) {
	ccs, err := readConstraintSystem(filepath.Join(dir, constraintFilename))
	if err != nil {
		return nil, err
	}
	pk, err := readProvingKey(filepath.Join(dir, provingKeyFilename))
	if err != nil {
		return nil, err
	}
	vk, err := readVerifyingKey(filepath.Join(dir, verifyingKeyFilename))
	if err != nil {
		return nil, err
	}

	return &System{ccs: ccs, pk: pk, vk: vk}, nil
}

func LoadVerifier(dir string) (*System, error) {
	vk, err := readVerifyingKey(filepath.Join(dir, verifyingKeyFilename))
	if err != nil {
		return nil, err
	}

	return &System{vk: vk}, nil
}

func ArtifactsExist(dir string) bool {
	for _, path := range []string{
		filepath.Join(dir, constraintFilename),
		filepath.Join(dir, provingKeyFilename),
		filepath.Join(dir, verifyingKeyFilename),
	} {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	return true
}

func GeneratePatientCommitmentSalt() ([]byte, error) {
	var salt bn254fr.Element
	if _, err := salt.SetRandom(); err != nil {
		return nil, fmt.Errorf("generate patient commitment salt: %w", err)
	}

	return salt.Marshal(), nil
}

func ComputePatientCommitment(recordID, patientID string, salt []byte) (string, error) {
	recordField, err := encodeIDFieldElement(recordID)
	if err != nil {
		return "", fmt.Errorf("encode record ID field: %w", err)
	}
	patientField, err := encodeIDFieldElement(patientID)
	if err != nil {
		return "", fmt.Errorf("encode patient ID field: %w", err)
	}
	saltField, err := saltElement(salt)
	if err != nil {
		return "", fmt.Errorf("decode patient commitment salt: %w", err)
	}

	hasher := bn254poseidon2.NewMerkleDamgardHasher()
	if _, err := hasher.Write(recordField.Marshal()); err != nil {
		return "", fmt.Errorf("hash record ID field: %w", err)
	}
	if _, err := hasher.Write(patientField.Marshal()); err != nil {
		return "", fmt.Errorf("hash patient ID field: %w", err)
	}
	if _, err := hasher.Write(saltField.Marshal()); err != nil {
		return "", fmt.Errorf("hash patient commitment salt: %w", err)
	}

	digest := hasher.Sum(nil)
	var commitment bn254fr.Element
	if err := commitment.SetBytesCanonical(digest); err != nil {
		return "", fmt.Errorf("decode patient commitment digest: %w", err)
	}

	return commitment.Text(10), nil
}

func EncodeIDFieldString(id string) (string, error) {
	field, err := encodeIDFieldElement(id)
	if err != nil {
		return "", err
	}

	return field.Text(10), nil
}

func (s *System) GenerateRedactionProof(recordID, patientID, patientCommitment string, salt []byte) (medical.RedactionProof, error) {
	if s == nil || s.ccs == nil || s.pk == nil {
		return medical.RedactionProof{}, fmt.Errorf("zk prover artifacts are not loaded")
	}

	recordField, err := EncodeIDFieldString(recordID)
	if err != nil {
		return medical.RedactionProof{}, fmt.Errorf("encode record ID field: %w", err)
	}
	patientField, err := EncodeIDFieldString(patientID)
	if err != nil {
		return medical.RedactionProof{}, fmt.Errorf("encode patient ID field: %w", err)
	}
	saltField, err := saltFieldString(salt)
	if err != nil {
		return medical.RedactionProof{}, fmt.Errorf("encode patient commitment salt: %w", err)
	}

	assignment := &patientBindingCircuit{
		PatientCommitment:    patientCommitment,
		RecordIDField:        recordField,
		PatientIDField:       patientField,
		SecretRecordIDField:  recordField,
		SecretPatientIDField: patientField,
		Salt:                 saltField,
	}

	fullWitness, err := frontend.NewWitness(assignment, gnarkecc.BN254.ScalarField())
	if err != nil {
		return medical.RedactionProof{}, fmt.Errorf("build proof witness: %w", err)
	}

	proof, err := groth16.Prove(s.ccs, s.pk, fullWitness)
	if err != nil {
		return medical.RedactionProof{}, fmt.Errorf("generate groth16 proof: %w", err)
	}

	var proofBytes bytes.Buffer
	if _, err := proof.WriteTo(&proofBytes); err != nil {
		return medical.RedactionProof{}, fmt.Errorf("serialize groth16 proof: %w", err)
	}

	return medical.RedactionProof{
		Scheme:            medical.RedactionProofScheme,
		PatientCommitment: patientCommitment,
		RecordIDField:     recordField,
		PatientIDField:    patientField,
		Proof:             base64.StdEncoding.EncodeToString(proofBytes.Bytes()),
	}, nil
}

func (s *System) VerifyRecordProof(record medical.EncryptedRecord) error {
	if s == nil || s.vk == nil {
		return fmt.Errorf("zk verifier artifacts are not loaded")
	}
	if record.RedactionProof == nil {
		return fmt.Errorf("missing redaction proof")
	}
	if record.RedactionRequest == nil {
		return fmt.Errorf("missing redaction request for proof verification")
	}
	if err := record.RedactionProof.Validate(); err != nil {
		return err
	}
	if record.RedactionProof.PatientCommitment != record.PatientCommitment {
		return fmt.Errorf("redaction proof patient commitment mismatch")
	}

	expectedRecordField, err := EncodeIDFieldString(record.RecordID)
	if err != nil {
		return fmt.Errorf("encode record ID field: %w", err)
	}
	if record.RedactionProof.RecordIDField != expectedRecordField {
		return fmt.Errorf("redaction proof record_id_field mismatch")
	}

	expectedPatientField, err := EncodeIDFieldString(record.RedactionRequest.PatientID)
	if err != nil {
		return fmt.Errorf("encode patient ID field: %w", err)
	}
	if record.RedactionProof.PatientIDField != expectedPatientField {
		return fmt.Errorf("redaction proof patient_id_field mismatch")
	}

	proofBytes, err := base64.StdEncoding.DecodeString(record.RedactionProof.Proof)
	if err != nil {
		return fmt.Errorf("decode groth16 proof: %w", err)
	}
	proof := groth16.NewProof(gnarkecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return fmt.Errorf("deserialize groth16 proof: %w", err)
	}

	publicWitness, err := frontend.NewWitness(&patientBindingCircuit{
		PatientCommitment: record.RedactionProof.PatientCommitment,
		RecordIDField:     record.RedactionProof.RecordIDField,
		PatientIDField:    record.RedactionProof.PatientIDField,
	}, gnarkecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("build public witness: %w", err)
	}

	if err := groth16.Verify(proof, s.vk, publicWitness); err != nil {
		return fmt.Errorf("verify groth16 proof: %w", err)
	}

	return nil
}

func encodeIDFieldElement(id string) (bn254fr.Element, error) {
	if len(id) == 0 {
		return bn254fr.Element{}, fmt.Errorf("identifier is required")
	}
	if len(id) > idFieldByteLength {
		return bn254fr.Element{}, fmt.Errorf("identifier exceeds %d-byte bound", idFieldByteLength)
	}

	var padded [idFieldByteLength]byte
	copy(padded[:], []byte(id))

	var value big.Int
	value.SetBytes(padded[:])

	var field bn254fr.Element
	field.SetBigInt(&value)
	return field, nil
}

func saltElement(salt []byte) (bn254fr.Element, error) {
	if len(salt) != bn254fr.Bytes {
		return bn254fr.Element{}, fmt.Errorf("unexpected salt length: %d", len(salt))
	}

	var element bn254fr.Element
	if err := element.SetBytesCanonical(salt); err != nil {
		return bn254fr.Element{}, err
	}

	return element, nil
}

func saltFieldString(salt []byte) (string, error) {
	element, err := saltElement(salt)
	if err != nil {
		return "", err
	}
	return element.Text(10), nil
}

func writeConstraintSystem(path string, ccs constraint.ConstraintSystem) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create constraint system artifact: %w", err)
	}
	defer file.Close()

	if _, err := ccs.WriteTo(file); err != nil {
		return fmt.Errorf("write constraint system artifact: %w", err)
	}

	return nil
}

func readConstraintSystem(path string) (constraint.ConstraintSystem, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open constraint system artifact: %w", err)
	}
	defer file.Close()

	ccs := groth16.NewCS(gnarkecc.BN254)
	if _, err := ccs.ReadFrom(file); err != nil {
		return nil, fmt.Errorf("read constraint system artifact: %w", err)
	}

	return ccs, nil
}

func writeSerializable(path string, value io.WriterTo) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create zk artifact %s: %w", filepath.Base(path), err)
	}
	defer file.Close()

	if _, err := value.WriteTo(file); err != nil {
		return fmt.Errorf("write zk artifact %s: %w", filepath.Base(path), err)
	}

	return nil
}

func readProvingKey(path string) (groth16.ProvingKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open proving key artifact: %w", err)
	}
	defer file.Close()

	pk := groth16.NewProvingKey(gnarkecc.BN254)
	if _, err := pk.ReadFrom(file); err != nil {
		return nil, fmt.Errorf("read proving key artifact: %w", err)
	}

	return pk, nil
}

func readVerifyingKey(path string) (groth16.VerifyingKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open verifying key artifact: %w", err)
	}
	defer file.Close()

	vk := groth16.NewVerifyingKey(gnarkecc.BN254)
	if _, err := vk.ReadFrom(file); err != nil {
		return nil, fmt.Errorf("read verifying key artifact: %w", err)
	}

	return vk, nil
}

func IsArtifactsMissing(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}
