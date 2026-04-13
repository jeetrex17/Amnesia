package medical

import (
	"encoding/base64"
	"fmt"
	"strings"
)

const RedactionProofScheme = "groth16-bn254-poseidon2-patient-v1"

type RedactionProof struct {
	Scheme            string `json:"scheme"`
	PatientCommitment string `json:"patient_commitment"`
	RecordIDField     string `json:"record_id_field"`
	PatientIDField    string `json:"patient_id_field"`
	Proof             string `json:"proof"`
}

func (p RedactionProof) Validate() error {
	if strings.TrimSpace(p.Scheme) == "" {
		return fmt.Errorf("redaction proof scheme is required")
	}
	if p.Scheme != RedactionProofScheme {
		return fmt.Errorf("unsupported redaction proof scheme: %s", p.Scheme)
	}
	if strings.TrimSpace(p.PatientCommitment) == "" {
		return fmt.Errorf("redaction proof patient commitment is required")
	}
	if strings.TrimSpace(p.RecordIDField) == "" {
		return fmt.Errorf("redaction proof record_id_field is required")
	}
	if strings.TrimSpace(p.PatientIDField) == "" {
		return fmt.Errorf("redaction proof patient_id_field is required")
	}
	if strings.TrimSpace(p.Proof) == "" {
		return fmt.Errorf("redaction proof payload is required")
	}
	if _, err := base64.StdEncoding.DecodeString(p.Proof); err != nil {
		return fmt.Errorf("decode redaction proof payload: %w", err)
	}

	return nil
}
