# Amnesia

Amnesia is a single-node prototype for controlled redaction of medical records on a blockchain-style ledger. The repository implements encrypted records, per-actor access to decryption keys, doctor/patient/authority signatures, chameleon-hash block links, full-record redaction, and a Groth16 proof layer for redacted records. It is a research prototype and CLI system, not a production deployment.

## What This Repository Demonstrates

This codebase demonstrates an end-to-end redaction flow with explicit authorization and auditable retention:

- A doctor creates an encrypted medical record and signs the stored record form.
- The patient signs a redaction request.
- An authority signs a redaction approval.
- The record is redacted by removing the encrypted payload while preserving the block, metadata, and authorization trail.
- Chameleon-hash block links preserve chain validity under that authorized mutation.
- Each redacted record carries a Groth16 proof that binds the public patient ID in the redaction request to the original stored patient commitment for that record.

The current proof scope is intentionally narrow. It proves patient binding to the stored commitment. It does **not** prove title or content consistency inside the circuit.

## System Model

### Actors

- **Doctor**: creates records, signs stored encrypted records, and can decrypt records they are authorized to view.
- **Patient**: can decrypt their own records and sign redaction requests.
- **Authority**: can decrypt records for review and sign redaction approvals.
- **Verifier**: runs CLI verification over chain links, signatures, and redaction proofs.

The prototype is permissioned and local. Actor state lives in `actors.json`. Actor key material and per-record proof salts live in `keystore.json`.

### Record Lifecycle

1. **Creation**
   A doctor submits a plaintext medical record. The record is assigned a new `R...` identifier. A patient commitment is computed before encryption. The payload is then encrypted with a fresh AES-256-GCM key.

2. **Encrypted storage**
   The record AES key is wrapped separately for the patient, the creating doctor, and active authorities using X25519. The stored record contains only visible metadata, ciphertext, wrapped keys, and the doctor signature.

3. **Authorization**
   The patient signs a redaction request. An authority signs a redaction approval. Both signed objects are attached to the record.

4. **Execution**
   `redact-record` removes the ciphertext, nonce, and wrapped keys, marks the record as redacted, and preserves the block plus the authorization trail.

5. **Proof verification**
   During redaction, the system generates a Groth16 proof that the public patient ID in the request matches the original patient commitment stored on the record. `verify` and `verify-proof` both enforce that proof.

### Stored Artifacts

The local prototype creates and uses these artifacts:

- `chain.json`: blockchain state
- `actors.json`: actor registry
- `keystore.json`: actor keys and per-record proof secrets
- `chameleon.json`: system chameleon-hash key material
- `zk-artifacts/`: Groth16 circuit artifacts created by `setup-zk`

### Trust Model

This is a local research prototype. The CLI auto-uses local key material from `keystore.json`. That is acceptable for a prototype, but it is not a production security boundary. Anyone with raw access to the local secret files can bypass the intended CLI trust model.

## Cryptographic Design

- **Ed25519**
  Used for signatures.
  - doctor signs stored encrypted records
  - patient signs redaction requests
  - authority signs redaction approvals

- **X25519**
  Used to wrap a record AES key separately for each authorized actor.

- **AES-256-GCM**
  Used to encrypt the record payload before redaction.

- **SHA-256**
  Used for deterministic block content hashing.

- **Chameleon hash**
  Used for mutable block linking. Authorized changes to a block update the link randomness while preserving the block’s public link hash.

- **Poseidon2 on BN254**
  Used to compute the public patient commitment stored on each record.

- **Groth16 with `gnark`**
  Used to prove patient binding for redacted records.

## What Is Public vs Hidden

Before redaction, the chain stores visible metadata and encrypted payload material.

Visible in the block:

- block index and timestamps
- record ID
- doctor ID
- record type
- patient commitment
- ciphertext
- wrapped keys
- doctor signature
- chameleon-link fields

Hidden inside the encrypted payload:

- patient ID
- title
- content

After redaction:

- the block remains in the chain
- the record ID remains
- the doctor ID remains
- the patient commitment remains
- the patient request and authority approval remain
- the Groth16 proof remains
- the ciphertext, nonce, and wrapped keys are removed

The design goal is auditability without retaining decryptable medical content after authorized redaction.

## Running the Prototype

Build and test:

```bash
go test ./...
go build -o amnesia ./cmd/amnesia
```

Initialize local state:

```bash
./amnesia init
./amnesia setup-zk
```

Create and inspect a record:

```bash
./amnesia add-record -p P001 -d D001 -r diagnosis -t "Flu" -c "Patient has seasonal flu"
./amnesia view-chain
./amnesia view-record -i R001 -a D001
```

Authorize and execute redaction:

```bash
./amnesia authorize-redaction -i R001 -p P001 -a A001 -r "Patient requested deletion"
./amnesia redact-record -i R001
```

Verify the result:

```bash
./amnesia verify
./amnesia verify-proof -i R001
```

Additional operational commands:

```bash
./amnesia add-actor -r doctor -n "Dr. Kapoor"
./amnesia list-actors
./amnesia deactivate-actor -i D002
```

Seeded demo actors after `init`:

- Patients: `P001`, `P002`, `P007`
- Doctors: `D001`, `D002`
- Authorities: `A001`

## Repository Layout

```text
cmd/amnesia/   CLI entrypoint and command wiring
core/          block, blockchain, validation, redaction execution
auth/          signatures, encryption, key wrapping, keystore logic
medical/       record models, encrypted-record shape, redaction metadata
zk/            patient commitment, circuit setup, proof generation and verification
storage/       JSON persistence for chain, keys, actors, and chameleon material
```

## Current Limitations

- This is a single-node prototype. There is no distributed consensus or peer-to-peer network.
- The local keystore is trusted by the CLI. There is no passphrase-protected or external key management yet.
- Redaction is whole-record only. There is no field-level edit or partial redaction flow.
- The current Groth16 proof covers patient binding only. It does not prove title/content consistency.
- Signatures are verified outside the circuit by design.
- There is no production access-control layer, remote identity model, or hardened audit subsystem.

## Status

For the current prototype scope, the technical core is implemented:

- encrypted records with actor-gated decryption
- signed redaction authorization and full-record redaction
- chameleon-hash block links
- proof-backed verification for redacted records

What remains outside the implementation core is project packaging: diagrams, report writing, and any optional expansion of the proof statement beyond patient binding.
