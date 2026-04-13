# Amnesia

Amnesia is a single-node prototype for redactable medical records on a blockchain-style ledger.

The current repository implements:
- hash-linked blocks
- encrypted medical record payloads
- actor registry and local keystore
- doctor signatures on stored records
- patient-signed redaction requests
- authority-signed redaction approvals
- execution of full-record redaction

The repository does **not** yet implement the two cryptographic pieces that define the final project claim:
- chameleon-hash block links
- zero-knowledge proofs for authorized redaction

So, at the moment, this is an encrypted and signed redaction prototype with a conventional hash-linked chain. It is not yet a true redactable blockchain in the cryptographic sense.

## Current Model

Each record is handled in three stages.

1. **Creation**
   A doctor creates a medical record. The payload is encrypted with a fresh AES-256-GCM key. That record key is wrapped separately for the patient, the doctor, and active authorities using X25519.

2. **Authorization**
   A patient signs a redaction request. An authority signs a redaction approval. Both signed objects are stored on the record.

3. **Execution**
   The encrypted payload is removed and the record is marked as redacted. The block remains in the chain so the audit trail is preserved.

Because chameleon hashes are not implemented yet, redaction currently keeps the chain valid by rehashing forward from the modified block. That is a temporary mechanism.

## What Is Stored

Visible on chain:
- block index and timestamps
- record ID
- doctor ID
- record type
- encrypted ciphertext
- wrapped record keys
- doctor signature
- redaction request and approval metadata when present
- redacted status

Hidden inside the encrypted payload before redaction:
- patient ID
- title
- content

After redaction:
- the block stays
- the record ID stays
- the authorization trail stays
- the encrypted payload and wrapped keys are removed

## Roles

- **Doctor**: creates records, signs them, can decrypt records they are authorized to view
- **Patient**: can decrypt their own records and sign redaction requests
- **Authority**: can decrypt records for review and sign redaction approvals
- **Auditor**: verifies chain integrity and signatures through the CLI

This is a permissioned local model. Actor state lives in `actors.json`. Key material lives in `keystore.json`.

## Repository Layout

```text
cmd/amnesia/   CLI entrypoint
core/          block and chain logic
medical/       medical record, encrypted record, redaction metadata
auth/          signing, encryption, key wrapping, keystore logic
actors/        actor registry and role handling
storage/       JSON persistence
```

## Commands

Build the binary once:

```bash
go build -o amnesia ./cmd/amnesia
```

Initialize local state:

```bash
./amnesia init
```

Add a record:

```bash
./amnesia add-record -p P001 -d D001 -r diagnosis -t "Flu" -c "Patient has seasonal flu"
```

View the chain:

```bash
./amnesia view-chain
```

Decrypt a record as an authorized actor:

```bash
./amnesia view-record -i R001 -a D001
```

Authorize redaction:

```bash
./amnesia authorize-redaction -i R001 -p P001 -a A001 -r "Patient requests deletion"
```

Execute redaction:

```bash
./amnesia redact-record -i R001
```

Verify chain integrity and signatures:

```bash
./amnesia verify
```

Manage actors:

```bash
./amnesia add-actor -r doctor -n "Dr. Kapoor"
./amnesia list-actors
./amnesia deactivate-actor -i D002
```

## Seeded Demo Actors

`init` creates these actors:

- Patients: `P001`, `P002`, `P007`
- Doctors: `D001`, `D002`
- Authorities: `A001`

## Cryptography In Use

- **AES-256-GCM** for record payload encryption
- **X25519** for per-actor wrapping of record encryption keys
- **Ed25519** for signatures
  - doctor signs stored record form
  - patient signs redaction request
  - authority signs redaction approval
- **SHA-256** for current block linking

Planned but not implemented:
- chameleon hash links
- Pedersen commitments for patient identity hiding
- Poseidon-based record commitments for the proof layer
- Groth16 proof generation and verification with `gnark`

## Development Notes

- This is a learning project and a prototype, not a production system.
- Storage is JSON by design. That is acceptable here and intentionally simple.
- The local keystore is auto-used by the CLI. That is convenient for development, but it is not a strong security boundary.
- Redaction is whole-record only. There is no field-level edit or partial redaction flow.
