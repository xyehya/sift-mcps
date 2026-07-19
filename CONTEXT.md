# Protocol SIFT Domain Language

> **P4.23 remediation freeze (2026-07-16; SPEC accepted 2026-07-19):** this file still mixes
> retained terms with pre-remediation/as-built concepts. Do not use it to infer the remediation
> target: the sole behavioral authority is `docs/architecture/EVIDENCE-CUSTODY-SPEC.md`
> (accepted 2026-07-19). This glossary is reconciled during the remediation sprint; the decision
> register remains frozen provenance.

Protocol SIFT separates human custody authority from agent investigation. These terms are the canonical language for evidence custody across code, tests, APIs, Portal copy, and documentation.

## Cases

**Case Lifecycle**:
The operational lifecycle of a case: `ACTIVE`, `INACTIVE`, or `CLOSED`. It is independent of evidence custody.
_Avoid_: Sealed case, unsealed case

**Active Case**:
The single Postgres-authoritative case bound to an operator or agent session.
_Avoid_: Current folder, environment-selected case

## Custody

**Custody Gate**:
The case-wide, Postgres-authoritative admission state for agent work: `OPEN`, `BLOCKED_PENDING`, `BLOCKED_VIOLATION`, or `BLOCKED_UNAVAILABLE`.
_Avoid_: Case seal, chain seal status

**Evidence Object**:
The durable identity of one real-world item of evidence. It may have multiple Evidence Versions over time.
_Avoid_: Registered file, manifest file entry

**Evidence Version**:
One content-addressed snapshot of an Evidence Object, identified by a full SHA-256 digest and custody metadata.
_Avoid_: Resealed file

**Evidence Object State**:
The custody lifecycle of an Evidence Object: `DETECTED`, `REGISTERED`, `SEALED`, `IGNORED`, `RETIRED`, or `VIOLATED`.
_Avoid_: Sealed case, unregistered manifest item

**Manifest Version**:
An immutable declaration of the active Evidence Versions admitted for agent use at one custody point.
_Avoid_: Evidence version

**Custody Ledger**:
The append-only Postgres event chain recording custody transitions, actors, reasons, re-authentication references, and before/after state.
_Avoid_: File ledger, HMAC ledger, audit log

**Custody Operation**:
A durable, idempotent operator-authorized workflow that blocks the Custody Gate before any filesystem mutation and remains blocked until filesystem and ledger completion are verified.
_Avoid_: Unseal window, best-effort evidence action

**Mounted Evidence File**:
The filesystem representation of an Evidence Version. It uses either the Local Immutable or Externally Read-Only storage profile.
_Avoid_: Evidence authority

**Local Immutable**:
A storage profile whose sealed regular files are service-owned and protected with the immutable filesystem flag.
_Avoid_: Read-only mode bit

**Externally Read-Only**:
A storage profile backed by a stable read-only mount controlled outside Protocol SIFT. Local immutable flags are neither required nor assumed.
_Avoid_: Unprotected evidence

**Inventory Reconciliation**:
A read-only comparison of the mounted evidence inventory with Postgres custody authority. It may record observations and block admission, but never modifies evidence filesystem content or metadata.
_Avoid_: Rescan as a security prerequisite, file authority

**Verify Ledger**:
A fast verification of custody-event linkage, manifest linkage, and signatures without reading all evidence bytes.
_Avoid_: Verify HMAC

**Full Verify Evidence**:
A verification that includes Verify Ledger plus full hashing and storage-posture checks for the relevant evidence bytes.
_Avoid_: Rescan, Verify HMAC

**Replace/Reacquire**:
The operator workflow that creates a new Evidence Version for the same Evidence Object after an explicitly authorized replacement or re-imaging.
_Avoid_: Standalone Unseal

## Authority

**Operator Custody Authority**:
The Portal and fixed local operator helpers that may initiate or perform evidence custody mutations after the required authorization.
_Avoid_: MCP custody tool, agent evidence administration

**MCP Evidence Admission Guard**:
The read-only Gateway control that reconciles custody observations, checks the Custody Gate, and authorizes only active sealed Evidence Versions before an MCP tool body can run.
_Avoid_: MCP evidence manager, file gate

**Custody Proof Bundle**:
A versioned, path-sanitized JSON export containing manifests, evidence identities and digests, custody events, verification state, and detached signature material for independent verification.
_Avoid_: Audit export, manifest file

**Signed Ledger Checkpoint**:
An append-only record binding a canonical custody-ledger head to an installation-held Ed25519 public-key identity. The fixed-path private key is service-only and never appears in Postgres, source, logs, trackers, or proof bundles.
_Avoid_: HMAC proof, DB signing key
