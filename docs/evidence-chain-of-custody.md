# AgentIR — Evidence Chain of Custody

Chain of custody is the documented, unbroken record of who handled evidence, when, and what state it was in. In digital forensics, it is the difference between an admissible report and a dismissed case.

AgentIR implements a four-layer chain of custody:
1. **Cryptographic** — SHA-256 per file, HMAC-signed ledger, versioned manifest
2. **Operational** — portal-only sealing, HMAC password confirmation required
3. **OS-level** — `chattr +i`, auditd kernel records, AppArmor DENY write
4. **Blockchain** — Solana SPL Memo timestamp, public and independent of the SIFT VM

---

## Evidence Directory Structure

```
/cases/{case-id}/
├── evidence/
│   ├── host1/disk.E01        ← acquired artifact (chattr +i after seal)
│   ├── host1/memory.raw
│   └── network/capture.pcap
├── evidence-manifest.json    ← current sealed state snapshot
├── evidence-ledger.jsonl     ← append-only signed event log
└── evidence-anchor-v{N}.json ← Solana anchor proof per manifest version
```

---

## Layer 1: Cryptographic Chain

### Per-File SHA-256

Every file in `evidence/` that is registered and sealed gets a SHA-256 hash computed at seal time. The hash is stored in the manifest and re-verified on demand.

- Symlinks are rejected (`_resolve_evidence_path` checks `os.path.realpath`)
- Directories are not registerable — individual files only
- Path traversal (`../`) is rejected with `ValueError` before any manifest operation

### The Evidence Manifest

`evidence-manifest.json` is the current sealed state. It is a JSON document with a hash of itself (excluded from hash computation) and a hash of the previous version, creating a forward-linked chain:

```json
{
  "version": 3,
  "case_id": "case-2026-001",
  "created_at": "2026-05-24T12:00:00Z",
  "created_by": "alice",
  "previous_manifest_hash": "sha256:a1b2c3...",
  "manifest_hash": "sha256:d4e5f6...",
  "files": [
    {
      "path": "evidence/host1/disk.E01",
      "sha256": "sha256:7890ab...",
      "bytes": 137438953472,
      "mtime_ns": 1770000000000000000,
      "registered_at": "2026-05-24T12:00:00Z",
      "registered_by": "alice",
      "source": "Acquistion via FTK, physical write-blocker, USB serial ABC123",
      "description": "Primary disk image, Host 1",
      "status": "ACTIVE"
    }
  ]
}
```

**Important:** `mtime_ns` is recorded for informational context only. It is trivially spoofable (`touch -t`) and is never used in any integrity assertion. SHA-256 is the only integrity anchor.

File status lifecycle:
- `ACTIVE` — registered and sealed
- `IGNORED` — examiner explicitly excluded with documented reason (never analyzed)
- `RETIRED` — removed from disk after documented reason (e.g., duplicate image, consent withdrawn)

IGNORED and RETIRED entries are carried forward in every subsequent manifest version. This means:
- Re-sealing after adding new evidence cannot "forget" a previously ignored or retired file
- Retired file paths cannot re-appear as UNREGISTERED (they remain RETIRED in the manifest)

### The Evidence Ledger

`evidence-ledger.jsonl` is append-only. Every evidence decision appends one line. Each line is a JSON object with an HMAC signature over its own content:

```jsonl
{"event":"MANIFEST_SEALED","case_id":"case-2026-001","version":1,"files_added":["evidence/host1/disk.E01"],"previous_manifest_hash":"sha256:0000...","new_manifest_hash":"sha256:a1b2...","sealed_by":"alice","sealed_at":"2026-05-24T12:00:00Z","hmac":"abc123..."}
{"event":"FILE_IGNORED","case_id":"case-2026-001","version":2,"path":"evidence/host1/pagefile.sys","reason":"Not relevant to scope","ignored_by":"alice","ignored_at":"2026-05-24T12:30:00Z","hmac":"def456..."}
{"event":"FILE_RETIRED","case_id":"case-2026-001","version":3,"path":"evidence/host1/duplicate.E01","reason":"Duplicate image, hash confirmed identical","retired_by":"alice","retired_at":"2026-05-24T13:00:00Z","deleted_from_disk":true,"hmac":"ghi789..."}
```

HMAC key derivation: `derive_ledger_key(stored_password_hash_hex)` — uses `HKDF(stored_hash, info=b"agentir-signing-v1")`. This key is domain-separated from the authentication key and is only available when the examiner provides their password.

After each ledger write:
- `fsync()` is called — event is on disk before the function returns
- `chmod 0444` is set on the ledger file — no application path can silently append without removing permissions first

### Chain Verification

`verify_chain_integrity()` re-hashes every ACTIVE file and verifies:
1. Each file's SHA-256 matches the manifest
2. `manifest_hash` correctly commits to all file entries
3. Each ledger event's HMAC is valid
4. `previous_manifest_hash` chains correctly from version to version

`verify_chain_hmac()` additionally requires the examiner's derived key to verify ledger HMACs — proving the ledger was signed by someone with the examiner password.

The portal shows:
- Last HMAC verification timestamp and examiner
- Amber reminder if no HMAC verification in 24 hours
- Per-file OK/MODIFIED/MISSING status

---

## Layer 2: Operational Controls

### Portal-Only Sealing

Evidence sealing cannot be done by the AI agent. The evidence chain endpoints in `case-dashboard/routes.py` require:
- `role: examiner` (service-agent tokens are rejected)
- Active portal session
- HMAC challenge-response password confirmation for every seal/ignore/retire operation

The challenge is:
- Generated server-side as a cryptographic nonce
- Bound to the examiner's username and source IP
- Single-use and 5-minute TTL
- Domain-separated from login challenges and response-guard override challenges

### Two-Tier Evidence Gate

The gateway enforces evidence chain state before every agent tool call:

```
SEALED + clean diff    →  all tools pass
UNSEALED + read-only   →  pass with warning injected into tool response
UNSEALED + analysis    →  blocked: "evidence_chain_unsealed"
ANY VIOLATION          →  all tools blocked: "evidence_chain_violation"
```

A "violation" is any of: MODIFIED, MISSING, UNREGISTERED, LEDGER_ERROR.

This means an agent working on a case with modified evidence cannot call any tool, not even a read-only status check. The examiner must resolve the chain state before the agent can proceed.

### Evidence Diff

`diff_manifest(case_dir, manifest)` compares the live `evidence/` tree to the sealed manifest and returns:

- `ok` — files present with matching SHA-256
- `modified` — files present with changed SHA-256
- `missing` — sealed files absent from disk
- `unregistered` — files in `evidence/` not in the manifest

The diff result drives both the portal warning display and the gateway block decision.

---

## Layer 3: OS-Level Hardening

### `chattr +i` Immutable Flag

After `seal_manifest()` writes the ledger event, it calls `_set_immutable(abs_path, True)` on every newly sealed file. This sets the Linux immutable flag via `fcntl.ioctl(FS_IOC_SETFLAGS)`.

A file with the immutable flag set:
- Cannot be deleted, renamed, or modified — even by root
- Cannot have its permissions changed
- Requires explicit `chattr -i` before any of the above can happen

Clearing the flag before tampering is the key insight: it creates an auditable act rather than a silent one.

`get_immutable_flag(path)` is exposed via the portal chain status API — the portal displays `immutable: true/false` per ACTIVE file so the examiner can see at a glance if any file has lost its flag.

### auditd Kernel Records

`/etc/audit/rules.d/99-agentir-evidence.rules`:

```
-a always,exit -F dir=/cases -F perm=wa -F key=agentir_evidence_write
-a always,exit -F dir=/var/lib/agentir -F perm=wa -F key=agentir_core_write
```

`perm=a` (attribute change) specifically catches `chattr -i`. If anyone deliberately clears the immutable flag, the kernel audit log records:
- Timestamp
- UID and PID of the process
- Executable path
- System call (setxattr/ioctl)

Query: `ausearch -k agentir_evidence_write --format text`

### AppArmor DENY write

The AppArmor profile for the sift-gateway process includes:

```
/cases/*/evidence/**   r,      # read for hashing
deny /cases/*/evidence/**   w, # no write ever
```

Even if the gateway process is fully compromised, it cannot write to evidence files at the MAC layer — the kernel will reject the write before it reaches the filesystem.

---

## Layer 4: Solana On-Chain Anchoring

### Why Blockchain Timestamping?

The HMAC ledger proves integrity within the trust boundary of the SIFT VM and the examiner's password. Solana anchoring provides an **independent, public, tamper-proof timestamp** that:
- Cannot be backdated (Solana block timestamps are consensus-agreed)
- Does not require trusting the SIFT VM operator
- Is publicly verifiable by anyone with the transaction signature
- Creates a record outside the jurisdiction of any single organization

For enterprise incident response involving regulatory scrutiny, litigation, or third-party auditors, this creates a timestamped proof of the sealed evidence state that predates any dispute.

### Implementation

`anchor_manifest()` in `agentir_core/evidence_chain.py`:

1. Extracts `manifest_hash[:16]` (first 16 hex chars of the SHA-256 manifest hash)
2. Extracts the HMAC of the latest ledger tip (first 16 hex chars)
3. Builds payload: `AGENTIR|{manifest_hash[:16]}|{ledger_tip[:16]}`
4. Signs and submits a Solana SPL Memo transaction containing this payload
5. Writes `evidence-anchor-v{N}.json` with the transaction signature and explorer URL

Example payload: `AGENTIR|d4e5f6a7b8c9d0e1|f2a3b4c5d6e7f8a9`

The SPL Memo program stores arbitrary UTF-8 memo data in the transaction, permanently recorded on-chain. The full manifest hash and ledger tip HMAC are stored in `evidence-anchor-v{N}.json` alongside the on-chain transaction signature for offline verification.

### Proof File

```json
{
  "case_id": "case-2026-001",
  "manifest_version": 3,
  "manifest_hash": "sha256:d4e5f6...",
  "ledger_tip_hmac": "f2a3b4...",
  "payload": "AGENTIR|d4e5f6a7b8c9d0e1|f2a3b4c5d6e7f8a9",
  "solana_tx": "5J7rFxKmY9Pv8wNqR3eLfT2gHdSuVkBzCnAoWiXpM6jQ",
  "solana_cluster": "devnet",
  "confirmed": true,
  "timestamp": "2026-05-24T12:05:00Z",
  "explorer_url": "https://explorer.solana.com/tx/5J7rFxKmY9Pv8wNqR3eLfT2gHdSuVkBzCnAoWiXpM6jQ?cluster=devnet"
}
```

### Setup

```bash
# On the SIFT VM — generate a keypair
~/.local/bin/uv run python -c "
from solders.keypair import Keypair
import json, pathlib
kp = Keypair()
pathlib.Path('/var/lib/agentir/solana-keypair.json').write_text(
    json.dumps(list(bytes(kp)))
)
print('pubkey:', kp.pubkey())
"

# Fund the keypair (devnet)
curl -s -X POST https://api.devnet.solana.com \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"requestAirdrop","params":["YOUR_PUBKEY",1000000000]}'

# Configure the gateway
# In ~/.agentir/gateway.yaml or via environment:
export AGENTIR_SOLANA_KEYPAIR=/var/lib/agentir/solana-keypair.json
export AGENTIR_SOLANA_CLUSTER=devnet   # or mainnet

# Auto-anchoring: triggered automatically after every seal
# Manual re-anchor: POST /portal/api/evidence/chain/anchor
```

The `solders` library is an optional dependency (`pip install "agentir-core[solana]"`). Without it, the anchoring step is silently skipped and the ledger/manifest remain the sole chain-of-custody proof. The gateway does not require Solana to function.

### Verifying an Anchor On-Chain

Any auditor with the `evidence-anchor-v{N}.json` proof file can independently verify:

1. Look up the transaction on any Solana explorer or via RPC: `getTransaction(solana_tx)`
2. The transaction memo field should contain `AGENTIR|{manifest_hash[:16]}|{ledger_tip[:16]}`
3. The full `manifest_hash` in the proof file should match the `evidence-manifest.json` content hash
4. The block timestamp proves the evidence was sealed before the transaction was confirmed

This verification requires no access to the SIFT VM, no special tooling, and no trust in the operator.

---

## Verification Workflow (Operational Checklist)

### Before Starting Agent Investigation

1. **Open the portal** evidence intake panel
2. **Confirm the diff is clean** — no unregistered, missing, or modified files
3. **Confirm the manifest is sealed** — status shows OK, not UNSEALED
4. **Confirm the immutable flags** — all ACTIVE files show `immutable: true`
5. **Run HMAC verification** if last verification is older than 24 hours
6. **Check the anchor** — if Solana is configured, confirm the latest version has `confirmed: true`

### After Investigation / Before Report

1. **Run HMAC verification** — portal will show amber reminder if needed
2. **Review the ledger** — any unexpected events (FILE_IGNORED, FILE_RETIRED) should be explained
3. **Generate the report** — `report-mcp` will embed current chain state; review the embedded status

### For Litigation or Audit

1. Provide `evidence-ledger.jsonl` — the complete signed event log
2. Provide `evidence-manifest.json` — the current sealed state
3. Provide `evidence-anchor-v{N}.json` for each version — the on-chain proof
4. Provide `audit/sift-gateway.jsonl` — the complete agent tool call record
5. Provide `approvals.jsonl` — the examiner approval audit log
6. The verifier can independently re-hash evidence files and verify HMAC signatures without any special software

---

## Honest Limitations

- **chattr +i does not stop a root attacker.** `sudo chattr -i` clears the flag. The immutable flag converts deliberate tampering into an auditable act (auditd records it) but does not prevent it. The cryptographic ledger is the actual chain-of-custody proof.
- **HMAC security depends on the examiner password.** If the password is compromised, a forged ledger event could be constructed. The Solana anchor is independent of the password and provides an out-of-band reference.
- **Solana devnet can be reset.** Use mainnet for any incident with real evidentiary value.
- **The SHA-256 hash is the integrity anchor.** `mtime_ns` is recorded for context but is trivially spoofable and is never used in integrity assertions.
- **The AppArmor profile is in complain mode by default.** It logs violations but does not block them. Run `aa-logprof` after exercising all gateway paths and switch to enforce mode.
