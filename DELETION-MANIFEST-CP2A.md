# CP2A Deferred-Deletion Manifest — root executes at the CP3 sweep

**Author:** CP2A writer (2026-07-20) · **Consumer:** root (integration orchestrator)
**Decision (operator, 2026-07-20):** CP2A ships its green build + tests now; the paired
deletions are DEFERRED because every dependent file is owned by another lane and not yet
rewritten. Executing them on the CP2A branch would break the green baseline / installer
fail-on-revert contract tests / live CP1 code. This matches the CP1 precedent already in the
ledger: *file deletions land with their owning packets + the CP3 sweep; keep branches green.*

**What CP2A DID ship:** `custody/seal.py` + `custody/reauth.py` + `custody/actions.py` bodies
+ unit/composed acceptance suites. custody_operations.py and test_custody_operations.py were
LEFT INTACT (operator direction B) so the as-built engine + its coverage stay green until CP2B
rewrites portal_services off it.

---

## 1. custody_operations.py — gut to import-compat tombstone, then delete the file

**Sequencing (hard):** portal_services.py (CP2B-owned) `PortalEvidenceService.__init__`
(portal_services.py:564–569) CONSTRUCTS `CustodyOperationRepository()` +
`LocalImmutablePostureAdapter()` + `ExternalReadOnlyPostureAdapter()`, and its seal/dispose/
recover methods DRIVE `SealCustodyOperation` / `DispositionCustodyOperation` /
`RecoveryCustodyOperation` (portal_services.py ~1958, 2164, 2245, 2329, 2364). Inert stubs break
`PortalEvidenceService` construction across the portal_services test set. **So the tombstone can
only go inert AFTER CP2B rewrites portal_services off the engine.** Order: CP2B rewrite → gut to
tombstone → root deletes the file at CP3.

**Keep ONLY these 14 symbols** (the exact `portal_services.py:42` import set) as deprecated inert
re-exports under a `DELETER: root @ CP3` header; delete everything else in the 1,855-line file:

```
RESUMABLE_SEAL_PHASES        CustodyAction                 CustodyOperationError
CustodyOperationRepository   CustodyOperationRepositoryProtocol
DispositionCustodyOperation  ExternalReadOnlyPostureAdapter  LocalImmutablePostureAdapter
LocalImmutablePostureProtocol  ObjectCustodyCommand         RecoveryCustodyOperation
SealCommand                  SealCustodyOperation          public_operation
```
(Note `CustodyOperationPhase` is a supporting enum behind `RESUMABLE_SEAL_PHASES`; keep it too or
inline the phase values.)

**Also delete** `packages/sift-gateway/tests/test_custody_operations.py` WITH the file — CP2A's
`test_cp2a_unit.py` + `test_cp2a_custody_postgres.py` replace its custody-mutation coverage.
Deleted-test mapping: its seal/disposition/recovery/posture-adapter cases are superseded by the
CP2A composed matrix (EC-6 seal, §4 retry, EC-2, D2 window, TOCTOU) + the CP1 gate/RPC contract
tests; its delete-broker case (`/usr/local/sbin/ln` helper) is superseded by §4 below.

**Gateway-code delete-broker remnant** removed with this gut: `custody_operations.py`
`LocalCustodyDeleteBroker` + `_HELPER = "/usr/local/sbin/ln"` (delete-broker client).

---

## 2. delete-broker — DEFER FULL removal to CP3 (against the actual fast-reset VM install)

The broker is the `ln`-aliased no-arg sudo-transition helper. It is NOT importer-free — it is
wired through the installer stack and guarded by fail-on-revert contract tests.

**Files to delete:**
- `scripts/setup-custody-delete-broker.sh`
- `scripts/sift-custody-delete-broker`
- `configs/apparmor/sift-custody-delete-broker.template`
- (`scripts/ln` and `configs/apparmor/ln.template` are referenced by the contract test but DO NOT
  exist on this branch — the helper is installed AS `/usr/local/sbin/ln` by the setup script whose
  `HELPER_SRC=.../ln`. Re-verify presence at CP3.)

**Installer scrub sites (must land in lockstep):**
- `install.sh:274` `configure_custody_delete_broker` · `install.sh:290` `provision_custody_delete_broker`
- `lib/migrations.sh:305` `_custody_delete_broker_scope_valid`, `:338` `provision_custody_delete_broker`
  (+ its refs to the `sift_custody_delete_broker` DB role and `custody_delete_broker_receipts` table, ~305–351)
- `lib/hardening.sh` — the `ln` AppArmor profile wiring (`profile_src=configs/apparmor/ln.template`,
  `profile_dst=/etc/apparmor.d/ln`, the `aa-status | grep -Fq 'ln'` gate, `--helper-src .../scripts/ln`)
- `scripts/uninstall.sh` — remove the `/etc/apparmor.d/ln`, `/etc/sudoers.d/ln`, `/usr/local/sbin/ln` cleanup lines

**Contract tests:**
- delete `tests/test_custody_delete_broker_contract.py` (fail-on-revert asserting the broker EXISTS)
- scrub `tests/test_greenfield_uninstall_contract.py` (asserts `/etc/apparmor.d/ln` is in the uninstall section)

**⚠ CRITICAL LIVE-INSTALL LANDMINE:** CP1 already DELETED the broker's DB migration
`202607145200_custody_delete_broker_receipts.sql`. So `provision_custody_delete_broker` in
`lib/migrations.sh` now provisions a role/scope (`sift_custody_delete_broker`) bound to a
`custody_delete_broker_receipts` table the migration chain **no longer creates**. At the CP3
fresh / fast-reset VM install, if `install.sh` still calls `provision_custody_delete_broker`, it
can FAIL exactly like the P0 superuser-migration failure. **Root MUST scrub the installer broker
provisioning in lockstep with (or before) the next fresh install** — this is not optional cleanup.

**I6 overlap:** OPERATING-MODEL §3 routes installer/config deletion to I6 (identity phase). Root
decides CP3-vs-I6 for the installer scrub, BUT the migration-already-deleted landmine forces it no
later than the next fresh install.

---

## 3. sift-core external-storage — DEFER ALL to CP3; per-symbol split below

Owned files: `packages/sift-core/src/sift_core/evidence_storage.py`,
`.../execute/evidence_binding.py`, `.../execute/run_command_job.py`.

**Why defer everything now:** while `custody_operations.py` (kept per direction B) and
`portal_services.py` (CP2B) are intact, they import `StorageProfile` AND `external_storage_facts`
(custody_operations imports the latter — its test monkeypatches
`sift_gateway.custody_operations.external_storage_facts`), which drives the mount branches. So the
external code is NOT dead yet. It becomes dead only after custody_operations is gone (§1) and
portal_services + custody_drift are rewritten off external storage.

**MUST SURVIVE (LOCAL_IMMUTABLE core — live/other-lane importers):**
- `evidence_binding.py`: `classify_inventory_entries`, `AdmittedEvidenceBinding`, `validate_binding_fd`
  — **admission.py (CP1) imports the first two**; the local reconcile/pinning path.
- `evidence_storage.py`: `StorageProfile` (imported by admission-adjacent custody_drift +
  custody_operations + portal_services + run_command_job + evidence_binding),
  `MountedEvidence`, `InventorySnapshot`, `StorageAvailability`, `classify_inventory`
  (portal_services + custody_drift + **admission.py**). `StorageProfile.LOCAL_IMMUTABLE` is the
  surviving value; after external storage is gone, StorageProfile may collapse to a single-value
  enum — root's call at CP3, keep the enum shape if any consumer still switches on it.

**DEAD external/mount branches to DELETE at CP3** (no importer outside evidence_storage.py; reached
only via `external_storage_facts()` ← the soon-deleted custody_operations + soon-rewritten
portal_services):
- `evidence_storage.py`: `_request_host_mount_observation` (@~426, the dormant client the brief
  tagged at :434), `host_mount_observation`, `HostMountObservation`, `ExternalStorageFacts`,
  `ExternalReadOnlyStorage`, `mount_for_fd`, `_stable_mount_for`, `MountInfo`, `parse_mountinfo`,
  `parse_fd_mount_id`, `_unique_mount_id_for_fd`, `_StatxTimestamp`/`_Statx`, `_boot_identity`,
  `_observer_peer_credentials`, `StorageAuthorityError`, the external arm of
  `external_storage_facts`, the external `PinnedEvidenceFacts` fields, and the `_MOUNT_*` /
  `_SUPPORTED_EXTERNAL_FILESYSTEMS` module constants.
- `evidence_binding.py`: the `elif profile == StorageProfile.EXTERNALLY_READ_ONLY:` arms.
- `run_command_job.py`: the `EXTERNALLY_READ_ONLY` arms (keep the LOCAL_IMMUTABLE path — imported by
  mcp_server / policy_middleware / job_tools / agent_tools / discovery / job_worker_cli).
- also delete `mount_observer.py` if still present (CP1 was to remove it with external storage).

**Tombstone-vs-delete rule (restate for root):** a symbol still imported by a CP2B-owned or CP1
file → tombstone/keep until that file is rewritten; a symbol whose importers are all in the owned
3-file set (or gone) → delete outright.

---

## 4. Absence tests root must ADD at CP3 (§9, fail-on-revert / cheap)

- **Broker files absent:** `scripts/setup-custody-delete-broker.sh`,
  `scripts/sift-custody-delete-broker`, `configs/apparmor/sift-custody-delete-broker.template`.
- **Broker installer refs absent:** no `configure_custody_delete_broker` /
  `provision_custody_delete_broker` in `install.sh`; no `provision_custody_delete_broker` /
  `custody_delete_broker_receipts` in `lib/migrations.sh`; no `ln` profile wiring in
  `lib/hardening.sh`; no `/etc/apparmor.d/ln|/etc/sudoers.d/ln|/usr/local/sbin/ln` in `uninstall.sh`.
- **Broker DB role/table absent** on a fresh migrated DB: no `sift_custody_delete_broker` role, no
  `app.custody_delete_broker_receipts` table.
- **custody_operations gone/inert:** the file is deleted (or the 14 tombstone symbols raise on any
  custody MUTATION); no `from sift_gateway.custody_operations import` remains in portal_services.
- **Removed workflow routes 404:** Replace/Reacquire, Restore-Exact, Delete-Stray, signing-rotation
  (SPEC Out of Scope).
- **sift-core external-storage gone:** `host_mount_observation` / `_request_host_mount_observation` /
  `ExternalReadOnlyStorage` / `mount_for_fd` / `HostMountObservation` unimportable from
  `sift_core.evidence_storage`; no `EXTERNALLY_READ_ONLY` branch in evidence_binding/run_command_job.
- **Survivor guard (must NOT be deleted):** `classify_inventory_entries` + `AdmittedEvidenceBinding`
  still importable from `sift_core.execute.evidence_binding`; admission.py still imports them.
