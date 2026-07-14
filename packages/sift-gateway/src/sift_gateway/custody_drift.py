"""Pure, path-free evidence inventory drift classification.

The scanner and Postgres repository deliberately live outside this module. Callers
provide server-resolved facts; the classifier returns deterministic gate facts and
never performs filesystem, database, Portal, or MCP work.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import StrEnum

_OPAQUE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_INVENTORY_DEPTH = 64


class CustodyGateState(StrEnum):
    OPEN = "OPEN"
    BLOCKED_PENDING = "BLOCKED_PENDING"
    BLOCKED_VIOLATION = "BLOCKED_VIOLATION"
    BLOCKED_UNAVAILABLE = "BLOCKED_UNAVAILABLE"


class StorageAvailability(StrEnum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    SCAN_FAILED = "SCAN_FAILED"


class StorageProfile(StrEnum):
    LOCAL_IMMUTABLE = "LOCAL_IMMUTABLE"
    EXTERNALLY_READ_ONLY = "EXTERNALLY_READ_ONLY"


class EntryKind(StrEnum):
    REGULAR = "REGULAR"
    DIRECTORY = "DIRECTORY"
    SYMLINK = "SYMLINK"
    OTHER = "OTHER"


class DriftCode(StrEnum):
    STORAGE_UNAVAILABLE = "STORAGE_UNAVAILABLE"
    INVENTORY_SCAN_FAILED = "INVENTORY_SCAN_FAILED"
    MOUNT_IDENTITY_CHANGED = "MOUNT_IDENTITY_CHANGED"
    LEDGER_INVALID = "LEDGER_INVALID"
    CONFLICTING_AUTHORITY = "CONFLICTING_AUTHORITY"
    CONFLICTING_OBSERVATION = "CONFLICTING_OBSERVATION"
    UNKNOWN_OBJECT_BINDING = "UNKNOWN_OBJECT_BINDING"
    DETECTED_NEW_ITEM = "DETECTED_NEW_ITEM"
    UNSAFE_PENDING_ITEM = "UNSAFE_PENDING_ITEM"
    SEALED_EVIDENCE_MISSING = "SEALED_EVIDENCE_MISSING"
    UNSAFE_SEALED_ENTRY = "UNSAFE_SEALED_ENTRY"
    CONTENT_CHANGED = "CONTENT_CHANGED"
    IDENTITY_CHANGED = "IDENTITY_CHANGED"
    FULL_VERIFY_REQUIRED = "FULL_VERIFY_REQUIRED"
    POSTURE_DRIFT = "POSTURE_DRIFT"
    PERSISTED_VIOLATION = "PERSISTED_VIOLATION"


class RecoveryRequirement(StrEnum):
    INVESTIGATE_AVAILABILITY = "INVESTIGATE_AVAILABILITY"
    RECONNECT_AND_VERIFY = "RECONNECT_AND_VERIFY"
    REPAIR_LEDGER = "REPAIR_LEDGER"
    OPERATOR_DISPOSITION = "OPERATOR_DISPOSITION"
    RESTORE_REACQUIRE_RETIRE = "RESTORE_REACQUIRE_RETIRE"
    FULL_VERIFY_AND_REPAIR = "FULL_VERIFY_AND_REPAIR"


@dataclass(frozen=True, slots=True)
class FileIdentity:
    """Cheap descriptor identity; it contains no pathname or evidence bytes."""

    device: int
    inode: int
    byte_count: int
    mtime_ns: int
    ctime_ns: int
    link_count: int

    def __post_init__(self) -> None:
        for name in ("device", "inode", "byte_count", "mtime_ns", "ctime_ns"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be non-negative")
        if (
            not isinstance(self.link_count, int)
            or isinstance(self.link_count, bool)
            or self.link_count < 1
        ):
            raise ValueError("link_count must be positive")


@dataclass(frozen=True, slots=True)
class AuthorityEvidence:
    evidence_object_id: str
    sha256: str
    byte_count: int
    storage_profile: StorageProfile
    identity: FileIdentity | None = None
    mount_identity: str | None = None

    def __post_init__(self) -> None:
        _validate_opaque_id("evidence_object_id", self.evidence_object_id)
        _validate_sha256(self.sha256)
        if (
            not isinstance(self.byte_count, int)
            or isinstance(self.byte_count, bool)
            or self.byte_count < 0
        ):
            raise ValueError("byte_count must be non-negative")
        if not isinstance(self.storage_profile, StorageProfile):
            raise ValueError("storage_profile must use the closed vocabulary")
        if self.identity is not None and not isinstance(self.identity, FileIdentity):
            raise ValueError("identity must use FileIdentity")
        if self.identity is not None and self.identity.byte_count != self.byte_count:
            raise ValueError("authority identity byte count must match authority bytes")
        if self.mount_identity is not None:
            _validate_opaque_id("mount_identity", self.mount_identity)
        if (
            self.storage_profile is StorageProfile.LOCAL_IMMUTABLE
            and self.mount_identity is not None
        ):
            raise ValueError("local immutable authority cannot carry mount identity")
        if self.storage_profile is StorageProfile.EXTERNALLY_READ_ONLY:
            _validate_opaque_id("mount_identity", self.mount_identity)


@dataclass(frozen=True, slots=True)
class MountedEvidence:
    """One scanner observation, identified without exposing a filesystem path."""

    observation_id: str
    evidence_object_id: str | None
    entry_kind: EntryKind
    identity: FileIdentity | None = None
    byte_count: int | None = None
    sha256: str | None = None
    immutable: bool | None = None
    read_only: bool | None = None
    mount_identity: str | None = None
    depth: int = 1
    hidden: bool = False

    def __post_init__(self) -> None:
        _validate_opaque_id("observation_id", self.observation_id)
        if self.evidence_object_id is not None:
            _validate_opaque_id("evidence_object_id", self.evidence_object_id)
        if not isinstance(self.entry_kind, EntryKind):
            raise ValueError("entry_kind must use the closed vocabulary")
        if self.identity is not None and not isinstance(self.identity, FileIdentity):
            raise ValueError("identity must use FileIdentity")
        if self.byte_count is not None:
            if (
                not isinstance(self.byte_count, int)
                or isinstance(self.byte_count, bool)
                or self.byte_count < 0
            ):
                raise ValueError("byte_count must be non-negative")
            if self.identity is not None and self.identity.byte_count != self.byte_count:
                raise ValueError("observed byte counts must agree")
        if self.sha256 is not None:
            _validate_sha256(self.sha256)
        if self.mount_identity is not None:
            _validate_opaque_id("mount_identity", self.mount_identity)
        for name in ("immutable", "read_only"):
            value = getattr(self, name)
            if value is not None and type(value) is not bool:
                raise ValueError(f"{name} must be a boolean when supplied")
        if type(self.hidden) is not bool:
            raise ValueError("hidden must be a boolean")
        if (
            not isinstance(self.depth, int)
            or isinstance(self.depth, bool)
            or not 1 <= self.depth <= _MAX_INVENTORY_DEPTH
        ):
            raise ValueError("depth must be an integer from 1 to 64")

    @property
    def observed_byte_count(self) -> int | None:
        return self.identity.byte_count if self.identity is not None else self.byte_count

    @property
    def unsafe_shape(self) -> bool:
        return (
            self.entry_kind is not EntryKind.REGULAR
            or self.depth != 1
            or (self.identity is not None and self.identity.link_count != 1)
        )


@dataclass(frozen=True, slots=True)
class InventorySnapshot:
    availability: StorageAvailability
    expected: tuple[AuthorityEvidence, ...] = ()
    observed: tuple[MountedEvidence, ...] = ()
    ledger_valid: bool = True
    persisted_violation_object_ids: tuple[str, ...] = ()
    persisted_head_violation: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.availability, StorageAvailability):
            raise ValueError("availability must use the closed vocabulary")
        if not isinstance(self.expected, tuple) or not isinstance(self.observed, tuple):
            raise ValueError("inventory facts must be immutable tuples")
        if not all(isinstance(item, AuthorityEvidence) for item in self.expected):
            raise ValueError("expected must contain authority evidence facts")
        if not all(isinstance(item, MountedEvidence) for item in self.observed):
            raise ValueError("observed must contain mounted evidence facts")
        if type(self.ledger_valid) is not bool:
            raise ValueError("ledger_valid must be a boolean")
        if not isinstance(self.persisted_violation_object_ids, tuple):
            raise ValueError("persisted violation object ids must be an immutable tuple")
        for object_id in self.persisted_violation_object_ids:
            _validate_opaque_id("persisted_violation_object_id", object_id)
        if type(self.persisted_head_violation) is not bool:
            raise ValueError("persisted_head_violation must be a boolean")


@dataclass(frozen=True, slots=True)
class DriftFinding:
    code: DriftCode
    gate_state: CustodyGateState
    recovery: RecoveryRequirement
    evidence_object_id: str | None = None
    observation_id: str | None = None
    full_verification_required: bool = False
    # Classification is read-only and can never authorize a version mutation.
    authorizes_new_version: bool = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class InventoryClassification:
    gate_state: CustodyGateState
    findings: tuple[DriftFinding, ...]


def classify_inventory(snapshot: InventorySnapshot) -> InventoryClassification:
    """Classify already-resolved facts without consulting ambient authority."""
    findings: list[DriftFinding] = []
    persisted_ids = tuple(sorted(set(snapshot.persisted_violation_object_ids)))
    for object_id in persisted_ids:
        findings.append(
            _finding(
                DriftCode.PERSISTED_VIOLATION,
                CustodyGateState.BLOCKED_VIOLATION,
                evidence_object_id=object_id,
            )
        )
    if snapshot.persisted_head_violation and not persisted_ids:
        findings.append(
            _finding(
                DriftCode.PERSISTED_VIOLATION,
                CustodyGateState.BLOCKED_VIOLATION,
            )
        )
    if snapshot.availability is not StorageAvailability.AVAILABLE:
        code = (
            DriftCode.INVENTORY_SCAN_FAILED
            if snapshot.availability is StorageAvailability.SCAN_FAILED
            else DriftCode.STORAGE_UNAVAILABLE
        )
        findings.append(
            _finding(
                code,
                CustodyGateState.BLOCKED_UNAVAILABLE,
                RecoveryRequirement.INVESTIGATE_AVAILABILITY,
            )
        )
        if not snapshot.ledger_valid:
            findings.append(
                _finding(
                    DriftCode.LEDGER_INVALID,
                    CustodyGateState.BLOCKED_VIOLATION,
                    RecoveryRequirement.REPAIR_LEDGER,
                )
            )
        return _result(tuple(findings))
    if not snapshot.ledger_valid:
        return _result(
            (
                _finding(
                    DriftCode.LEDGER_INVALID,
                    CustodyGateState.BLOCKED_VIOLATION,
                    RecoveryRequirement.REPAIR_LEDGER,
                ),
            )
        )

    expected_by_object: dict[str, AuthorityEvidence] = {}
    conflicting_authority: set[str] = set()
    for item in snapshot.expected:
        prior = expected_by_object.get(item.evidence_object_id)
        if prior is not None and prior != item:
            conflicting_authority.add(item.evidence_object_id)
        else:
            expected_by_object[item.evidence_object_id] = item

    unique_observations = set(snapshot.observed)
    observations_by_id: dict[str, set[MountedEvidence]] = defaultdict(set)
    for item in unique_observations:
        observations_by_id[item.observation_id].add(item)
    conflicting_observation_ids = {
        observation_id
        for observation_id, items in observations_by_id.items()
        if len(items) > 1
    }

    conflicting_bound_ids: set[str] = set()
    for observation_id in sorted(conflicting_observation_ids):
        items = observations_by_id[observation_id]
        object_ids = {
            item.evidence_object_id
            for item in items
            if item.evidence_object_id is not None
        }
        conflicting_bound_ids.update(object_ids)
        findings.append(
            _finding(
                DriftCode.CONFLICTING_OBSERVATION,
                CustodyGateState.BLOCKED_VIOLATION,
                evidence_object_id=next(iter(object_ids)) if len(object_ids) == 1 else None,
                observation_id=observation_id,
            )
        )

    bound: dict[str, list[MountedEvidence]] = defaultdict(list)
    for item in unique_observations:
        if item.observation_id in conflicting_observation_ids:
            continue
        if item.evidence_object_id is None:
            findings.append(_classify_pending(item))
        else:
            bound[item.evidence_object_id].append(item)

    for object_id in sorted(conflicting_authority):
        findings.append(
            _finding(
                DriftCode.CONFLICTING_AUTHORITY,
                CustodyGateState.BLOCKED_VIOLATION,
                evidence_object_id=object_id,
            )
        )

    for object_id, observations in sorted(bound.items()):
        if object_id not in expected_by_object:
            findings.append(
                _finding(
                    DriftCode.UNKNOWN_OBJECT_BINDING,
                    CustodyGateState.BLOCKED_VIOLATION,
                    evidence_object_id=object_id,
                    observation_id=observations[0].observation_id,
                )
            )
            continue
        if len(observations) != 1:
            findings.append(
                _finding(
                    DriftCode.CONFLICTING_OBSERVATION,
                    CustodyGateState.BLOCKED_VIOLATION,
                    evidence_object_id=object_id,
                )
            )
            continue
        if object_id not in conflicting_authority:
            finding = _classify_bound(expected_by_object[object_id], observations[0])
            if finding is not None:
                findings.append(finding)

    for object_id in sorted(expected_by_object):
        if (
            object_id not in bound
            and object_id not in conflicting_authority
            and object_id not in conflicting_bound_ids
        ):
            findings.append(
                _finding(
                    DriftCode.SEALED_EVIDENCE_MISSING,
                    CustodyGateState.BLOCKED_VIOLATION,
                    evidence_object_id=object_id,
                )
            )

    return _result(tuple(findings))


def _classify_pending(item: MountedEvidence) -> DriftFinding:
    return _finding(
        DriftCode.UNSAFE_PENDING_ITEM if item.unsafe_shape else DriftCode.DETECTED_NEW_ITEM,
        CustodyGateState.BLOCKED_PENDING,
        RecoveryRequirement.OPERATOR_DISPOSITION,
        observation_id=item.observation_id,
    )


def _classify_bound(
    expected: AuthorityEvidence, observed: MountedEvidence
) -> DriftFinding | None:
    object_id = expected.evidence_object_id
    observation_id = observed.observation_id
    if expected.storage_profile is StorageProfile.LOCAL_IMMUTABLE and (
        observed.mount_identity is not None or observed.read_only is not None
    ):
        raise ValueError("local immutable observation cannot carry external facts")
    if (
        expected.storage_profile is StorageProfile.EXTERNALLY_READ_ONLY
        and observed.immutable is not None
    ):
        raise ValueError("external observation cannot carry local immutable facts")
    if observed.unsafe_shape:
        return _finding(
            DriftCode.UNSAFE_SEALED_ENTRY,
            CustodyGateState.BLOCKED_VIOLATION,
            evidence_object_id=object_id,
            observation_id=observation_id,
        )
    if (
        expected.storage_profile is StorageProfile.EXTERNALLY_READ_ONLY
        and observed.mount_identity != expected.mount_identity
    ):
        return _finding(
            DriftCode.MOUNT_IDENTITY_CHANGED,
            CustodyGateState.BLOCKED_UNAVAILABLE,
            RecoveryRequirement.RECONNECT_AND_VERIFY,
            evidence_object_id=object_id,
            observation_id=observation_id,
            full_verification_required=True,
        )
    if (
        observed.observed_byte_count is not None
        and observed.observed_byte_count != expected.byte_count
    ) or (observed.sha256 is not None and observed.sha256 != expected.sha256):
        return _finding(
            DriftCode.CONTENT_CHANGED,
            CustodyGateState.BLOCKED_VIOLATION,
            evidence_object_id=object_id,
            observation_id=observation_id,
        )
    if (expected.identity is not None and observed.identity is None) or (
        expected.identity is None and observed.sha256 is None
    ):
        return _finding(
            DriftCode.FULL_VERIFY_REQUIRED,
            CustodyGateState.BLOCKED_VIOLATION,
            RecoveryRequirement.FULL_VERIFY_AND_REPAIR,
            evidence_object_id=object_id,
            observation_id=observation_id,
            full_verification_required=True,
        )
    if (
        expected.identity is not None
        and observed.identity is not None
        and observed.identity != expected.identity
    ):
        stable_except_ctime = (
            observed.identity.device == expected.identity.device
            and observed.identity.inode == expected.identity.inode
            and observed.identity.byte_count == expected.identity.byte_count
            and observed.identity.mtime_ns == expected.identity.mtime_ns
            and observed.identity.link_count == expected.identity.link_count
        )
        if stable_except_ctime and observed.sha256 == expected.sha256:
            code = DriftCode.POSTURE_DRIFT
        elif observed.sha256 == expected.sha256:
            code = DriftCode.IDENTITY_CHANGED
        else:
            code = DriftCode.FULL_VERIFY_REQUIRED
        return _finding(
            code,
            CustodyGateState.BLOCKED_VIOLATION,
            RecoveryRequirement.FULL_VERIFY_AND_REPAIR,
            evidence_object_id=object_id,
            observation_id=observation_id,
            full_verification_required=True,
        )

    posture_ok = (
        observed.immutable is True
        if expected.storage_profile is StorageProfile.LOCAL_IMMUTABLE
        else observed.read_only is True
    )
    if not posture_ok:
        full_hash_matches = observed.sha256 == expected.sha256
        return _finding(
            DriftCode.POSTURE_DRIFT if full_hash_matches else DriftCode.FULL_VERIFY_REQUIRED,
            CustodyGateState.BLOCKED_VIOLATION,
            RecoveryRequirement.FULL_VERIFY_AND_REPAIR,
            evidence_object_id=object_id,
            observation_id=observation_id,
            full_verification_required=True,
        )
    return None


def _finding(
    code: DriftCode,
    gate_state: CustodyGateState,
    recovery: RecoveryRequirement = RecoveryRequirement.RESTORE_REACQUIRE_RETIRE,
    *,
    evidence_object_id: str | None = None,
    observation_id: str | None = None,
    full_verification_required: bool = False,
) -> DriftFinding:
    return DriftFinding(
        code=code,
        gate_state=gate_state,
        recovery=recovery,
        evidence_object_id=evidence_object_id,
        observation_id=observation_id,
        full_verification_required=full_verification_required,
    )


def _result(findings: tuple[DriftFinding, ...]) -> InventoryClassification:
    unique = sorted(
        set(findings),
        key=lambda item: (
            item.observation_id or "",
            item.evidence_object_id or "",
            item.code.value,
        ),
    )
    priorities = {
        CustodyGateState.OPEN: 0,
        CustodyGateState.BLOCKED_PENDING: 1,
        CustodyGateState.BLOCKED_VIOLATION: 2,
        CustodyGateState.BLOCKED_UNAVAILABLE: 3,
    }
    gate_state = max(
        (item.gate_state for item in unique),
        key=priorities.__getitem__,
        default=CustodyGateState.OPEN,
    )
    return InventoryClassification(gate_state=gate_state, findings=tuple(unique))


def _validate_opaque_id(name: str, value: str | None) -> None:
    if value is None or not isinstance(value, str) or _OPAQUE_ID.fullmatch(value) is None:
        raise ValueError(f"{name} must be a bounded opaque identifier")


def _validate_sha256(value: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError("sha256 must be a lowercase hexadecimal SHA-256 digest")
