import pytest
from sift_gateway.custody_drift import (
    AuthorityEvidence,
    CustodyGateState,
    DriftCode,
    DriftFinding,
    EntryKind,
    FileIdentity,
    InventorySnapshot,
    MountedEvidence,
    RecoveryRequirement,
    StorageAvailability,
    StorageProfile,
    classify_inventory,
)

LOCAL_IDENTITY = FileIdentity(
    device=11,
    inode=22,
    byte_count=4096,
    mtime_ns=33,
    ctime_ns=44,
    link_count=1,
)


def _sealed_local(**changes: object) -> AuthorityEvidence:
    values: dict[str, object] = {
        "evidence_object_id": "object-1",
        "sha256": "a" * 64,
        "byte_count": 4096,
        "storage_profile": StorageProfile.LOCAL_IMMUTABLE,
        "identity": LOCAL_IDENTITY,
    }
    values.update(changes)
    return AuthorityEvidence(**values)  # type: ignore[arg-type]


def _mounted(**changes: object) -> MountedEvidence:
    values: dict[str, object] = {
        "observation_id": "observation-1",
        "evidence_object_id": "object-1",
        "entry_kind": EntryKind.REGULAR,
        "identity": LOCAL_IDENTITY,
        "sha256": "a" * 64,
        "immutable": True,
    }
    values.update(changes)
    return MountedEvidence(**values)  # type: ignore[arg-type]


def test_unavailable_storage_is_not_misclassified_as_missing_evidence() -> None:
    result = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.UNAVAILABLE,
            expected=(
                AuthorityEvidence(
                    evidence_object_id="object-1",
                    sha256="a" * 64,
                    byte_count=4096,
                    storage_profile=StorageProfile.EXTERNALLY_READ_ONLY,
                    mount_identity="mount-a",
                ),
            ),
        )
    )

    assert result.gate_state is CustodyGateState.BLOCKED_UNAVAILABLE
    assert [finding.code for finding in result.findings] == ["STORAGE_UNAVAILABLE"]
    assert result.findings[0].evidence_object_id is None
    assert (
        result.findings[0].recovery
        is RecoveryRequirement.INVESTIGATE_AVAILABILITY
    )


def test_scan_failure_is_unavailable_not_a_tamper_accusation() -> None:
    result = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.SCAN_FAILED,
            expected=(_sealed_local(),),
        )
    )

    assert result.gate_state is CustodyGateState.BLOCKED_UNAVAILABLE
    assert result.findings[0].code is DriftCode.INVENTORY_SCAN_FAILED
    assert (
        result.findings[0].recovery
        is RecoveryRequirement.INVESTIGATE_AVAILABILITY
    )


def test_new_and_structurally_unsafe_items_remain_pending_not_violations() -> None:
    observed = (
        _mounted(
            observation_id="regular",
            evidence_object_id=None,
            sha256=None,
            immutable=None,
        ),
        _mounted(
            observation_id="hidden",
            evidence_object_id=None,
            hidden=True,
            sha256=None,
            immutable=None,
        ),
        _mounted(
            observation_id="nested",
            evidence_object_id=None,
            depth=2,
            sha256=None,
            immutable=None,
        ),
        _mounted(
            observation_id="symlink",
            evidence_object_id=None,
            entry_kind=EntryKind.SYMLINK,
            identity=None,
            sha256=None,
            immutable=None,
        ),
        _mounted(
            observation_id="hardlink",
            evidence_object_id=None,
            identity=FileIdentity(
                device=11,
                inode=99,
                byte_count=1,
                mtime_ns=33,
                ctime_ns=44,
                link_count=2,
            ),
            sha256=None,
            immutable=None,
        ),
    )

    result = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            observed=observed,
        )
    )

    assert result.gate_state is CustodyGateState.BLOCKED_PENDING
    assert [(item.observation_id, item.code) for item in result.findings] == [
        ("hardlink", DriftCode.UNSAFE_PENDING_ITEM),
        ("hidden", DriftCode.DETECTED_NEW_ITEM),
        ("nested", DriftCode.UNSAFE_PENDING_ITEM),
        ("regular", DriftCode.DETECTED_NEW_ITEM),
        ("symlink", DriftCode.UNSAFE_PENDING_ITEM),
    ]
    assert all(
        item.recovery is RecoveryRequirement.OPERATOR_DISPOSITION
        for item in result.findings
    )


def test_missing_sealed_item_on_available_storage_is_a_violation() -> None:
    result = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            expected=(_sealed_local(),),
        )
    )

    assert result.gate_state is CustodyGateState.BLOCKED_VIOLATION
    assert result.findings[0].code is DriftCode.SEALED_EVIDENCE_MISSING
    assert result.findings[0].recovery is RecoveryRequirement.RESTORE_REACQUIRE_RETIRE


def test_matching_bytes_identity_and_local_posture_are_open() -> None:
    result = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            expected=(_sealed_local(),),
            observed=(_mounted(),),
        )
    )

    assert result.gate_state is CustodyGateState.OPEN
    assert result.findings == ()


def test_size_and_same_size_digest_changes_are_violations() -> None:
    size_change = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            expected=(_sealed_local(),),
            observed=(
                _mounted(
                    identity=FileIdentity(
                        device=11,
                        inode=22,
                        byte_count=4097,
                        mtime_ns=33,
                        ctime_ns=45,
                        link_count=1,
                    ),
                    sha256=None,
                ),
            ),
        )
    )
    digest_change = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            expected=(_sealed_local(),),
            observed=(_mounted(sha256="b" * 64),),
        )
    )

    assert size_change.findings[0].code is DriftCode.CONTENT_CHANGED
    assert digest_change.findings[0].code is DriftCode.CONTENT_CHANGED
    assert size_change.gate_state is CustodyGateState.BLOCKED_VIOLATION
    assert digest_change.gate_state is CustodyGateState.BLOCKED_VIOLATION


def test_posture_only_requires_matching_full_hash_and_never_a_new_version() -> None:
    unverified = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            expected=(_sealed_local(),),
            observed=(_mounted(sha256=None, immutable=False),),
        )
    )
    verified = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            expected=(_sealed_local(),),
            observed=(_mounted(immutable=False),),
        )
    )

    assert unverified.findings[0].code is DriftCode.FULL_VERIFY_REQUIRED
    assert verified.findings[0].code is DriftCode.POSTURE_DRIFT
    assert verified.findings[0].full_verification_required is True
    assert verified.findings[0].authorizes_new_version is False
    assert verified.findings[0].recovery is RecoveryRequirement.FULL_VERIFY_AND_REPAIR


def test_missing_trusted_change_signal_requires_full_verification() -> None:
    result = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            expected=(_sealed_local(),),
            observed=(_mounted(identity=None, byte_count=4096, sha256=None),),
        )
    )

    assert result.gate_state is CustodyGateState.BLOCKED_VIOLATION
    assert result.findings[0].code is DriftCode.FULL_VERIFY_REQUIRED


def test_external_mount_identity_drift_is_unavailable_until_reverified() -> None:
    expected = AuthorityEvidence(
        evidence_object_id="object-1",
        sha256="a" * 64,
        byte_count=4096,
        storage_profile=StorageProfile.EXTERNALLY_READ_ONLY,
        mount_identity="mount-a",
    )
    observed = _mounted(
        identity=None,
        immutable=None,
        read_only=True,
        mount_identity="mount-b",
    )

    result = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            expected=(expected,),
            observed=(observed,),
        )
    )

    assert result.gate_state is CustodyGateState.BLOCKED_UNAVAILABLE
    assert result.findings[0].code is DriftCode.MOUNT_IDENTITY_CHANGED
    assert result.findings[0].recovery is RecoveryRequirement.RECONNECT_AND_VERIFY


def test_external_read_only_posture_drift_is_a_verified_posture_violation() -> None:
    expected = AuthorityEvidence(
        evidence_object_id="object-1",
        sha256="a" * 64,
        byte_count=4096,
        storage_profile=StorageProfile.EXTERNALLY_READ_ONLY,
        mount_identity="mount-a",
    )
    result = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            expected=(expected,),
            observed=(
                _mounted(
                    identity=None,
                    immutable=None,
                    read_only=False,
                    mount_identity="mount-a",
                ),
            ),
        )
    )

    assert result.gate_state is CustodyGateState.BLOCKED_VIOLATION
    assert result.findings[0].code is DriftCode.POSTURE_DRIFT


def test_rename_surfaces_missing_authority_and_pending_new_identity() -> None:
    result = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            expected=(_sealed_local(),),
            observed=(
                _mounted(
                    observation_id="renamed-observation",
                    evidence_object_id=None,
                    sha256="a" * 64,
                ),
            ),
        )
    )

    assert result.gate_state is CustodyGateState.BLOCKED_VIOLATION
    assert {finding.code for finding in result.findings} == {
        DriftCode.DETECTED_NEW_ITEM,
        DriftCode.SEALED_EVIDENCE_MISSING,
    }


def test_duplicate_concurrent_observations_are_idempotent_and_order_independent() -> None:
    first = _mounted(observation_id="z-observation")
    second = _mounted(
        observation_id="a-observation",
        evidence_object_id=None,
        sha256=None,
        immutable=None,
    )
    left = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            expected=(_sealed_local(),),
            observed=(first, second, first),
        )
    )
    right = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            expected=(_sealed_local(),),
            observed=(second, first),
        )
    )

    assert left == right
    assert len(left.findings) == 1
    assert left.findings[0].observation_id == "a-observation"


def test_conflicting_observations_for_one_object_fail_closed() -> None:
    result = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            expected=(_sealed_local(),),
            observed=(
                _mounted(observation_id="observation-a"),
                _mounted(observation_id="observation-b", sha256="b" * 64),
            ),
        )
    )

    assert result.gate_state is CustodyGateState.BLOCKED_VIOLATION
    assert [finding.code for finding in result.findings] == [
        DriftCode.CONFLICTING_OBSERVATION
    ]


def test_fact_identifiers_are_bounded_and_cannot_carry_paths() -> None:
    for path_shape in ("evidence/secret.E01", "C:secret", "file:secret", "https:evil"):
        with pytest.raises(
            ValueError, match="observation_id must be a bounded opaque identifier"
        ):
            _mounted(observation_id=path_shape)


@pytest.mark.parametrize("invalid", ["false", 0, 1, None])
def test_ledger_valid_requires_an_exact_boolean(invalid: object) -> None:
    with pytest.raises(ValueError, match="ledger_valid must be a boolean"):
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            ledger_valid=invalid,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("invalid", [True, False, "2", 1.5, 0, 65])
def test_inventory_depth_requires_a_bounded_non_boolean_integer(invalid: object) -> None:
    with pytest.raises(ValueError, match="depth must be an integer from 1 to 64"):
        _mounted(depth=invalid)


def test_local_authority_rejects_external_mount_identity_facts() -> None:
    with pytest.raises(
        ValueError, match="local immutable authority cannot carry mount identity"
    ):
        _sealed_local(mount_identity="mount-a")

    with pytest.raises(
        ValueError, match="local immutable observation cannot carry external facts"
    ):
        classify_inventory(
            InventorySnapshot(
                availability=StorageAvailability.AVAILABLE,
                expected=(_sealed_local(),),
                observed=(_mounted(mount_identity="mount-a"),),
            )
        )


@pytest.mark.parametrize(
    ("availability", "availability_code"),
    [
        (StorageAvailability.UNAVAILABLE, DriftCode.STORAGE_UNAVAILABLE),
        (StorageAvailability.SCAN_FAILED, DriftCode.INVENTORY_SCAN_FAILED),
    ],
)
def test_outage_preserves_independent_ledger_invalid_finding(
    availability: StorageAvailability, availability_code: DriftCode
) -> None:
    result = classify_inventory(
        InventorySnapshot(
            availability=availability,
            ledger_valid=False,
        )
    )

    assert result.gate_state is CustodyGateState.BLOCKED_UNAVAILABLE
    assert {finding.code: finding.recovery for finding in result.findings} == {
        availability_code: RecoveryRequirement.INVESTIGATE_AVAILABILITY,
        DriftCode.LEDGER_INVALID: RecoveryRequirement.REPAIR_LEDGER,
    }


def test_conflicting_duplicate_authority_fails_closed_once() -> None:
    result = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            expected=(_sealed_local(), _sealed_local(sha256="b" * 64)),
        )
    )

    assert result.gate_state is CustodyGateState.BLOCKED_VIOLATION
    assert [finding.code for finding in result.findings] == [
        DriftCode.CONFLICTING_AUTHORITY
    ]


def test_exact_duplicate_authority_is_idempotent() -> None:
    authority = _sealed_local()
    result = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            expected=(authority, authority),
            observed=(_mounted(),),
        )
    )

    assert result.gate_state is CustodyGateState.OPEN
    assert result.findings == ()


def test_same_observation_identifier_with_conflicting_facts_fails_closed_once() -> None:
    result = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            expected=(_sealed_local(),),
            observed=(_mounted(), _mounted(sha256="b" * 64)),
        )
    )

    assert result.gate_state is CustodyGateState.BLOCKED_VIOLATION
    assert [finding.code for finding in result.findings] == [
        DriftCode.CONFLICTING_OBSERVATION
    ]


def test_unknown_authority_binding_fails_closed() -> None:
    result = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            observed=(_mounted(evidence_object_id="unknown-object"),),
        )
    )

    assert result.gate_state is CustodyGateState.BLOCKED_VIOLATION
    assert result.findings[0].code is DriftCode.UNKNOWN_OBJECT_BINDING


def test_mixed_findings_retain_each_fact_and_strongest_gate() -> None:
    external = AuthorityEvidence(
        evidence_object_id="object-external",
        sha256="a" * 64,
        byte_count=4096,
        storage_profile=StorageProfile.EXTERNALLY_READ_ONLY,
        mount_identity="mount-a",
    )
    local = _sealed_local(evidence_object_id="object-local")
    result = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.AVAILABLE,
            expected=(external, local),
            observed=(
                _mounted(
                    observation_id="external-observation",
                    evidence_object_id="object-external",
                    identity=None,
                    immutable=None,
                    read_only=True,
                    mount_identity="mount-b",
                ),
                _mounted(
                    observation_id="local-observation",
                    evidence_object_id="object-local",
                    sha256="b" * 64,
                ),
                _mounted(
                    observation_id="pending-observation",
                    evidence_object_id=None,
                    sha256=None,
                    immutable=None,
                ),
            ),
        )
    )

    assert result.gate_state is CustodyGateState.BLOCKED_UNAVAILABLE
    assert {finding.code for finding in result.findings} == {
        DriftCode.MOUNT_IDENTITY_CHANGED,
        DriftCode.CONTENT_CHANGED,
        DriftCode.DETECTED_NEW_ITEM,
    }
    assert all(finding.authorizes_new_version is False for finding in result.findings)


def test_new_version_authority_cannot_be_supplied_to_a_finding() -> None:
    with pytest.raises(TypeError, match="authorizes_new_version"):
        DriftFinding(
            code=DriftCode.CONTENT_CHANGED,
            gate_state=CustodyGateState.BLOCKED_VIOLATION,
            recovery=RecoveryRequirement.RESTORE_REACQUIRE_RETIRE,
            authorizes_new_version=True,  # type: ignore[call-arg]
        )
