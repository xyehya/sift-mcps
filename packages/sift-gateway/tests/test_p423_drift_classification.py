from sift_gateway.custody_drift import (
    AuthorityEvidence,
    CustodyGateState,
    DriftCode,
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


def test_scan_failure_is_unavailable_not_a_tamper_accusation() -> None:
    result = classify_inventory(
        InventorySnapshot(
            availability=StorageAvailability.SCAN_FAILED,
            expected=(_sealed_local(),),
        )
    )

    assert result.gate_state is CustodyGateState.BLOCKED_UNAVAILABLE
    assert result.findings[0].code is DriftCode.INVENTORY_SCAN_FAILED


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
    try:
        _mounted(observation_id="evidence/secret.E01")
    except ValueError as exc:
        assert str(exc) == "observation_id must be a bounded opaque identifier"
    else:
        raise AssertionError("path-shaped observation identifier was accepted")
