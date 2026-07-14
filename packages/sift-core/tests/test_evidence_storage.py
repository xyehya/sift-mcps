from __future__ import annotations

import os

import pytest
from sift_core.evidence_storage import (
    StorageAuthorityError,
    external_storage_facts,
    mount_for_fd,
    parse_fd_mount_id,
    parse_mountinfo,
)

MOUNTINFO = "36 25 0:32 /export\\040share /mnt/evidence ro,nosuid - nfs4 server:/export\\040share ro,vers=4.2\n"


def test_mountinfo_unescapes_fields_but_exposes_only_opaque_identities() -> None:
    row = parse_mountinfo(MOUNTINFO)[0]
    assert row.root == "/export share"
    assert row.mount_point == "/mnt/evidence"
    assert len(row.source_identity) == 64
    assert len(row.mount_instance_identity) == 64
    assert "server" not in row.source_identity


def test_source_identity_survives_reconnect_but_mount_instance_changes() -> None:
    first = parse_mountinfo(MOUNTINFO)[0]
    second = parse_mountinfo(
        "48 25 0:99 /export\\040share /mnt/evidence ro,nosuid - nfs4 "
        "server:/export\\040share ro,vers=4.2\n"
    )[0]
    assert first.source_identity == second.source_identity
    assert first.mount_instance_identity != second.mount_instance_identity


def test_same_path_different_source_changes_stable_identity() -> None:
    first = parse_mountinfo(MOUNTINFO)[0]
    replacement = parse_mountinfo(
        "36 25 0:32 /other /mnt/evidence ro,nosuid - nfs4 attacker:/other ro,vers=4.2\n"
    )[0]
    assert first.mount_point == replacement.mount_point
    assert first.source_identity != replacement.source_identity


@pytest.mark.parametrize(
    "payload",
    [
        "",
        "36 25 0:32 / /mnt ro nfs source ro",
        "x 25 0:32 / /mnt ro - nfs source ro",
        "36 25 bad / /mnt ro - nfs source ro",
    ],
)
def test_mountinfo_malformed_rows_fail_closed(payload: str) -> None:
    with pytest.raises(StorageAuthorityError):
        parse_mountinfo(payload)


def test_mountinfo_duplicate_mount_id_fails_closed() -> None:
    with pytest.raises(StorageAuthorityError, match="duplicated"):
        parse_mountinfo(MOUNTINFO + MOUNTINFO)


@pytest.mark.parametrize(
    "escape",
    [r"\\777", r"\\000", r"\\xyz", "\\", r"\\1", r"\\12", r"\\134\\"],
)
def test_mountinfo_unknown_escape_fails_closed(escape: str) -> None:
    with pytest.raises(StorageAuthorityError, match="escape"):
        parse_mountinfo(
            f"36 25 0:32 /export{escape}share /mnt ro - nfs4 server:/export ro\n"
        )


@pytest.mark.parametrize(
    "payload", ["pos:\t0\n", "mnt_id:\t\n", "mnt_id:\t3\nmnt_id:\t4\n", "mnt_id:\tx\n"]
)
def test_fd_mount_id_missing_or_ambiguous_fails_closed(payload: str) -> None:
    with pytest.raises(StorageAuthorityError):
        parse_fd_mount_id(payload)


def test_fd_mount_id_must_match_exactly_one_mount() -> None:
    with pytest.raises(StorageAuthorityError, match="missing or ambiguous"):
        mount_for_fd(7, fdinfo_text="mnt_id:\t99\n", mountinfo_text=MOUNTINFO)


def test_external_read_only_requires_mountinfo_and_statvfs_agreement() -> None:
    facts = external_storage_facts(
        7,
        fdinfo_text="mnt_id:\t36\n",
        mountinfo_text=MOUNTINFO,
        statvfs_flags=getattr(os, "ST_RDONLY", 1),
        descriptor_flags=os.O_RDONLY,
        unique_mount_id=9001,
    )
    assert facts.read_only is True
    with pytest.raises(StorageAuthorityError, match="consistently read-only"):
        external_storage_facts(
            7,
            fdinfo_text="mnt_id:\t36\n",
            mountinfo_text=MOUNTINFO,
            statvfs_flags=0,
            descriptor_flags=os.O_RDONLY,
            unique_mount_id=9001,
        )


def test_unsupported_external_filesystem_fails_closed() -> None:
    overlay = "36 25 0:32 / /mnt/evidence ro - overlay overlay ro\n"
    with pytest.raises(StorageAuthorityError, match="unsupported"):
        external_storage_facts(
            7,
            fdinfo_text="mnt_id:\t36\n",
            mountinfo_text=overlay,
            statvfs_flags=getattr(os, "ST_RDONLY", 1),
            descriptor_flags=os.O_RDONLY,
            unique_mount_id=9001,
        )
