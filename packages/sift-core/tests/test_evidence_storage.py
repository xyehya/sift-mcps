from __future__ import annotations

import os

import pytest
from sift_core.evidence_storage import (
    ExternalReadOnlyStorage,
    ExternalStorageFacts,
    StorageAuthorityError,
    external_storage_facts,
    mount_for_fd,
    parse_fd_mount_id,
    parse_mountinfo,
)

MOUNTINFO = "36 25 0:32 /export\\040share /mnt/evidence ro,nosuid - nfs4 server:/export\\040share ro,vers=4.2\n"
HOST_MOUNTINFO = "81 25 0:32 /export\\040share /mnt/evidence ro,nosuid - nfs4 server:/export\\040share ro,vers=4.2\n"
BOOT_ID = "01234567-89ab-4cde-8fab-0123456789ab"


def test_mountinfo_unescapes_fields_but_exposes_only_opaque_identities() -> None:
    row = parse_mountinfo(MOUNTINFO)[0]
    assert row.root == "/export share"
    assert row.mount_point == "/mnt/evidence"
    assert len(row.source_identity) == 64
    assert "server" not in row.source_identity


def test_source_identity_survives_namespace_mount_clone() -> None:
    first = parse_mountinfo(MOUNTINFO)[0]
    second = parse_mountinfo(
        "48 25 0:99 /export\\040share /mnt/evidence ro,nosuid - nfs4 "
        "server:/export\\040share ro,vers=4.2\n"
    )[0]
    assert first.source_identity == second.source_identity


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
        stable_mountinfo_text=HOST_MOUNTINFO,
        stable_unique_mount_id=9001,
        boot_id=BOOT_ID,
    )
    assert facts.read_only is True
    with pytest.raises(StorageAuthorityError, match="consistently read-only"):
        external_storage_facts(
            7,
            fdinfo_text="mnt_id:\t36\n",
            mountinfo_text=MOUNTINFO,
            statvfs_flags=0,
            descriptor_flags=os.O_RDONLY,
            stable_mountinfo_text=HOST_MOUNTINFO,
            stable_unique_mount_id=9001,
            boot_id=BOOT_ID,
        )

    host_writable = HOST_MOUNTINFO.replace("ro,nosuid", "rw,nosuid").replace(
        " ro,vers=4.2", " rw,vers=4.2"
    )
    with pytest.raises(StorageAuthorityError, match="consistently read-only"):
        external_storage_facts(
            7,
            fdinfo_text="mnt_id:\t36\n",
            mountinfo_text=MOUNTINFO,
            stable_mountinfo_text=host_writable,
            stable_unique_mount_id=9001,
            boot_id=BOOT_ID,
            statvfs_flags=getattr(os, "ST_RDONLY", 1),
            descriptor_flags=os.O_RDONLY,
        )


def test_external_mount_identity_ignores_namespace_local_mount_ids() -> None:
    first = external_storage_facts(
        7,
        fdinfo_text="mnt_id:\t36\n",
        mountinfo_text=MOUNTINFO,
        stable_mountinfo_text=HOST_MOUNTINFO,
        stable_unique_mount_id=9001,
        boot_id=BOOT_ID,
        statvfs_flags=getattr(os, "ST_RDONLY", 1),
        descriptor_flags=os.O_RDONLY,
    )
    restarted_namespace = external_storage_facts(
        7,
        fdinfo_text="mnt_id:\t963\n",
        mountinfo_text=MOUNTINFO.replace("36 25", "963 901"),
        stable_mountinfo_text=HOST_MOUNTINFO,
        stable_unique_mount_id=9001,
        boot_id=BOOT_ID,
        statvfs_flags=getattr(os, "ST_RDONLY", 1),
        descriptor_flags=os.O_RDONLY,
    )

    assert restarted_namespace.source_identity == first.source_identity
    assert restarted_namespace.mount_instance_identity == first.mount_instance_identity


def test_external_mount_identity_changes_for_host_remount() -> None:
    first = external_storage_facts(
        7,
        fdinfo_text="mnt_id:\t36\n",
        mountinfo_text=MOUNTINFO,
        stable_mountinfo_text=HOST_MOUNTINFO,
        stable_unique_mount_id=9001,
        boot_id=BOOT_ID,
        statvfs_flags=getattr(os, "ST_RDONLY", 1),
        descriptor_flags=os.O_RDONLY,
    )
    remounted = external_storage_facts(
        7,
        fdinfo_text="mnt_id:\t48\n",
        mountinfo_text=MOUNTINFO.replace("36 25", "48 25"),
        stable_mountinfo_text=HOST_MOUNTINFO.replace("81 25", "104 25"),
        stable_unique_mount_id=9002,
        boot_id=BOOT_ID,
        statvfs_flags=getattr(os, "ST_RDONLY", 1),
        descriptor_flags=os.O_RDONLY,
    )

    assert remounted.source_identity == first.source_identity
    assert remounted.mount_instance_identity != first.mount_instance_identity


def test_external_mount_identity_requires_one_matching_stable_mount() -> None:
    with pytest.raises(StorageAuthorityError, match="stable mount"):
        external_storage_facts(
            7,
            fdinfo_text="mnt_id:\t36\n",
            mountinfo_text=MOUNTINFO,
            stable_mountinfo_text=HOST_MOUNTINFO.replace("/mnt/evidence", "/mnt/other"),
            stable_unique_mount_id=9001,
            boot_id=BOOT_ID,
            statvfs_flags=getattr(os, "ST_RDONLY", 1),
            descriptor_flags=os.O_RDONLY,
        )

    duplicate_match = HOST_MOUNTINFO + HOST_MOUNTINFO.replace("81 25", "82 25")
    with pytest.raises(StorageAuthorityError, match="stable mount"):
        external_storage_facts(
            7,
            fdinfo_text="mnt_id:\t36\n",
            mountinfo_text=MOUNTINFO,
            stable_mountinfo_text=duplicate_match,
            stable_unique_mount_id=9001,
            boot_id=BOOT_ID,
            statvfs_flags=getattr(os, "ST_RDONLY", 1),
            descriptor_flags=os.O_RDONLY,
        )


def test_external_mount_identity_changes_for_same_path_source_replacement() -> None:
    first = external_storage_facts(
        7,
        fdinfo_text="mnt_id:\t36\n",
        mountinfo_text=MOUNTINFO,
        stable_mountinfo_text=HOST_MOUNTINFO,
        stable_unique_mount_id=9001,
        boot_id=BOOT_ID,
        statvfs_flags=getattr(os, "ST_RDONLY", 1),
        descriptor_flags=os.O_RDONLY,
    )
    replacement_mount = (
        "48 25 0:99 /other /mnt/evidence ro,nosuid - nfs4 "
        "replacement:/other ro,vers=4.2\n"
    )
    replacement_host = replacement_mount.replace("48 25", "104 25")
    replacement = external_storage_facts(
        7,
        fdinfo_text="mnt_id:\t48\n",
        mountinfo_text=replacement_mount,
        stable_mountinfo_text=replacement_host,
        stable_unique_mount_id=9002,
        boot_id=BOOT_ID,
        statvfs_flags=getattr(os, "ST_RDONLY", 1),
        descriptor_flags=os.O_RDONLY,
    )

    assert replacement.source_identity != first.source_identity
    assert replacement.mount_instance_identity != first.mount_instance_identity


def test_external_mount_identity_changes_across_boot_epoch() -> None:
    first = external_storage_facts(
        7,
        fdinfo_text="mnt_id:\t36\n",
        mountinfo_text=MOUNTINFO,
        stable_mountinfo_text=HOST_MOUNTINFO,
        stable_unique_mount_id=9001,
        boot_id=BOOT_ID,
        statvfs_flags=getattr(os, "ST_RDONLY", 1),
        descriptor_flags=os.O_RDONLY,
    )
    rebooted = external_storage_facts(
        7,
        fdinfo_text="mnt_id:\t36\n",
        mountinfo_text=MOUNTINFO,
        stable_mountinfo_text=HOST_MOUNTINFO,
        stable_unique_mount_id=9001,
        boot_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        statvfs_flags=getattr(os, "ST_RDONLY", 1),
        descriptor_flags=os.O_RDONLY,
    )

    assert rebooted.mount_instance_identity != first.mount_instance_identity


@pytest.mark.parametrize("boot_id", ["", "not-a-uuid", BOOT_ID.upper(), f" {BOOT_ID}"])
def test_external_mount_identity_rejects_invalid_boot_epoch(boot_id: str) -> None:
    with pytest.raises(StorageAuthorityError, match="boot identity"):
        external_storage_facts(
            7,
            fdinfo_text="mnt_id:\t36\n",
            mountinfo_text=MOUNTINFO,
            stable_mountinfo_text=HOST_MOUNTINFO,
            stable_unique_mount_id=9001,
            boot_id=boot_id,
            statvfs_flags=getattr(os, "ST_RDONLY", 1),
            descriptor_flags=os.O_RDONLY,
        )


def test_external_root_must_be_the_exact_mount_point() -> None:
    facts = external_storage_facts(
        7,
        fdinfo_text="mnt_id:\t36\n",
        mountinfo_text=MOUNTINFO,
        statvfs_flags=0,
        descriptor_flags=os.O_RDONLY,
        stable_mountinfo_text=HOST_MOUNTINFO,
        stable_unique_mount_id=9001,
        boot_id=BOOT_ID,
        require_read_only=False,
        expected_mount_path="/mnt/evidence/",
    )
    assert facts.read_only is False

    writable_underlay = "25 1 8:1 / / rw - ext4 /dev/vda1 rw\n"
    with pytest.raises(StorageAuthorityError, match="not the mounted source"):
        external_storage_facts(
            7,
            fdinfo_text="mnt_id:\t25\n",
            mountinfo_text=writable_underlay,
            statvfs_flags=0,
            descriptor_flags=os.O_RDONLY,
            stable_mountinfo_text="25 1 8:1 / / rw - ext4 /dev/vda1 rw\n",
            stable_unique_mount_id=9002,
            boot_id=BOOT_ID,
            require_read_only=False,
            expected_mount_path="/cases/case-one/evidence",
        )


def test_external_storage_constructor_binds_exact_requested_root(
    tmp_path, monkeypatch
) -> None:
    captured: dict[str, object] = {}

    def facts_for_root(_fd: int, **kwargs: object) -> ExternalStorageFacts:
        captured.update(kwargs)
        return ExternalStorageFacts(
            source_identity="a" * 64,
            mount_instance_identity="b" * 64,
            filesystem_type="nfs4",
            read_only=True,
        )

    monkeypatch.setattr(
        "sift_core.evidence_storage.external_storage_facts", facts_for_root
    )
    with ExternalReadOnlyStorage(tmp_path):
        pass

    assert captured["expected_mount_path"] == tmp_path


def test_unsupported_external_filesystem_fails_closed() -> None:
    overlay = "36 25 0:32 / /mnt/evidence ro - overlay overlay ro\n"
    with pytest.raises(StorageAuthorityError, match="unsupported"):
        external_storage_facts(
            7,
            fdinfo_text="mnt_id:\t36\n",
            mountinfo_text=overlay,
            statvfs_flags=getattr(os, "ST_RDONLY", 1),
            descriptor_flags=os.O_RDONLY,
            stable_mountinfo_text=overlay,
            stable_unique_mount_id=9001,
            boot_id=BOOT_ID,
        )
