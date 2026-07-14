"""Descriptor-pinned evidence storage authority.

The module deliberately separates local immutable posture from externally
read-only posture. External source and host-namespace-stable mount-instance
identifiers are opaque SHA-256 values; raw mount paths, remote source strings,
and credentials never leave this process.
"""

from __future__ import annotations

import ctypes
import fcntl
import hashlib
import json
import os
import platform
import re
import socket
import stat
import struct
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class StorageAuthorityError(RuntimeError):
    """A storage fact could not be established unambiguously."""


class StorageProfile(StrEnum):
    LOCAL_IMMUTABLE = "LOCAL_IMMUTABLE"
    EXTERNALLY_READ_ONLY = "EXTERNALLY_READ_ONLY"


_MOUNT_ESCAPE = re.compile(r"\\([0-7]{3})")
_OPAQUE = re.compile(r"[0-9a-f]{64}\Z")
_MOUNT_OBSERVER_SOCKET = "/run/sift-mount-observer/observer.sock"
_MOUNT_OBSERVER_REQUEST_SCHEMA = "sift.mount-observer.request.v1"
_MOUNT_OBSERVER_RESPONSE_SCHEMA = "sift.mount-observer.response.v1"
_MOUNT_OBSERVER_LIMIT = 4096
_SUPPORTED_EXTERNAL_FILESYSTEMS = frozenset(
    {
        "9p",
        "btrfs",
        "cifs",
        "exfat",
        "ext4",
        "f2fs",
        "fuseblk",
        "fuse.sshfs",
        "hfsplus",
        "iso9660",
        "nfs",
        "nfs4",
        "ntfs3",
        "smb3",
        "udf",
        "vfat",
        "xfs",
    }
)


def _unescape_mount_field(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        encoded = match.group(1)
        if encoded not in {"011", "012", "040", "134"}:
            raise StorageAuthorityError("mountinfo contains an unsupported escape")
        return chr(int(encoded, 8))

    decoded = _MOUNT_ESCAPE.sub(replace, value)
    # A backslash is not a literal mountinfo character.  After the four kernel
    # escapes above have been decoded, any residual backslash -- including a
    # truncated one at end-of-field -- is malformed and must fail closed.
    if "\\" in decoded:
        raise StorageAuthorityError("mountinfo contains a malformed escape")
    return decoded


def _opaque_identity(*parts: str) -> str:
    material = "\0".join(parts).encode("utf-8", "strict")
    return hashlib.sha256(material).hexdigest()


@dataclass(frozen=True, slots=True)
class MountInfo:
    mount_id: int
    parent_id: int
    major_minor: str
    root: str
    mount_point: str
    mount_options: frozenset[str]
    filesystem_type: str
    source: str
    super_options: frozenset[str]

    @property
    def read_only(self) -> bool:
        return "ro" in self.mount_options and "ro" in self.super_options

    @property
    def source_identity(self) -> str:
        # Source may contain a remote hostname/share. It is hashed immediately
        # and never persisted or returned in clear text.
        return _opaque_identity(
            "source-v1", self.filesystem_type, self.root, self.source
        )


def parse_mountinfo(text: str) -> tuple[MountInfo, ...]:
    """Parse Linux mountinfo strictly; malformed or duplicate IDs fail closed."""
    if not isinstance(text, str) or not text.strip():
        raise StorageAuthorityError("mountinfo is empty")
    rows: list[MountInfo] = []
    seen: set[int] = set()
    for raw_line in text.splitlines():
        left, separator, right = raw_line.partition(" - ")
        if not separator:
            raise StorageAuthorityError("mountinfo separator is missing")
        left_fields = left.split()
        right_fields = right.split()
        if len(left_fields) < 6 or len(right_fields) < 3:
            raise StorageAuthorityError("mountinfo row is incomplete")
        try:
            mount_id = int(left_fields[0])
            parent_id = int(left_fields[1])
        except ValueError as exc:
            raise StorageAuthorityError("mountinfo ID is invalid") from exc
        if mount_id <= 0 or parent_id < 0 or mount_id in seen:
            raise StorageAuthorityError("mountinfo ID is invalid or duplicated")
        seen.add(mount_id)
        major_minor = left_fields[2]
        if not re.fullmatch(r"\d+:\d+", major_minor):
            raise StorageAuthorityError("mountinfo device is invalid")
        rows.append(
            MountInfo(
                mount_id=mount_id,
                parent_id=parent_id,
                major_minor=major_minor,
                root=_unescape_mount_field(left_fields[3]),
                mount_point=_unescape_mount_field(left_fields[4]),
                mount_options=frozenset(left_fields[5].split(",")),
                filesystem_type=right_fields[0],
                source=_unescape_mount_field(right_fields[1]),
                super_options=frozenset(right_fields[2].split(",")),
            )
        )
    return tuple(rows)


def parse_fd_mount_id(text: str) -> int:
    """Read the single Linux ``mnt_id`` fact from an fdinfo payload."""
    values: list[str] = []
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() == "mnt_id":
            values.append(value.strip())
    if len(values) != 1 or not values[0].isdigit() or int(values[0]) <= 0:
        raise StorageAuthorityError("fdinfo mount identity is missing or ambiguous")
    return int(values[0])


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise StorageAuthorityError("kernel mount facts are unavailable") from exc


def mount_for_fd(
    fd: int,
    *,
    fdinfo_text: str | None = None,
    mountinfo_text: str | None = None,
) -> MountInfo:
    """Resolve an open descriptor to exactly one mountinfo row."""
    if fd < 0:
        raise StorageAuthorityError("descriptor is invalid")
    fdinfo = (
        fdinfo_text
        if fdinfo_text is not None
        else _read_text(Path(f"/proc/self/fdinfo/{fd}"))
    )
    mountinfo = (
        mountinfo_text
        if mountinfo_text is not None
        else _read_text(Path("/proc/self/mountinfo"))
    )
    mount_id = parse_fd_mount_id(fdinfo)
    matches = [row for row in parse_mountinfo(mountinfo) if row.mount_id == mount_id]
    if len(matches) != 1:
        raise StorageAuthorityError("descriptor mount is missing or ambiguous")
    return matches[0]


def _stable_mount_for(
    mount: MountInfo,
    *,
    stable_mountinfo_text: str | None = None,
) -> MountInfo:
    """Resolve a namespace-local mount clone to its stable system mount.

    systemd filesystem hardening creates a fresh mount-namespace clone on each
    service start. Linux mount IDs, including ``STATX_MNT_ID_UNIQUE``, identify
    those clone objects and therefore cannot be persisted as restart-stable
    custody authority. Production obtains this host-namespace observation from
    the bounded ancillary observer; injected mountinfo is test authority only.
    """
    if stable_mountinfo_text is None:
        raise StorageAuthorityError("stable mount observer result is unavailable")
    stable_mountinfo = stable_mountinfo_text
    matches = [
        row
        for row in parse_mountinfo(stable_mountinfo)
        if (
            row.major_minor,
            row.root,
            row.mount_point,
            row.filesystem_type,
            row.source,
        )
        == (
            mount.major_minor,
            mount.root,
            mount.mount_point,
            mount.filesystem_type,
            mount.source,
        )
    ]
    if len(matches) != 1:
        raise StorageAuthorityError("stable mount identity is missing or ambiguous")
    return matches[0]


def _boot_identity(value: str | None = None) -> str:
    raw = (
        value
        if value is not None
        else _read_text(Path("/proc/sys/kernel/random/boot_id"))
    )
    normalized = raw[:-1] if raw.endswith("\n") else raw
    if raw not in {normalized, f"{normalized}\n"} or not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        normalized,
    ):
        raise StorageAuthorityError("host boot identity is unavailable")
    return normalized


class _StatxTimestamp(ctypes.Structure):
    _fields_ = [
        ("tv_sec", ctypes.c_int64),
        ("tv_nsec", ctypes.c_uint32),
        ("reserved", ctypes.c_int32),
    ]


class _Statx(ctypes.Structure):
    _fields_ = [
        ("mask", ctypes.c_uint32),
        ("blksize", ctypes.c_uint32),
        ("attributes", ctypes.c_uint64),
        ("nlink", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("mode", ctypes.c_uint16),
        ("spare0", ctypes.c_uint16),
        ("ino", ctypes.c_uint64),
        ("size", ctypes.c_uint64),
        ("blocks", ctypes.c_uint64),
        ("attributes_mask", ctypes.c_uint64),
        ("atime", _StatxTimestamp),
        ("btime", _StatxTimestamp),
        ("ctime", _StatxTimestamp),
        ("mtime", _StatxTimestamp),
        ("rdev_major", ctypes.c_uint32),
        ("rdev_minor", ctypes.c_uint32),
        ("dev_major", ctypes.c_uint32),
        ("dev_minor", ctypes.c_uint32),
        ("mnt_id", ctypes.c_uint64),
        ("dio_mem_align", ctypes.c_uint32),
        ("dio_offset_align", ctypes.c_uint32),
        ("subvol", ctypes.c_uint64),
        ("atomic_write_unit_min", ctypes.c_uint32),
        ("atomic_write_unit_max", ctypes.c_uint32),
        ("atomic_write_segments_max", ctypes.c_uint32),
        ("spare1", ctypes.c_uint32),
        ("spare3", ctypes.c_uint64 * 9),
    ]


def _unique_mount_id_for_fd(fd: int) -> int:
    if not sys.platform.startswith("linux"):
        raise StorageAuthorityError("unique mount identity requires Linux")
    syscall_number = {"x86_64": 332, "aarch64": 291}.get(platform.machine())
    if syscall_number is None:
        raise StorageAuthorityError("statx architecture is unsupported")
    libc = ctypes.CDLL(None, use_errno=True)
    result = _Statx()
    statx_mnt_id_unique = 0x00004000
    rc = libc.syscall(
        syscall_number,
        fd,
        ctypes.c_char_p(b""),
        0x1000 | 0x800,
        statx_mnt_id_unique,
        ctypes.byref(result),
    )
    if rc != 0 or result.mask & statx_mnt_id_unique == 0 or result.mnt_id == 0:
        raise StorageAuthorityError("unique mount identity is unavailable")
    return int(result.mnt_id)


@dataclass(frozen=True, slots=True)
class ExternalStorageFacts:
    source_identity: str
    mount_instance_identity: str
    filesystem_type: str
    read_only: bool

    def __post_init__(self) -> None:
        if not _OPAQUE.fullmatch(self.source_identity):
            raise ValueError("source identity must be opaque")
        if not _OPAQUE.fullmatch(self.mount_instance_identity):
            raise ValueError("mount instance identity must be opaque")


@dataclass(frozen=True, slots=True)
class HostMountObservation:
    source_identity: str
    mount_instance_identity: str
    mount_match_identity: str
    filesystem_type: str
    read_only: bool

    def __post_init__(self) -> None:
        for value in (
            self.source_identity,
            self.mount_instance_identity,
            self.mount_match_identity,
        ):
            if not _OPAQUE.fullmatch(value):
                raise ValueError("host mount identity must be opaque")
        if not self.filesystem_type or len(self.filesystem_type) > 64:
            raise ValueError("host mount filesystem type is invalid")
        if not isinstance(self.read_only, bool):
            raise ValueError("host mount read-only posture is invalid")


def _mount_match_identity(mount: MountInfo) -> str:
    return _opaque_identity(
        "mount-match-v1",
        mount.major_minor,
        mount.root,
        mount.mount_point,
        mount.filesystem_type,
        mount.source,
    )


def host_mount_observation(
    fd: int,
    *,
    expected_mount_path: str | os.PathLike[str],
    fdinfo_text: str | None = None,
    mountinfo_text: str | None = None,
    statvfs_flags: int | None = None,
    descriptor_flags: int | None = None,
    unique_mount_id: int | None = None,
    boot_id: str | None = None,
    supported_filesystems: Iterable[str] = _SUPPORTED_EXTERNAL_FILESYSTEMS,
) -> HostMountObservation:
    """Observe one exact read-only mount from the observer's host namespace."""
    mount = mount_for_fd(fd, fdinfo_text=fdinfo_text, mountinfo_text=mountinfo_text)
    expected = os.path.abspath(os.path.normpath(os.fspath(expected_mount_path)))
    if mount.mount_point != expected:
        raise StorageAuthorityError("external evidence root is not the mounted source")
    if mount.filesystem_type not in frozenset(supported_filesystems):
        raise StorageAuthorityError("external filesystem semantics are unsupported")
    host_unique_mount_id = (
        unique_mount_id if unique_mount_id is not None else _unique_mount_id_for_fd(fd)
    )
    if (
        not isinstance(host_unique_mount_id, int)
        or isinstance(host_unique_mount_id, bool)
        or host_unique_mount_id <= 0
    ):
        raise StorageAuthorityError("stable unique mount identity is unavailable")
    host_boot_identity = _boot_identity(boot_id)
    try:
        flags = os.fstatvfs(fd).f_flag if statvfs_flags is None else statvfs_flags
        open_flags = (
            fcntl.fcntl(fd, fcntl.F_GETFL)
            if descriptor_flags is None
            else descriptor_flags
        )
    except OSError as exc:
        raise StorageAuthorityError("host mount posture is unavailable") from exc
    read_only = (
        mount.read_only
        and bool(flags & getattr(os, "ST_RDONLY", 1))
        and open_flags & os.O_ACCMODE == os.O_RDONLY
    )
    return HostMountObservation(
        source_identity=mount.source_identity,
        mount_instance_identity=_opaque_identity(
            "mount-host-v2",
            host_boot_identity,
            str(host_unique_mount_id),
            str(mount.mount_id),
            str(mount.parent_id),
            mount.major_minor,
            mount.filesystem_type,
            mount.root,
            mount.mount_point,
            mount.source,
        ),
        mount_match_identity=_mount_match_identity(mount),
        filesystem_type=mount.filesystem_type,
        read_only=read_only,
    )


def _request_host_mount_observation(
    mount_point: str,
    *,
    socket_path: str = _MOUNT_OBSERVER_SOCKET,
) -> HostMountObservation:
    request_id = os.urandom(16).hex()
    request = (
        json.dumps(
            {
                "schema": _MOUNT_OBSERVER_REQUEST_SCHEMA,
                "request_id": request_id,
                "mount_point": mount_point,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )
    try:
        socket_stat = os.stat(socket_path, follow_symlinks=False)
        if (
            not stat.S_ISSOCK(socket_stat.st_mode)
            or socket_stat.st_uid != os.geteuid()
            or stat.S_IMODE(socket_stat.st_mode) != 0o600
            or socket_stat.st_nlink != 1
        ):
            raise StorageAuthorityError("mount observer socket posture is invalid")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(1.0)
            client.connect(socket_path)
            peer_pid, peer_uid, _peer_gid = _observer_peer_credentials(client)
            if peer_pid <= 0 or peer_uid != os.geteuid():
                raise StorageAuthorityError("mount observer peer is unauthorized")
            client.sendall(request)
            response = bytearray()
            while not response.endswith(b"\n"):
                chunk = client.recv(
                    min(1024, _MOUNT_OBSERVER_LIMIT + 1 - len(response))
                )
                if not chunk:
                    raise StorageAuthorityError("mount observer response is incomplete")
                response.extend(chunk)
                if len(response) > _MOUNT_OBSERVER_LIMIT:
                    raise StorageAuthorityError("mount observer response is oversized")
    except (OSError, TimeoutError) as exc:
        raise StorageAuthorityError("mount observer is unavailable") from exc
    try:
        payload = json.loads(response)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StorageAuthorityError("mount observer response is invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema",
        "request_id",
        "source_identity",
        "mount_instance_identity",
        "mount_match_identity",
        "filesystem_type",
        "read_only",
    }:
        raise StorageAuthorityError("mount observer response schema is invalid")
    if (
        payload.get("schema") != _MOUNT_OBSERVER_RESPONSE_SCHEMA
        or payload.get("request_id") != request_id
    ):
        raise StorageAuthorityError("mount observer response binding is invalid")
    try:
        return HostMountObservation(
            source_identity=payload["source_identity"],
            mount_instance_identity=payload["mount_instance_identity"],
            mount_match_identity=payload["mount_match_identity"],
            filesystem_type=payload["filesystem_type"],
            read_only=payload["read_only"],
        )
    except (TypeError, ValueError) as exc:
        raise StorageAuthorityError(
            "mount observer response facts are invalid"
        ) from exc


def _observer_peer_credentials(client: socket.socket) -> tuple[int, int, int]:
    so_peercred = getattr(socket, "SO_PEERCRED", None)
    if so_peercred is None:
        raise StorageAuthorityError("mount observer peer credentials are unavailable")
    try:
        return struct.unpack(
            "3i", client.getsockopt(socket.SOL_SOCKET, so_peercred, 12)
        )
    except (OSError, struct.error) as exc:
        raise StorageAuthorityError(
            "mount observer peer credentials are unavailable"
        ) from exc


def external_storage_facts(
    fd: int,
    *,
    fdinfo_text: str | None = None,
    mountinfo_text: str | None = None,
    statvfs_flags: int | None = None,
    descriptor_flags: int | None = None,
    stable_mountinfo_text: str | None = None,
    stable_unique_mount_id: int | None = None,
    boot_id: str | None = None,
    host_observation: HostMountObservation | None = None,
    require_read_only: bool = True,
    expected_mount_path: str | os.PathLike[str] | None = None,
    supported_filesystems: Iterable[str] = _SUPPORTED_EXTERNAL_FILESYSTEMS,
) -> ExternalStorageFacts:
    """Establish external identity and read-only posture from one pinned fd."""
    mount = mount_for_fd(fd, fdinfo_text=fdinfo_text, mountinfo_text=mountinfo_text)
    if expected_mount_path is not None:
        expected = os.path.abspath(os.path.normpath(os.fspath(expected_mount_path)))
        observed = os.path.abspath(os.path.normpath(mount.mount_point))
        if observed != expected:
            raise StorageAuthorityError(
                "external evidence root is not the mounted source"
            )
    if mount.filesystem_type not in frozenset(supported_filesystems):
        raise StorageAuthorityError("external filesystem semantics are unsupported")
    if host_observation is None and any(
        value is not None
        for value in (stable_mountinfo_text, stable_unique_mount_id, boot_id)
    ):
        if (
            stable_mountinfo_text is None
            or stable_unique_mount_id is None
            or boot_id is None
        ):
            raise StorageAuthorityError("stable mount test authority is incomplete")
        stable_mount = _stable_mount_for(
            mount, stable_mountinfo_text=stable_mountinfo_text
        )
        host_observation = host_mount_observation(
            fd,
            expected_mount_path=stable_mount.mount_point,
            fdinfo_text=f"mnt_id:\t{stable_mount.mount_id}\n",
            mountinfo_text=stable_mountinfo_text,
            statvfs_flags=statvfs_flags,
            descriptor_flags=descriptor_flags,
            unique_mount_id=stable_unique_mount_id,
            boot_id=boot_id,
            supported_filesystems=supported_filesystems,
        )
    if host_observation is None:
        host_observation = _request_host_mount_observation(mount.mount_point)
    if (
        host_observation.source_identity != mount.source_identity
        or host_observation.mount_match_identity != _mount_match_identity(mount)
        or host_observation.filesystem_type != mount.filesystem_type
    ):
        raise StorageAuthorityError("host and local mount authority disagree")
    try:
        flags = os.fstatvfs(fd).f_flag if statvfs_flags is None else statvfs_flags
    except OSError as exc:
        raise StorageAuthorityError(
            "descriptor filesystem posture is unavailable"
        ) from exc
    statvfs_read_only = bool(flags & getattr(os, "ST_RDONLY", 1))
    try:
        open_flags = (
            fcntl.fcntl(fd, fcntl.F_GETFL)
            if descriptor_flags is None
            else descriptor_flags
        )
    except OSError as exc:
        raise StorageAuthorityError("descriptor access posture is unavailable") from exc
    descriptor_read_only = open_flags & os.O_ACCMODE == os.O_RDONLY
    posture_read_only = (
        mount.read_only
        and host_observation.read_only
        and statvfs_read_only
        and descriptor_read_only
    )
    if require_read_only and not posture_read_only:
        raise StorageAuthorityError("external storage is not consistently read-only")
    return ExternalStorageFacts(
        source_identity=mount.source_identity,
        mount_instance_identity=host_observation.mount_instance_identity,
        filesystem_type=mount.filesystem_type,
        read_only=posture_read_only,
    )


@dataclass(frozen=True, slots=True)
class PinnedEvidenceFacts:
    byte_count: int
    sha256: str
    device: int
    inode: int
    mtime_ns: int
    ctime_ns: int
    link_count: int
    source_identity: str
    mount_instance_identity: str


class ExternalReadOnlyStorage:
    """A root descriptor plus descriptor-relative, no-follow evidence reads."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        flags = (
            os.O_RDONLY
            | os.O_CLOEXEC
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        self._root_fd = os.open(os.fspath(root), flags)
        try:
            root_stat = os.fstat(self._root_fd)
            if not stat.S_ISDIR(root_stat.st_mode):
                raise StorageAuthorityError("external evidence root is not a directory")
            self.facts = external_storage_facts(self._root_fd, expected_mount_path=root)
        except Exception:
            os.close(self._root_fd)
            raise

    def close(self) -> None:
        if self._root_fd >= 0:
            os.close(self._root_fd)
            self._root_fd = -1

    def __enter__(self) -> ExternalReadOnlyStorage:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def open_evidence(self, name: str) -> tuple[int, PinnedEvidenceFacts]:
        if not name or name in {".", ".."} or "/" in name or "\0" in name:
            raise StorageAuthorityError("evidence name must be one direct entry")
        if self._root_fd < 0:
            raise StorageAuthorityError("storage authority is closed")
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(name, flags, dir_fd=self._root_fd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise StorageAuthorityError("external evidence entry is unsafe")
            entry_facts = external_storage_facts(fd)
            if entry_facts != self.facts:
                raise StorageAuthorityError("nested or changed mount is not allowed")
            digest = hashlib.sha256()
            os.lseek(fd, 0, os.SEEK_SET)
            while chunk := os.read(fd, 1024 * 1024):
                digest.update(chunk)
            after = os.fstat(fd)
            final_facts = external_storage_facts(fd)
            identity_before = (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
                before.st_nlink,
            )
            identity_after = (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
                after.st_nlink,
            )
            if identity_before != identity_after or final_facts != self.facts:
                raise StorageAuthorityError("external evidence changed while hashing")
            os.lseek(fd, 0, os.SEEK_SET)
            return fd, PinnedEvidenceFacts(
                byte_count=after.st_size,
                sha256=digest.hexdigest(),
                device=after.st_dev,
                inode=after.st_ino,
                mtime_ns=after.st_mtime_ns,
                ctime_ns=after.st_ctime_ns,
                link_count=after.st_nlink,
                source_identity=self.facts.source_identity,
                mount_instance_identity=self.facts.mount_instance_identity,
            )
        except Exception:
            os.close(fd)
            raise
