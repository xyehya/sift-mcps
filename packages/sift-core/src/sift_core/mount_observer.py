"""Host-namespace mount identity observer for external custody storage."""

from __future__ import annotations

import json
import os
import re
import socket
import stat
import struct
import sys
from pathlib import Path
from typing import Any

from sift_core.evidence_storage import (
    _MOUNT_OBSERVER_LIMIT,
    _MOUNT_OBSERVER_REQUEST_SCHEMA,
    _MOUNT_OBSERVER_RESPONSE_SCHEMA,
    _MOUNT_OBSERVER_SOCKET,
    HostMountObservation,
    StorageAuthorityError,
    host_mount_observation,
)

_REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")
_CASE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")


def _read_request(connection: socket.socket) -> dict[str, Any]:
    data = bytearray()
    while not data.endswith(b"\n"):
        chunk = connection.recv(min(1024, _MOUNT_OBSERVER_LIMIT + 1 - len(data)))
        if not chunk:
            raise StorageAuthorityError("observer request is incomplete")
        data.extend(chunk)
        if len(data) > _MOUNT_OBSERVER_LIMIT:
            raise StorageAuthorityError("observer request is oversized")
    try:
        payload = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StorageAuthorityError("observer request is invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema",
        "request_id",
        "mount_point",
    }:
        raise StorageAuthorityError("observer request schema is invalid")
    if (
        payload.get("schema") != _MOUNT_OBSERVER_REQUEST_SCHEMA
        or not isinstance(payload.get("request_id"), str)
        or not _REQUEST_ID.fullmatch(payload["request_id"])
        or not isinstance(payload.get("mount_point"), str)
    ):
        raise StorageAuthorityError("observer request binding is invalid")
    return payload


def _open_evidence_root(mount_point: str, cases_root: Path) -> int:
    normalized_root = Path(os.path.abspath(os.path.normpath(cases_root)))
    normalized_mount = Path(os.path.abspath(os.path.normpath(mount_point)))
    try:
        relative = normalized_mount.relative_to(normalized_root)
    except ValueError as exc:
        raise StorageAuthorityError(
            "observer mount point is outside cases root"
        ) from exc
    if (
        os.fspath(normalized_mount) != mount_point
        or len(relative.parts) != 2
        or not _CASE_COMPONENT.fullmatch(relative.parts[0])
        or relative.parts[1] != "evidence"
    ):
        raise StorageAuthorityError("observer mount point is invalid")
    directory_flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    root_fd = os.open(normalized_root, directory_flags)
    try:
        case_fd = os.open(relative.parts[0], directory_flags, dir_fd=root_fd)
    finally:
        os.close(root_fd)
    try:
        return os.open("evidence", directory_flags, dir_fd=case_fd)
    finally:
        os.close(case_fd)


def _response_payload(request_id: str, observation: HostMountObservation) -> bytes:
    return (
        json.dumps(
            {
                "schema": _MOUNT_OBSERVER_RESPONSE_SCHEMA,
                "request_id": request_id,
                "source_identity": observation.source_identity,
                "mount_instance_identity": observation.mount_instance_identity,
                "mount_match_identity": observation.mount_match_identity,
                "filesystem_type": observation.filesystem_type,
                "read_only": observation.read_only,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def _peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    so_peercred = getattr(socket, "SO_PEERCRED", None)
    if so_peercred is None:
        raise StorageAuthorityError("observer peer credentials are unavailable")
    return struct.unpack(
        "3i", connection.getsockopt(socket.SOL_SOCKET, so_peercred, 12)
    )


def _serve_connection(
    connection: socket.socket,
    *,
    cases_root: Path,
) -> None:
    peer_pid, peer_uid, _peer_gid = _peer_credentials(connection)
    if peer_pid <= 0 or peer_uid != os.geteuid():
        raise StorageAuthorityError("observer peer is unauthorized")
    request = _read_request(connection)
    fd = _open_evidence_root(request["mount_point"], cases_root)
    try:
        observation = host_mount_observation(
            fd, expected_mount_path=request["mount_point"]
        )
    finally:
        os.close(fd)
    connection.sendall(_response_payload(request["request_id"], observation))


def serve(
    *,
    socket_path: Path = Path(_MOUNT_OBSERVER_SOCKET),
    cases_root: Path = Path("/cases"),
) -> None:
    if os.geteuid() == 0:
        raise RuntimeError("mount observer must run as the service user")
    socket_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    current = socket_path.lstat() if socket_path.exists() else None
    if current is not None:
        if not stat.S_ISSOCK(current.st_mode) or current.st_uid != os.geteuid():
            raise RuntimeError("mount observer socket path is unsafe")
        socket_path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(os.fspath(socket_path))
        os.chmod(socket_path, 0o600)
        listener.listen(16)
        while True:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(1.0)
                try:
                    _serve_connection(connection, cases_root=cases_root)
                except (OSError, TimeoutError, StorageAuthorityError, ValueError):
                    # The client fails closed on an incomplete response. Do not
                    # echo paths, kernel facts, or exception text across the seam.
                    continue


def main() -> int:
    if len(sys.argv) != 1:
        return 2
    serve(
        socket_path=Path(
            os.environ.get("SIFT_MOUNT_OBSERVER_SOCKET", _MOUNT_OBSERVER_SOCKET)
        ),
        cases_root=Path(os.environ.get("SIFT_CASES_ROOT", "/cases")),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
