from __future__ import annotations

import json
import os
import socket
import threading
from pathlib import Path

import pytest
from sift_core.evidence_storage import (
    HostMountObservation,
    StorageAuthorityError,
    _request_host_mount_observation,
)
from sift_core.mount_observer import _open_evidence_root, _serve_connection


def _observation() -> HostMountObservation:
    return HostMountObservation(
        source_identity="a" * 64,
        mount_instance_identity="b" * 64,
        mount_match_identity="c" * 64,
        filesystem_type="ext4",
        read_only=True,
    )


def test_observer_opens_only_exact_direct_evidence_directory(tmp_path) -> None:
    cases = tmp_path / "cases"
    evidence = cases / "case-one" / "evidence"
    evidence.mkdir(parents=True)

    fd = _open_evidence_root(os.fspath(evidence), cases)
    os.close(fd)

    with pytest.raises(StorageAuthorityError):
        _open_evidence_root(os.fspath(evidence / "nested"), cases)
    with pytest.raises(StorageAuthorityError):
        _open_evidence_root(os.fspath(cases / "../other/evidence"), cases)


def test_observer_rejects_symlinked_case_component(tmp_path) -> None:
    cases = tmp_path / "cases"
    real_case = tmp_path / "real-case"
    (real_case / "evidence").mkdir(parents=True)
    cases.mkdir()
    (cases / "case-link").symlink_to(real_case, target_is_directory=True)

    with pytest.raises(OSError):
        _open_evidence_root(os.fspath(cases / "case-link" / "evidence"), cases)


def test_observer_response_is_peer_and_request_bound(tmp_path, monkeypatch) -> None:
    evidence = tmp_path / "cases" / "case-one" / "evidence"
    evidence.mkdir(parents=True)
    fd = os.open(evidence, os.O_RDONLY | os.O_DIRECTORY)
    monkeypatch.setattr(
        "sift_core.mount_observer._open_evidence_root", lambda *_args: os.dup(fd)
    )
    monkeypatch.setattr(
        "sift_core.mount_observer.host_mount_observation",
        lambda *_args, **_kwargs: _observation(),
    )
    monkeypatch.setattr(
        "sift_core.mount_observer._peer_credentials",
        lambda *_args: (os.getpid(), os.geteuid(), os.getegid()),
    )
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        request_id = "d" * 32
        client.sendall(
            json.dumps(
                {
                    "schema": "sift.mount-observer.request.v1",
                    "request_id": request_id,
                    "mount_point": "/cases/case-one/evidence",
                }
            ).encode()
            + b"\n"
        )
        _serve_connection(server, cases_root=tmp_path / "cases")
        response = json.loads(client.recv(4096))
    finally:
        client.close()
        server.close()
        os.close(fd)

    assert response["request_id"] == request_id
    assert response["mount_instance_identity"] == "b" * 64
    assert set(response) == {
        "schema",
        "request_id",
        "source_identity",
        "mount_instance_identity",
        "mount_match_identity",
        "filesystem_type",
        "read_only",
    }


def test_client_rejects_response_for_another_request(tmp_path, monkeypatch) -> None:
    del tmp_path
    socket_path = Path(f"/tmp/sift-observer-test-{os.getpid()}.sock")
    socket_path.unlink(missing_ok=True)
    ready = threading.Event()

    def fake_observer() -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(os.fspath(socket_path))
            os.chmod(socket_path, 0o600)
            listener.listen(1)
            ready.set()
            connection, _ = listener.accept()
            with connection:
                connection.recv(4096)
                connection.sendall(
                    json.dumps(
                        {
                            "schema": "sift.mount-observer.response.v1",
                            "request_id": "0" * 32,
                            "source_identity": "a" * 64,
                            "mount_instance_identity": "b" * 64,
                            "mount_match_identity": "c" * 64,
                            "filesystem_type": "ext4",
                            "read_only": True,
                        }
                    ).encode()
                    + b"\n"
                )

    thread = threading.Thread(target=fake_observer)
    thread.start()
    assert ready.wait(1)
    monkeypatch.setattr(
        "sift_core.evidence_storage._observer_peer_credentials",
        lambda *_args: (os.getpid(), os.geteuid(), os.getegid()),
    )
    try:
        with pytest.raises(StorageAuthorityError, match="binding"):
            _request_host_mount_observation(
                "/cases/case-one/evidence", socket_path=os.fspath(socket_path)
            )
    finally:
        thread.join(1)
        socket_path.unlink(missing_ok=True)


def test_client_rejects_observer_with_wrong_peer_uid(tmp_path, monkeypatch) -> None:
    del tmp_path
    socket_path = Path(f"/tmp/sift-observer-peer-{os.getpid()}.sock")
    socket_path.unlink(missing_ok=True)
    ready = threading.Event()

    def fake_observer() -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(os.fspath(socket_path))
            os.chmod(socket_path, 0o600)
            listener.listen(1)
            ready.set()
            connection, _ = listener.accept()
            connection.close()

    thread = threading.Thread(target=fake_observer)
    thread.start()
    assert ready.wait(1)
    monkeypatch.setattr(
        "sift_core.evidence_storage._observer_peer_credentials",
        lambda *_args: (os.getpid(), os.geteuid() + 1, os.getegid()),
    )
    try:
        with pytest.raises(StorageAuthorityError, match="unauthorized"):
            _request_host_mount_observation(
                "/cases/case-one/evidence", socket_path=os.fspath(socket_path)
            )
    finally:
        thread.join(1)
        socket_path.unlink(missing_ok=True)
