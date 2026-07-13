#!/usr/bin/env python3
"""Prepare manually copied evidence for portal Seal without accepting paths.

This is deliberately invoked only by ``stage-evidence.sh --prepare`` through a
fixed system interpreter. The installer copies this file and its minimal Python
dependencies to root-owned system locations. It is not an MCP tool or a general-purpose
privileged file utility: it resolves the DB-active case itself, opens the
canonical evidence directory without following links, and changes metadata only
through file descriptors pinned during validation.
"""

from __future__ import annotations

import array
import errno
import fcntl
import os
import pwd
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

FS_IOC_GETFLAGS = 0x80086601
FS_IMMUTABLE_FL = 0x00000010
INSTALLED_HELPER = Path("/usr/local/lib/sift/prepare_evidence.py")
ROOT_PYTHON_DEPS = Path("/usr/local/lib/sift/prepare-evidence-python")
CONTROL_PLANE_ENV = Path("/var/lib/sift/.sift/control-plane.env")
CASES_ROOT = Path("/cases")
SERVICE_USER = "sift-service"
CASE_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# Indirection keeps the descriptor contract testable without changing actual
# filesystem ownership in the test process.
os_fchown = os.fchown
os_fchmod = os.fchmod


class PrepareEvidenceError(RuntimeError):
    """The operator must correct intake state before evidence can be prepared."""


@dataclass(frozen=True)
class ServiceIdentity:
    name: str
    uid: int
    gid: int


def _die(message: str) -> NoReturn:
    raise PrepareEvidenceError(message)


def _get_immutable_flags(fd: int) -> int:
    flags = array.array("I", [0])
    try:
        fcntl.ioctl(fd, FS_IOC_GETFLAGS, flags, True)
    except OSError as exc:
        _die(f"cannot inspect immutable state: {exc.strerror or 'ioctl failed'}")
    return int(flags[0])


def _open_service_directory(path: Path, service: ServiceIdentity, *, label: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        _die(f"cannot open {label}: {exc.strerror or 'open failed'}")

    return _validate_service_directory(fd, service, label=label)


def _open_service_child_directory(parent_fd: int, name: str, service: ServiceIdentity, *, label: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        _die(f"cannot open {label}: {exc.strerror or 'open failed'}")
    return _validate_service_directory(fd, service, label=label)


def _validate_service_directory(fd: int, service: ServiceIdentity, *, label: str) -> int:

    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        os.close(fd)
        _die(f"{label} is not a directory")
    if info.st_uid != service.uid or info.st_gid != service.gid:
        os.close(fd)
        _die(f"{label} must be owned by {service.name}")
    if stat.S_IMODE(info.st_mode) != 0o755:
        os.close(fd)
        _die(f"{label} must have mode 0755")
    return fd


def _open_regular_entry(dir_fd: int, name: str, service: ServiceIdentity) -> tuple[int, bool]:
    """Open and validate one direct entry, returning its immutable state.

    Immutable entries are already sealed evidence.  They are validated so a
    malformed directory still fails closed, but callers must leave their
    metadata untouched while preparing newly added evidence in the same case.
    """
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(name, flags, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            _die(f"refusing symlink evidence entry: {name}")
        _die(f"cannot safely open evidence entry {name!r}: {exc.strerror or 'open failed'}")

    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        _die(f"refusing non-regular evidence entry: {name}")
    if info.st_nlink != 1:
        os.close(fd)
        _die(f"refusing hard-linked evidence entry: {name}")
    if info.st_uid not in (0, service.uid):
        os.close(fd)
        _die(f"refusing evidence entry not owned by root or {service.name}: {name}")
    return fd, bool(_get_immutable_flags(fd) & FS_IMMUTABLE_FL)


def _prepare_open_evidence_dir(dir_fd: int, service: ServiceIdentity) -> int:
    """Descriptor-pin and prepare each eligible direct evidence entry.

    All entries are opened and validated before the first metadata operation.
    Existing immutable evidence remains untouched; only validated, non-immutable
    entries are held open for the subsequent ``fchown``/``fchmod`` calls, which
    cannot follow a name changed by a concurrent writer.  No source path is
    accepted by this helper.
    """
    entry_fds: list[int] = []
    try:
        names = os.listdir(dir_fd)
        if not names:
            _die("no evidence entries found to prepare")
        for name in names:
            fd, immutable = _open_regular_entry(dir_fd, name, service)
            if immutable:
                os.close(fd)
            else:
                entry_fds.append(fd)
        for fd in entry_fds:
            os_fchown(fd, service.uid, service.gid)
            os_fchmod(fd, 0o644)
        return len(entry_fds)
    finally:
        for fd in entry_fds:
            os.close(fd)


def prepare_evidence_dir(evidence_dir: Path, service: ServiceIdentity) -> int:
    """Prepare a direct native evidence directory (unit-testable primitive)."""
    dir_fd = _open_service_directory(evidence_dir, service, label="evidence directory")
    try:
        return _prepare_open_evidence_dir(dir_fd, service)
    finally:
        os.close(dir_fd)


def prepare_active_case_evidence(case_key: str, service: ServiceIdentity) -> int:
    """Descriptor-pin `/cases/<active-case>/evidence` one component at a time."""
    root_fd = _open_service_directory(CASES_ROOT, service, label="cases root")
    try:
        case_fd = _open_service_child_directory(
            root_fd, case_key, service, label="canonical active case directory"
        )
    finally:
        os.close(root_fd)
    try:
        evidence_fd = _open_service_child_directory(
            case_fd, "evidence", service, label="canonical evidence directory"
        )
    finally:
        os.close(case_fd)
    try:
        return _prepare_open_evidence_dir(evidence_fd, service)
    finally:
        os.close(evidence_fd)


def _read_control_plane_dsn(path: Path, service: ServiceIdentity) -> str:
    try:
        info = path.stat()
    except OSError as exc:
        _die(f"cannot read installed control-plane configuration: {exc.strerror or 'missing'}")
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, service.uid):
        _die("installed control-plane configuration has an unexpected owner or type")
    if stat.S_IMODE(info.st_mode) & 0o077:
        _die("installed control-plane configuration must not be group- or world-readable")

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        _die(f"cannot read installed control-plane configuration: {exc.strerror or 'read failed'}")
    for line in lines:
        line = line.strip()
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        if separator and key == "SIFT_CONTROL_PLANE_DSN":
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            if value:
                return value
    _die("installed control-plane configuration has no SIFT_CONTROL_PLANE_DSN")


def _resolve_unsealed_active_case(dsn: str) -> str:
    try:
        import psycopg

        with psycopg.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(
                "select c.case_key, gate.seal_status "
                "from app.active_case_state state "
                "join app.cases c on c.id = state.active_case_id "
                "cross join lateral app.evidence_gate_status(c.id) gate "
                "where state.scope = 'deployment' and state.active_case_id is not null"
            )
            row = cur.fetchone()
    except Exception as exc:  # DB outage/credentials must block preparation.
        _die(f"cannot resolve the active case from the control plane: {type(exc).__name__}")
    if not row:
        _die("no active case is set in the portal")
    case_key, seal_status = str(row[0]), str(row[1])
    if not CASE_KEY_RE.fullmatch(case_key):
        _die("control plane returned an invalid active case key")
    if seal_status != "unsealed":
        _die("active case is not unsealed; create or activate an unsealed case before preparation")
    return case_key


def _require_installed_root_owned() -> None:
    actual = Path(__file__).resolve()
    if actual != INSTALLED_HELPER:
        _die("prepare helper must run from the installed SIFT path")
    info = actual.stat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
        _die("installed prepare helper must be root-owned and not group- or world-writable")


def _activate_root_owned_dependencies() -> None:
    try:
        root_info = ROOT_PYTHON_DEPS.stat()
    except OSError as exc:
        _die(f"root-owned prepare dependencies are unavailable: {exc.strerror or 'missing'}")
    if root_info.st_uid != 0 or not stat.S_ISDIR(root_info.st_mode) or stat.S_IMODE(root_info.st_mode) & 0o022:
        _die("root-owned prepare dependencies have an unsafe owner, type, or mode")
    for path in ROOT_PYTHON_DEPS.rglob("*"):
        try:
            info = path.lstat()
        except OSError as exc:
            _die(f"cannot inspect root-owned prepare dependency: {exc.strerror or 'failed'}")
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            _die("root-owned prepare dependencies contain an unsafe entry")
    sys.path.insert(0, str(ROOT_PYTHON_DEPS))


def main(argv: list[str]) -> int:
    if argv:
        _die("prepare helper accepts no arguments")
    _require_installed_root_owned()
    try:
        account = pwd.getpwnam(SERVICE_USER)
    except KeyError:
        _die(f"gateway service account {SERVICE_USER!r} does not exist")
    service = ServiceIdentity(SERVICE_USER, account.pw_uid, account.pw_gid)
    if service.uid == 0:
        _die("gateway service account must not be root")
    dsn = _read_control_plane_dsn(CONTROL_PLANE_ENV, service)
    _activate_root_owned_dependencies()
    case_key = _resolve_unsealed_active_case(dsn)
    prepared = prepare_active_case_evidence(case_key, service)
    print(f"Prepared {prepared} evidence file(s) for the active unsealed case.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except PrepareEvidenceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
