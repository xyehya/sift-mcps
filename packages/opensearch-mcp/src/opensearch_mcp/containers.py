"""Container handling: archive extraction and disk image mounting."""

from __future__ import annotations

import glob
import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
import time
import urllib.parse
from pathlib import Path
from typing import NamedTuple

from sift_core.case_io import cases_root

from opensearch_mcp.discover import safe_rglob

logger = logging.getLogger(__name__)


def detect_container(path: Path) -> str:
    """Detect container type from file extension.

    Returns: "archive", "ewf", "nbd", "raw", "directory", or "unknown".
    """
    suffix = path.suffix.lower()
    suffixes = "".join(path.suffixes[-2:]).lower()
    if suffix in (".zip", ".7z"):
        return "archive"
    if suffixes in (".tar.gz", ".tgz") or suffix == ".tar":
        return "archive"
    if suffix in (".e01", ".ex01"):
        return "ewf"
    if suffix in (".vhdx", ".vhd", ".vmdk"):
        return "nbd"
    if suffix in (".dd", ".raw", ".img", ".iso"):
        return "raw"
    if path.is_dir():
        return "directory"
    return "unknown"


# ---------------------------------------------------------------------------
# SEC-8: single hardened archive extraction chokepoint
#
# All archive extraction (scan path + memory path) funnels through
# ``extract_container``. Containment no longer rests solely on the external
# tar/7z binaries' version defaults: every archive is (1) member-preflighted
# (traversal / absolute / symlink / hardlink / device / fifo / setuid-setgid
# rejected before a single byte is written), (2) capped against decompression
# bombs / disk exhaustion (entry count, uncompressed total, compression ratio,
# free-space), and (3) post-walked for any escape the binary might still have
# produced. Caps carry operator-approved defaults and are env-overridable.
# ---------------------------------------------------------------------------


class ArchiveRejected(ValueError):
    """An archive member or resource cap violated extraction policy.

    Raised *before* (or instead of) writing anything outside ``dest`` so callers
    can surface a typed rejection reason at the agent-facing status surface
    (``opensearch_ingest_status`` / ``result_public``) rather than letting the
    rejection masquerade as a generic crash.
    """


class _Member(NamedTuple):
    """One archive entry as seen during preflight (no extraction yet)."""

    name: str
    size: int  # declared uncompressed size in bytes (0 for non-files)
    kind: str  # file | dir | symlink | hardlink | char | block | fifo | socket
    setid: bool  # setuid or setgid bit set on the member


# Anti-bomb / containment caps (operator-approved defaults; env-overridable).
_DEFAULT_MAX_RATIO = 200  # uncompressed:compressed
_DEFAULT_MAX_ENTRIES = 1_000_000
_DEFAULT_MAX_UNCOMPRESSED = 512 * 1024**3  # 512 GiB absolute backstop
_DEFAULT_TIMEOUT_S = 3600  # one hour per extraction subprocess
_FREE_SPACE_MARGIN = 0.95  # projected size must stay under 95% of free space

# Member kinds that have no place in forensic triage/evidence archives and that
# are the classic write-escape / privilege vectors. Reject on sight.
_UNSAFE_KINDS = frozenset({"symlink", "hardlink", "char", "block", "fifo", "socket"})

# Unix mode token inside a 7z ``-slt`` Attributes line, e.g. ``-rw-r--r--`` or
# ``lrwxrwxrwx`` (symlink) or ``-rwsr-xr-x`` (setuid). Matched per-token via
# fullmatch (a leading ``-`` defeats ``\b`` word-boundary anchoring).
_UNIX_MODE_RE = re.compile(r"[-dlbcps][-rwxsStT]{9}")
_UNIX_TYPE_MAP = {
    "-": "file",
    "d": "dir",
    "l": "symlink",
    "b": "block",
    "c": "char",
    "p": "fifo",
    "s": "socket",
}


def _cap_int(env: str, default: int) -> int:
    """Read a positive-int cap from the environment, falling back to default."""
    raw = os.environ.get(env, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _extract_timeout() -> int:
    return _cap_int("SIFT_ARCHIVE_TIMEOUT_SECONDS", _DEFAULT_TIMEOUT_S)


def extract_container(path: Path, dest: Path, password: str | None = None) -> None:
    """Extract an archive to ``dest`` through the hardened SEC-8 chokepoint.

    Order is deliberate and fail-closed: enumerate + validate every member and
    enforce the anti-bomb caps BEFORE invoking the extractor binary, then walk
    the result to catch any escape the binary itself produced. Raises
    ``ArchiveRejected`` on any policy violation (a subclass of ``ValueError`` so
    existing ``except ValueError`` callers still catch it).
    """
    suffix = path.suffix.lower()
    suffixes = "".join(path.suffixes[-2:]).lower()

    if suffix in (".zip", ".7z"):
        members = _list_7z_members(path, password)
        _enforce_policy(path, dest, members)
        _extract_7z(path, dest, password)
    elif suffixes in (".tar.gz", ".tgz") or suffix == ".tar":
        members = _list_tar_members(path, dest)
        _enforce_policy(path, dest, members)
        _extract_tar(path, dest)
    else:
        raise ValueError(f"Unknown archive format: {path.name}")

    _verify_no_escape(dest)


def _is_unsafe_path(name: str) -> bool:
    """True if a member name is absolute or contains a ``..`` traversal segment.

    Handles POSIX absolute paths, Windows drive-letter / UNC absolute paths, and
    both separator styles. Note: Velociraptor collections legitimately carry
    URL-encoded names such as ``C%3A/Windows`` — those are relative and remain
    safe here (decoding to ``C:`` happens post-extraction in
    ``normalize_velociraptor``).
    """
    if not name:
        return False
    if name.startswith("/") or name.startswith("\\"):
        return True
    # Windows drive letter (``C:\``) or UNC (``\\host``) absolute paths.
    if re.match(r"^[A-Za-z]:", name):
        return True
    parts = re.split(r"[\\/]+", name)
    return ".." in parts


def _reject_unsafe_member(m: _Member) -> None:
    """Raise ``ArchiveRejected`` if a single member violates the safety policy."""
    if _is_unsafe_path(m.name):
        raise ArchiveRejected(f"unsafe member path: {m.name!r}")
    if m.kind in _UNSAFE_KINDS:
        raise ArchiveRejected(f"disallowed member type {m.kind}: {m.name!r}")
    if m.setid:
        raise ArchiveRejected(f"setuid/setgid member: {m.name!r}")


def _enforce_policy(path: Path, dest: Path, members: list[_Member]) -> None:
    """Apply per-member safety + anti-bomb caps before any extraction."""
    for m in members:
        _reject_unsafe_member(m)

    max_entries = _cap_int("SIFT_ARCHIVE_MAX_ENTRIES", _DEFAULT_MAX_ENTRIES)
    if len(members) > max_entries:
        raise ArchiveRejected(
            f"archive entry count {len(members)} exceeds cap {max_entries}"
        )

    total = sum(m.size for m in members if m.size > 0)
    max_total = _cap_int("SIFT_ARCHIVE_MAX_UNCOMPRESSED_BYTES", _DEFAULT_MAX_UNCOMPRESSED)
    if total > max_total:
        raise ArchiveRejected(
            f"declared uncompressed size {total} exceeds cap {max_total}"
        )

    max_ratio = _cap_int("SIFT_ARCHIVE_MAX_RATIO", _DEFAULT_MAX_RATIO)
    try:
        compressed = path.stat().st_size
    except OSError:
        compressed = 0
    if compressed > 0 and total > compressed * max_ratio:
        raise ArchiveRejected(
            f"compression ratio {total // compressed}:1 exceeds cap {max_ratio}:1"
        )

    _check_free_space(dest, total)


def _check_free_space(dest: Path, projected: int) -> None:
    """Refuse extraction if the projected uncompressed size would fill the disk."""
    try:
        st = os.statvfs(dest)
    except OSError:
        return  # Cannot stat (e.g. dest not yet created) — best-effort only.
    free = st.f_bavail * st.f_frsize
    if projected > free * _FREE_SPACE_MARGIN:
        raise ArchiveRejected(
            f"projected uncompressed size {projected} would exhaust free space "
            f"({free} bytes available)"
        )


def _list_tar_members(path: Path, dest: Path) -> list[_Member]:
    """Enumerate tar members and apply PEP-706 ``data`` filter validation.

    The data filter (rejects absolute paths, traversal, device/fifo nodes, and
    links that escape ``dest``) is the maintained, well-reviewed implementation
    of the rules SEC-8 needs; we layer our own stricter link/setid rejection on
    top (we forbid links entirely, not just escaping ones).
    """
    members: list[_Member] = []
    data_filter = getattr(tarfile, "data_filter", None)
    try:
        with tarfile.open(path, "r:*") as tf:
            for ti in tf.getmembers():
                if data_filter is not None:
                    try:
                        data_filter(ti, str(dest))
                    except tarfile.FilterError as exc:  # type: ignore[attr-defined]
                        raise ArchiveRejected(
                            f"tar member rejected by data filter: {exc}"
                        ) from exc
                kind = _tarinfo_kind(ti)
                setid = bool(ti.mode & 0o6000)
                members.append(
                    _Member(
                        name=ti.name,
                        size=ti.size if ti.isreg() else 0,
                        kind=kind,
                        setid=setid,
                    )
                )
    except ArchiveRejected:
        raise
    except (tarfile.TarError, OSError) as exc:
        raise ArchiveRejected(f"cannot read tar archive: {exc}") from exc
    return members


def _tarinfo_kind(ti: tarfile.TarInfo) -> str:
    if ti.isdir():
        return "dir"
    if ti.issym():
        return "symlink"
    if ti.islnk():
        return "hardlink"
    if ti.ischr():
        return "char"
    if ti.isblk():
        return "block"
    if ti.isfifo():
        return "fifo"
    return "file"


def _list_7z_members(path: Path, password: str | None = None) -> list[_Member]:
    """Enumerate zip/7z members via ``7z l -slt`` (technical listing)."""
    cmd = ["7z", "l", "-slt", str(path)]
    if password:
        cmd.append(f"-p{password}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=_extract_timeout()
        )
    except subprocess.TimeoutExpired as exc:
        raise ArchiveRejected("listing archive exceeded timeout") from exc
    # rc 0=ok, 1=warning, 2+=fatal. We cannot trust a listing we could not fully
    # read, so anything >=2 is a hard reject (fail-closed).
    if result.returncode >= 2:
        raise ArchiveRejected(f"cannot list archive (7z rc={result.returncode})")
    return _parse_7z_slt(result.stdout)


def _parse_7z_slt(output: str) -> list[_Member]:
    """Parse ``7z l -slt`` output into members.

    The technical listing emits an archive-level header block first, then a
    ``----------`` separator, then one ``key = value`` block per member. Only
    records after the separator are members (the header's own ``Path`` is the
    archive file itself and must not be treated as an entry).
    """
    members: list[_Member] = []
    cur: dict[str, str] | None = None
    in_members = False

    def _flush() -> None:
        nonlocal cur
        if cur is not None:
            m = _member_from_record(cur)
            if m is not None:
                members.append(m)
            cur = None

    for line in output.splitlines():
        if line.strip() == "----------":
            in_members = True
            continue
        if not in_members:
            continue
        if line.startswith("Path = "):
            _flush()
            cur = {"Path": line[len("Path = ") :]}
        elif cur is not None and " = " in line:
            key, _, value = line.partition(" = ")
            cur[key] = value
        elif not line.strip():
            _flush()
    _flush()
    return members


def _member_from_record(rec: dict[str, str]) -> _Member | None:
    name = rec.get("Path", "")
    if not name:
        return None
    try:
        size = int(rec.get("Size", "0") or 0)
    except ValueError:
        size = 0
    kind, setid = _classify_7z_attrs(rec.get("Attributes", ""), rec.get("Folder", ""))
    return _Member(name=name, size=size if kind == "file" else 0, kind=kind, setid=setid)


def _classify_7z_attrs(attrs: str, folder: str) -> tuple[str, bool]:
    """Classify a 7z member from its Attributes/Folder fields.

    7z encodes the unix mode (when present) inside ``Attributes`` alongside the
    DOS flags, e.g. ``A_ -rw-r--r--`` or ``D_ drwxr-xr-x`` or ``A_ lrwxrwxrwx``.
    The unix type char and the setuid/setgid bits are read from that token; the
    DOS ``D`` flag and the ``Folder = +`` field are the directory fallback.
    """
    kind = "dir" if folder == "+" else "file"
    tokens = attrs.split()
    if tokens and tokens[0].startswith("D"):
        kind = "dir"

    setid = False
    mode = next((t for t in tokens if _UNIX_MODE_RE.fullmatch(t)), None)
    if mode:
        kind = _UNIX_TYPE_MAP.get(mode[0], kind)
        # setuid lives at index 3 (owner-exec), setgid at index 6 (group-exec);
        # 's'/'S' there means the bit is set.
        if mode[3] in ("s", "S") or mode[6] in ("s", "S"):
            setid = True
    return kind, setid


def _extract_7z(path: Path, dest: Path, password: str | None = None) -> None:
    """Extract a zip/7z archive (called only after preflight + caps pass)."""
    cmd = ["7z", "x", str(path), f"-o{dest}", "-y"]
    if password:
        cmd.append(f"-p{password}")
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=_extract_timeout())
    except subprocess.TimeoutExpired as exc:
        raise ArchiveRejected("7z extraction exceeded timeout") from exc
    # SEC-8: 7z rc==1 (warning — e.g. a member could not be read) is treated as
    # FAILURE, not success. A partial extraction must never be mistaken for a
    # clean one when the output is forensic evidence.
    if result.returncode != 0:
        # Sanitize command to strip password before including in error
        safe_cmd = [c if not c.startswith("-p") else "-p***" for c in cmd]
        raise subprocess.CalledProcessError(
            result.returncode, safe_cmd, result.stdout, result.stderr
        )


def _extract_tar(path: Path, dest: Path) -> None:
    """Extract a tar/tar.gz archive (called only after preflight + caps pass)."""
    try:
        subprocess.run(
            ["tar", "xf", str(path), "-C", str(dest)],
            check=True,
            capture_output=True,
            timeout=_extract_timeout(),
        )
    except subprocess.TimeoutExpired as exc:
        raise ArchiveRejected("tar extraction exceeded timeout") from exc


def _verify_no_escape(dest: Path) -> None:
    """Post-extraction walk: no symlink and nothing resolving outside ``dest``.

    Generalised from the old files-only tar check to also cover directories and
    symlinks. A symlink is rejected outright (a member-type check already blocks
    them at preflight, but if a binary ignored that we must not leave a link
    behind that a later scan could follow out of the case jail).
    """
    dest_resolved = dest.resolve()
    for root, dirs, files in os.walk(dest):
        for name in (*dirs, *files):
            full = Path(root, name)
            if full.is_symlink():
                raise ArchiveRejected(f"symlink created during extraction: {full}")
            if not full.resolve().is_relative_to(dest_resolved):
                raise ArchiveRejected(f"path traversal detected in archive: {full}")


# ---------------------------------------------------------------------------
# Disk image mounting
# ---------------------------------------------------------------------------


class MountContext:
    """Track mounts for cleanup."""

    def __init__(self) -> None:
        self._mounts: list[Path] = []  # mount points (sudo umount)
        self._fuse_mounts: list[Path] = []  # FUSE mounts (fusermount -u)
        self._nbd_devices: list[str] = []  # qemu-nbd -d
        self._loop_devices: list[str] = []  # losetup -d

    def add_mount(self, mount_point: Path) -> None:
        self._mounts.append(mount_point)

    def add_fuse(self, mount_point: Path) -> None:
        self._fuse_mounts.append(mount_point)

    def add_nbd(self, device: str) -> None:
        self._nbd_devices.append(device)

    def add_loop(self, device: str) -> None:
        self._loop_devices.append(device)

    def cleanup(self) -> None:
        """Unmount everything in reverse order."""
        for mp in reversed(self._mounts):
            result = subprocess.run(["sudo", "umount", str(mp)], capture_output=True)
            if result.returncode != 0:
                logger.warning(
                    "umount %s failed: %s, trying lazy",
                    mp,
                    result.stderr.decode(errors="replace").strip(),
                )
                subprocess.run(["sudo", "umount", "-l", str(mp)], capture_output=True)
        for mp in reversed(self._fuse_mounts):
            # FUSE mounts are root-owned (sudo xmount/ewfmount) — use sudo
            result = subprocess.run(
                ["sudo", "fusermount", "-u", str(mp)], capture_output=True
            )
            if result.returncode != 0:
                # Fall back to unprivileged in case mount is user-owned
                result2 = subprocess.run(
                    ["fusermount", "-u", str(mp)], capture_output=True
                )
                if result2.returncode != 0:
                    logger.warning(
                        "fusermount -u %s failed: %s",
                        mp,
                        result.stderr.decode(errors="replace").strip(),
                    )
        for dev in self._nbd_devices:
            subprocess.run(["sudo", "qemu-nbd", "-d", dev], capture_output=True)
        for dev in self._loop_devices:
            subprocess.run(["sudo", "losetup", "-d", dev], capture_output=True)


def check_sudo() -> None:
    """Verify non-interactive sudo is available."""
    result = subprocess.run(["sudo", "-n", "true"], capture_output=True)
    if result.returncode != 0:
        raise PermissionError(
            "Disk image mounting requires sudo.\n"
            "Run with: sudo sift ingest <path>\n"
            "Or configure passwordless sudo for mount/umount."
        )


def mount_image(path: Path, dest: Path, ctx: MountContext) -> list[Path]:
    """Mount a disk image read-only. Returns list of mounted volume paths."""
    suffix = path.suffix.lower()
    if suffix in (".e01", ".ex01"):
        return _mount_ewf(path, dest, ctx)
    elif suffix in (".dd", ".raw", ".img", ".iso"):
        return _mount_raw(path, dest, ctx)
    elif suffix in (".vmdk", ".vhd", ".vhdx"):
        return _mount_nbd(path, dest, ctx)
    else:
        raise ValueError(f"Unknown disk image format: {path.name}")


def _mount_ewf(path: Path, dest: Path, ctx: MountContext) -> list[Path]:
    """Mount E01/Ex01 image read-only. Returns list of mounted volume paths.

    Uses a multi-strategy ladder to handle the diversity of E01 images
    found in the wild:

    1. xmount → ntfs-3g       (volume images, FUSE-safe, best success rate)
    2. xmount → mount -o loop  (partitioned images via xmount)
    3. ewfmount → loop mount   (legacy, partitioned images on older systems)
    4. ewfmount → direct mount (last-resort volume images)

    Each strategy is tried in order. Failures are logged and the next
    strategy is attempted. Only when ALL strategies fail does the function
    return an empty list, which the caller surfaces as a structured error.

    xmount requires ``user_allow_other`` in /etc/fuse.conf. The installer
    enables this via ``configure_fuse()``. If missing, strategies 1-2 will
    fail and the function falls through to ewfmount (3-4).
    """
    strategies = [
        _try_xmount_ntfs3g,
        _try_xmount_loop,
        _try_ewfmount_loop,
        _try_ewfmount_direct,
    ]

    last_error = ""
    for strategy in strategies:
        try:
            name = strategy.__name__
            logger.info("E01 mount: trying %s for %s", name, path.name)
            volumes = strategy(path, dest, ctx)
            if volumes:
                logger.info("E01 mount: %s SUCCESS → %d volume(s)", name, len(volumes))
                return volumes
            logger.info("E01 mount: %s returned no volumes, trying next", name)
        except Exception as exc:
            last_error = str(exc)
            logger.warning("E01 mount: %s failed — %s", name, last_error)

    logger.error(
        "E01 mount: ALL strategies exhausted for %s. Last error: %s",
        path.name,
        last_error or "no volumes mounted",
    )
    return []


def _try_xmount_ntfs3g(path: Path, dest: Path, ctx: MountContext) -> list[Path]:
    """Strategy 1: sudo xmount → ntfs-3g (best for volume images).

    xmount is run as root so the FUSE mount is root-owned and accessible
    to sudo mount/ntfs-3g. xmount 0.7.6 (standard on SIFT) does not
    support --allow-other. ntfs-3g reads the exposed .dd file directly
    without loop — avoids the kernel's ``Can't lookup blockdev`` error.
    """
    xmount_dir = dest / "_xmount1"
    xmount_dir.mkdir(exist_ok=True)
    try:
        subprocess.run(
            [
                "sudo", "xmount",
                "--in", "ewf",
                "--out", "raw",
                str(path),
                str(xmount_dir),
            ],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        xmount_dir.rmdir()
        return []

    ctx.add_fuse(xmount_dir)  # cleaned up via sudo fusermount -u
    dd_files = sorted(xmount_dir.glob("*.dd"))
    if not dd_files:
        logger.warning("xmount produced no .dd files in %s", xmount_dir)
        return []

    mounted = []
    for dd_path in dd_files:
        vol = _mount_with_ntfs3g(dd_path, dest, ctx, label=f"xmount-{dd_path.stem}")
        if vol:
            mounted.extend(vol)
    return mounted


def _try_xmount_loop(path: Path, dest: Path, ctx: MountContext) -> list[Path]:
    """Strategy 2: sudo xmount → mount -o loop (for partitioned images).

    sudo xmount makes the .dd file accessible to root's mount command,
    so loop device creation works here (unlike user-owned ewfmount).
    """
    xmount_dir = dest / "_xmount2"
    xmount_dir.mkdir(exist_ok=True)
    try:
        subprocess.run(
            [
                "sudo", "xmount",
                "--in", "ewf",
                "--out", "raw",
                str(path),
                str(xmount_dir),
            ],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        xmount_dir.rmdir()
        return []

    ctx.add_fuse(xmount_dir)
    dd_files = sorted(xmount_dir.glob("*.dd"))
    if not dd_files:
        return []

    mounted = []
    for dd_path in dd_files:
        volumes = _mount_raw_partitions(dd_path, dest, ctx)
        mounted.extend(volumes)
    return mounted


def _try_ewfmount_loop(path: Path, dest: Path, ctx: MountContext) -> list[Path]:
    """Strategy 3: sudo ewfmount → mount -o loop (legacy, partitioned images)."""
    ewf_dir = dest / "_ewf3"
    ewf_dir.mkdir(exist_ok=True)
    try:
        subprocess.run(["sudo", "ewfmount", str(path), str(ewf_dir)], check=True)
    except subprocess.CalledProcessError:
        ewf_dir.rmdir()
        return []

    ctx.add_fuse(ewf_dir)
    raw_path = ewf_dir / "ewf1"
    return _mount_raw_partitions(raw_path, dest, ctx)


def _try_ewfmount_direct(path: Path, dest: Path, ctx: MountContext) -> list[Path]:
    """Strategy 4: sudo ewfmount → direct ntfs-3g (last resort, volume images)."""
    ewf_dir = dest / "_ewf4"
    ewf_dir.mkdir(exist_ok=True)
    try:
        subprocess.run(["sudo", "ewfmount", str(path), str(ewf_dir)], check=True)
    except subprocess.CalledProcessError:
        ewf_dir.rmdir()
        return []

    ctx.add_fuse(ewf_dir)
    raw_path = ewf_dir / "ewf1"

    if _is_ntfs_volume(raw_path):
        return _mount_volume_direct(raw_path, dest, ctx)
    return _mount_raw_partitions(raw_path, dest, ctx)


def _mount_with_ntfs3g(
    dd_path: Path, dest: Path, ctx: MountContext, label: str = "vol"
) -> list[Path]:
    """Mount a raw DD file with ntfs-3g (FUSE-safe, no loop needed)."""
    mount_point = dest / label
    mount_point.mkdir(exist_ok=True)
    try:
        subprocess.run(
            [
                "sudo",
                "ntfs-3g",
                "-o", "ro,noexec",
                str(dd_path),
                str(mount_point),
            ],
            check=True,
            capture_output=True,
        )
        ctx.add_mount(mount_point)
        return [mount_point]
    except (subprocess.CalledProcessError, FileNotFoundError):
        # ntfs-3g may not be installed; that's OK — caller falls through
        try:
            mount_point.rmdir()
        except OSError:
            pass
        return []


def _mount_raw(path: Path, dest: Path, ctx: MountContext) -> list[Path]:
    """Mount raw/dd image via loop device."""
    return _mount_raw_partitions(path, dest, ctx)


def _is_ntfs_volume(path: Path) -> bool:
    """Check if a file starts with an NTFS boot sector (not an MBR/GPT).

    When True, the image is a raw NTFS volume — skip fdisk and mount directly.
    fdisk misinterprets the NTFS boot sector as garbage partition entries,
    producing nonsense offsets that exceed the actual file size.
    """
    try:
        with open(path, "rb") as fh:
            magic = fh.read(8)
        return len(magic) >= 8 and magic[3:8] == b"NTFS "
    except OSError:
        return False


def _mount_raw_partitions(raw_path: Path, dest: Path, ctx: MountContext) -> list[Path]:
    """Detect and mount NTFS partitions from a raw disk image.

    Handles three cases:
    1. Partitioned disk (MBR/GPT with NTFS partitions) — uses fdisk + offset mount.
    2. Raw NTFS volume (no partition table) — detected by NTFS magic bytes,
       skipping the fdisk step that would produce garbage partitions.
    3. Fallback direct mount for anything fdisk could not parse.
    """
    check_sudo()
    mounted = []

    # If this is a raw NTFS volume (starts with NTFS boot sector), skip fdisk
    # entirely. The NTFS magic lives at offset 3. fdisk -l on a volume image
    # produces garbage partition offsets that can exceed the actual file size.
    if _is_ntfs_volume(raw_path):
        return _mount_volume_direct(raw_path, dest, ctx)

    result = subprocess.run(
        ["fdisk", "-l", str(raw_path)],
        capture_output=True,
        text=True,
    )
    partitions = _parse_fdisk_output(result.stdout)

    if partitions:
        for idx, part in enumerate(partitions):
            if part["type"] not in ("NTFS", "Microsoft basic data", "7"):
                continue
            mount_point = dest / f"vol{idx}"
            mount_point.mkdir()
            offset = part["start"] * part["sector_size"]
            try:
                subprocess.run(
                    [
                        "sudo",
                        "mount",
                        "-o",
                        f"ro,loop,offset={offset},noexec",
                        str(raw_path),
                        str(mount_point),
                    ],
                    check=True,
                    capture_output=True,
                )
                ctx.add_mount(mount_point)
                mounted.append(mount_point)
            except subprocess.CalledProcessError:
                mount_point.rmdir()

    # Fallback: direct mount (volume images, or fdisk found nothing useful).
    # _mount_volume_direct already succeeded for detected NTFS volumes above,
    # so this only runs for non-NTFS images where fdisk produced nothing.
    if not mounted:
        return _mount_volume_direct(raw_path, dest, ctx)

    return mounted


def _mount_volume_direct(raw_path: Path, dest: Path, ctx: MountContext) -> list[Path]:
    """Mount a raw volume directly (no partition table / fallback).

    Tries three strategies in order for FUSE-resident files (ewf1 from
    ewfmount), where the kernel loop driver cannot create a device node:
      1. ntfs-3g -o ro,noexec (best for FUSE-hosted NTFS files)
      2. mount -o ro,noexec (kernel NTFS3 driver, no loop)
      3. mount -o ro,loop,noexec (classic fallback for real files)

    Returns a one-element list on success, empty list on failure.
    """
    mount_point = dest / "vol0"
    mount_point.mkdir(exist_ok=True)

    strategies = [
        # ntfs-3g works with regular files and FUSE files alike
        (["sudo", "ntfs-3g", "-o", "ro,noexec", str(raw_path), str(mount_point)], {}),
        # kernel NTFS3 driver without loop (works on some kernels)
        (["sudo", "mount", "-t", "ntfs", "-o", "ro,noexec", str(raw_path), str(mount_point)], {}),
        # classic loop fallback (real files only, fails on FUSE)
        (["sudo", "mount", "-o", "ro,loop,noexec", str(raw_path), str(mount_point)], {}),
    ]

    for cmd, kw in strategies:
        try:
            subprocess.run(cmd, check=True, capture_output=True, **kw)
            ctx.add_mount(mount_point)
            return [mount_point]
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue

    mount_point.rmdir()
    return []


def _parse_fdisk_output(output: str) -> list[dict]:
    """Parse fdisk -l output for partition info."""
    partitions = []
    sector_size = 512

    for line in output.splitlines():
        # Parse sector size line: "Sector size (logical/physical): 512 bytes / 512 bytes"
        m = re.match(r"Sector size.*?:\s*(\d+)\s*bytes", line)
        if m:
            sector_size = int(m.group(1))
            continue

        # Parse partition lines — they start with the device path
        # /dev/sda1  *  2048  1023999  1021952  499M  7  HPFS/NTFS/exFAT
        # Or GPT: /dev/sda1  2048  1023999  1021952  499M  Microsoft basic data
        if not line.startswith("/"):
            continue

        parts = line.split()
        if len(parts) < 6:
            continue

        # Find the start sector — skip boot flag (*) if present
        try:
            start_idx = 1
            if parts[1] == "*":
                start_idx = 2
            start = int(parts[start_idx])
        except (ValueError, IndexError):
            continue

        # Type is the last words after the size column
        # For MBR: type ID then name
        # For GPT: just the name
        ptype = " ".join(parts[start_idx + 4 :])

        partitions.append({"start": start, "sector_size": sector_size, "type": ptype})

    return partitions


# ---------------------------------------------------------------------------
# TSK-based filesystem metadata helpers
# ---------------------------------------------------------------------------

_MEMORY_MAGIC: list[tuple[bytes, int, str]] = [
    (b"LIME", 0, "lime"),
    (b"HIBR", 0, "hibr"),
    (b"PAGEDU64", 0, "pagedu64"),
]


def _run_tsk(tool: str, *args: str) -> tuple[str, int]:
    """Run a Sleuth Kit tool, return (stdout, returncode). Returns ("", -1) if not installed."""
    try:
        result = subprocess.run([tool, *args], capture_output=True, text=True)
        return result.stdout, result.returncode
    except FileNotFoundError:
        return "", -1


def _parse_mmls_output(output: str) -> list[dict]:
    """Parse mmls partition table output, returning real (non-meta) partition rows.

    mmls row format:
      NNN:  NNN:NNN   SSSSSSSS   EEEEEEEE   LLLLLLLL   Description
    Meta/unallocated rows have 'Meta' or '-------' in the slot field.
    """
    partitions = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        # Outer counter ends with ':'
        if not parts[0].endswith(":"):
            continue
        slot = parts[1]
        # Skip meta and unallocated rows
        if slot == "Meta" or slot.startswith("-"):
            continue
        # Real partitions have slot like "000:000"
        if ":" not in slot:
            continue
        try:
            start = int(parts[2])
            end = int(parts[3])
            length = int(parts[4])
        except (ValueError, IndexError):
            continue
        description = " ".join(parts[5:]) if len(parts) > 5 else ""
        partitions.append({
            "slot": slot,
            "start": start,
            "end": end,
            "length": length,
            "description": description,
        })
    return partitions


def _parse_fsstat_output(output: str) -> dict:
    """Parse fsstat output. Note: fsstat uses 'Sector Size' (capital S)."""
    result: dict = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if key == "File System Type":
            result["fs_type"] = value
        elif key == "Cluster Size":
            try:
                result["cluster_size"] = int(value)
            except ValueError:
                pass
        elif key == "Sector Size":
            try:
                result["sector_size"] = int(value)
            except ValueError:
                pass
    return result


def _parse_img_stat_output(output: str) -> dict:
    """Parse img_stat output. Note: img_stat uses 'Sector size' (lowercase s)."""
    result: dict = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if key == "Image Type":
            result["image_format"] = value
        elif key == "Size in bytes":
            try:
                result["size_bytes"] = int(value)
            except ValueError:
                pass
        elif key == "Sector size":
            try:
                result["sector_size"] = int(value)
            except ValueError:
                pass
    return result


def _fs_meta_memory(image_path: str) -> dict:
    """Collect metadata for a memory image via magic-byte detection."""
    size_bytes = 0
    try:
        size_bytes = Path(image_path).stat().st_size
    except OSError:
        pass

    memory_format = "raw"
    try:
        with open(image_path, "rb") as f:
            header = f.read(16)
        for magic, offset, fmt in _MEMORY_MAGIC:
            if header[offset : offset + len(magic)] == magic:
                memory_format = fmt
                break
    except OSError:
        pass

    return {
        "image_type": "memory_image",
        "memory_format": memory_format,
        "size_bytes": size_bytes,
    }


def _fs_meta_disk(image_path: str) -> dict:
    """Collect filesystem metadata for a disk/EWF image via TSK.

    Three outcomes:
    - partitioned_disk: mmls exits 0 and returns real partition rows
    - ntfs_volume: mmls exits non-zero; fsstat at offset 0 succeeds
    - unknown: all TSK probes fail or tools absent
    """
    mmls_out, mmls_rc = _run_tsk("mmls", image_path)
    partitions = _parse_mmls_output(mmls_out) if mmls_rc == 0 else []

    stat_out, stat_rc = _run_tsk("img_stat", image_path)
    img_meta = _parse_img_stat_output(stat_out) if stat_rc == 0 else {}

    if partitions:
        partition_meta = []
        for p in partitions:
            fs_out, fs_rc = _run_tsk("fsstat", "-o", str(p["start"]), image_path)
            fs_meta = _parse_fsstat_output(fs_out) if fs_rc == 0 else {}
            partition_meta.append({
                "slot": p["slot"],
                "start_sector": p["start"],
                "length_sectors": p["length"],
                "description": p["description"],
                **fs_meta,
            })
        return {"image_type": "partitioned_disk", "partitions": partition_meta, **img_meta}

    # No partition table — try fsstat at offset 0 (raw volume image)
    fs_out, fs_rc = _run_tsk("fsstat", image_path)
    if fs_rc == 0:
        return {"image_type": "ntfs_volume", **img_meta, **_parse_fsstat_output(fs_out)}

    return {"image_type": "unknown"}


def _collect_filesystem_meta(image_path: str, container_format: str) -> dict:
    """Collect filesystem metadata sidecar for disk or memory images.

    Returns a dict suitable for JSON serialisation. Always returns at minimum
    {"image_type": "unknown"} — never raises.
    """
    try:
        if container_format == "memory":
            return _fs_meta_memory(image_path)
        return _fs_meta_disk(image_path)
    except Exception:
        return {"image_type": "unknown"}


def _mount_nbd(path: Path, dest: Path, ctx: MountContext) -> list[Path]:
    """Mount VMDK/VHD/VHDX via qemu-nbd."""
    check_sudo()
    subprocess.run(
        ["sudo", "modprobe", "nbd", "max_part=8"],
        capture_output=True,
    )
    nbd_dev = _find_free_nbd()
    subprocess.run(
        ["sudo", "qemu-nbd", "-r", "-c", nbd_dev, str(path)],
        check=True,
        capture_output=True,
    )
    ctx.add_nbd(nbd_dev)

    # Wait for kernel to detect partitions (retry under concurrent I/O load)
    partitions: list[str] = []
    for _attempt in range(10):
        time.sleep(1)
        partitions = sorted(glob.glob(f"{nbd_dev}p*"))
        if partitions:
            break
    else:
        # Last resort: force kernel to re-read partition table
        subprocess.run(["sudo", "partprobe", nbd_dev], capture_output=True)
        time.sleep(1)
        partitions = sorted(glob.glob(f"{nbd_dev}p*"))

    mounted = []
    for part_dev in partitions:
        mount_point = dest / Path(part_dev).name
        mount_point.mkdir()
        try:
            subprocess.run(
                [
                    "sudo",
                    "mount",
                    "-o",
                    "ro,noexec",
                    part_dev,
                    str(mount_point),
                ],
                check=True,
                capture_output=True,
            )
            ctx.add_mount(mount_point)
            mounted.append(mount_point)
        except subprocess.CalledProcessError:
            mount_point.rmdir()

    return mounted


def _find_free_nbd() -> str:
    """Find an unused /dev/nbd* device."""
    for i in range(8):
        dev = f"/dev/nbd{i}"
        size_path = Path(f"/sys/block/nbd{i}/size")
        if size_path.exists():
            size = int(size_path.read_text().strip())
            if size == 0:
                return dev
    raise RuntimeError("No available NBD devices (nbd0-nbd7 all in use)")


# ---------------------------------------------------------------------------
# VSS
# ---------------------------------------------------------------------------


def mount_vss(raw_path: Path, dest: Path, ctx: MountContext) -> list[tuple[str, Path]]:
    """Mount volume shadow copies. Returns list of (vss_id, mount_path)."""
    # Check if vshadowinfo is available and image has VSS
    result = subprocess.run(
        ["vshadowinfo", str(raw_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return []

    # Parse number of stores
    num_stores = 0
    for line in result.stdout.splitlines():
        m = re.match(r"Number of stores:\s*(\d+)", line.strip())
        if m:
            num_stores = int(m.group(1))
            break
    if num_stores == 0:
        return []

    # Mount all stores via vshadowmount
    vss_mount = dest / "_vss"
    vss_mount.mkdir()
    try:
        subprocess.run(
            ["vshadowmount", str(raw_path), str(vss_mount)],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        vss_mount.rmdir()
        return []
    ctx.add_fuse(vss_mount)

    # Mount each vssN file as a filesystem
    results = []
    for i in range(1, num_stores + 1):
        vss_file = vss_mount / f"vss{i}"
        if not vss_file.exists():
            continue
        vss_mp = dest / f"vss{i}"
        vss_mp.mkdir()
        try:
            subprocess.run(
                [
                    "sudo",
                    "mount",
                    "-o",
                    "ro,loop,noexec",
                    str(vss_file),
                    str(vss_mp),
                ],
                check=True,
                capture_output=True,
            )
            ctx.add_mount(vss_mp)
            results.append((f"vss{i}", vss_mp))
        except subprocess.CalledProcessError:
            vss_mp.rmdir()

    return results


# ---------------------------------------------------------------------------
# Velociraptor offline collector
# ---------------------------------------------------------------------------


def is_velociraptor_collection(extract_dir: Path) -> bool:
    """Check if extracted directory is a Velociraptor offline collector."""
    return (extract_dir / "uploads" / "auto").is_dir()


def normalize_velociraptor(extract_dir: Path) -> Path:
    """Normalize Velociraptor offline collector directory structure.

    URL-decodes all path names under uploads/auto/ (e.g., C%3A → C:).
    Returns the auto/ directory for volume root scanning.
    """
    auto_dir = extract_dir / "uploads" / "auto"
    if not auto_dir.is_dir():
        raise ValueError("Not a Velociraptor offline collector (no uploads/auto/)")

    # URL-decode all directory and file names (bottom-up to avoid
    # renaming parents before children).
    for path in sorted(safe_rglob(auto_dir, "*"), key=lambda p: len(p.parts), reverse=True):
        decoded = urllib.parse.unquote(path.name)
        if decoded != path.name:
            # Validate decoded name doesn't contain path separators or traversal
            if "/" in decoded or "\\" in decoded or ".." in decoded:
                continue
            new_path = path.parent / decoded
            path.rename(new_path)
            print(f"  Renamed {path.name} -> {decoded}")

    return auto_dir


def read_velociraptor_hostname(extract_dir: Path) -> str | None:
    """Read hostname from Velociraptor collection_context.json."""
    ctx_file = extract_dir / "collection_context.json"
    if not ctx_file.exists():
        return None
    try:
        ctx = json.loads(ctx_file.read_text())
        client = ctx.get("client_info", {})
        return client.get("fqdn") or client.get("hostname")
    except (json.JSONDecodeError, OSError):
        return None


# ---------------------------------------------------------------------------
# Temp directory management
# ---------------------------------------------------------------------------


def make_ingest_tmpdir(case_id: str) -> Path:
    """Create temp dir for container extraction under the actual case directory."""
    import os
    from datetime import datetime, timezone

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")

    # Use SIFT_CASE_DIR if set (portal workflow); else fall back to SIFT_CASES_ROOT/case_id
    case_dir_env = os.environ.get("SIFT_CASE_DIR", "").strip()
    if case_dir_env:
        case_dir = Path(case_dir_env)
    else:
        # Legacy CLI fallback — not used in portal workflow
        case_dir = cases_root() / case_id

    tmp = case_dir / "tmp" / f"ingest-{ts}-{os.getpid()}"
    tmp.mkdir(parents=True, exist_ok=True)
    return tmp


def cleanup_orphaned_mounts() -> None:
    """Clean up orphaned nbd connections from prior failed ingests.

    Skips cleanup if another ingest is currently running -- avoids
    disconnecting devices held by a concurrent process (B18).

    NOTE: TOCTOU race exists between reading active ingests and
    disconnecting nbd devices. A new ingest could start between the
    check and the disconnect. Full fix requires file-level locking
    around nbd operations. Current risk is low (cleanup only runs
    at ingest start, not continuously).
    """
    import sys

    from opensearch_mcp.ingest_status import read_active_ingests

    try:
        active = read_active_ingests()
        if any(ing.get("status") == "running" for ing in active):
            return
    except Exception as exc:
        logger.debug("Failed to read active ingests during cleanup check: %s", exc)

    for i in range(8):
        size_path = Path(f"/sys/block/nbd{i}/size")
        if size_path.exists():
            try:
                size = int(size_path.read_text().strip())
            except (OSError, ValueError):
                continue
            if size > 0:
                dev = f"/dev/nbd{i}"
                # Try to unmount any partitions first
                for part in sorted(glob.glob(f"{dev}p*")):
                    subprocess.run(["sudo", "umount", part], capture_output=True)
                subprocess.run(["sudo", "qemu-nbd", "-d", dev], capture_output=True)
                print(f"  Cleaned orphaned nbd: {dev}", file=sys.stderr)


def cleanup_tmpdir(tmpdir: Path, force: bool = False) -> None:
    """Clean up temp directory. On failure, preserve with warning."""
    try:
        shutil.rmtree(tmpdir)
    except OSError as e:
        if force:
            raise
        import sys

        print(
            f"WARNING: Could not remove temp dir {tmpdir}: {e}\n"
            "  Extracted evidence preserved for re-processing.",
            file=sys.stderr,
        )
