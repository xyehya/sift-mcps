"""Container handling: archive extraction and disk image mounting."""

from __future__ import annotations

import glob
import json
import logging
import os
import re
import shutil
import subprocess
import time
import urllib.parse
from pathlib import Path

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


def extract_container(path: Path, dest: Path, password: str | None = None) -> None:
    """Extract archive to dest directory."""
    suffix = path.suffix.lower()
    suffixes = "".join(path.suffixes[-2:]).lower()

    if suffix in (".zip", ".7z"):
        _extract_7z(path, dest, password)
    elif suffixes in (".tar.gz", ".tgz") or suffix == ".tar":
        _extract_tar(path, dest)
    else:
        raise ValueError(f"Unknown archive format: {path.name}")


def _extract_7z(path: Path, dest: Path, password: str | None = None) -> None:
    """Extract archive with 7z."""
    cmd = ["7z", "x", str(path), f"-o{dest}", "-y"]
    if password:
        cmd.append(f"-p{password}")
    result = subprocess.run(cmd, capture_output=True)
    # 7z exit codes: 0=ok, 1=warning (timestamps), 2+=error
    if result.returncode > 1:
        # Sanitize command to strip password before including in error
        safe_cmd = [c if not c.startswith("-p") else "-p***" for c in cmd]
        raise subprocess.CalledProcessError(
            result.returncode, safe_cmd, result.stdout, result.stderr
        )


def _extract_tar(path: Path, dest: Path) -> None:
    """Extract tar/tar.gz archive with path traversal validation."""
    subprocess.run(["tar", "xf", str(path), "-C", str(dest)], check=True)
    # Validate no files escaped destination
    dest_resolved = dest.resolve()
    for root, _dirs, files in os.walk(dest):
        for f in files:
            full = Path(root, f).resolve()
            if not full.is_relative_to(dest_resolved):
                raise ValueError(f"Path traversal detected in archive: {full}")


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
            "Run with: sudo agentir ingest <path>\n"
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

    # Use AGENTIR_CASE_DIR if set (portal workflow); else fall back to AGENTIR_CASES_ROOT/case_id
    case_dir_env = os.environ.get("AGENTIR_CASE_DIR", "").strip()
    if case_dir_env:
        case_dir = Path(case_dir_env)
    else:
        # Legacy CLI fallback — not used in portal workflow
        cases_root = Path(
            os.environ.get("AGENTIR_CASES_ROOT")
            or os.environ.get("AGENTIR_CASES_DIR")
            or str(Path.home() / "cases")
        )
        case_dir = cases_root / case_id

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
    except Exception:
        pass

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
