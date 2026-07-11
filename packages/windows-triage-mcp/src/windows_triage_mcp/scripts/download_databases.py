"""Download pre-built triage databases from GitHub releases.

Replaces the shell script ``download-databases.sh`` with a cross-platform
Python implementation that works inside the Valhuntir venv.

Usage:
    python -m windows_triage_mcp.scripts.download_databases [--dest DIR] [--tag TAG]
        [--with-registry] [--yes]

    The default install fetches known_good.db + context.db. The optional full
    registry baseline (known_good_registry.db, ~12 GB decompressed) is fetched
    only with --with-registry, gated on a disk-space check and operator
    confirmation (--yes assumes yes for non-interactive installs).

Authentication:
    For private repos, set GITHUB_TOKEN or have ``gh`` CLI authenticated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from windows_triage_mcp.config import BASELINE_TRANSACTION_MARKER, get_config

REPO = "AppliedIR/sift-mcp"
DEFAULT_RELEASE_TAG = "triage-db-v2026.02.25"
ASSETS = ("known_good.db.zst", "context.db.zst", "checksums.sha256")
BASELINE_PROVENANCE_NAME = "baseline-provenance.json"
BASELINE_PROVENANCE_SCHEMA = "sift.windows-triage.baseline-provenance/v1"
PINNED_BASELINE = {
    "known_good.db": {
        "compressed_asset": "known_good.db.zst",
        "compressed_asset_sha256": "95c739d6b3932aaf85366b3c031ada9c21abd52a109fa81d5bd81c880120173e",
        "decompressed_sha256": "d80df709eb2a0cbcf5217ca06e724bcd471cb00c1d47c1e943b529ab271f0472",
        "size_bytes": 5_935_333_376,
    },
    "context.db": {
        "compressed_asset": "context.db.zst",
        "compressed_asset_sha256": "615b668a7a23741ec9995e5b976901d63ec639f30128601145277198f6c95bd0",
        "decompressed_sha256": "133e7d020ddc86b078f9e9ce699350c2548f3d69b0d5e3d0fa17253f9bea0236",
        "size_bytes": 2_486_272,
    },
}
# Optional full registry baseline. ~500 MB compressed, ~12 GB decompressed.
# Downloaded only on explicit opt-in (--with-registry) because of its size; the
# default ASSETS install never fetches it.
REGISTRY_ASSET = "known_good_registry.db.zst"
REGISTRY_DB_NAME = "known_good_registry.db"
# Decompressed registry DB is ~12 GB; require headroom for the .zst plus the DB.
REGISTRY_MIN_FREE_BYTES = 15 * 1024 * 1024 * 1024  # ~15 GB
MAX_ATTEMPTS = 3
CHUNK_SIZE = 1024 * 1024  # 1 MB


def _github_headers() -> dict[str, str]:
    """Build HTTP headers for GitHub API, including token if available.

    Token sources (in order): GITHUB_TOKEN env var, ``gh auth token`` CLI.
    """
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        try:
            result = subprocess.run(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                token = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch_release(tag: str = DEFAULT_RELEASE_TAG) -> dict:
    """Fetch metadata for an exact release tag from the GitHub API."""
    headers = _github_headers()
    url = f"https://api.github.com/repos/{REPO}/releases/tags/{tag}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _get_asset_url(release: dict, asset_name: str) -> str | None:
    """Extract the API download URL for a named asset."""
    for asset in release.get("assets", []):
        if asset["name"] == asset_name:
            return asset["url"]
    return None


def _download_asset(url: str, dest: Path) -> None:
    """Download a single asset to dest with progress indication."""
    headers = _github_headers()
    headers["Accept"] = "application/octet-stream"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=300) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(CHUNK_SIZE)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if total > 0:
                    pct = downloaded * 100 // total
                    mb = downloaded / (1024 * 1024)
                    print(f"\r  {dest.name}: {mb:.1f} MB ({pct}%)", end="", flush=True)
        print()


def _sha256_file(path: Path) -> str:
    """Return a file's SHA-256 without loading a large baseline into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_checksums(checksum_file: Path) -> dict[str, str] | None:
    """Read a strict SHA-256 manifest keyed by basename.

    Release metadata is untrusted until verified.  Ignore unrelated entries but
    reject malformed entries for requested assets rather than silently skipping
    their integrity check.
    """
    if not checksum_file.is_file():
        print("  Missing checksums.sha256; refusing unverified baseline assets.")
        return None

    checksums: dict[str, str] = {}
    for raw_line in checksum_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        digest, filename = parts
        filename = filename.strip().lstrip("*")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            continue
        # A checksum manifest must name a plain release asset, not traverse out
        # of the temporary download directory.
        if not filename or Path(filename).name != filename:
            continue
        checksums[filename] = digest.lower()
    return checksums


def _verify_checksums(temp_dir: Path, required_assets: tuple[str, ...]) -> bool:
    """Fail closed unless every requested compressed asset has a valid SHA-256."""
    checksum_file = temp_dir / "checksums.sha256"
    checksums = _load_checksums(checksum_file)
    if checksums is None:
        return False

    for file_name in required_assets:
        file_path = temp_dir / file_name
        if not file_path.is_file():
            print(f"  Missing downloaded asset: {file_name}")
            return False
        expected_hash = checksums.get(file_name)
        if expected_hash is None:
            print(f"  Missing SHA-256 manifest entry: {file_name}")
            return False
        actual_hash = _sha256_file(file_path)
        if actual_hash == expected_hash:
            print(f"  OK: {file_name}")
        else:
            print(f"  FAILED: {file_name}")
            print(f"    expected: {expected_hash}")
            print(f"    got:      {actual_hash}")
            return False
    return True


def _write_registry_provenance(
    dest: Path, tag_name: str, compressed_sha256: str
) -> None:
    """Persist non-secret provenance after the optional registry DB verifies."""
    registry_db = dest / REGISTRY_DB_NAME
    provenance = registry_db.with_name(f"{REGISTRY_DB_NAME}.provenance.json")
    payload = {
        "schema": "sift.windows-triage.registry-provenance/v1",
        "repository": REPO,
        "release_tag": tag_name,
        "asset": REGISTRY_ASSET,
        "compressed_asset_sha256": compressed_sha256,
        "decompressed_sha256": _sha256_file(registry_db),
        "verified_at": datetime.now(UTC).isoformat(),
    }
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=dest,
        prefix=f".{provenance.name}.",
        delete=False,
    ) as handle:
        json.dump(payload, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    os.replace(temporary, provenance)
    os.chmod(provenance, 0o640)


def _write_baseline_provenance(
    dest: Path, tag_name: str, compressed_hashes: dict[str, str]
) -> None:
    """Atomically bind installed core DB bytes to their verified release assets."""
    provenance = dest / BASELINE_PROVENANCE_NAME
    databases = {}
    for asset in ("known_good.db.zst", "context.db.zst"):
        db = dest / asset.removesuffix(".zst")
        databases[db.name] = {
            "compressed_asset": asset,
            "compressed_asset_sha256": compressed_hashes[asset],
            "decompressed_sha256": _sha256_file(db),
            "size_bytes": db.stat().st_size,
        }
    payload = {
        "schema": BASELINE_PROVENANCE_SCHEMA,
        "repository": REPO,
        "release_tag": tag_name,
        "databases": databases,
        "verified_at": datetime.now(UTC).isoformat(),
    }
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=dest,
        prefix=f".{provenance.name}.",
        delete=False,
    ) as handle:
        json.dump(payload, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    os.replace(temporary, provenance)
    os.chmod(provenance, 0o640)


def _installed_baseline_is_verified(dest: Path, tag: str) -> bool:
    """Validate the installed pinned baseline without consulting the network."""
    if (dest / BASELINE_TRANSACTION_MARKER).exists():
        return False
    provenance = dest / BASELINE_PROVENANCE_NAME
    try:
        payload = json.loads(provenance.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    if (
        payload.get("schema") != BASELINE_PROVENANCE_SCHEMA
        or payload.get("repository") != REPO
        or payload.get("release_tag") != tag
    ):
        return False
    databases = payload.get("databases")
    if not isinstance(databases, dict):
        return False
    expected_tables = {
        "known_good.db": (("baseline_files", 1_000_000),),
        "context.db": (("lolbins", 100), ("vulnerable_drivers", 100)),
    }
    for name, table_checks in expected_tables.items():
        record = databases.get(name)
        pinned = PINNED_BASELINE[name]
        db = dest / name
        if not isinstance(record, dict) or not db.is_file() or db.is_symlink():
            return False
        digest = record.get("decompressed_sha256")
        size = record.get("size_bytes")
        if (
            not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not isinstance(size, int)
            or size <= 0
            or db.stat().st_size != size
            or _sha256_file(db) != digest
            or record != pinned
        ):
            return False
        for table, minimum in table_checks:
            if not _verify_database(db, table, minimum, f"installed {name} ({table})"):
                return False
    return True


def _adopt_verified_pinned_baseline(dest: Path, tag: str) -> bool:
    """Create a receipt for a legacy install only when its bytes match the repo pin."""
    if tag != DEFAULT_RELEASE_TAG:
        return False
    compressed_hashes: dict[str, str] = {}
    for name, pinned in PINNED_BASELINE.items():
        db = dest / name
        if (
            not db.is_file()
            or db.is_symlink()
            or db.stat().st_size != pinned["size_bytes"]
            or _sha256_file(db) != pinned["decompressed_sha256"]
        ):
            return False
        compressed_hashes[str(pinned["compressed_asset"])] = str(
            pinned["compressed_asset_sha256"]
        )
    _write_baseline_provenance(dest, tag, compressed_hashes)
    return _installed_baseline_is_verified(dest, tag)


def _checksums_match_repository_pin(tag: str, checksums: dict[str, str]) -> bool:
    """Reject a validly formatted release checksum file that differs from our pin."""
    return tag == DEFAULT_RELEASE_TAG and all(
        checksums.get(str(pinned["compressed_asset"]))
        == pinned["compressed_asset_sha256"]
        for pinned in PINNED_BASELINE.values()
    )


def verify_installed_baseline(dest: Path, tag: str = DEFAULT_RELEASE_TAG) -> bool:
    """Network-free validation for installer offline mode and rerun preflight."""
    return _installed_baseline_is_verified(
        dest, tag
    ) or _adopt_verified_pinned_baseline(dest, tag)


def _begin_baseline_transaction(dest: Path, tag: str) -> Path:
    """Publish a fail-closed marker before committing a multi-file baseline set."""
    marker = dest / BASELINE_TRANSACTION_MARKER
    if not marker.exists():
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, f"{tag}\n".encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_directory(dest)
    return marker


def _fsync_directory(path: Path) -> None:
    """Persist rename/unlink ordering for the baseline transaction."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _finish_baseline_transaction(marker: Path) -> None:
    """Make a completely committed release set visible to the runtime."""
    _fsync_directory(marker.parent)
    marker.unlink()
    _fsync_directory(marker.parent)


def _free_bytes(path: Path) -> int:
    """Free bytes available at the nearest existing ancestor of path."""
    probe = path
    while not probe.exists():
        if probe.parent == probe:
            break
        probe = probe.parent
    return shutil.disk_usage(probe).free


def _check_registry_disk_space(dest: Path) -> bool:
    """Verify enough free space at dest for the ~12 GB registry DB.

    Returns True when at least REGISTRY_MIN_FREE_BYTES is available.
    """
    free = _free_bytes(dest)
    free_gb = free / (1024 * 1024 * 1024)
    need_gb = REGISTRY_MIN_FREE_BYTES / (1024 * 1024 * 1024)
    if free < REGISTRY_MIN_FREE_BYTES:
        print(
            f"  Insufficient disk space at {dest}: "
            f"{free_gb:.1f} GB free, need ~{need_gb:.0f} GB for the "
            f"registry baseline (~12 GB decompressed)."
        )
        return False
    print(f"  Disk space OK: {free_gb:.1f} GB free at {dest}.")
    return True


def _decompress_zst(src: Path, dest: Path) -> None:
    """Decompress a .zst file using the zstandard library."""
    import zstandard as zstd

    dctx = zstd.ZstdDecompressor()
    with open(src, "rb") as fin, open(dest, "wb") as fout:
        dctx.copy_stream(fin, fout)


def _verify_database(db_path: Path, table: str, min_rows: int, label: str) -> bool:
    """Check that a database table has at least min_rows rows."""
    if not db_path.is_file():
        print(f"  {label}: missing")
        return False
    try:
        conn = sqlite3.connect(str(db_path))
        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        conn.close()
        if count >= min_rows:
            print(f"  {label}: {count:,} rows")
            return True
        else:
            print(f"  {label}: only {count:,} rows (expected {min_rows:,}+)")
            return False
    except Exception as e:
        print(f"  {label}: verification error ({e})")
        return False


def download_databases(
    dest_dir: str | Path, tag: str = DEFAULT_RELEASE_TAG, with_registry: bool = False
) -> bool:
    """Download and verify triage databases.

    Args:
        dest_dir: Directory to place the decompressed .db files.
        tag: GitHub release tag (default: "latest").
        with_registry: When True, also download the optional ~12 GB full
            registry baseline (known_good_registry.db). Off by default because
            of its size; the caller is responsible for the disk-space check and
            operator confirmation before opting in.

    Returns:
        True on success, False on failure.
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    if tag != DEFAULT_RELEASE_TAG:
        print(
            f"Refusing unpinned Windows-triage release {tag!r}; "
            f"this build permits only {DEFAULT_RELEASE_TAG!r}."
        )
        return False
    installed_verified = _installed_baseline_is_verified(dest, tag)
    if not installed_verified:
        installed_verified = _adopt_verified_pinned_baseline(dest, tag)
    if installed_verified and not with_registry:
        print(
            f"Verified installed Windows-triage baseline for pinned release {tag}; skipping download."
        )
        return True
    if with_registry and not _check_registry_disk_space(dest):
        # Keep the free-space gate inside the reusable API as well as main(),
        # so programmatic callers cannot accidentally bypass the 12 GiB guard.
        return False

    print(f"Fetching release info from {REPO}...")
    try:
        release = _fetch_release(tag)
    except Exception as e:
        print(f"Failed to fetch release: {e}")
        return False

    tag_name = release.get("tag_name", tag)
    print(f"Release: {tag_name}")

    # Compose the per-run download set: the default baseline assets plus the
    # optional registry asset when explicitly requested.
    core_update_needed = not installed_verified
    assets: list[str] = ["checksums.sha256"]
    if core_update_needed:
        assets[:0] = ["known_good.db.zst", "context.db.zst"]
    if with_registry:
        if _get_asset_url(release, REGISTRY_ASSET) is None:
            print(
                f"  Optional registry asset {REGISTRY_ASSET} is not present in "
                f"release {tag_name}; cannot fulfill --with-registry."
            )
            return False
        assets.append(REGISTRY_ASSET)
        print(
            f"  Registry baseline requested: will also download {REGISTRY_ASSET} "
            f"(~12 GB decompressed)."
        )

    for attempt in range(1, MAX_ATTEMPTS + 1):
        # Co-locate the per-attempt temp dir under dest (created above) so it
        # lives on the same filesystem as the final .db files. The compressed
        # .zst download (~500 MB for the registry asset) lands here before being
        # decompressed (~12 GB) into dest, so keeping both on one filesystem lets
        # the single disk-space check at dest correctly cover the whole pipeline
        # instead of silently passing when a small/separate system /tmp would
        # fill mid-download.
        temp_dir = Path(tempfile.mkdtemp(prefix="triage-db-", dir=dest))
        try:
            # Download assets
            print(f"\nDownloading (attempt {attempt}/{MAX_ATTEMPTS})...")
            download_ok = True
            for asset_name in assets:
                url = _get_asset_url(release, asset_name)
                if not url:
                    print(f"  Asset not found in release: {asset_name}")
                    download_ok = False
                    continue
                try:
                    _download_asset(url, temp_dir / asset_name)
                except Exception as e:
                    print(f"  Download failed for {asset_name}: {e}")
                    download_ok = False

            if not download_ok:
                if attempt < MAX_ATTEMPTS:
                    wait = attempt * 5
                    print(f"  Retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                print("All download attempts failed.")
                return False

            # Verify checksums
            print("\nVerifying checksums...")
            required_assets = tuple(
                asset for asset in assets if asset != "checksums.sha256"
            )
            if not _verify_checksums(temp_dir, required_assets):
                if attempt < MAX_ATTEMPTS:
                    wait = attempt * 5
                    print(f"  Checksum mismatch. Retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                print("Checksum verification failed after all attempts.")
                return False
            checksums = _load_checksums(temp_dir / "checksums.sha256")
            if checksums is None or not _checksums_match_repository_pin(
                tag_name, checksums
            ):
                print(
                    "Release checksums do not match the repository-pinned baseline; refusing update."
                )
                return False

            # Decompress into the attempt directory. Never overwrite a known-good
            # installed DB until every requested replacement has validated.
            print("\nDecompressing...")
            decompress_set = (
                ["known_good.db.zst", "context.db.zst"] if core_update_needed else []
            )
            if with_registry:
                decompress_set.append(REGISTRY_ASSET)
            for zst_name in decompress_set:
                zst_path = temp_dir / zst_name
                db_name = zst_name.removesuffix(".zst")
                db_path = temp_dir / db_name
                print(f"  {db_name}...", end="", flush=True)
                _decompress_zst(zst_path, db_path)
                size_mb = db_path.stat().st_size / (1024 * 1024)
                print(f" {size_mb:.1f} MB")

            # Verify databases
            print("\nVerifying databases...")
            ok = True
            if core_update_needed:
                ok &= _verify_database(
                    temp_dir / "known_good.db",
                    "baseline_files",
                    1_000_000,
                    "known_good.db",
                )
                ok &= _verify_database(
                    temp_dir / "context.db", "lolbins", 100, "context.db (lolbins)"
                )
                ok &= _verify_database(
                    temp_dir / "context.db",
                    "vulnerable_drivers",
                    100,
                    "context.db (drivers)",
                )
            if with_registry:
                ok &= _verify_database(
                    temp_dir / REGISTRY_DB_NAME,
                    "baseline_registry",
                    1_000_000,
                    "known_good_registry.db",
                )

            if ok:
                if (
                    core_update_needed
                    and tag_name == DEFAULT_RELEASE_TAG
                    and any(
                        (temp_dir / name).stat().st_size != pinned["size_bytes"]
                        or _sha256_file(temp_dir / name)
                        != pinned["decompressed_sha256"]
                        for name, pinned in PINNED_BASELINE.items()
                    )
                ):
                    print(
                        "Decompressed databases do not match the repository pin; refusing update."
                    )
                    return False
                marker = None
                if core_update_needed:
                    marker = _begin_baseline_transaction(dest, tag_name)
                    for db_name in ("known_good.db", "context.db"):
                        os.replace(temp_dir / db_name, dest / db_name)
                    _write_baseline_provenance(dest, tag_name, checksums)
                if with_registry:
                    registry_sha256 = (
                        checksums.get(REGISTRY_ASSET) if checksums else None
                    )
                    if registry_sha256 is None:
                        print("Registry provenance failed: missing registry SHA-256.")
                        return False
                    os.replace(temp_dir / REGISTRY_DB_NAME, dest / REGISTRY_DB_NAME)
                    _write_registry_provenance(dest, tag_name, registry_sha256)
                if marker is not None:
                    _finish_baseline_transaction(marker)
                print("\nDatabases installed successfully.")
                return True
            else:
                print("\nDatabase verification failed.")
                return False

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download pre-built triage databases from GitHub releases.",
    )
    parser.add_argument(
        "--dest",
        default=None,
        help=(
            "Destination directory. When omitted, defers to the add-on's "
            "runtime config: $SIFT_WINDOWS_TRIAGE_DB_DIR, then $WT_DATA_DIR, "
            "then /var/lib/sift/windows-triage."
        ),
    )
    parser.add_argument(
        "--verify-installed",
        action="store_true",
        help="Verify the installed repository-pinned core baseline without network access.",
    )
    parser.add_argument(
        "--tag",
        default=DEFAULT_RELEASE_TAG,
        help=f"Exact release tag to download (default: pinned {DEFAULT_RELEASE_TAG})",
    )
    parser.add_argument(
        "--with-registry",
        action="store_true",
        help=(
            "Also download the OPTIONAL full registry baseline "
            "(known_good_registry.db, ~12 GB decompressed). Requires ~15 GB free "
            "at the destination. Skipped by default."
        ),
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help=(
            "Assume yes to the registry-baseline confirmation prompt "
            "(for non-interactive installs)."
        ),
    )
    args = parser.parse_args()

    # Single source of truth for the baseline dir: an explicit --dest wins,
    # otherwise defer to the add-on's own runtime resolution
    # (config.get_config: SIFT_WINDOWS_TRIAGE_DB_DIR -> WT_DATA_DIR ->
    # /var/lib/sift/windows-triage). This guarantees the download lands exactly
    # where the runtime later reads the databases from, rather than diverging
    # into the package source tree. reload=True so this one-shot CLI honors the
    # current process environment.
    if args.dest:
        dest = Path(args.dest)
    else:
        dest = get_config(reload=True).data_dir

    if args.verify_installed:
        if args.with_registry:
            parser.error(
                "--verify-installed does not provision the optional registry baseline"
            )
        sys.exit(0 if verify_installed_baseline(dest, args.tag) else 1)

    # Gate the optional ~12 GB registry baseline on (a) a disk-space check and
    # (b) explicit operator confirmation, so it is never pulled silently.
    with_registry = args.with_registry
    if with_registry:
        print(
            "\nThe optional full registry baseline (known_good_registry.db) is "
            "~500 MB compressed and ~12 GB on disk."
        )
        if not _check_registry_disk_space(dest):
            print("Aborting: not enough free disk space for the registry baseline.")
            sys.exit(1)
        if not args.yes:
            confirm = ""
            try:
                confirm = input(
                    f"Download and install the ~12 GB registry baseline to "
                    f"{dest}? [y/N]: "
                ).strip()
            except EOFError:
                confirm = ""
            if confirm.lower() not in ("y", "yes"):
                print("Skipping registry baseline (not confirmed).")
                with_registry = False

    if download_databases(dest, args.tag, with_registry=with_registry):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
