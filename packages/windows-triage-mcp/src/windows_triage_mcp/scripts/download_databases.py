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
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from windows_triage_mcp.config import get_config

REPO = "AppliedIR/sift-mcp"
ASSETS = ("known_good.db.zst", "context.db.zst", "checksums.sha256")
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


def _fetch_release(tag: str = "latest") -> dict:
    """Fetch release metadata from GitHub API.

    When tag is "latest", finds the most recent triage-db-* release
    that contains .db.zst assets. Otherwise fetches the exact tag.
    """
    headers = _github_headers()

    if tag == "latest":
        # Find most recent triage DB release by tag prefix.
        # per_page=100 prevents pagination issues as code releases
        # accumulate (default is 30).
        url = f"https://api.github.com/repos/{REPO}/releases?per_page=100"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            releases = json.loads(resp.read())
            matching = [
                r
                for r in releases
                if r["tag_name"].startswith("triage-db-")
                and any(a["name"].endswith(".db.zst") for a in r.get("assets", []))
            ]
            if matching:
                return matching[0]  # GitHub returns most recent first
            raise ValueError(
                "No triage database releases found. "
                "Expected releases with tag prefix 'triage-db-' "
                "containing .db.zst assets."
            )
    else:
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


def _verify_checksums(temp_dir: Path) -> bool:
    """Verify SHA-256 checksums of downloaded compressed files."""
    checksum_file = temp_dir / "checksums.sha256"
    if not checksum_file.is_file():
        print("  No checksums file. Skipping verification.")
        return True

    ok = True
    for line in checksum_file.read_text().strip().splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        expected_hash = parts[0]
        file_name = parts[1]
        file_path = temp_dir / file_name
        if not file_path.is_file():
            # Skip files not in our download list (e.g. registry DB)
            continue
        actual_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
        if actual_hash == expected_hash:
            print(f"  OK: {file_name}")
        else:
            print(f"  FAILED: {file_name}")
            print(f"    expected: {expected_hash}")
            print(f"    got:      {actual_hash}")
            ok = False
    return ok


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
    dest_dir: str | Path, tag: str = "latest", with_registry: bool = False
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
    assets = list(ASSETS)
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
            if not _verify_checksums(temp_dir):
                if attempt < MAX_ATTEMPTS:
                    wait = attempt * 5
                    print(f"  Checksum mismatch. Retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                print("Checksum verification failed after all attempts.")
                return False

            # Decompress
            print("\nDecompressing...")
            decompress_set = ["known_good.db.zst", "context.db.zst"]
            if with_registry:
                decompress_set.append(REGISTRY_ASSET)
            for zst_name in decompress_set:
                zst_path = temp_dir / zst_name
                db_name = zst_name.removesuffix(".zst")
                db_path = dest / db_name
                print(f"  {db_name}...", end="", flush=True)
                _decompress_zst(zst_path, db_path)
                size_mb = db_path.stat().st_size / (1024 * 1024)
                print(f" {size_mb:.1f} MB")

            # Verify databases
            print("\nVerifying databases...")
            ok = True
            ok &= _verify_database(
                dest / "known_good.db", "baseline_files", 1_000_000, "known_good.db"
            )
            ok &= _verify_database(
                dest / "context.db", "lolbins", 100, "context.db (lolbins)"
            )
            ok &= _verify_database(
                dest / "context.db", "vulnerable_drivers", 100, "context.db (drivers)"
            )
            if with_registry:
                ok &= _verify_database(
                    dest / REGISTRY_DB_NAME,
                    "baseline_registry",
                    1_000_000,
                    "known_good_registry.db",
                )

            if ok:
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
        "--tag",
        default="latest",
        help="Release tag to download (default: latest)",
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
