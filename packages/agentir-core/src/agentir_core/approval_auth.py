"""Approval authentication: mandatory password for approve/reject.

Password hashes stored in /var/lib/agentir/passwords/{examiner}.json (0o600).
Password prompts use /dev/tty raw mode to block both LLM-via-Bash and
expect-style automation.
"""

from __future__ import annotations

import getpass as getpass_mod
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time

try:
    import termios
    import tty as tty_mod

    _HAS_TERMIOS = True
except ImportError:
    _HAS_TERMIOS = False
from pathlib import Path

import yaml

PBKDF2_ITERATIONS = 600_000
_MAX_PASSWORD_ATTEMPTS = 3
_LOCKOUT_SECONDS = 900
_LOCKOUT_FILE = Path.home() / ".agentir" / ".password_lockout"
_MIN_PASSWORD_LENGTH = 8
_PASSWORDS_DIR = Path("/var/lib/agentir/passwords")

_EXAMINER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")


def _validate_examiner_name(analyst: str) -> None:
    if not _EXAMINER_RE.match(analyst):
        raise ValueError(f"Invalid examiner name: {analyst!r}")


def _password_file(passwords_dir: Path, analyst: str) -> Path:
    _validate_examiner_name(analyst)
    return passwords_dir / f"{analyst}.json"


def _load_password_entry(passwords_dir: Path, analyst: str) -> dict | None:
    path = _password_file(passwords_dir, analyst)
    try:
        data = json.loads(path.read_text())
        if isinstance(data, dict) and "hash" in data and "salt" in data:
            return data
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return None


def _save_password_entry(passwords_dir: Path, analyst: str, entry: dict) -> None:
    _validate_examiner_name(analyst)
    passwords_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = _password_file(passwords_dir, analyst)
    fd, tmp_path = tempfile.mkstemp(dir=str(passwords_dir), suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(entry, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, str(path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _ensure_passwords_dir(passwords_dir: Path) -> None:
    if passwords_dir.is_dir():
        return
    try:
        passwords_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        return
    except OSError:
        pass
    user = getpass_mod.getuser()
    print(f"Creating {passwords_dir}/ (requires sudo)...")
    result = None
    for cmd in [
        ["sudo", "mkdir", "-p", str(passwords_dir)],
        ["sudo", "chown", f"{user}:{user}", str(passwords_dir)],
        ["sudo", "chmod", "700", str(passwords_dir)],
    ]:
        result = subprocess.run(cmd, timeout=30)
        if result.returncode != 0:
            break
    if result and result.returncode != 0:
        print(
            f"Could not create {passwords_dir}/. Create it manually:\n"
            f"  sudo mkdir -p {passwords_dir} && "
            f"sudo chown $USER:$USER {passwords_dir} && "
            f"sudo chmod 700 {passwords_dir}",
            file=sys.stderr,
        )
        sys.exit(1)


def require_confirmation(config_path: Path, analyst: str) -> tuple[str, str | None]:
    """Require password. Returns ('password', raw_password) on success."""
    if not has_password(config_path, analyst):
        print(
            "No approval password configured. Set one with:\n  agentir config --setup-password\n",
            file=sys.stderr,
        )
        sys.exit(1)
    _check_lockout(analyst)
    password = getpass_prompt("Enter password to confirm: ")
    if not verify_password(config_path, analyst, password):
        _record_failure(analyst)
        remaining = _MAX_PASSWORD_ATTEMPTS - _recent_failure_count(analyst)
        if remaining <= 0:
            print(
                f"Too many failed attempts. Locked out for {_LOCKOUT_SECONDS}s.",
                file=sys.stderr,
            )
        else:
            print(
                f"Incorrect password. {remaining} attempt(s) remaining.",
                file=sys.stderr,
            )
        sys.exit(1)
    _clear_failures(analyst)
    return ("password", password)


def require_tty_confirmation(prompt: str) -> bool:
    """Prompt y/N via /dev/tty. Returns True if confirmed."""
    try:
        tty = open("/dev/tty")
    except OSError:
        print(
            "No terminal available (/dev/tty). Cannot confirm interactively.",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        sys.stderr.write(prompt)
        sys.stderr.flush()
        response = tty.readline().strip().lower()
        return response == "y"
    finally:
        tty.close()


def has_password(
    config_path: Path, analyst: str, *, passwords_dir: Path | None = None
) -> bool:
    passwords_dir = passwords_dir or _PASSWORDS_DIR
    if _load_password_entry(passwords_dir, analyst) is not None:
        return True
    config = _load_config(config_path)
    section = config.get("passwords", {})
    return (
        isinstance(section, dict)
        and analyst in section
        and "hash" in section[analyst]
        and "salt" in section[analyst]
    )


def verify_password(
    config_path: Path, analyst: str, password: str, *, passwords_dir: Path | None = None
) -> bool:
    passwords_dir = passwords_dir or _PASSWORDS_DIR
    entry = _load_password_entry(passwords_dir, analyst)
    if entry is None:
        config = _load_config(config_path)
        section = config.get("passwords", {})
        entry = section.get(analyst) if isinstance(section, dict) else None
    if not entry:
        return False
    try:
        stored_hash = entry["hash"]
        salt = bytes.fromhex(entry["salt"])
    except (KeyError, ValueError):
        return False
    computed = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, PBKDF2_ITERATIONS
    ).hex()
    return secrets.compare_digest(computed, stored_hash)


def setup_password(
    config_path: Path, analyst: str, *, passwords_dir: Path | None = None
) -> str:
    """Set up a new password for the analyst. Returns the raw password."""
    passwords_dir = passwords_dir or _PASSWORDS_DIR
    _ensure_passwords_dir(passwords_dir)
    pw1 = getpass_prompt("Enter new password: ")
    if not pw1:
        print("Password cannot be empty.", file=sys.stderr)
        sys.exit(1)
    if len(pw1) < _MIN_PASSWORD_LENGTH:
        print(f"Password must be at least {_MIN_PASSWORD_LENGTH} characters.", file=sys.stderr)
        sys.exit(1)
    pw2 = getpass_prompt("Confirm new password: ")
    if pw1 != pw2:
        print("Passwords do not match.", file=sys.stderr)
        sys.exit(1)
    salt = secrets.token_bytes(32)
    pw_hash = hashlib.pbkdf2_hmac("sha256", pw1.encode(), salt, PBKDF2_ITERATIONS).hex()
    _save_password_entry(passwords_dir, analyst, {"hash": pw_hash, "salt": salt.hex()})
    print(f"Password configured for analyst '{analyst}'.")
    return pw1


def get_analyst_salt(
    config_path: Path, analyst: str, *, passwords_dir: Path | None = None
) -> bytes:
    passwords_dir = passwords_dir or _PASSWORDS_DIR
    entry = _load_password_entry(passwords_dir, analyst)
    if entry is None:
        config = _load_config(config_path)
        section = config.get("passwords", {})
        entry = section.get(analyst) if isinstance(section, dict) else None
    if not entry or "salt" not in entry:
        raise ValueError(f"No salt found for analyst '{analyst}'")
    return bytes.fromhex(entry["salt"])


def _load_failures() -> dict[str, list[float]]:
    try:
        data = json.loads(_LOCKOUT_FILE.read_text())
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return {}


def _save_failures(data: dict[str, list[float]]) -> None:
    _LOCKOUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(_LOCKOUT_FILE.parent), suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.replace(tmp_path, str(_LOCKOUT_FILE))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _recent_failure_count(analyst: str) -> int:
    now = time.time()
    failures = _load_failures().get(analyst, [])
    return sum(1 for t in failures if now - t < _LOCKOUT_SECONDS)


def _check_lockout(analyst: str) -> None:
    if _recent_failure_count(analyst) >= _MAX_PASSWORD_ATTEMPTS:
        now = time.time()
        failures = _load_failures().get(analyst, [])
        recent = [t for t in failures if now - t < _LOCKOUT_SECONDS]
        if recent:
            remaining = max(int(_LOCKOUT_SECONDS - (now - min(recent))), 1)
        else:
            remaining = _LOCKOUT_SECONDS
        print(
            f"Password locked. Too many failed attempts. Try again in {remaining} seconds.",
            file=sys.stderr,
        )
        sys.exit(1)


def _record_failure(analyst: str) -> None:
    data = _load_failures()
    data.setdefault(analyst, []).append(time.time())
    _save_failures(data)


def _clear_failures(analyst: str) -> None:
    data = _load_failures()
    if analyst in data:
        del data[analyst]
        _save_failures(data)


def getpass_prompt(prompt: str) -> str:
    """Read password from /dev/tty with masked input (shows * per keystroke).

    Raises RuntimeError if /dev/tty or termios is unavailable.
    """
    if not _HAS_TERMIOS:
        raise RuntimeError(
            "Password entry requires a terminal with termios support."
        )
    try:
        tty_in = open("/dev/tty")
    except OSError as err:
        raise RuntimeError(
            "Password entry requires /dev/tty. Ensure you are running from an interactive terminal."
        ) from err
    try:
        fd = tty_in.fileno()
        sys.stderr.write(prompt)
        sys.stderr.flush()
        old_settings = termios.tcgetattr(fd)
        try:
            tty_mod.setraw(fd)
            chars = []
            while True:
                ch = os.read(fd, 1).decode("utf-8", errors="replace")
                if ch in ("\r", "\n"):
                    break
                elif ch in ("\x7f", "\x08"):
                    if chars:
                        chars.pop()
                        sys.stderr.write("\b \b")
                        sys.stderr.flush()
                elif ch == "\x03":
                    sys.stderr.write("\n")
                    sys.stderr.flush()
                    raise KeyboardInterrupt
                elif ch >= " ":
                    chars.append(ch)
                    sys.stderr.write("*")
                    sys.stderr.flush()
            return "".join(chars)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            sys.stderr.write("\n")
            sys.stderr.flush()
    finally:
        tty_in.close()


def _load_config(config_path: Path) -> dict:
    if not config_path.exists():
        return {}
    try:
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    except (yaml.YAMLError, OSError):
        return {}


def _save_config(config_path: Path, config: dict) -> None:
    config_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(config_path.parent), suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
        os.replace(tmp_path, str(config_path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
