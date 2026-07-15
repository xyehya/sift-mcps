#!/usr/bin/env bash
# Provision the installation-held custody signing authority.  This is an
# installer/local-admin operation only; it must never be exposed through MCP.
set -Eeuo pipefail
umask 077

SERVICE_USER="${SIFT_GATEWAY_SERVICE_USER:-sift-service}"
PYTHON_BIN="/opt/sift-mcps/.venv/bin/python"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --service-user) SERVICE_USER="${2:?missing service user}"; shift 2 ;;
    --python) PYTHON_BIN="${2:?missing python path}"; shift 2 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done

[[ "${EUID}" -eq 0 ]] || { printf 'ERROR: run as root\n' >&2; exit 1; }
[[ "$SERVICE_USER" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]] || { printf 'ERROR: invalid service user\n' >&2; exit 1; }
[[ "$PYTHON_BIN" == /* && -x "$PYTHON_BIN" ]] || { printf 'ERROR: trusted runtime Python not found\n' >&2; exit 1; }
id -u "$SERVICE_USER" >/dev/null 2>&1 || { printf 'ERROR: service user not found\n' >&2; exit 1; }

# /etc is root-owned; unlike /var/lib/sift and .sift it cannot be used by the
# service account to rename or replace this child directory.
KEY_DIR="/etc/sift/custody"
KEY_PATH="$KEY_DIR/ed25519-private.pem"
# Root owns the directory so the runtime service can read the fixed key but
# cannot replace, unlink, or create a signing authority.
install -d -o root -g "$SERVICE_USER" -m 0750 /etc/sift
install -d -o root -g "$SERVICE_USER" -m 0750 "$KEY_DIR"

"$PYTHON_BIN" - "$KEY_DIR" "$KEY_PATH" "$SERVICE_USER" <<'PY'
import os
import stat
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

directory, key_path, service_user = sys.argv[1:]
uid = __import__("pwd").getpwnam(service_user).pw_uid
gid = __import__("pwd").getpwnam(service_user).pw_gid

def safe_existing() -> bool:
    try:
        info = os.stat(key_path, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o640:
        raise SystemExit("ERROR: existing custody signing key has unsafe ownership or mode")
    return True

if safe_existing():
    raise SystemExit(0)

raw = Ed25519PrivateKey.generate().private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
tmp = os.path.join(directory, ".ed25519-private.pem.new-%d" % os.getpid())
try:
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    try:
        os.fchown(fd, 0, gid)
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("failed to write custody signing key")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        # link(2) is create-only: unlike rename it cannot overwrite an existing
        # authority if a concurrent installer won the race.
        os.link(tmp, key_path, follow_symlinks=False)
    except FileExistsError:
        if not safe_existing():
            raise SystemExit("ERROR: custody signing key creation race failed")
    finally:
        os.unlink(tmp)
except BaseException:
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    raise
PY
