#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./install.sh --user
  ./install.sh --repo /path/to/repo
  ./install.sh --dest /custom/skills/directory
  ./install.sh --dry-run --user

Installs this skill folder as agentic-security.
EOF
}

DRY_RUN=0
MODE=""
DEST=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)
      MODE="user"; shift ;;
    --repo)
      MODE="repo"; DEST="${2:-}"; shift 2 ;;
    --dest)
      MODE="dest"; DEST="${2:-}"; shift 2 ;;
    --dry-run)
      DRY_RUN=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2 ;;
  esac
done

if [[ -z "$MODE" ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -f "$SCRIPT_DIR/SKILL.md" ]]; then
  echo "Could not find SKILL.md next to install.sh" >&2
  exit 1
fi

case "$MODE" in
  user)
    TARGET_PARENT="$HOME/.agents/skills" ;;
  repo)
    if [[ -z "$DEST" ]]; then echo "--repo requires a repo path" >&2; exit 2; fi
    TARGET_PARENT="$DEST/.agents/skills" ;;
  dest)
    if [[ -z "$DEST" ]]; then echo "--dest requires a directory" >&2; exit 2; fi
    TARGET_PARENT="$DEST" ;;
esac

TARGET="$TARGET_PARENT/agentic-security"

echo "Install source: $SCRIPT_DIR"
echo "Install target: $TARGET"

if [[ "$DRY_RUN" == "1" ]]; then
  echo "Dry run only; no files copied."
  exit 0
fi

mkdir -p "$TARGET_PARENT"
rm -rf "$TARGET"
cp -a "$SCRIPT_DIR" "$TARGET"
chmod +x "$TARGET/install.sh" "$TARGET/scripts/agentic_security_scan.py" "$TARGET/scripts/generate_report_skeleton.py" "$TARGET/scripts/validate_skill.py"
echo "Installed agentic-security skill to $TARGET"
