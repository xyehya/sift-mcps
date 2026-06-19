#!/usr/bin/env python3
"""Check docs/new-docs headers, file references, and covered-path drift."""
from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

DOCS_ROOT = Path("docs/new-docs")
ALLOWED_CLASSES = {"live-reference", "living-plan", "point-in-time"}
HEADER_RE = re.compile(r"^> (Covers|Class|Last validated): (.+)$", re.MULTILINE)
LAST_VALIDATED_RE = re.compile(r"^[0-9a-f]{7,40} \(\d{4}-\d{2}-\d{2}\)$")
FILE_LINE_RE = re.compile(
    r"(?P<path>(?:\.github|docs|packages|portal|scripts|supabase|tests)/"
    r"[\w./*{}-]+|(?:README|AGENTS|CLAUDE)\.md|"
    r"(?:install|pyproject|uv)\.(?:sh|toml|lock))"
    r"(?::(?P<line>\d+))?"
)
BACKTICK_RE = re.compile(r"`([^`\n]+)`")
PATH_PREFIXES = (".github/", "docs/", "packages/", "portal/", "scripts/", "supabase/", "tests/")
PATH_NAMES = {"README.md", "AGENTS.md", "CLAUDE.md", "install.sh", "pyproject.toml", "uv.lock"}
# Host-local agent instruction files are untracked per workstation (see .gitignore)
# and are intentionally absent from a fresh checkout. Docs may still name them, so
# their references must not be treated as dangling.
HOST_LOCAL_UNTRACKED = {"CLAUDE.md", "AGENTS.md"}


@dataclass
class DocInfo:
    path: Path
    covers: list[str]
    doc_class: str
    last_validated: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--docs-root", type=Path, default=DOCS_ROOT)
    parser.add_argument(
        "--base-ref",
        default=None,
        help="Git ref for covered-path drift checks. Defaults to origin/main if present.",
    )
    parser.add_argument(
        "--changed-path",
        action="append",
        default=None,
        help="Changed path to use instead of git diff. Repeatable; useful for tests.",
    )
    return parser.parse_args()


def warn(messages: list[str], message: str) -> None:
    messages.append("WARN " + message)


def error(messages: list[str], message: str) -> None:
    messages.append("ERROR " + message)


def normalize_path(raw: str) -> str | None:
    value = raw.strip().rstrip(".,;:)")
    if not value or "://" in value or value.startswith("#"):
        return None
    if value.startswith("/"):
        return None
    if value.startswith("./"):
        value = value[2:]
    if value.startswith("../../"):
        value = value[6:]
    if value.startswith("../"):
        value = value[3:]
    if value.endswith(":"):
        value = value[:-1]
    if "::" in value:
        value = value.split("::", 1)[0]
    if "#" in value:
        value = value.split("#", 1)[0]
    line_suffix = re.match(r"^(?P<path>.+):(?P<line>\d+)(?:[-,].*)?$", value)
    if line_suffix:
        value = line_suffix.group("path")
    return value or None


def looks_like_path(value: str) -> bool:
    normalized = normalize_path(value)
    if not normalized:
        return False
    if any(normalized.startswith(prefix) for prefix in PATH_PREFIXES):
        return True
    return normalized in PATH_NAMES


def parse_header(path: Path, text: str, errors: list[str]) -> DocInfo | None:
    scan_text = text.split("```", 1)[0]
    found = {key: value.strip() for key, value in HEADER_RE.findall(scan_text)}
    missing = {"Covers", "Class", "Last validated"} - found.keys()
    if missing:
        error(errors, f"{path}: missing header field(s): {', '.join(sorted(missing))}")
        return None
    doc_class = found["Class"]
    if doc_class not in ALLOWED_CLASSES:
        error(errors, f"{path}: unsupported Class: {doc_class}")
    if not LAST_VALIDATED_RE.match(found["Last validated"]):
        error(errors, f"{path}: invalid Last validated: {found['Last validated']}")
    covers = [item.strip() for item in found["Covers"].split(",") if item.strip()]
    if not covers:
        error(errors, f"{path}: Covers must list at least one path or glob")
    return DocInfo(path=path, covers=covers, doc_class=doc_class, last_validated=found["Last validated"])


def iter_reference_paths(text: str) -> set[tuple[str, int | None]]:
    refs: set[tuple[str, int | None]] = set()
    # Strip URLs first so a path-like fragment inside a link (e.g. the
    # "docs/triage" in "https://linear.app/docs/triage") is not mistaken for a
    # local file reference. Backtick scanning below still uses the original text;
    # a backticked URL is filtered by the "://" guard in normalize_path.
    text_no_urls = re.sub(r"https?://\S+", " ", text)
    for match in FILE_LINE_RE.finditer(text_no_urls):
        raw_path = normalize_path(match.group("path"))
        if raw_path:
            refs.add((raw_path, int(match.group("line")) if match.group("line") else None))
    for match in BACKTICK_RE.finditer(text):
        candidate = match.group(1).split()[0]
        if looks_like_path(candidate):
            raw_path = normalize_path(candidate)
            if raw_path:
                line_match = re.match(r"^(?P<path>.+):(?P<line>\d+)$", raw_path)
                if line_match:
                    refs.add((line_match.group("path"), int(line_match.group("line"))))
                else:
                    refs.add((raw_path, None))
    return refs


def check_references(repo_root: Path, doc_path: Path, text: str, errors: list[str], warnings: list[str]) -> None:
    refs = sorted(iter_reference_paths(text), key=lambda item: (item[0], item[1] or 0))
    for raw_path, line_no in refs:
        if "*" in raw_path or "{" in raw_path or "}" in raw_path:
            continue
        if raw_path in HOST_LOCAL_UNTRACKED:
            continue
        target = repo_root / raw_path
        if not target.exists():
            error(errors, f"{doc_path}: dangling file reference: {raw_path}")
            continue
        if line_no is None or not target.is_file():
            continue
        try:
            line_count = len(target.read_text(encoding="utf-8", errors="ignore").splitlines())
        except OSError as exc:
            warn(warnings, f"{doc_path}: could not read {raw_path} for line hint check ({exc})")
            continue
        if line_no > line_count:
            warn(warnings, f"{doc_path}: line hint {raw_path}:{line_no} exceeds file length {line_count}")


def git_changed_paths(repo_root: Path, base_ref: str | None) -> set[str]:
    if base_ref is None:
        probe = subprocess.run(
            ["git", "rev-parse", "--verify", "origin/main"],
            cwd=repo_root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        base_ref = "origin/main" if probe.returncode == 0 else "HEAD"
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return set()
    changed = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    wt = subprocess.run(
        ["git", "diff", "--name-only"],
        cwd=repo_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if wt.returncode == 0:
        changed.update(line.strip() for line in wt.stdout.splitlines() if line.strip())
    return changed


def cover_matches(pattern: str, changed_path: str) -> bool:
    normalized = normalize_path(pattern.rstrip("/"))
    if not normalized:
        return False
    if pattern.endswith("/"):
        return changed_path.startswith(pattern)
    if any(char in normalized for char in "*?[]"):
        return fnmatch.fnmatch(changed_path, normalized)
    return changed_path == normalized or changed_path.startswith(normalized + "/")


def check_drift(docs: list[DocInfo], changed_paths: set[str], warnings: list[str]) -> None:
    doc_paths = {doc.path.as_posix() for doc in docs}
    changed_docs = changed_paths & doc_paths
    for doc in docs:
        if doc.doc_class != "live-reference":
            continue
        matched = sorted(
            path
            for path in changed_paths
            if path not in doc_paths and any(cover_matches(pattern, path) for pattern in doc.covers)
        )
        if matched and doc.path.as_posix() not in changed_docs:
            sample = ", ".join(matched[:3])
            if len(matched) > 3:
                sample += ", ..."
            warn(warnings, f"{doc.path}: may be stale; covered path changed without doc update: {sample}")


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    docs_root = args.docs_root if args.docs_root.is_absolute() else repo_root / args.docs_root
    errors: list[str] = []
    warnings: list[str] = []
    docs: list[DocInfo] = []

    if not docs_root.exists():
        error(errors, f"{docs_root}: docs root does not exist")
    else:
        for doc_path in sorted(docs_root.glob("*.md")):
            text = doc_path.read_text(encoding="utf-8")
            rel_doc_path = doc_path.relative_to(repo_root)
            info = parse_header(rel_doc_path, text, errors)
            if info is not None:
                docs.append(info)
            check_references(repo_root, rel_doc_path, text, errors, warnings)

    changed_paths = set(args.changed_path or []) or git_changed_paths(repo_root, args.base_ref)
    check_drift(docs, changed_paths, warnings)

    for message in warnings:
        print(message)
    for message in errors:
        print(message)
    if errors:
        print(f"FAILED - {len(errors)} docs/new-docs freshness error(s).")
        return 1
    print("OK - docs/new-docs freshness checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
