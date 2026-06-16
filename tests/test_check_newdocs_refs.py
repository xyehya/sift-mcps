from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_newdocs_refs.py"


def test_dangling_path_reference_fails(tmp_path: Path) -> None:
    docs_root = tmp_path / "docs" / "new-docs"
    docs_root.mkdir(parents=True)
    (docs_root / "SYSTEM_OVERVIEW.md").write_text(
        "\n".join(
            [
                "# System Overview",
                "",
                "> Covers: packages/sift-gateway/src/",
                "> Class: live-reference",
                "> Last validated: a7ddaaa (2026-06-16)",
                "",
                "This cites `packages/sift-gateway/src/missing.py`.",
            ]
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo-root",
            str(tmp_path),
            "--docs-root",
            str(docs_root),
            "--changed-path",
            "README.md",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert "dangling file reference: packages/sift-gateway/src/missing.py" in result.stdout


def test_covered_code_change_warns_when_doc_not_changed(tmp_path: Path) -> None:
    docs_root = tmp_path / "docs" / "new-docs"
    docs_root.mkdir(parents=True)
    covered = tmp_path / "packages" / "sift-gateway" / "src" / "sift_gateway"
    covered.mkdir(parents=True)
    (covered / "server.py").write_text("class Gateway:\n    pass\n", encoding="utf-8")
    (docs_root / "SYSTEM_OVERVIEW.md").write_text(
        "\n".join(
            [
                "# System Overview",
                "",
                "> Covers: packages/sift-gateway/src/",
                "> Class: live-reference",
                "> Last validated: a7ddaaa (2026-06-16)",
                "",
                "This cites `packages/sift-gateway/src/sift_gateway/server.py`.",
            ]
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo-root",
            str(tmp_path),
            "--docs-root",
            str(docs_root),
            "--changed-path",
            "packages/sift-gateway/src/sift_gateway/server.py",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert "may be stale; covered path changed without doc update" in result.stdout
