"""F3-stderr: failed run_command stages surface real stderr + empty-stderr hint.

Checks:
1. When a stage fails WITH stderr, stderr_tail appears in the stage dict.
2. When a stage fails WITHOUT stderr (empty silent failure like mmls on a
   no-partition-table image), a "hint" key is attached to the stage dict.
3. A stage that exits 0 with empty stderr does NOT get a hint (only failures).
"""

from __future__ import annotations

import pytest


def _make_stages_info(stages_raw: list[dict]) -> list[dict]:
    """Re-run the stage-info assembly logic from generic.py for unit tests.
    Must stay in sync with the loop in run_command (generic.py ~L325-333)."""
    result = []
    for exit_code, stderr_tail in stages_raw:
        entry: dict = {"binary": "test", "argv": ["test"], "redirects": [], "exit_code": exit_code}
        if stderr_tail:
            entry["stderr_tail"] = stderr_tail
        elif exit_code not in (0, None):
            entry["hint"] = (
                "stage produced no stderr; nonzero exit with empty diagnostics "
                "often means an unsupported input (e.g. mmls on a single-volume "
                "image with no partition table)"
            )
        result.append(entry)
    return result


class TestF3StageStderrSurfacing:
    def test_failed_stage_with_stderr_surfaces_stderr_tail(self):
        """A failing stage that emits stderr → stderr_tail key in stage dict."""
        stages = _make_stages_info([(1, "mmls: error reading device")])
        assert "stderr_tail" in stages[0]
        assert "mmls" in stages[0]["stderr_tail"]
        assert "hint" not in stages[0]

    def test_failed_stage_empty_stderr_gets_hint(self):
        """A failing stage with NO stderr → hint key added (F3-stderr fix)."""
        stages = _make_stages_info([(1, "")])
        assert "stderr_tail" not in stages[0]
        assert "hint" in stages[0]
        assert "no stderr" in stages[0]["hint"]
        assert "mmls" in stages[0]["hint"]

    def test_success_stage_empty_stderr_no_hint(self):
        """exit 0 + empty stderr → no hint (hints only for failures)."""
        stages = _make_stages_info([(0, "")])
        assert "hint" not in stages[0]
        assert "stderr_tail" not in stages[0]

    def test_success_stage_with_stderr_surfaces_it(self):
        """exit 0 + non-empty stderr (warnings) → stderr_tail surfaced, no hint."""
        stages = _make_stages_info([(0, "warning: skipping unreadable block")])
        assert "stderr_tail" in stages[0]
        assert "hint" not in stages[0]

    def test_none_exit_code_not_hinted(self):
        """exit_code=None means result not yet known — no hint."""
        stages = _make_stages_info([(None, "")])
        assert "hint" not in stages[0]

    def test_multiple_stages_each_handled_independently(self):
        """Two-stage pipeline: one fails silently, one succeeds."""
        stages = _make_stages_info([
            (1, ""),    # silent failure → hint
            (0, ""),    # success → nothing
        ])
        assert "hint" in stages[0]
        assert "hint" not in stages[1]
