"""F12: benign broken-pipe on non-final stage must NOT set partial_failure.

Bug: ``fls ... | grep ... | head -N`` → grep exits 2 (not 141/SIGPIPE) on
Linux when head closes the pipe early, emitting
"grep: write error: Broken pipe" to stderr.  The existing SIGPIPE_EXIT_CODES
check only matched (141, -13) so exit-2 was treated as a real failure and
partial_failure=True was set even though the output was correct.

Fix: extend the non-final-stage exemption for exit-nonzero stages where a
LATER stage exited 0 AND stderr_tail matches a broken-pipe write-error marker.

Tests:
1. grep exit-2 + "write error: Broken pipe" before head exit-0 → NOT partial_failure.
2. grep exit-2 + "grep: write error" (abbreviated) before head exit-0 → NOT partial_failure.
3. grep exit-2 + "No such file or directory" → STILL partial_failure (real error).
4. grep exit-1 (no match found, not a pipe error) → STILL partial_failure.
5. grep exit-2 + broken-pipe stderr but it IS the final stage → STILL partial_failure.
6. Classic SIGPIPE exit-141 non-final stage → already exempt (regression guard).
7. _is_broken_pipe_stderr unit: verifies the helper function directly.
"""

from __future__ import annotations

import pytest

from sift_core.execute.tools.generic import _is_broken_pipe_stderr


# ---------------------------------------------------------------------------
# _is_broken_pipe_stderr unit tests
# ---------------------------------------------------------------------------


class TestIsBrokenPipeStderr:
    def test_empty_string_false(self):
        assert _is_broken_pipe_stderr("") is False

    def test_none_equivalent_empty_false(self):
        # Called with empty string (the .get("stderr_tail", "") default).
        assert _is_broken_pipe_stderr("") is False

    def test_broken_pipe_detected(self):
        assert _is_broken_pipe_stderr("grep: write error: Broken pipe") is True

    def test_bare_write_error_NOT_detected(self):
        """Reviewer tightening: bare 'write error' (no 'broken pipe') must NOT
        match — a real failure like 'write error: No space left on device'
        must stay flagged."""
        assert _is_broken_pipe_stderr("grep: write error") is False
        assert _is_broken_pipe_stderr("write error: No space left on device") is False

    def test_broken_pipe_case_insensitive(self):
        assert _is_broken_pipe_stderr("Broken Pipe") is True
        assert _is_broken_pipe_stderr("BROKEN PIPE") is True
        assert _is_broken_pipe_stderr("grep: write error: BROKEN PIPE") is True

    def test_real_error_not_detected(self):
        assert _is_broken_pipe_stderr("grep: No such file or directory") is False
        assert _is_broken_pipe_stderr("grep: Invalid option") is False
        assert _is_broken_pipe_stderr("Permission denied") is False
        assert _is_broken_pipe_stderr("write error: No space left on device") is False


# ---------------------------------------------------------------------------
# partial_failure logic tests — exercise via the function directly
# ---------------------------------------------------------------------------


def _check_partial_failure(stages: list[dict]) -> bool:
    """Re-implement the partial_failure loop from generic.py for unit testing
    without needing a real executor.  Must stay in sync with the loop in
    generic.py (copy-updated when the loop changes)."""
    from sift_core.execute.tools.generic import (
        _SIGPIPE_EXIT_CODES,
        _is_broken_pipe_stderr,
    )

    n_stages = len(stages)
    partial_failure = False
    for idx, s_info in enumerate(stages):
        rc = s_info.get("exit_code")
        if rc in (0, None):
            continue
        is_non_final = idx < n_stages - 1
        if rc in _SIGPIPE_EXIT_CODES and is_non_final:
            continue
        if (
            is_non_final
            and _is_broken_pipe_stderr(s_info.get("stderr_tail", ""))
            and any(
                later.get("exit_code") in (0, None)
                for later in stages[idx + 1 :]
            )
        ):
            continue
        partial_failure = True
        break
    return partial_failure


class TestPartialFailureBrokenPipe:
    def test_grep_exit2_broken_pipe_before_head_exit0_not_partial(self):
        """F12: grep exits 2 with broken-pipe stderr before head exit-0 → NOT failure."""
        stages = [
            {"argv": ["fls", "-r", "image.e01"], "exit_code": 0},
            {
                "argv": ["grep", "foo"],
                "exit_code": 2,
                "stderr_tail": "grep: write error: Broken pipe",
            },
            {"argv": ["head", "-20"], "exit_code": 0},
        ]
        assert _check_partial_failure(stages) is False

    def test_write_error_no_space_left_still_partial(self):
        """Reviewer tightening: a non-final stage failing with
        'write error: No space left on device' followed by a later exit-0 stage
        must STILL flag partial_failure — it is a real failure, not a pipe close."""
        stages = [
            {
                "argv": ["grep", "pattern"],
                "exit_code": 2,
                "stderr_tail": "grep: write error: No space left on device",
            },
            {"argv": ["head", "-5"], "exit_code": 0},
        ]
        assert _check_partial_failure(stages) is True

    def test_grep_exit2_real_error_no_such_file_still_partial(self):
        """grep exits 2 with a real error → partial_failure stays True."""
        stages = [
            {"argv": ["grep", "foo"], "exit_code": 2, "stderr_tail": "grep: /missing: No such file or directory"},
            {"argv": ["head", "-20"], "exit_code": 0},
        ]
        assert _check_partial_failure(stages) is True

    def test_grep_exit1_no_match_still_partial(self):
        """grep exit 1 (no match, no broken-pipe) → partial_failure (real outcome)."""
        stages = [
            {"argv": ["grep", "nothing_here"], "exit_code": 1, "stderr_tail": ""},
            {"argv": ["head", "-20"], "exit_code": 0},
        ]
        assert _check_partial_failure(stages) is True

    def test_grep_exit2_broken_pipe_but_final_stage_still_partial(self):
        """If the broken-pipe stage IS the final stage, it's not exempt."""
        stages = [
            {"argv": ["fls", "-r", "image.e01"], "exit_code": 0},
            {
                "argv": ["grep", "foo"],
                "exit_code": 2,
                "stderr_tail": "grep: write error: Broken pipe",
            },
        ]
        assert _check_partial_failure(stages) is True

    def test_classic_sigpipe_141_non_final_still_exempt_regression(self):
        """Existing SIGPIPE exit-141 exemption must still work (regression guard)."""
        stages = [
            {"argv": ["fls", "-r", "image.e01"], "exit_code": 141},
            {"argv": ["head", "-5"], "exit_code": 0},
        ]
        assert _check_partial_failure(stages) is False

    def test_three_stage_pipeline_middle_broken_pipe_not_partial(self):
        """Three-stage pipeline: fls | grep (exit 2 broken-pipe) | head → NOT partial."""
        stages = [
            {"argv": ["fls", "-r", "image.e01"], "exit_code": 0},
            {
                "argv": ["grep", "foo"],
                "exit_code": 2,
                "stderr_tail": "grep: write error: Broken pipe\n",
            },
            {"argv": ["head", "-10"], "exit_code": 0},
        ]
        assert _check_partial_failure(stages) is False

    def test_upstream_real_error_still_flagged_even_with_broken_pipe_later(self):
        """An upstream real error (fls exit 1) is not masked by a later broken-pipe."""
        stages = [
            {"argv": ["fls", "-r", "/nonexistent"], "exit_code": 1, "stderr_tail": "fls: error"},
            {
                "argv": ["grep", "foo"],
                "exit_code": 2,
                "stderr_tail": "grep: write error: Broken pipe",
            },
            {"argv": ["head", "-5"], "exit_code": 0},
        ]
        # The FIRST nonzero stage (fls) is a real error → partial_failure=True.
        assert _check_partial_failure(stages) is True

    def test_no_stages_not_partial(self):
        """Empty stages list → not partial (no nonzero exit codes)."""
        assert _check_partial_failure([]) is False

    def test_single_stage_exit0_not_partial(self):
        assert _check_partial_failure([{"argv": ["ls"], "exit_code": 0}]) is False

    def test_single_stage_exit1_partial(self):
        assert _check_partial_failure([{"argv": ["ls", "/missing"], "exit_code": 1}]) is True
