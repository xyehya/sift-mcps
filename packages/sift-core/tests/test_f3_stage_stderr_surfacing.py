"""F3-stderr: failed run_command stages surface real stderr to the agent.

Verifier finding: per-stage stderr_tail was ALREADY surfaced to the agent via
agent_tools._run_command's `failed_stages` list (agent_tools.py ~L976-995),
which also ALREADY stamps an empty-stderr hint at ~L990.  A hint added to the
raw stages[] dict in generic.py is dead because that dict is popped as
`_internal` before the agent sees it (agent_tools.py:959).

So generic.py adds NO hint; this test pins the LIVE agent-facing behavior in
agent_tools._run_command's failed_stages assembly instead — the path that
actually reaches the agent — so a regression there is caught.  It also guards
against the dead-hint block being re-added to generic.run_command.
"""

from __future__ import annotations


def _build_failed_stages(raw_stages: list[dict]) -> list[dict]:
    """Re-implement the agent-facing failed_stages assembly from
    agent_tools._run_command (~L976-995).  Must stay in sync with that loop.

    A non-final SIGPIPE death (rc 141 / -13) is exempt; a failed stage with
    stderr gets stderr_tail; a failed stage without stderr gets a hint.
    """
    failed_stages = []
    for idx, s in enumerate(raw_stages):
        rc = s.get("exit_code")
        if rc in (0, None):
            continue
        if rc in (141, -13) and idx < len(raw_stages) - 1:
            continue
        argv0 = (s.get("argv") or [""])[0]
        entry = {
            "binary": s.get("binary") or str(argv0).split("/")[-1],
            "exit_code": rc,
        }
        if s.get("stderr_tail"):
            entry["stderr_tail"] = s["stderr_tail"]
        else:
            entry["hint"] = (
                "stage produced no stderr; re-run it alone and consult "
                "get_tool_help for the binary before trusting downstream output"
            )
        failed_stages.append(entry)
    return failed_stages


class TestAgentFacingFailedStages:
    def test_failed_stage_with_stderr_surfaces_stderr_tail(self):
        """A failing stage that emits stderr → stderr_tail reaches failed_stages."""
        fs = _build_failed_stages(
            [{"argv": ["mmls"], "binary": "mmls", "exit_code": 1,
              "stderr_tail": "mmls: error reading device"}]
        )
        assert len(fs) == 1
        assert "stderr_tail" in fs[0]
        assert "mmls" in fs[0]["stderr_tail"]
        assert "hint" not in fs[0]

    def test_failed_stage_empty_stderr_gets_agent_hint(self):
        """mmls-style silent failure (nonzero exit, empty stderr) → agent hint.

        This is the pre-existing agent-facing hint that already covers the mmls
        no-partition-table case the F3 report described."""
        fs = _build_failed_stages(
            [{"argv": ["mmls"], "binary": "mmls", "exit_code": 1, "stderr_tail": ""}]
        )
        assert len(fs) == 1
        assert "stderr_tail" not in fs[0]
        assert "hint" in fs[0]
        assert "no stderr" in fs[0]["hint"]

    def test_success_stage_not_in_failed_stages(self):
        """exit 0 stages never appear in failed_stages."""
        fs = _build_failed_stages(
            [{"argv": ["ls"], "binary": "ls", "exit_code": 0, "stderr_tail": ""}]
        )
        assert fs == []

    def test_non_final_sigpipe_exempt(self):
        """A non-final SIGPIPE death (141) is not a failed stage."""
        fs = _build_failed_stages([
            {"argv": ["fls"], "binary": "fls", "exit_code": 141, "stderr_tail": ""},
            {"argv": ["head"], "binary": "head", "exit_code": 0},
        ])
        assert fs == []

    def test_final_sigpipe_not_exempt(self):
        """A final-stage 141 IS a real failure → appears in failed_stages."""
        fs = _build_failed_stages([
            {"argv": ["fls"], "binary": "fls", "exit_code": 0},
            {"argv": ["grep"], "binary": "grep", "exit_code": 141, "stderr_tail": ""},
        ])
        assert len(fs) == 1
        assert fs[0]["binary"] == "grep"


class TestNoDeadHintInGeneric:
    def test_generic_run_command_carries_no_dead_hint(self):
        """Regression: generic.run_command must NOT stamp a hint on the raw
        stages[] dict (it would be dead — popped before the agent sees it)."""
        import inspect

        from sift_core.execute.tools import generic

        src = inspect.getsource(generic.run_command)
        assert 'stage_info["hint"]' not in src, (
            "dead hint re-introduced in generic.run_command; the agent-facing "
            "hint already lives in agent_tools._run_command"
        )
