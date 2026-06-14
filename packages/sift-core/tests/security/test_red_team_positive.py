from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from sift_core.active_case_context import AuthorityContext, use_active_case_context
from sift_core.execute import security, worker
from sift_core.execute.security_policy import build_security_policy


RUNBOOK = Path(__file__).with_name("RUN3_LIVE_GATE_RUNBOOK.md")


def _policy_for_validation() -> dict:
    policy = build_security_policy(
        {"mode": "allowlist", "allowed_binaries": ["@mvp_forensic"]}
    )
    return {
        "mode": policy["mode"],
        "allowed_binaries": frozenset(policy.get("allowed_binaries", [])),
        "dangerous_flags": set(policy.get("dangerous_flags", [])),
        "tool_allowed_flags": {
            key: set(values)
            for key, values in policy.get("tool_allowed_flags", {}).items()
        },
        "tool_blocked_flags": {
            key: set(values)
            for key, values in policy.get("tool_blocked_flags", {}).items()
        },
        "denied_binaries": frozenset(policy.get("denied_binaries", [])),
        "output_flags": frozenset(policy.get("output_flags", [])),
    }


@pytest.fixture
def gate_case(tmp_path: Path) -> Path:
    case_dir = tmp_path / "case-active"
    for rel in (
        "agent",
        "agent/run_commands",
        "extractions",
        "tmp",
        "evidence",
        "evidence/evtx",
        "evidence/rules",
    ):
        (case_dir / rel).mkdir(parents=True, exist_ok=True)
    return case_dir


@pytest.fixture(autouse=True)
def fake_policy_and_binary_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(security, "_get_policy", _policy_for_validation)
    monkeypatch.setattr(
        security,
        "find_binary",
        lambda name: f"/usr/bin/{Path(str(name)).name}",
    )


def _with_case(case_dir: Path):
    return use_active_case_context(
        AuthorityContext(
            case_id="11111111-1111-1111-1111-111111111111",
            case_key="case-active",
            artifact_path=str(case_dir),
            db_active=True,
        )
    )


POSITIVE_FORENSIC_COMMANDS = [
    pytest.param(
        "vol -f evidence/mem.raw windows.pslist",
        "vol-memory",
        id="positive-volatility-memory",
    ),
    pytest.param(
        "mmls evidence/disk.E01 ; fls -r -m / evidence/disk.E01",
        "tsk-disk",
        id="positive-tsk-mmls-fls",
    ),
    pytest.param(
        "icat evidence/disk.E01 42 > extractions/file",
        "tsk-icat-redirect",
        id="positive-tsk-icat-redirect",
    ),
    pytest.param(
        "EvtxECmd -f evidence/x.evtx --csv extractions/",
        "eztools-evtxecmd",
        id="positive-eztools-evtxecmd",
    ),
    pytest.param(
        "tshark -r evidence/capture.pcap -Y http -T json",
        "tshark-pcap",
        id="positive-tshark-pcap",
    ),
    pytest.param(
        "yara evidence/rules/admin.yar evidence/sample",
        "yara-scan",
        id="positive-yara-scan",
    ),
    pytest.param(
        "rg -i password extractions/strings.txt",
        "ripgrep-search",
        id="positive-rg-search",
    ),
    pytest.param(
        "strings evidence/mem.raw | rg -i pass > extractions/hits.txt",
        "pipeline-redirect",
        id="positive-pipeline-redirect",
    ),
    pytest.param(
        "hayabusa csv-timeline -d evidence/evtx -o extractions/ht.csv",
        "hayabusa-timeline",
        id="positive-hayabusa",
    ),
    pytest.param(
        "curl -s https://otx.example.invalid/api/v1/indicators",
        "curl-threat-intel-read",
        id="positive-curl-readonly-threat-intel",
    ),
]


@pytest.mark.parametrize(("command", "matrix_id"), POSITIVE_FORENSIC_COMMANDS)
def test_positive_forensic_matrix_preserves_parser_contract(
    command: str,
    matrix_id: str,
    gate_case: Path,
) -> None:
    assert isinstance(command, str)
    with _with_case(gate_case):
        stages = security.validate_shell_command(command, cwd=gate_case)

    assert stages, matrix_id
    for stage in stages:
        assert isinstance(stage["argv"], list)
        assert stage["argv"][0].startswith("/usr/bin/")
        assert stage["binary"]


def test_pipeline_redirect_positive_matrix_stays_structured(gate_case: Path) -> None:
    command = "strings evidence/mem.raw | rg -i pass > extractions/hits.txt"
    with _with_case(gate_case):
        stages = security.validate_shell_command(command, cwd=gate_case)

    assert [stage["binary"] for stage in stages] == ["strings", "rg"]
    assert stages[0]["operator"] == "|"
    assert stages[1]["redirects"] == [
        (">", str((gate_case / "extractions" / "hits.txt").resolve()))
    ]


def test_worker_public_contract_remains_shell_false() -> None:
    source = inspect.getsource(worker._execute_payload)
    assert "shell=False" in source


def test_live_gate_runbook_covers_positive_and_checklist_rows() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")
    required_tokens = [
        "vol -f <CASE_DIR>/evidence/mem.raw windows.pslist",
        "mmls <CASE_DIR>/evidence/disk.E01",
        "EvtxECmd -f <CASE_DIR>/evidence/x.evtx --csv <CASE_DIR>/extractions/",
        "tshark -r <CASE_DIR>/evidence/capture.pcap -Y http -T json",
        "yara <ADMIN_RO_RULES> <CASE_DIR>/evidence/sample",
        "rg -i password <CASE_DIR>/extractions/strings.txt",
        "strings <CASE_DIR>/evidence/mem.raw | rg -i pass > <CASE_DIR>/extractions/hits.txt",
        "hayabusa csv-timeline -d <CASE_DIR>/evidence/evtx -o <CASE_DIR>/extractions/ht.csv",
        "Negative red-team harness",
        "Positive forensic matrix",
        "Evidence pre/post hash",
        "No approval_required",
        "Ceiling",
        "Floor",
    ]
    missing = [token for token in required_tokens if token not in text]
    assert missing == []
