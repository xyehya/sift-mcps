"""BATCH-K5 — run_command authority-isolation hardening.

Proves the four K5 guarantees on top of the I1 sandbox:

  * the run_command subprocess environment is scrubbed of DB DSNs, Supabase /
    service-role keys, OpenSearch credentials, and other VM secrets;
  * the safe runtime allowlist (PATH, locale, SIFT_EXECUTE_* knobs, security
    policy) still passes through so tools and policy keep working;
  * a command cannot write to an authority/proof artifact (defense in depth on
    top of host ACLs and the case write-jail);
  * a path-free command receipt is persisted to Postgres (job step + result)
    and is reportable without local paths, for both allowed and denied runs.
"""

from __future__ import annotations

import io
import json

import pytest

from sift_common.audit import AuditWriter
from sift_core.evidence_chain import init_evidence_chain, seal_manifest
from sift_core.execute.catalog import clear_catalog_cache
from sift_core.execute.job_worker import ClaimedJob, JobResult, JobWorker
from sift_core.execute.run_command_job import run_command_job_handler
from sift_core.execute.runtime_acl import (
    assert_no_authority_write_target,
    build_sandbox_env,
    env_leak_report,
    is_authority_path,
)
from sift_core.execute.security_policy import SECURITY_POLICY_ENV

# Reuse the durable-job fake Postgres from the D1 worker tests so the receipt
# path under test is identical to production; only the SQL engine is simulated.
from .test_job_worker import FakeJobDB, _Job, _worker

_KEY = b"k5-run-command-isolation-derived-key32"


@pytest.fixture(autouse=True)
def _run_as_current_user(monkeypatch):
    monkeypatch.setenv("SIFT_EXECUTE_AS_USER", "__current__")
    clear_catalog_cache()


@pytest.fixture
def sealed_case(tmp_path, monkeypatch):
    monkeypatch.setattr("sift_core.evidence_chain._set_immutable", lambda *_a: True)
    case_dir = tmp_path / "case-k5-06080101"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("case_id: K5-001\nexaminer: analyst\n")
    ev = case_dir / "evidence" / "disk.txt"
    ev.write_bytes(b"sealed evidence bytes\n")
    init_evidence_chain(case_dir)
    seal_manifest(
        case_dir,
        [{"path": "evidence/disk.txt", "source": "fixture", "description": "d"}],
        "analyst",
        _KEY,
    )
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    monkeypatch.setenv("SIFT_EXAMINER", "analyst")
    return case_dir


# --- environment scrubbing ---------------------------------------------------


_SECRET_ENV = {
    "SUPABASE_SERVICE_ROLE_KEY": "sr-secret",
    "SUPABASE_URL": "https://x.supabase.co",
    "SUPABASE_ANON_KEY": "anon",
    "CONTROL_PLANE_DSN": "postgresql://u:p@h/db",
    "DATABASE_URL": "postgresql://u:p@h/db",
    "PGPASSWORD": "hunter2",
    "OPENSEARCH_PASSWORD": "os-secret",
    "OPENSEARCH_URL": "https://os:9200",
    "SIFT_HMAC_KEY": "hmac-secret",
    "AWS_SECRET_ACCESS_KEY": "aws-secret",
    "SOLANA_PRIVATE_KEY": "sol-secret",
    "AUTH_TOKEN": "bearer-xyz",
}


def test_sandbox_env_strips_db_and_service_secrets(monkeypatch):
    for k, v in _SECRET_ENV.items():
        monkeypatch.setenv(k, v)
    env = build_sandbox_env()
    for name in _SECRET_ENV:
        assert name not in env, f"secret {name} leaked into sandbox env"
    assert env_leak_report(env) == []


def test_sandbox_env_keeps_safe_runtime_allowlist(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("SIFT_CASE_DIR", "/cases/case-x")
    monkeypatch.setenv("SIFT_EXECUTE_AS_USER", "agent_runtime")
    monkeypatch.setenv(SECURITY_POLICY_ENV, '{"mode":"denylist"}')
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "sr-secret")
    env = build_sandbox_env()
    assert env["PATH"] == "/usr/bin:/bin"
    assert env["SIFT_CASE_DIR"] == "/cases/case-x"
    assert env["SIFT_EXECUTE_AS_USER"] == "agent_runtime"
    assert env[SECURITY_POLICY_ENV] == '{"mode":"denylist"}'
    # Non-interactive hardening defaults applied.
    assert env["TERM"] == "dumb"


def test_sandbox_env_overrides_cannot_smuggle_secret():
    env = build_sandbox_env(
        base_env={"PATH": "/bin"},
        overrides={"FOO": "ok", "API_TOKEN": "leak"},
    )
    assert env["FOO"] == "ok"
    assert "API_TOKEN" not in env


def test_sandbox_env_strips_runtime_code_injection_vectors():
    env = build_sandbox_env(
        base_env={
            "PATH": "/bin",
            "DOTNET_STARTUP_HOOKS": "/tmp/hook.dll",
            "CORECLR_PROFILER": "{evil}",
            "LD_PRELOAD": "/tmp/x.so",
            "LD_AUDIT": "/tmp/audit.so",
            "PYTHONPATH": "/tmp/py",
            "PYTHONHOME": "/tmp/pyhome",
            "PYTHONSTARTUP": "/tmp/start.py",
            "PERL5LIB": "/tmp/perl",
            "RUBYOPT": "-r/tmp/r.rb",
            "NODE_OPTIONS": "--require /tmp/n.js",
            "LUA_PATH": "/tmp/?.lua",
            "BASH_ENV": "/tmp/bashenv",
            "GCONV_PATH": "/tmp/gconv",
            "IFS": ":",
        },
        overrides={
            "DOTNET_ADDITIONAL_DEPS": "/tmp/deps",
            "CORECLR_ENABLE_PROFILING": "1",
            "NODE_PATH": "/tmp/node",
            "FOO": "ok",
        },
    )

    assert env["PATH"] == "/bin"
    assert env["FOO"] == "ok"
    for name in (
        "DOTNET_STARTUP_HOOKS",
        "CORECLR_PROFILER",
        "LD_PRELOAD",
        "LD_AUDIT",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PERL5LIB",
        "RUBYOPT",
        "NODE_OPTIONS",
        "LUA_PATH",
        "BASH_ENV",
        "GCONV_PATH",
        "IFS",
        "DOTNET_ADDITIONAL_DEPS",
        "CORECLR_ENABLE_PROFILING",
        "NODE_PATH",
    ):
        assert name not in env


def test_worker_spawns_tool_with_scrubbed_env(monkeypatch):
    """The forensic tool subprocess receives the scrubbed env, not parent secrets."""
    from sift_core.execute import worker

    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "sr-secret")
    monkeypatch.setenv("CONTROL_PLANE_DSN", "postgresql://u:p@h/db")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")

    captured = {}

    class FakeProcess:
        pid = 4242
        returncode = 0
        stdout = io.BytesIO(b"ok\n")
        stderr = io.BytesIO(b"")

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = -9

        def poll(self):
            return self.returncode

    def fake_popen(cmd, **kwargs):
        captured["env"] = kwargs.get("env")
        return FakeProcess()

    monkeypatch.setattr(worker.subprocess, "Popen", fake_popen)
    worker._execute_payload(
        {"cmd": ["/bin/echo", "ok"], "timeout": 5, "cwd": None,
         "max_output_bytes": 1024, "memory_limit_bytes": 0}
    )
    env = captured["env"]
    assert env is not None, "Popen must receive an explicit scrubbed env"
    assert "SUPABASE_SERVICE_ROLE_KEY" not in env
    assert "CONTROL_PLANE_DSN" not in env
    assert env.get("PATH") == "/usr/bin:/bin"
    assert env_leak_report(env) == []


# --- authority-file write protection -----------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/cases/c/evidence-manifest.json",
        "/cases/c/evidence-ledger.jsonl",
        "/cases/c/approvals.jsonl",
        "/cases/c/findings.json",
        "/cases/c/CASE.yaml",
        "/cases/c/audit/2026.jsonl",
        "/cases/c/evidence-anchor-v3.json",
        "/home/u/.sift/active_case",
        "/var/lib/sift/integrity.db",
        "host-dictionary.yaml",
    ],
)
def test_is_authority_path_flags_authority_artifacts(path):
    assert is_authority_path(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "/cases/c/agent/run_commands/output1/out.txt",
        "/cases/c/extractions/strings.txt",
        "/cases/c/tmp/scratch.bin",
        "report.csv",
    ],
)
def test_is_authority_path_allows_workspace_outputs(path):
    assert is_authority_path(path) is False


def test_assert_no_authority_write_target_blocks_manifest():
    with pytest.raises(PermissionError, match="authority"):
        assert_no_authority_write_target(["/cases/c/evidence-manifest.json"])


def test_assert_no_authority_write_target_allows_scratch():
    # No exception for legitimate workspace output.
    assert_no_authority_write_target(["/cases/c/agent/run_commands/o/out.txt"])


def test_worker_redirect_to_authority_file_fails_closed(monkeypatch, tmp_path):
    """A redirect aimed at an authority artifact is refused before any process spawns."""
    from sift_core.execute import worker

    def fail_if_called(*a, **k):  # pragma: no cover - must not run
        raise AssertionError("process spawned despite authority-write target")

    monkeypatch.setattr(worker.subprocess, "Popen", fail_if_called)
    with pytest.raises(PermissionError, match="authority"):
        worker._execute_payload(
            {
                "stages": [
                    {"argv": ["/bin/echo", "x"], "redirects": [[">", str(tmp_path / "evidence-manifest.json")]]}
                ],
                "timeout": 5,
                "cwd": None,
                "max_output_bytes": 1024,
                "memory_limit_bytes": 0,
            }
        )


# --- DB-backed receipt (allowed + denied) ------------------------------------


@pytest.fixture
def db():
    _Job._seq = 0
    return FakeJobDB()


def _enqueue_run_command(db, case_dir, *, command, purpose, evidence_refs=None,
                         output_ref=None, save_output=False):
    spec_public = {"command": command, "purpose": purpose}
    if evidence_refs is not None:
        spec_public["evidence_refs"] = evidence_refs
    if output_ref is not None:
        spec_public["output_ref"] = output_ref
    if save_output:
        spec_public["save_output"] = True
    return db.enqueue(
        _Job(
            "run_command",
            case_id="K5-001",
            max_attempts=1,
            spec_public=spec_public,
            spec_internal={"case_dir": str(case_dir), "case_key": "K5-001", "examiner": "analyst"},
        )
    )


def test_allowed_run_command_persists_receipt_and_no_paths(db, sealed_case):
    job = _enqueue_run_command(
        db, sealed_case,
        command="cat evidence/disk.txt",
        purpose="read sealed evidence",
        evidence_refs=["disk.txt"],
        output_ref="catdump",
        save_output=True,
    )
    w = _worker(db, {"run_command": run_command_job_handler})
    w.run_once(job_types=["run_command"])

    stored = db.get(job.id)
    assert stored.status == "succeeded"
    receipt = stored.result_public["receipt"]
    # Hash-linked, path-free receipt fields.
    assert receipt["job_id"] == job.id
    assert receipt["command_plan_sha256"]  # sha256 of the command plan
    assert receipt["evidence_refs"] == ["disk.txt"]
    assert len(receipt["input_sha256s"]) == 1
    assert receipt["audit_id"]
    assert receipt["success"] is True
    assert receipt["output_ref"].startswith("agent/run_commands/")
    assert receipt["output_sha256"]
    # The receipt is also persisted as a durable job-step detail.
    step = next(s for s in db.steps if s["job_id"] == job.id)
    assert step["detail"]["receipt"]["command_plan_sha256"] == receipt["command_plan_sha256"]
    # No absolute case path anywhere in what Postgres stored.
    blob = json.dumps(stored.result_public) + json.dumps(db.steps)
    assert str(sealed_case) not in blob
    assert "[REDACTED:absolute_path]" not in receipt.get("output_ref", "")


def test_denied_command_fails_closed_with_receipt(db, sealed_case):
    # `env` is on the hard deny floor — used to also be the classic env-dump
    # vector. It must fail closed and still produce an auditable receipt.
    job = _enqueue_run_command(
        db, sealed_case,
        command="env",
        purpose="attempt to dump environment",
    )
    w = _worker(db, {"run_command": run_command_job_handler})
    w.run_once(job_types=["run_command"])

    stored = db.get(job.id)
    receipt = stored.result_public["receipt"]
    # Denied: surfaced as a failure result, audited, no successful execution.
    assert stored.result_public.get("success") is False
    assert receipt["success"] is False
    assert receipt["audit_id"]
    assert receipt["command_plan_sha256"]


def test_run_command_cannot_read_secret_env_via_proc(db, sealed_case, monkeypatch):
    """A command that tries to read the parent's secret env sees nothing."""
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "sr-secret-should-not-leak")
    monkeypatch.setenv("CONTROL_PLANE_DSN", "postgresql://u:p@h/db")
    job = _enqueue_run_command(
        db, sealed_case,
        # `cat /proc/self/environ` is the canonical env-exfil attempt; the tool
        # runs with a scrubbed env so the secret is simply absent.
        command="cat /proc/self/environ",
        purpose="probe for inherited secrets",
        save_output=True,
    )
    w = _worker(db, {"run_command": run_command_job_handler})
    w.run_once(job_types=["run_command"])
    stored = db.get(job.id)
    blob = json.dumps(stored.result_public)
    assert "sr-secret-should-not-leak" not in blob
    assert "postgresql://u:p@h/db" not in blob
