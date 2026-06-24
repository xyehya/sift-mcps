"""Unit 2 / Gap B-D3: record_finding forward-writes one app.audit_events row per
agent-narrated supporting command, keyed by the ``shell-*`` id as
``details.backend_audit_id``, ONLY in DB-active mode and with the command/purpose
REDACTED + bounded.

These exercise ``_persist_shell_audit_event`` and ``_redact_supporting_command``
directly with a faithful in-memory fake ``psycopg`` (no real Postgres). The
record_finding wiring (DB-active gate via ``_db_case_id``, best-effort try/except
that appends to ``audit_warnings`` and never raises) is unit-tested separately
against the same redaction contract.
"""

from __future__ import annotations

import sys
import types

import pytest

import sift_core.case_manager as cm


class _FakeCursor:
    def __init__(self, store):
        self._store = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, values):
        self._store["sql"] = sql
        self._store["values"] = values


class _FakeConn:
    def __init__(self, store):
        self._store = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self):
        return _FakeCursor(self._store)

    def commit(self):
        self._store["committed"] = True


def _install_fake_psycopg(monkeypatch, store, *, raise_on_connect=False):
    mod = types.ModuleType("psycopg")

    def connect(dsn):
        store["dsn"] = dsn
        if raise_on_connect:
            raise RuntimeError("boom")
        return _FakeConn(store)

    mod.connect = connect
    types_mod = types.ModuleType("psycopg.types")
    json_mod = types.ModuleType("psycopg.types.json")

    class Jsonb:
        def __init__(self, value):
            self.value = value

    json_mod.Jsonb = Jsonb
    types_mod.json = json_mod
    monkeypatch.setitem(sys.modules, "psycopg", mod)
    monkeypatch.setitem(sys.modules, "psycopg.types", types_mod)
    monkeypatch.setitem(sys.modules, "psycopg.types.json", json_mod)


# ---------------------------------------------------------------------------
# redaction
# ---------------------------------------------------------------------------


def test_redact_strips_obvious_secrets():
    r = cm._redact_supporting_command
    assert "abc123secret" not in r('curl -H "Authorization: Bearer abc123secret" http://x')
    assert "Sup3rSecret" not in r("mysql --password=Sup3rSecret -u root")
    assert "pass" not in r("git clone https://user:pass@github.com/x/y.git").split("github")[0]
    assert "AKIAIOSFODNN7EXAMPLE" not in r("export AWS=AKIAIOSFODNN7EXAMPLE")
    assert "[REDACTED:secret]" in r("--token=zzz")


def test_redact_bounds_length():
    out = cm._redact_supporting_command("g" * 5000)
    assert len(out) <= cm._SHELL_AUDIT_FIELD_MAX + 20
    assert out.endswith("...[truncated]")


def test_redact_preserves_a_clean_command():
    out = cm._redact_supporting_command("grep -i evil C/Windows/System32/config")
    assert out == "grep -i evil C/Windows/System32/config"


def test_redact_never_raises_on_bad_input():
    class Bad:
        def __str__(self):
            raise ValueError("nope")

    assert cm._redact_supporting_command(Bad()) == "[REDACTED:error]"


def test_redact_underscore_prefixed_and_bare_provider_tokens():
    """Security follow-up: underscore-prefixed key names (client_secret,
    AWS_SECRET_ACCESS_KEY, GH_TOKEN, my_access_key) and BARE provider PAT tokens
    (ghp_…) must be scrubbed — none of the secret values may survive."""
    r = cm._redact_supporting_command
    # key=value with the keyword as a substring of a longer identifier
    assert "abc123def456" not in r("foo --client_secret=abc123def456")
    assert "wJalrXUtnFEMI" not in r("env AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIsecretvalue")
    assert "ghp_0123456789abcdef" not in r("export GH_TOKEN=ghp_0123456789abcdef")
    assert "AKIAIOSFODNN7EXAMPLE" not in r("set my_access_key=AKIAIOSFODNN7EXAMPLE")
    # BARE provider token with no key= prefix
    assert "ghp_0123456789abcdefABCD" not in r("curl -u ghp_0123456789abcdefABCD https://api")


def test_redact_does_not_over_redact_benign_forensic_command():
    """The benign forensic command must pass through UN-redacted — the broadened
    keyword/substring rules must not catch ordinary EZ-tool invocations/paths."""
    cmd = "EvtxECmd.exe -f Security.evtx --csv /tmp/out"
    assert cm._redact_supporting_command(cmd) == cmd


def test_redact_i2_sk_pk_full_stripe_forms_only():
    """I-2: only the FULL Stripe key forms (sk_live_/sk_test_/pk_live_/pk_test_/
    rk_live_/rk_test_) are redacted; a benign `sk-something-1234567890` token (a
    generic short prefix) must NOT be over-redacted, and representative forensic
    arg strings must pass through untouched."""
    r = cm._redact_supporting_command

    # Benign short prefixes must survive verbatim (the old over-redaction bug).
    assert r("sk-something-1234567890") == "sk-something-1234567890"
    assert r("pk-some-config-9876543210") == "pk-some-config-9876543210"

    # Full Stripe secret keys MUST be redacted to the marker (value gone).
    sk_live = "sk_live_" + "a" * 24
    sk_test = "sk_test_" + "b" * 24
    pk_live = "pk_live_" + "c" * 24
    rk_live = "rk_live_" + "d" * 24
    for tok in (sk_live, sk_test, pk_live, rk_live):
        out = r(tok)
        assert tok not in out, f"full Stripe key not redacted: {tok!r} -> {out!r}"
        assert "[REDACTED:secret]" in out

    # Other provider prefixes still redact (no regression).
    assert "ghp_0123456789abcdef" not in r("export GH=ghp_0123456789abcdef")

    # Representative forensic args must NOT be over-redacted.
    for cmd in (
        "EvtxECmd.exe -f x.evtx --csv /tmp/out",
        "grep -r foo",
        "fls -r image.dd",
        "vol -f mem.raw windows.pslist",
    ):
        assert r(cmd) == cmd, f"forensic command over-redacted: {cmd!r}"


# ---------------------------------------------------------------------------
# DB forward-write
# ---------------------------------------------------------------------------


def test_writes_row_keyed_by_shell_eid(monkeypatch):
    store: dict = {}
    _install_fake_psycopg(monkeypatch, store)
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://svc:pw@db/sift")
    cm._persist_shell_audit_event(
        "shell-alice-20260624-003",
        command="grep -i logon C/Windows/System32/winevt",
        purpose="confirm interactive logon",
        case_id="88888888-8888-8888-8888-888888888888",
        examiner="alice",
    )
    assert store.get("committed") is True
    vals = store["values"]
    assert vals[0] == "finding.supporting_command"
    assert vals[1] == "service"
    assert vals[3] == "success"
    assert vals[4] == "88888888-8888-8888-8888-888888888888"
    details = vals[6].value
    assert details["backend_audit_id"] == "shell-alice-20260624-003"
    assert "grep -i logon" in details["command"]
    assert details["purpose"] == "confirm interactive logon"


def test_command_is_redacted_in_the_row(monkeypatch):
    store: dict = {}
    _install_fake_psycopg(monkeypatch, store)
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://x@db/s")
    cm._persist_shell_audit_event(
        "shell-x-20260624-001",
        command='curl -H "Authorization: Bearer SUPERSECRETTOKEN" https://x',
        purpose="api call",
        case_id="99999999-9999-9999-9999-999999999999",
    )
    details = store["values"][6].value
    assert "SUPERSECRETTOKEN" not in details["command"]


def test_noop_without_dsn(monkeypatch):
    store: dict = {}
    _install_fake_psycopg(monkeypatch, store)
    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
    cm._persist_shell_audit_event(
        "shell-x-1", command="ls", purpose="p", case_id="aaaa-bbbb"
    )
    assert "dsn" not in store


def test_noop_without_case_id(monkeypatch):
    store: dict = {}
    _install_fake_psycopg(monkeypatch, store)
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://x@db/s")
    cm._persist_shell_audit_event(
        "shell-x-1", command="ls", purpose="p", case_id=""
    )
    assert "dsn" not in store


def test_connect_error_propagates_for_caller_to_catch(monkeypatch):
    """The helper itself does not swallow — the caller in record_finding wraps it
    in try/except and appends to audit_warnings (so it never blocks)."""
    store: dict = {}
    _install_fake_psycopg(monkeypatch, store, raise_on_connect=True)
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://x@db/s")
    monkeypatch.delenv("SIFT_AUDIT_WRITER_DSN", raising=False)
    with pytest.raises(RuntimeError):
        cm._persist_shell_audit_event(
            "shell-x-1", command="ls", purpose="p", case_id="cccc-dddd"
        )


# ---------------------------------------------------------------------------
# L-1b: audit_forward_write_dsn() selection helper (direct unit)
# ---------------------------------------------------------------------------


def test_l1b_helper_prefers_writer_dsn(monkeypatch):
    from sift_core.investigation_store import audit_forward_write_dsn, audit_writer_dsn

    monkeypatch.setenv("SIFT_AUDIT_WRITER_DSN", "postgresql://w@db/scoped")
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://s@db/full")
    assert audit_writer_dsn() == "postgresql://w@db/scoped"
    assert audit_forward_write_dsn() == "postgresql://w@db/scoped"


def test_l1b_helper_falls_back_to_control_plane(monkeypatch):
    from sift_core.investigation_store import audit_forward_write_dsn

    monkeypatch.delenv("SIFT_AUDIT_WRITER_DSN", raising=False)
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://s@db/full")
    assert audit_forward_write_dsn() == "postgresql://s@db/full"


def test_l1b_helper_none_when_neither_set(monkeypatch):
    from sift_core.investigation_store import audit_forward_write_dsn, audit_writer_dsn

    monkeypatch.delenv("SIFT_AUDIT_WRITER_DSN", raising=False)
    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
    assert audit_writer_dsn() is None
    assert audit_forward_write_dsn() is None


def test_l1b_helper_empty_writer_dsn_is_unset(monkeypatch):
    from sift_core.investigation_store import audit_writer_dsn

    monkeypatch.setenv("SIFT_AUDIT_WRITER_DSN", "   ")
    assert audit_writer_dsn() is None


# ---------------------------------------------------------------------------
# L-1b: least-privilege audit-writer DSN selection (shell forward-write path)
# ---------------------------------------------------------------------------


def test_l1b_writer_dsn_preferred_when_set(monkeypatch):
    """L-1b: the shell forward-write connects with SIFT_AUDIT_WRITER_DSN (the
    scoped role) when it is set, NOT the full control-plane DSN."""
    store: dict = {}
    _install_fake_psycopg(monkeypatch, store)
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://service@db/full")
    monkeypatch.setenv("SIFT_AUDIT_WRITER_DSN", "postgresql://sift_audit_writer@db/scoped")
    cm._persist_shell_audit_event(
        "shell-x-20260624-009", command="ls", purpose="p",
        case_id="11111111-1111-1111-1111-111111111111",
    )
    assert store.get("dsn") == "postgresql://sift_audit_writer@db/scoped"
    assert store.get("committed") is True


def test_l1b_falls_back_to_control_plane_dsn_when_writer_unset(monkeypatch):
    """L-1b non-breaking rollout: with the writer DSN unset the shell forward-write
    falls back to the full control-plane DSN (provenance keeps working)."""
    store: dict = {}
    _install_fake_psycopg(monkeypatch, store)
    monkeypatch.delenv("SIFT_AUDIT_WRITER_DSN", raising=False)
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://service@db/full")
    cm._persist_shell_audit_event(
        "shell-x-20260624-010", command="ls", purpose="p",
        case_id="22222222-2222-2222-2222-222222222222",
    )
    assert store.get("dsn") == "postgresql://service@db/full"


def test_l1b_empty_writer_dsn_falls_back(monkeypatch):
    """L-1b: an empty/whitespace writer DSN is treated as unset."""
    store: dict = {}
    _install_fake_psycopg(monkeypatch, store)
    monkeypatch.setenv("SIFT_AUDIT_WRITER_DSN", "   ")
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://service@db/full")
    cm._persist_shell_audit_event(
        "shell-x-20260624-011", command="ls", purpose="p",
        case_id="33333333-3333-3333-3333-333333333333",
    )
    assert store.get("dsn") == "postgresql://service@db/full"


def test_l1b_noop_when_neither_dsn_set(monkeypatch):
    """L-1b: with NEITHER DSN configured the helper no-ops (no connection)."""
    store: dict = {}
    _install_fake_psycopg(monkeypatch, store)
    monkeypatch.delenv("SIFT_AUDIT_WRITER_DSN", raising=False)
    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
    cm._persist_shell_audit_event(
        "shell-x-1", command="ls", purpose="p",
        case_id="44444444-4444-4444-4444-444444444444",
    )
    assert "dsn" not in store


def test_l1b_permission_error_propagates_for_caller_failsoft(monkeypatch):
    """L-1b fail-soft: a permission error under the scoped role raises from the
    helper for record_finding's try/except to catch (append to audit_warnings,
    never block). This mirrors the connect-error contract.

    The record_finding caller wrapping is exercised separately; here we prove the
    scoped-DSN permission failure surfaces the SAME way (so the existing
    best-effort wrapper degrades to a skipped row)."""
    store: dict = {}

    class _DeniedCursor:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, values):
            raise RuntimeError("permission denied for table audit_events")

    class _Conn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def cursor(self):
            return _DeniedCursor()

        def commit(self):
            store["committed"] = True

    import sys
    import types

    mod = types.ModuleType("psycopg")
    mod.connect = lambda dsn: (_Conn())
    types_mod = types.ModuleType("psycopg.types")
    json_mod = types.ModuleType("psycopg.types.json")

    class Jsonb:
        def __init__(self, value):
            self.value = value

    json_mod.Jsonb = Jsonb
    types_mod.json = json_mod
    monkeypatch.setitem(sys.modules, "psycopg", mod)
    monkeypatch.setitem(sys.modules, "psycopg.types", types_mod)
    monkeypatch.setitem(sys.modules, "psycopg.types.json", json_mod)

    monkeypatch.setenv("SIFT_AUDIT_WRITER_DSN", "postgresql://sift_audit_writer@db/scoped")
    with pytest.raises(RuntimeError, match="permission denied"):
        cm._persist_shell_audit_event(
            "shell-x-1", command="ls", purpose="p",
            case_id="55555555-5555-5555-5555-555555555555",
        )
    # commit never ran (the row was not written).
    assert store.get("committed") is None
