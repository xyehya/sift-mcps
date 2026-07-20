"""P4.23 CP3 Scope B — Gateway startup wiring of the custody reauth verifier.

CP2A froze the private ``custody.reauth._VERIFIER`` seam and its fail-closed unit
tests (kept intact in ``test_cp2a_unit.py``). CP3 wires that seam to the concrete
``SupabaseAuthCallbacks.reverify_password`` at ``Gateway.create_app`` via the
sync-over-async bridge :func:`server._make_custody_reauth_verifier`.

These tests prove the bridge + the real startup wiring:

* success — a clean async verification returns ``None`` (contract: None on success);
* denial — a raising async verifier propagates, and once wired as ``_VERIFIER`` the
  denial maps to a shaped ``reauth_failed`` and records nothing;
* event-loop safety — invoked ON a running event loop (as the sync custody state
  machine is, from the async Portal handler) it completes WITHOUT deadlock and
  without ``asyncio.run() cannot be called from a running event loop``;
* fail-closed reset — constructing an UNCONFIGURED app after a configured one
  resets the module-global ``_VERIFIER`` to ``None`` so no stale verifier survives,
  and ``_run_verifier`` (the exact seam ``record_reauth`` delegates to) then raises
  ``reauth_unavailable`` and authorizes no audit write.

Never logs or persists password/token material; the fakes here only record the
bounded, non-secret source label the bridge forwards.
"""

from __future__ import annotations

import asyncio

import pytest
from sift_gateway.custody import reauth
from sift_gateway.custody.reauth import ReauthError
from sift_gateway.server import (
    _CUSTODY_REAUTH_SOURCE,
    Gateway,
    _make_custody_reauth_verifier,
)


def _execute_security() -> dict:
    # Minimal execute-security block so Gateway.__init__ / create_app build a
    # core-only app without a control-plane DSN (mirrors the existing gateway
    # app-build unit tests).
    return {"execute": {"security": {"denied_binaries": ["env"]}}}


# ---------------------------------------------------------------------------
# (a) success — clean verification returns None; the bounded source label flows
# ---------------------------------------------------------------------------
def test_bridge_returns_none_on_success_and_forwards_bounded_source() -> None:
    calls: list[tuple[str, str, str | None, str | None]] = []

    async def _reverify(
        email: str,
        password: str,
        source: str | None,
        *,
        expected_auth_user_id: str | None = None,
    ) -> dict:
        calls.append((email, password, source, expected_auth_user_id))
        # The real callback returns a session dict; the bridge DISCARDS it.
        return {"session": "discarded"}

    verify = _make_custody_reauth_verifier(_reverify)

    # No running loop here → the bridge runs the coroutine inline.
    assert verify(email="owner@example.com", password="pw", expected_auth_user_id="uid") is None
    # Exactly one call; the 3rd positional is the bounded, non-secret source label
    # (never an IP, never token material) and the identity binding is forwarded.
    assert calls == [("owner@example.com", "pw", _CUSTODY_REAUTH_SOURCE, "uid")]
    assert _CUSTODY_REAUTH_SOURCE == "custody-reauth"


def test_bridge_defaults_expected_auth_user_id_to_none() -> None:
    seen: list[str | None] = []

    async def _reverify(email, password, source, *, expected_auth_user_id=None):
        seen.append(expected_auth_user_id)
        return {}

    verify = _make_custody_reauth_verifier(_reverify)
    assert verify(email="o@e.com", password="pw") is None
    assert seen == [None]


# ---------------------------------------------------------------------------
# (b) denial — the async verifier's raise propagates and records nothing
# ---------------------------------------------------------------------------
def test_bridge_propagates_denial() -> None:
    async def _reject(email, password, source, *, expected_auth_user_id=None):
        raise ValueError("gotrue 401")

    verify = _make_custody_reauth_verifier(_reject)
    with pytest.raises(ValueError, match="gotrue 401"):
        verify(email="o@e.com", password="wrong")


def test_bridge_wired_as_verifier_maps_denial_to_reauth_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Wire the bridge exactly as create_app does, then drive _run_verifier — the
    # seam record_reauth delegates to BEFORE any audit INSERT. A denial raises
    # reauth_failed, so record_reauth records nothing (fail-closed).
    async def _reject(email, password, source, *, expected_auth_user_id=None):
        raise ValueError("gotrue 401")

    monkeypatch.setattr(reauth, "_VERIFIER", _make_custody_reauth_verifier(_reject))
    with pytest.raises(ReauthError) as exc:
        reauth._run_verifier("o@e.com", "wrong", "uid")
    assert exc.value.reason == "reauth_failed"


# ---------------------------------------------------------------------------
# (c) event-loop safety — invoked ON a running event loop, no deadlock/RuntimeError
# ---------------------------------------------------------------------------
async def test_bridge_completes_on_the_event_loop_thread_without_deadlock() -> None:
    seen: list[str | None] = []

    async def _reverify(email, password, source, *, expected_auth_user_id=None):
        # Yield control at least once so this only completes on a live loop.
        await asyncio.sleep(0)
        seen.append(source)
        return {}

    verify = _make_custody_reauth_verifier(_reverify)

    # We are ON the Gateway-style event-loop thread here (asyncio_mode=auto). The
    # sync custody state machine calls the verifier exactly like this. A naive
    # asyncio.run()/run_until_complete() on the running loop would raise or
    # deadlock; the bridge instead offloads to a worker thread with its own loop.
    assert asyncio.get_running_loop().is_running()
    result = verify(email="o@e.com", password="pw", expected_auth_user_id=None)
    assert result is None
    assert seen == [_CUSTODY_REAUTH_SOURCE]


async def test_bridge_denial_on_event_loop_thread_propagates() -> None:
    async def _reject(email, password, source, *, expected_auth_user_id=None):
        await asyncio.sleep(0)
        raise RuntimeError("control-plane unavailable")

    verify = _make_custody_reauth_verifier(_reject)
    # The worker thread's exception is re-raised on the calling (event-loop) thread.
    with pytest.raises(RuntimeError, match="control-plane unavailable"):
        verify(email="o@e.com", password="pw")


# ---------------------------------------------------------------------------
# (d) fail-closed reset — an unconfigured app after a configured one clears
#     _VERIFIER, and record_reauth's verify seam then fails closed
# ---------------------------------------------------------------------------
def test_unconfigured_create_app_resets_stale_verifier_to_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Simulate a prior CONFIGURED app instance having installed a verifier in the
    # same process.
    sentinel_calls: list[tuple] = []

    def _stale_verifier(*, email, password, expected_auth_user_id=None):
        sentinel_calls.append((email, password, expected_auth_user_id))

    monkeypatch.setattr(reauth, "_VERIFIER", _stale_verifier)
    assert reauth._VERIFIER is _stale_verifier  # prior configured state

    # Force the "unconfigured" branch deterministically (no Supabase auth), and
    # keep the app core-only (no control-plane DSN → no DB connections). The REAL
    # create_app wiring block runs and MUST reassign _VERIFIER to None.
    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
    from types import SimpleNamespace

    import sift_gateway.config as gw_config

    monkeypatch.setattr(
        gw_config, "load_auth_config", lambda _cfg: SimpleNamespace(configured=False)
    )

    gateway = Gateway({"backends": {}, **_execute_security()})
    app = gateway.create_app()
    assert app is not None

    # The stale verifier did NOT survive into the unconfigured instance.
    assert reauth._VERIFIER is None
    assert sentinel_calls == []

    # record_reauth delegates verification to _run_verifier; an unset verifier
    # raises reauth_unavailable BEFORE any audit write, so nothing is recorded.
    with pytest.raises(ReauthError) as exc:
        reauth._run_verifier("owner@example.com", "pw", "uid")
    assert exc.value.reason == "reauth_unavailable"
    assert exc.value.http_status == 503
