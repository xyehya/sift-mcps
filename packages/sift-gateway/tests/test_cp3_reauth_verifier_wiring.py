"""P4.23 CP3 (repair-1) — dedicated custody-reauth execution context.

CP2A froze the private ``custody.reauth._VERIFIER`` seam and its fail-closed unit
tests (kept intact in ``test_cp2a_unit.py``). CP3 wires that seam to the concrete
``SupabaseAuthCallbacks.reverify_password`` at ``Gateway.create_app``.

Repair-1 replaces the original throwaway-thread bridge (which drove the SHARED
main-loop ``httpx.AsyncClient`` from a foreign loop and reached ``PoolTimeout``
under pool contention, spuriously denying a valid operator password) with
:class:`server._CustodyReauthContext`: a dedicated loop/thread that exclusively
owns a dedicated ``SupabaseAuthClient``. reauth is submitted to that loop with
``run_coroutine_threadsafe``; the gateway main-loop client is never driven from
another loop.

These tests prove:

* success returns ``None`` and forwards only the bounded, non-secret source label;
* a denial propagates and, wired as ``_VERIFIER``, maps to a shaped ``reauth_failed``
  that records nothing;
* invoked ON a running event loop (as the sync custody state machine is) it
  completes WITHOUT deadlock — the coroutine runs on the dedicated loop;
* a hung verifier fails closed as ``reauth_unavailable`` (bounded);
* installing a new context retires the prior one (no dedicated-loop leak) and an
  unconfigured app resets ``_VERIFIER`` to ``None`` (fail-closed);
* shutdown closes the dedicated client ON its owning loop, joins the thread, and
  is idempotent;
* REGRESSION (fail-on-revert): a valid reauth completes under concurrent
  main-loop identity-client activity with REAL httpx clients, and the original
  b7d6f094 throwaway-loop shape cannot drive a main-loop-bound async primitive.

Password/token material is never logged or persisted; the fakes only record the
bounded source label.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading

import httpx
import pytest
from sift_gateway import server
from sift_gateway.custody import reauth
from sift_gateway.custody.reauth import ReauthError
from sift_gateway.server import _CUSTODY_REAUTH_SOURCE


async def _noop_aclose() -> None:
    return None


async def _noop_reverify(email, password, source, *, expected_auth_user_id=None):
    return {"ok": True}


@contextlib.contextmanager
def _dedicated(reverify, aclose=_noop_aclose):
    """A dedicated custody-reauth context, torn down after the test (bounded)."""
    ctx = server._CustodyReauthContext(reverify, aclose)
    try:
        yield ctx
    finally:
        ctx.close()


def _execute_security() -> dict:
    # Minimal execute-security block so create_app builds a core-only app without
    # a control-plane DSN (mirrors the existing gateway app-build unit tests).
    return {"execute": {"security": {"denied_binaries": ["env"]}}}


# ---------------------------------------------------------------------------
# success — clean verification returns None; the bounded source label flows
# ---------------------------------------------------------------------------
def test_context_returns_none_on_success_and_forwards_bounded_source() -> None:
    calls: list[tuple[str, str, str | None, str | None]] = []

    async def _reverify(email, password, source, *, expected_auth_user_id=None):
        calls.append((email, password, source, expected_auth_user_id))
        return {"session": "discarded"}  # the real callback returns a dict; discarded

    with _dedicated(_reverify) as ctx:
        assert ctx.verify(email="owner@example.com", password="pw", expected_auth_user_id="uid") is None

    # Exactly one call; the 3rd positional is the bounded, non-secret source label
    # (never an IP, never token material) and the identity binding is forwarded.
    assert calls == [("owner@example.com", "pw", _CUSTODY_REAUTH_SOURCE, "uid")]
    assert _CUSTODY_REAUTH_SOURCE == "custody-reauth"


def test_context_defaults_expected_auth_user_id_to_none() -> None:
    seen: list[str | None] = []

    async def _reverify(email, password, source, *, expected_auth_user_id=None):
        seen.append(expected_auth_user_id)
        return {}

    with _dedicated(_reverify) as ctx:
        assert ctx.verify(email="o@e.com", password="pw") is None
    assert seen == [None]


# ---------------------------------------------------------------------------
# denial — the async verifier's raise propagates and records nothing
# ---------------------------------------------------------------------------
def test_context_propagates_denial() -> None:
    async def _reject(email, password, source, *, expected_auth_user_id=None):
        raise ValueError("gotrue 401")

    with _dedicated(_reject) as ctx:
        with pytest.raises(ValueError, match="gotrue 401"):
            ctx.verify(email="o@e.com", password="wrong")


def test_context_wired_as_verifier_maps_denial_to_reauth_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Wire the dedicated context exactly as create_app installs it, then drive
    # _run_verifier — the seam record_reauth delegates to BEFORE any audit INSERT.
    # A denial raises reauth_failed, so record_reauth records nothing (fail-closed).
    async def _reject(email, password, source, *, expected_auth_user_id=None):
        raise ValueError("gotrue 401")

    with _dedicated(_reject) as ctx:
        monkeypatch.setattr(reauth, "_VERIFIER", ctx.verify)
        with pytest.raises(ReauthError) as exc:
            reauth._run_verifier("o@e.com", "wrong", "uid")
        assert exc.value.reason == "reauth_failed"


# ---------------------------------------------------------------------------
# event-loop safety — invoked ON a running loop, no deadlock/RuntimeError
# ---------------------------------------------------------------------------
async def test_context_completes_on_the_event_loop_thread_without_deadlock() -> None:
    seen: list[str | None] = []

    async def _reverify(email, password, source, *, expected_auth_user_id=None):
        await asyncio.sleep(0)  # only completes on a live loop
        seen.append(source)
        return {}

    with _dedicated(_reverify) as ctx:
        # We are ON the gateway-style event-loop thread here (asyncio_mode=auto),
        # exactly like the sync custody state machine. The coroutine runs on the
        # DEDICATED loop, so this synchronous call blocks only THIS thread and
        # never deadlocks or raises "asyncio.run() cannot be called from a running
        # event loop".
        assert asyncio.get_running_loop().is_running()
        result = ctx.verify(email="o@e.com", password="pw", expected_auth_user_id=None)
        assert result is None
        assert seen == [_CUSTODY_REAUTH_SOURCE]


async def test_context_denial_on_event_loop_thread_propagates() -> None:
    async def _reject(email, password, source, *, expected_auth_user_id=None):
        await asyncio.sleep(0)
        raise RuntimeError("control-plane unavailable")

    with _dedicated(_reject) as ctx:
        with pytest.raises(RuntimeError, match="control-plane unavailable"):
            ctx.verify(email="o@e.com", password="pw")


def test_context_hung_verifier_fails_closed_as_reauth_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A verifier that never returns must not block the caller forever: past the
    # bounded timeout the call fails closed as reauth_unavailable and the pending
    # coroutine is cancelled.
    monkeypatch.setattr(server, "_CUSTODY_REAUTH_TIMEOUT_S", 0.5)

    async def _hang(email, password, source, *, expected_auth_user_id=None):
        await asyncio.sleep(30)  # >> the patched timeout

    with _dedicated(_hang) as ctx:
        with pytest.raises(ReauthError) as exc:
            ctx.verify(email="o@e.com", password="pw")
        assert exc.value.reason == "reauth_unavailable"
        assert exc.value.http_status == 503


# ---------------------------------------------------------------------------
# lifecycle — install retires prior context; shutdown closes on-loop, idempotent
# ---------------------------------------------------------------------------
def test_installing_a_new_context_retires_the_prior_one() -> None:
    ctx1 = server._CustodyReauthContext(_noop_reverify, _noop_aclose)
    server._install_custody_reauth_context(ctx1)
    try:
        # ctx.verify is a bound method (a fresh object per access), so compare by
        # its owning instance, not identity.
        assert getattr(reauth._VERIFIER, "__self__", None) is ctx1
        ctx2 = server._CustodyReauthContext(_noop_reverify, _noop_aclose)
        server._install_custody_reauth_context(ctx2)
        assert getattr(reauth._VERIFIER, "__self__", None) is ctx2
        # The prior context's dedicated loop/thread was torn down — no leak.
        assert not ctx1._thread.is_alive()
        assert ctx2._thread.is_alive()
    finally:
        server._shutdown_custody_reauth_context()
    # Shutdown fully retires the context and fails closed.
    assert reauth._VERIFIER is None
    assert not ctx2._thread.is_alive()


def test_close_runs_aclose_on_the_dedicated_loop_and_is_idempotent() -> None:
    closed = {"n": 0, "loop_ids": []}

    async def _aclose():
        closed["n"] += 1
        closed["loop_ids"].append(id(asyncio.get_running_loop()))

    ctx = server._CustodyReauthContext(_noop_reverify, _aclose)
    dedicated_loop_id = id(ctx._loop)
    ctx.close()
    # The dedicated client is closed ON its owning loop (correct pool lifecycle).
    assert closed["n"] == 1
    assert closed["loop_ids"] == [dedicated_loop_id]
    assert not ctx._thread.is_alive()
    # Idempotent — a second close is a no-op.
    ctx.close()
    assert closed["n"] == 1


def test_unconfigured_create_app_resets_stale_verifier_to_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Simulate a prior CONFIGURED app having installed a verifier in this process.
    sentinel_calls: list[tuple] = []

    def _stale_verifier(*, email, password, expected_auth_user_id=None):
        sentinel_calls.append((email, password, expected_auth_user_id))

    monkeypatch.setattr(reauth, "_VERIFIER", _stale_verifier)
    assert reauth._VERIFIER is _stale_verifier

    # Force the "unconfigured" branch deterministically (no Supabase auth), and
    # keep the app core-only (no control-plane DSN → no DB connections). The REAL
    # create_app wiring runs and MUST reset _VERIFIER to None.
    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
    from types import SimpleNamespace

    import sift_gateway.config as gw_config

    monkeypatch.setattr(
        gw_config, "load_auth_config", lambda _cfg: SimpleNamespace(configured=False)
    )

    try:
        gateway = server.Gateway({"backends": {}, **_execute_security()})
        app = gateway.create_app()
        assert app is not None
        assert app.state.custody_reauth_context is None
        assert reauth._VERIFIER is None
        assert sentinel_calls == []

        # record_reauth delegates verification to _run_verifier; an unset verifier
        # raises reauth_unavailable BEFORE any audit write, so nothing is recorded.
        with pytest.raises(ReauthError) as exc:
            reauth._run_verifier("owner@example.com", "pw", "uid")
        assert exc.value.reason == "reauth_unavailable"
        assert exc.value.http_status == 503
    finally:
        server._shutdown_custody_reauth_context()


# ---------------------------------------------------------------------------
# repair-2 — app-owned retirement (identity compare-and-clear) + startup readiness
# ---------------------------------------------------------------------------
def test_older_app_retire_does_not_clobber_newer_apps_live_verifier() -> None:
    """Exact overlap ordering (the repair-2 blocking defect): app A installs A,
    app B installs B (superseding/closing A), then app A's OWN lifespan retire
    runs. It must NOT close or unset B — B stays alive and current, `_VERIFIER`
    still points to B. Then B retires through its own callback and fully tears
    down, fail-closed."""
    b_closed = {"n": 0}

    async def _b_aclose():
        b_closed["n"] += 1

    ctx_a = server._CustodyReauthContext(_noop_reverify, _noop_aclose)
    server._install_custody_reauth_context(ctx_a)
    ctx_b = server._CustodyReauthContext(_noop_reverify, _b_aclose)
    server._install_custody_reauth_context(ctx_b)  # B supersedes A (closes A)
    try:
        # app A's lifespan ends and retires A's OWN context — B must be untouched.
        server._retire_custody_reauth_context(ctx_a)
        assert server._CUSTODY_REAUTH_CTX is ctx_b
        assert getattr(reauth._VERIFIER, "__self__", None) is ctx_b
        assert ctx_b._thread.is_alive()          # B still live/current
        assert not ctx_a._thread.is_alive()      # A closed (by supersession)
        assert b_closed["n"] == 0                # B's client NOT closed by A's retire
    finally:
        server._retire_custody_reauth_context(ctx_b)  # B's own lifespan retire
    # B retired through its OWN callback: client/loop/thread closed, fail-closed.
    assert server._CUSTODY_REAUTH_CTX is None
    assert reauth._VERIFIER is None
    assert not ctx_b._thread.is_alive()
    assert b_closed["n"] == 1


def test_parameterless_shutdown_retires_current_showing_why_app_owned_retire() -> None:
    """Documents the repair-2 defect and why app lifespan must use the app-owned
    retire. The parameterless ``_shutdown_custody_reauth_context`` retires whatever
    is CURRENT — so if an OLDER app's lifespan called it after a NEWER app (B)
    superseded it, it would wrongly close B. The app-owned
    ``_retire_custody_reauth_context(ctx_a)`` (proven above) does not."""
    ctx_a = server._CustodyReauthContext(_noop_reverify, _noop_aclose)
    server._install_custody_reauth_context(ctx_a)
    ctx_b = server._CustodyReauthContext(_noop_reverify, _noop_aclose)
    server._install_custody_reauth_context(ctx_b)
    try:
        # The pre-repair-2 parameterless path retires the CURRENT context (B) —
        # exactly the clobbering bug when an OLDER app calls it at its shutdown.
        server._shutdown_custody_reauth_context()
        assert server._CUSTODY_REAUTH_CTX is None
        assert reauth._VERIFIER is None
        assert not ctx_b._thread.is_alive()
    finally:
        server._retire_custody_reauth_context(ctx_a)
        server._retire_custody_reauth_context(ctx_b)


def test_retire_is_idempotent_and_stale_retire_never_touches_current() -> None:
    a_closed = {"n": 0}

    async def _a_aclose():
        a_closed["n"] += 1

    ctx_a = server._CustodyReauthContext(_noop_reverify, _a_aclose)
    server._install_custody_reauth_context(ctx_a)
    server._retire_custody_reauth_context(ctx_a)
    assert server._CUSTODY_REAUTH_CTX is None
    assert reauth._VERIFIER is None
    assert a_closed["n"] == 1
    assert not ctx_a._thread.is_alive()

    # Repeated retire of an already-retired context is a no-op (no re-close).
    server._retire_custody_reauth_context(ctx_a)
    assert a_closed["n"] == 1

    # A stale retire (a context that is not the current global) only closes itself
    # and never clears a DIFFERENT current verifier.
    ctx_b = server._CustodyReauthContext(_noop_reverify, _noop_aclose)
    server._install_custody_reauth_context(ctx_b)
    try:
        server._retire_custody_reauth_context(ctx_a)  # stale / not current
        assert server._CUSTODY_REAUTH_CTX is ctx_b
        assert getattr(reauth._VERIFIER, "__self__", None) is ctx_b
    finally:
        server._retire_custody_reauth_context(ctx_b)

    # Retiring None never touches the global.
    server._retire_custody_reauth_context(None)
    assert reauth._VERIFIER is None


def test_startup_readiness_timeout_fails_closed_without_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dedicated loop that never becomes ready must NOT be installed: `ready` is
    False and cleanup leaves no live thread and a closed loop (fail-closed)."""
    monkeypatch.setattr(server, "_CUSTODY_REAUTH_TIMEOUT_S", 0.3)

    class _NeverReadyContext(server._CustodyReauthContext):
        def _run(self):  # never signal ready; close the loop so it cannot leak
            self._loop.close()

    ctx = _NeverReadyContext(_noop_reverify, _noop_aclose)
    assert ctx.ready is False
    # Deterministic cleanup: bounded close leaves no live thread and a closed loop.
    ctx.close()
    assert not ctx._thread.is_alive()
    assert ctx._loop.is_closed()


# ---------------------------------------------------------------------------
# REGRESSION (fail-on-revert): dedicated ownership under concurrent main-loop
# identity-client activity, and the b7d6f094 cross-loop shape fails.
# ---------------------------------------------------------------------------
async def test_reauth_completes_under_concurrent_main_loop_client_activity() -> None:
    """Real-httpx regression: the reauth client is driven ONLY by the dedicated
    loop, never the gateway main loop, so concurrent Portal/MCP JWT activity on
    the shared identity client cannot contend with custody reauth. b7d6f094 drove
    the SHARED main-loop client from a throwaway loop — the exact hazard this
    separation removes."""
    main_loop_id = id(asyncio.get_running_loop())
    reauth_driven_on: set[int] = set()
    shared_driven_on: set[int] = set()

    async def _reauth_handler(request: httpx.Request) -> httpx.Response:
        reauth_driven_on.add(id(asyncio.get_running_loop()))
        await asyncio.sleep(0.01)
        return httpx.Response(200, json={"ok": True})

    async def _shared_handler(request: httpx.Request) -> httpx.Response:
        shared_driven_on.add(id(asyncio.get_running_loop()))
        await asyncio.sleep(0.005)
        return httpx.Response(200, json={"ok": True})

    dedicated = httpx.AsyncClient(transport=httpx.MockTransport(_reauth_handler))
    shared = httpx.AsyncClient(transport=httpx.MockTransport(_shared_handler))

    # Concurrent main-loop "JWT resolution" churn on the shared identity client.
    churn = [
        asyncio.create_task(shared.get("http://gw/auth/v1/user")) for _ in range(30)
    ]

    async def _reverify(email, password, source, *, expected_auth_user_id=None):
        response = await dedicated.post("http://gw/auth/v1/token", json={"email": email})
        assert response.status_code == 200
        return {"ok": True}

    ctx = server._CustodyReauthContext(_reverify, dedicated.aclose)
    try:
        # Invoked from the main-loop thread exactly as the sync custody route does;
        # run it off the test loop so the main-loop churn proceeds concurrently.
        result = await asyncio.to_thread(
            lambda: ctx.verify(email="owner@x", password="pw", expected_auth_user_id="op-1")
        )
        assert result is None
        await asyncio.gather(*churn)
    finally:
        ctx.close()
        await shared.aclose()

    # The dedicated reauth client ran ONLY on the dedicated loop; the shared client
    # ONLY on the main loop; the two never shared a loop.
    assert reauth_driven_on and main_loop_id not in reauth_driven_on
    assert shared_driven_on == {main_loop_id}
    assert not (reauth_driven_on & shared_driven_on)


async def test_legacy_throwaway_shape_cannot_drive_a_main_loop_bound_primitive() -> None:
    """Fail-on-revert teeth. b7d6f094 ran the reauth coroutine via a throwaway
    thread + its own loop (``asyncio.run``) against the SHARED, main-loop-bound
    identity client. An httpx pool — like any asyncio synchronization primitive —
    binds to the loop that owns it and cannot be driven from another loop. Model
    that with a real Future bound to the main loop: the b7d6f094 shape
    fails to drive it, while the dedicated context (which owns its loop) does not."""
    main_loop = asyncio.get_running_loop()
    # A real awaitable OWNED by the main loop stands in for the shared identity
    # client's pool waiter, which binds to the loop that first drove it. An
    # UNLOCKED asyncio.Lock takes acquire()'s uncontended fast path and would NOT
    # exercise the cross-loop check, so use a main-loop Future, which asyncio
    # deterministically refuses to await from another loop.
    main_bound_awaitable = main_loop.create_future()

    async def _reverify_shared(email, password, source, *, expected_auth_user_id=None):
        # As reverify_password would await the shared main-loop client's pool.
        await main_bound_awaitable  # cross-loop when run off the main loop
        return {"ok": True}

    legacy_outcome: dict[str, str] = {}

    def _legacy_throwaway_bridge() -> None:
        # Verbatim b7d6f094 shape: a throwaway thread with its own event loop.
        try:
            asyncio.run(_reverify_shared("o@e.com", "pw", _CUSTODY_REAUTH_SOURCE))
            legacy_outcome["result"] = "completed"
        except BaseException as exc:  # cross-loop failure surfaces here
            legacy_outcome["result"] = type(exc).__name__

    thread = threading.Thread(target=_legacy_throwaway_bridge, daemon=True)
    thread.start()
    thread.join(5.0)
    assert not thread.is_alive()
    if not main_bound_awaitable.done():
        main_bound_awaitable.set_result(None)  # tidy: never left pending
    # The b7d6f094 throwaway-loop shape could NOT drive the main-loop-bound slot —
    # it failed instead of completing. This is the reviewer's cross-loop defect.
    assert legacy_outcome.get("result") != "completed"

    # The dedicated context owns its loop, so a slot created/used on THAT loop
    # completes normally.
    async def _reverify_dedicated(email, password, source, *, expected_auth_user_id=None):
        local_slot = asyncio.Lock()  # created and used on the dedicated loop
        async with local_slot:
            return {"ok": True}

    with _dedicated(_reverify_dedicated) as ctx:
        result = await asyncio.to_thread(
            lambda: ctx.verify(email="o@e.com", password="pw")
        )
        assert result is None
