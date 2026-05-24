"""Tests for Phase 12b — portal_session_secret config wiring.

Drivers: SIFT-MCPS-PLAN.md §Phase 12 / TASKS.md §12b.
"""

from __future__ import annotations

import secrets

import pytest
from starlette.applications import Starlette

import case_dashboard.routes as routes_mod
from case_dashboard.routes import create_dashboard_v2_app


@pytest.fixture(autouse=True)
def _reset_session_globals():
    """Restore module globals after each test."""
    old_secret = routes_mod._SESSION_SECRET
    old_max_age = routes_mod._SESSION_MAX_AGE
    yield
    routes_mod._SESSION_SECRET = old_secret
    routes_mod._SESSION_MAX_AGE = old_max_age


class TestSessionSecretWiring:
    def test_returns_starlette_app(self):
        app = create_dashboard_v2_app(session_secret=secrets.token_hex(32))
        assert isinstance(app, Starlette)

    def test_session_secret_stored_as_module_global(self):
        secret = secrets.token_hex(32)
        create_dashboard_v2_app(session_secret=secret)
        assert routes_mod._SESSION_SECRET == secret

    def test_session_max_age_stored_as_module_global(self):
        create_dashboard_v2_app(session_secret=secrets.token_hex(32), session_max_age=3600)
        assert routes_mod._SESSION_MAX_AGE == 3600

    def test_default_max_age_is_28800(self):
        create_dashboard_v2_app(session_secret=secrets.token_hex(32))
        assert routes_mod._SESSION_MAX_AGE == 28800

    def test_empty_secret_allowed_at_construction(self):
        """Empty secret is accepted at construction; auth endpoints will reject it at runtime."""
        app = create_dashboard_v2_app(session_secret="")
        assert isinstance(app, Starlette)
        assert routes_mod._SESSION_SECRET == ""

    def test_second_call_overwrites_globals(self):
        secret1 = secrets.token_hex(32)
        secret2 = secrets.token_hex(32)
        create_dashboard_v2_app(session_secret=secret1)
        assert routes_mod._SESSION_SECRET == secret1
        create_dashboard_v2_app(session_secret=secret2)
        assert routes_mod._SESSION_SECRET == secret2
