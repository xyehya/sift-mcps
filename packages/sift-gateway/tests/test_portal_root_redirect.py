"""PT1/WI3 — ergonomic root + bare-/portal redirects.

The gateway mounts the examiner portal at ``/portal``; ``Mount("/portal")`` only
serves ``/portal/...``. A request for ``/`` or ``/portal`` (no trailing slash)
must redirect cleanly to ``/portal/`` instead of returning a raw 404.

This mirrors the route wiring in ``Gateway.build_app`` (server.py): two
``Route`` redirect handlers registered *before* the portal ``Mount``.
"""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Mount, Route
from starlette.testclient import TestClient


async def _portal_index(_request) -> HTMLResponse:
    return HTMLResponse("<html><body>Examiner Portal</body></html>")


async def _redirect_to_portal(_request) -> RedirectResponse:
    # Same handler shape as server.py build_app.
    return RedirectResponse(url="/portal/", status_code=307)


def _make_app() -> Starlette:
    portal_app = Starlette(routes=[Route("/", _portal_index, methods=["GET"])])
    routes = [
        Route("/", _redirect_to_portal, methods=["GET"]),
        Route("/portal", _redirect_to_portal, methods=["GET"]),
        Mount("/portal", app=portal_app),
    ]
    return Starlette(routes=routes)


@pytest.fixture()
def client():
    # raise_server_exceptions so any handler error surfaces; follow_redirects off
    # so we can assert the redirect itself, not just the final page.
    return TestClient(_make_app(), raise_server_exceptions=True)


def test_root_redirects_to_portal_slash(client):
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 307
    assert resp.headers["location"] == "/portal/"


def test_bare_portal_redirects_to_portal_slash(client):
    resp = client.get("/portal", follow_redirects=False)
    assert resp.status_code == 307
    assert resp.headers["location"] == "/portal/"


def test_root_redirect_lands_on_portal_index(client):
    resp = client.get("/", follow_redirects=True)
    assert resp.status_code == 200
    assert "Examiner Portal" in resp.text


def test_portal_slash_still_served(client):
    resp = client.get("/portal/", follow_redirects=False)
    assert resp.status_code == 200
    assert "Examiner Portal" in resp.text
