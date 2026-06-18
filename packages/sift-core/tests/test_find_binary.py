"""Tests for execute.environment.find_binary resolution (tool-availability fix).

Covers the two resolution gaps the tool-availability track repaired:
  * per-tool subdir layout (``<dir>/<name>/<name>``, e.g. EZ RECmd/RECmd), and
  * ``/opt/*/bin`` glob fallback for bucket-D venv wrappers,
while preserving the fail-closed contract (missing tool ⇒ None) and the
``extra_paths`` override behavior.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from sift_core.execute.environment import find_binary


def _make_exe(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def test_subdir_layout_resolves_via_extra_paths(tmp_path):
    """A per-tool subdir layout (``zz/Foo/Foo``) resolves when ``zz`` is a
    fallback dir — the flat ``zz/Foo`` check alone would miss it."""
    fallback = tmp_path / "zz"
    inner = fallback / "Foo" / "Foo"
    _make_exe(inner)

    resolved = find_binary("Foo", extra_paths=[str(fallback)])
    assert resolved == str(inner)


def test_flat_layout_still_resolves_via_extra_paths(tmp_path):
    fallback = tmp_path / "flat"
    exe = fallback / "Bar"
    _make_exe(exe)

    assert find_binary("Bar", extra_paths=[str(fallback)]) == str(exe)


def test_opt_star_bin_glob_resolution(tmp_path, monkeypatch):
    """Default fallback must include ``/opt/*/bin`` dirs. We point ``/opt`` at a
    temp tree via the cwd-independent glob and assert the tool resolves."""
    fake_opt = tmp_path / "opt"
    exe = fake_opt / "mytool" / "bin" / "mytool-cli"
    _make_exe(exe)

    # Monkeypatch Path in the module namespace so Path("/opt") resolves to our
    # fake tree, leaving every other Path(...) call intact.
    import sift_core.execute.environment as env_mod

    orig_path = env_mod.Path

    def fake_path(arg="."):
        if str(arg) == "/opt":
            return orig_path(fake_opt)
        return orig_path(arg)

    monkeypatch.setattr(env_mod, "Path", fake_path)
    # Ensure PATH lookup misses so the fallback runs.
    monkeypatch.setattr(env_mod.shutil, "which", lambda _n: None)

    resolved = find_binary("mytool-cli")
    assert resolved == str(exe)


def test_missing_tool_returns_none(tmp_path, monkeypatch):
    import sift_core.execute.environment as env_mod

    monkeypatch.setattr(env_mod.shutil, "which", lambda _n: None)
    assert find_binary("definitely-not-here", extra_paths=[str(tmp_path)]) is None


def test_non_executable_file_is_not_resolved(tmp_path):
    fallback = tmp_path / "noexec"
    f = fallback / "Baz"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("not executable")
    f.chmod(0o644)

    assert find_binary("Baz", extra_paths=[str(fallback)]) is None
    assert not os.access(f, os.X_OK)
