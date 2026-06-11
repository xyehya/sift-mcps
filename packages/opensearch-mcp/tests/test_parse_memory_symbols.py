"""Tests for the shared, env-overridable Volatility 3 symbol cache resolution.

Covers `_user_symbol_dir()` resolution order:
  1. SIFT_VOL_SYMBOLS env var, if set.
  2. /var/cache/sift/volatility-symbols shared default.
  3. host fallback (~/.cache/volatility3/symbols) when the chosen dir cannot be
     created or is not writable.
"""

from __future__ import annotations

from pathlib import Path

from opensearch_mcp import parse_memory
from opensearch_mcp.parse_memory import _user_symbol_dir


def test_env_override_is_used_when_set(tmp_path, monkeypatch):
    override = tmp_path / "shared" / "vol-symbols"
    monkeypatch.setenv("SIFT_VOL_SYMBOLS", str(override))
    result = _user_symbol_dir()
    assert result == override
    assert result.is_dir()


def test_default_shared_dir_used_when_env_unset_and_writable(tmp_path, monkeypatch):
    monkeypatch.delenv("SIFT_VOL_SYMBOLS", raising=False)
    # Redirect the shared default to a writable tmp location so we don't depend
    # on /var/cache/sift existing on the host.
    fake_default = tmp_path / "var-cache-sift" / "volatility-symbols"
    monkeypatch.setattr(parse_memory, "_DEFAULT_SHARED_SYMBOL_DIR", fake_default)
    result = _user_symbol_dir()
    assert result == fake_default
    assert result.is_dir()


def test_falls_back_to_home_cache_when_default_unwritable(tmp_path, monkeypatch):
    monkeypatch.delenv("SIFT_VOL_SYMBOLS", raising=False)
    # Point the shared default at a child of a read-only dir so mkdir fails.
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o500)
    blocked = ro / "volatility-symbols"
    monkeypatch.setattr(parse_memory, "_DEFAULT_SHARED_SYMBOL_DIR", blocked)
    # Redirect HOME so the fallback lands in tmp, not the real user cache.
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    try:
        result = _user_symbol_dir()
    finally:
        ro.chmod(0o700)
    assert result == home / ".cache" / "volatility3" / "symbols"
    assert result.is_dir()


def test_falls_back_to_home_cache_when_env_override_unwritable(tmp_path, monkeypatch):
    ro = tmp_path / "ro2"
    ro.mkdir()
    ro.chmod(0o500)
    blocked = ro / "vol-symbols"
    monkeypatch.setenv("SIFT_VOL_SYMBOLS", str(blocked))
    home = tmp_path / "home2"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    try:
        result = _user_symbol_dir()
    finally:
        ro.chmod(0o700)
    assert result == home / ".cache" / "volatility3" / "symbols"
    assert result.is_dir()


def test_returns_path_object(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFT_VOL_SYMBOLS", str(tmp_path / "syms"))
    assert isinstance(_user_symbol_dir(), Path)
