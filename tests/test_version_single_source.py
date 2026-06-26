"""Fails-on-revert guard for version single-sourcing (#15 / I-PS1).

Every workspace member's version is derived from the git release tag via
hatch-vcs (`[tool.hatch.version] source = "vcs"`), and every package's
``__version__`` is read at runtime from installed distribution metadata via
``importlib.metadata.version``. There is a SINGLE source of truth (the tag); no
package carries a hand-edited literal that can drift.

Why this test asserts "resolves AND is not a stale literal" rather than
"== 0.6.2":
    The integration commit is NOT yet tagged ``v0.6.2``. On an untagged
    checkout hatch-vcs deliberately resolves to a DEV version derived from
    ``git describe`` (e.g. ``0.6.3.devN+g<sha>``) — that is the expected,
    correct behaviour, not a bug. Asserting equality to ``0.6.2`` here would
    make the test pass ONLY at tag time and fail on every dev checkout, which is
    backwards. Instead we assert the resolver produced a real PEP 440 version
    AND that the old hard-coded literals ("0.1.0" / "0.6.1") were genuinely
    removed. If anyone reintroduces a literal in a pyproject ``version = "..."``
    or a module ``__version__ = "..."``, the metadata reverts to that exact
    stale string and the ``not in {STALE...}`` assertions FAIL — that is the
    fails-on-revert property.
"""

from __future__ import annotations

import importlib
import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import pytest

# Repo root = parent of this tests/ directory. Used by the env-INDEPENDENT static
# guards below, which hold even when optional add-on dists are not pip-installed.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_PACKAGES_DIR = _REPO_ROOT / "packages"

# The 9 installable workspace MEMBER distributions. The build/version machinery
# (hatch-vcs) must resolve a version for each from installed metadata.
#
# The workspace ROOT ``sift-mcps`` is deliberately excluded: root pyproject sets
# ``[tool.uv] package = false`` (it is an aggregator / dependency-group host, not
# an installed distribution), so it has no ``importlib.metadata`` entry by
# design. Flipping that is a separate change (#20) and out of scope here. Its
# version is still single-sourced via the same ``[tool.hatch.version]`` block for
# when it is built (proven by ``uv build``), it just isn't pip-installed.
ALL_DISTS = (
    "sift-core",
    "sift-common",
    "sift-gateway",
    "forensic-knowledge",
    "opensearch-mcp",
    "rag-mcp",
    "opencti-mcp",
    "case-dashboard",
    "windows-triage-mcp",
)

# The exact literals that USED to be hand-coded in the pyprojects / __init__.py
# before single-sourcing. If any of these comes back, metadata reverts to it.
STALE_LITERALS = {"0.1.0", "0.6.1"}

# (importable module, its distribution name) for every package whose
# ``__version__`` we converted to importlib.metadata. ``__version__`` MUST equal
# the dist metadata version — proving the module reads the single source, not a
# literal of its own.
MODULE_TO_DIST = (
    ("opencti_mcp", "opencti-mcp"),
    ("forensic_knowledge", "forensic-knowledge"),
    ("rag_mcp", "rag-mcp"),
    ("opensearch_mcp", "opensearch-mcp"),
    ("sift_gateway", "sift-gateway"),
    ("sift_core", "sift-core"),
    ("windows_triage_mcp", "windows-triage-mcp"),
)


@pytest.mark.parametrize("dist", ALL_DISTS)
def test_dist_version_resolves_and_is_not_a_stale_literal(dist: str) -> None:
    try:
        resolved = version(dist)
    except PackageNotFoundError:
        # opencti-mcp / windows-triage-mcp are OPTIONAL add-ons not included in
        # the `full` extra, so they are absent from the standard `--extra full
        # --extra dev` CI/test env. Their single-sourcing is still enforced
        # env-independently by test_pyproject_is_single_sourced /
        # test_no_module_version_literals below; skip the runtime check rather
        # than hard-fail on an intentionally-uninstalled dist.
        pytest.skip(
            f"{dist!r} not installed in this env (optional add-on; needs its "
            "own extra) — static no-literal gates still cover single-sourcing"
        )

    assert resolved, f"{dist!r} resolved to an empty version string"
    # The untagged worktree yields a hatch-vcs dev version; a tagged tree yields
    # a clean release. Either way it must NOT be one of the removed literals.
    assert resolved not in STALE_LITERALS, (
        f"{dist!r} resolved to stale literal {resolved!r}; a hand-edited "
        "version literal was reintroduced — version is no longer single-sourced"
    )


@pytest.mark.parametrize("module_name,dist", MODULE_TO_DIST)
def test_module_version_matches_dist_metadata(module_name: str, dist: str) -> None:
    # Gate on DIST METADATA presence first: the modules now guard version() with
    # a PackageNotFoundError fallback ("0.0.0+unknown"), so importing them no
    # longer raises when uninstalled — without this gate the module would resolve
    # to its sentinel and spuriously mismatch.
    try:
        dist_version = version(dist)
    except PackageNotFoundError:
        pytest.skip(
            f"{dist!r} not installed in this env (optional add-on); static "
            "no-literal gate still covers it"
        )
    try:
        mod = importlib.import_module(module_name)
    except ModuleNotFoundError:
        pytest.skip(
            f"{module_name!r} not importable in this env (optional add-on); "
            "static no-literal gate still covers it"
        )
    mod_version = getattr(mod, "__version__", None)
    assert mod_version is not None, f"{module_name}.__version__ is missing"
    assert mod_version == dist_version, (
        f"{module_name}.__version__ ({mod_version!r}) != dist metadata for "
        f"{dist!r} ({dist_version!r}); the module is not reading the single "
        "source via importlib.metadata"
    )
    assert mod_version not in STALE_LITERALS, (
        f"{module_name}.__version__ is the stale literal {mod_version!r}"
    )


# --- Env-INDEPENDENT static guards ------------------------------------------
# These read source on disk, so they enforce single-sourcing for ALL 9 members
# (including the optional add-ons that the runtime tests skip when uninstalled)
# and in any environment, including a `--extra full` CI run.

_MEMBER_PYPROJECTS = sorted(_PACKAGES_DIR.glob("*/pyproject.toml"))
# `[project]`-level static version literal, e.g. `version = "0.6.1"`. The TOML
# key sits at column 0 inside [project]; `[tool.hatch.version]` lives under a
# different table and never uses a bare `version =` literal.
_STATIC_PROJECT_VERSION = re.compile(r'^version\s*=\s*["\']', re.MULTILINE)
_MODULE_VERSION_LITERAL = re.compile(r'^__version__\s*=\s*["\']', re.MULTILINE)


def test_member_pyprojects_discovered() -> None:
    # Guards against the glob silently matching nothing (which would make the
    # parametrized static tests vacuously pass).
    assert len(_MEMBER_PYPROJECTS) == 9, (
        f"expected 9 member pyprojects, found {len(_MEMBER_PYPROJECTS)}: "
        f"{[str(p.relative_to(_REPO_ROOT)) for p in _MEMBER_PYPROJECTS]}"
    )


@pytest.mark.parametrize("pyproject", _MEMBER_PYPROJECTS, ids=lambda p: p.parent.name)
def test_pyproject_is_single_sourced(pyproject: Path) -> None:
    text = pyproject.read_text(encoding="utf-8")
    assert 'dynamic = ["version"]' in text, (
        f"{pyproject.relative_to(_REPO_ROOT)} does not declare "
        '`dynamic = ["version"]` — version is not hatch-vcs single-sourced'
    )
    assert not _STATIC_PROJECT_VERSION.search(text), (
        f"{pyproject.relative_to(_REPO_ROOT)} reintroduced a static "
        "`version = \"...\"` literal — version is no longer single-sourced"
    )


def test_no_module_version_literals() -> None:
    offenders = [
        str(init.relative_to(_REPO_ROOT))
        for init in _PACKAGES_DIR.glob("*/src/**/__init__.py")
        if _MODULE_VERSION_LITERAL.search(init.read_text(encoding="utf-8"))
    ]
    assert not offenders, (
        "module __version__ literal(s) reintroduced (must read "
        f"importlib.metadata.version instead): {offenders}"
    )


_FALLBACK_VERSION = re.compile(r'^fallback-version\s*=\s*"([^"]+)"', re.MULTILINE)


def test_fallback_versions_are_consistent() -> None:
    # hatch-vcs `fallback-version` is a hand-edited per-package literal used when
    # there is no .git (e.g. an sdist install). It is the ONE place #15 could
    # silently re-introduce the cross-package version drift it set out to kill, so
    # assert every member (and the root meta) declares the SAME fallback-version.
    # The [tool.hatch.version] block is necessarily duplicated per package (TOML
    # has no include) — but its VALUE must not diverge.
    found: dict[str, str] = {}
    for pp in [*_MEMBER_PYPROJECTS, _REPO_ROOT / "pyproject.toml"]:
        m = _FALLBACK_VERSION.search(pp.read_text(encoding="utf-8"))
        assert m is not None, (
            f"{pp.relative_to(_REPO_ROOT)} declares no `fallback-version` in "
            "[tool.hatch.version] — hatch-vcs would have no deterministic version "
            "for a no-.git (sdist) install"
        )
        found[str(pp.relative_to(_REPO_ROOT))] = m.group(1)
    distinct = set(found.values())
    assert len(distinct) == 1, (
        f"fallback-version drifted across packages: {found} — every member must "
        "declare the same fallback-version (single source of truth)"
    )
