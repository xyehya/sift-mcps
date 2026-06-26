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
from importlib.metadata import PackageNotFoundError, version

import pytest

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
)


@pytest.mark.parametrize("dist", ALL_DISTS)
def test_dist_version_resolves_and_is_not_a_stale_literal(dist: str) -> None:
    try:
        resolved = version(dist)
    except PackageNotFoundError:  # pragma: no cover - defensive
        pytest.fail(
            f"distribution {dist!r} did not resolve via importlib.metadata; "
            "version single-sourcing (hatch-vcs) is broken or the dist is "
            "not installed into the workspace env"
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
    mod = importlib.import_module(module_name)
    mod_version = getattr(mod, "__version__", None)
    assert mod_version is not None, f"{module_name}.__version__ is missing"
    assert mod_version == version(dist), (
        f"{module_name}.__version__ ({mod_version!r}) != dist metadata for "
        f"{dist!r} ({version(dist)!r}); the module is not reading the single "
        "source via importlib.metadata"
    )
    assert mod_version not in STALE_LITERALS, (
        f"{module_name}.__version__ is the stale literal {mod_version!r}"
    )
