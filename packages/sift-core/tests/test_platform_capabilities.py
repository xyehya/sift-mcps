"""platform_capabilities must be declaration-driven (D-002).

It reports add-on capabilities ONLY from registered + available backends and
the capabilities their manifests advertise — never from installed-package
probing (find_spec) or hardcoded add-on names.
"""

import sift_core.case_manager as cm


def _reset_provider():
    cm.set_backend_capability_provider(None)


def test_no_provider_reports_no_addons():
    """No gateway/provider wired => no add-on capabilities, only core."""
    _reset_provider()
    try:
        out = cm.build_platform_capabilities()
    finally:
        _reset_provider()
    caps = out["platform_capabilities"]
    assert caps["sift_tools"] is True
    assert caps["provides"] == []
    assert caps["backends"] == []
    # The core tools line is always present; no add-on lines.
    assert "run_command" in out["investigation_guidance"]


def test_provider_drives_capabilities_by_advertised_provides():
    """A registered+available backend's advertised provides flow through."""
    cm.set_backend_capability_provider(
        lambda: [
            {"name": "acme-intel-mcp", "namespace": "acme", "provides": ["reference", "threat-intel"]},
        ]
    )
    try:
        out = cm.build_platform_capabilities()
    finally:
        _reset_provider()
    caps = out["platform_capabilities"]
    assert caps["provides"] == ["reference", "threat-intel"]
    assert caps["backends"] == [
        {"name": "acme-intel-mcp", "namespace": "acme", "provides": ["reference", "threat-intel"]}
    ]
    # Guidance is name-agnostic: it uses the advertised namespace/provides, not
    # any hardcoded add-on name.
    assert "acme add-on available" in out["investigation_guidance"]
    assert "reference, threat-intel" in out["investigation_guidance"]


def test_unregistered_addon_not_advertised_even_if_package_installed():
    """Declaration-driven: a capability appears only when a backend advertises
    it. With no provider entry, nothing is advertised regardless of which
    add-on packages happen to be importable in this venv (no find_spec)."""
    cm.set_backend_capability_provider(lambda: [])
    try:
        out = cm.build_platform_capabilities()
    finally:
        _reset_provider()
    caps = out["platform_capabilities"]
    assert caps["provides"] == []
    assert caps["backends"] == []


def test_provider_exception_degrades_to_core_only():
    def _boom():
        raise RuntimeError("provider down")

    cm.set_backend_capability_provider(_boom)
    try:
        out = cm.build_platform_capabilities()
    finally:
        _reset_provider()
    assert out["platform_capabilities"]["backends"] == []
    assert out["platform_capabilities"]["sift_tools"] is True
