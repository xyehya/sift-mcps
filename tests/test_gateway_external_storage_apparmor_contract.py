"""Fail-on-revert confinement contract for external read-only mount facts."""

from __future__ import annotations

from _installer_support import REPO_ROOT

APPARMOR = REPO_ROOT / "configs" / "apparmor" / "sift-gateway.template"


def _gateway_rules() -> set[str]:
    source = APPARMOR.read_text(encoding="utf-8")
    body = source.split("profile sift-gateway flags=(attach_disconnected) {", 1)[
        1
    ].split("\n}\n", 1)[0]
    return {" ".join(line.split()) for line in body.splitlines()}


def test_gateway_can_read_only_its_exact_external_storage_kernel_facts() -> None:
    rules = _gateway_rules()

    assert {
        rule
        for rule in rules
        if "/proc/" in rule and ("fdinfo" in rule or "mountinfo" in rule)
    } == {
        "/proc/1/mountinfo r,",
        "owner /proc/@{pid}/fdinfo/[0-9]* r,",
        "owner /proc/@{pid}/mountinfo r,",
    }
    assert "/proc/sys/kernel/random/boot_id r," in rules

    assert not any(rule.startswith("/proc/** ") for rule in rules)
    assert not any(rule.startswith("owner /proc/** ") for rule in rules)
    assert not any(rule.startswith("/proc/self/** ") for rule in rules)


def test_gateway_external_storage_introspection_cannot_control_mounts() -> None:
    rules = _gateway_rules()

    assert {"deny mount,", "deny remount,", "deny umount,"} <= rules
