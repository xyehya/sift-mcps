# 09 — Validate release readiness through a clean registry install

**What to build:** demonstrate the two-phase release and hash-pinned registry installation path on a clean VM without publishing or mutating external registries.

**Blocked by:** 08 — Fresh-VM OpenCTI golden-path acceptance.

**Status:** blocked

- [ ] Complete dry-run/build/provenance validation and the clean install-to-health matrix.
- [ ] Prove selected core add-ons, gated OpenCTI, uninstall, and reinstall are idempotent.
- [ ] Stop before package publication, tags, or PyPI/OIDC mutation unless separately authorized.
