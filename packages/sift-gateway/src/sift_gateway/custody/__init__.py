"""SIFT custody domain (P4.23 target).

This subpackage is the single home for evidence-custody domain logic in the
Gateway — the sole policy boundary and DB-authority holder. It replaces the
as-built ``custody_operations.py`` / ``custody_drift.py`` / ``evidence_gate.py``
sprawl with small, deep modules whose narrow public interfaces are frozen by CP1
so the CP2A (seal/reauth/actions) and CP2B (ledger/portal-routes) lanes can build
against them in parallel.

Authority: ``docs/architecture/EVIDENCE-CUSTODY-SPEC.md`` (behavioral) and the
sprint OPERATING-MODEL §1 module map. PostgreSQL is the sole custody authority;
MCP holds zero custody-mutation authority.
"""
