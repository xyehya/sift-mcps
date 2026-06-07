#!/usr/bin/env python3
"""Compatibility wrapper for the migration documentation validator.

The primary command is now:

    python3 scripts/validate_docs.py

This wrapper remains so historical runbooks and archived build prompts that call
`validate_migration_docs.py` continue to work.
"""
from __future__ import annotations

import runpy
from pathlib import Path


if __name__ == "__main__":
    runpy.run_path(str(Path(__file__).with_name("validate_docs.py")), run_name="__main__")
