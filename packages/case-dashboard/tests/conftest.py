"""Make the tests directory importable for shared test-only helper modules.

CL3a added ``_supabase_reauth_harness`` as a sibling helper imported by the
migrated re-auth suites. Ensure its directory is on ``sys.path`` regardless of
the pytest invocation's rootdir/import mode.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
