# Host command and parser execution hardening

Host command execution through MCP is the highest-risk feature in this environment. Review it as ASI02 and ASI05 by default.

## Required design

1. **Deny by default.** No arbitrary shell. Every command maps to a named operation such as `volatility_pslist`, `plaso_parse`, `hash_file`, or `list_case_dir`.
2. **Typed inputs.** Use Pydantic or equivalent schemas. Use enums for parser names, output modes, and flags.
3. **Fixed executable allowlist.** Resolve executable paths at startup and reject anything outside the allowlist.
4. **Argument list only.** Use `subprocess.run([exe, arg1, arg2], shell=False)`. Never concatenate model output into a shell string.
5. **Path jail.** Resolve real paths and require them to live under approved roots, such as case evidence, derived artifacts, and temporary working directories.
6. **Environment allowlist.** Build a minimal `env` dict. Do not inherit secrets by default.
7. **Resource limits.** Timeout, max output bytes, max files, max processes, no network unless needed, and optional cgroups/container sandbox.
8. **Human approval.** Require approval for destructive, network, privileged, or high-cost operations.
9. **Audit.** Log actor, agent, case, operation, args after normalization, policy decision, cwd, exe hash, start/end time, exit code, stdout/stderr hashes, and artifact hashes.
10. **Safe output handling.** Return summarized output with truncation; store full logs as artifacts with access controls.

## Dangerous patterns to remove

```python
os.system(user_input)
subprocess.run(user_input, shell=True)
asyncio.create_subprocess_shell(model_generated_command)
eval(model_output)
exec(model_output)
pickle.loads(untrusted_bytes)
yaml.load(untrusted_text)
```

## Safer wrapper pattern

```python
from pathlib import Path
import subprocess

ALLOWED_EXES = {"sha256sum": "/usr/bin/sha256sum"}
ALLOWED_ROOT = Path("/cases").resolve()

def resolve_case_path(case_id: str, relative_path: str) -> Path:
    base = (ALLOWED_ROOT / case_id).resolve()
    target = (base / relative_path).resolve()
    if base not in target.parents and target != base:
        raise ValueError("path escapes case directory")
    return target

def run_hash(case_id: str, relative_path: str) -> subprocess.CompletedProcess[str]:
    target = resolve_case_path(case_id, relative_path)
    return subprocess.run(
        [ALLOWED_EXES["sha256sum"], str(target)],
        shell=False,
        check=False,
        text=True,
        capture_output=True,
        timeout=30,
        env={"PATH": "/usr/bin:/bin"},
        cwd=str(target.parent),
    )
```

## Review questions

- Can any model output become a command, flag, path, SQL statement, OpenSearch DSL, or environment variable?
- Can filenames with `;`, `&&`, newline, unicode spaces, `$()`, backticks, or path traversal escape validation?
- Can a tool run `sudo`, package managers, network clients, deletion, chmod, chown, mount, or docker without approval?
- Does every command have an audit record even if it fails or times out?
- Are stdout and stderr treated as untrusted text if returned to an agent?
