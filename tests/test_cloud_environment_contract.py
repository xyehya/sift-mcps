"""Contracts for the committed Cursor Cloud environment bootstrap."""

from __future__ import annotations

import os
import shutil
import subprocess
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLOUD_INSTALL = REPO_ROOT / ".cursor" / "scripts" / "cloud-install.sh"
CLOUD_SCRIPTS = sorted((REPO_ROOT / ".cursor" / "scripts").glob("*.sh"))


def test_cloud_environment_scripts_have_valid_bash_syntax() -> None:
    result = subprocess.run(
        ["bash", "-n", *(str(script) for script in CLOUD_SCRIPTS)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def _write_executable(path: Path, source: str) -> None:
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    path.chmod(0o755)


def test_cloud_install_bootstraps_and_persists_node_24_on_a_cold_image(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    cloud_scripts = repo / ".cursor" / "scripts"
    bootstrap = repo / "scripts" / "cloud" / "bootstrap-agent-tools.sh"
    fake_bin = tmp_path / "bin"
    home = tmp_path / "home"
    sha_args = tmp_path / "sha-args"
    sha_input = tmp_path / "sha-input"
    cloud_scripts.mkdir(parents=True)
    bootstrap.parent.mkdir(parents=True)
    fake_bin.mkdir()
    home.mkdir()
    (home / ".bashrc").touch()
    (home / ".profile").touch()
    shutil.copy2(CLOUD_INSTALL, cloud_scripts / "cloud-install.sh")
    _write_executable(bootstrap, "#!/usr/bin/env bash\nexit 0\n")

    _write_executable(
        fake_bin / "tailscale",
        "#!/usr/bin/env bash\nexit 0\n",
    )
    _write_executable(
        fake_bin / "uv",
        "#!/usr/bin/env bash\nexit 0\n",
    )
    _write_executable(
        fake_bin / "curl",
        """
        #!/usr/bin/env bash
        set -euo pipefail
        output=""
        while (($#)); do
          if [[ "$1" == "--output" ]]; then
            output="$2"
            shift 2
          else
            shift
          fi
        done
        cat > "$output" <<'INSTALLER'
        #!/usr/bin/env bash
        set -euo pipefail
        mkdir -p "$NVM_DIR"
        cat > "$NVM_DIR/nvm.sh" <<'NVM'
        nvm() {
          if [[ "${1:-}" == "install" ]]; then
            mkdir -p "$NVM_DIR/versions/node/v24.13.1/bin"
            touch "$NVM_DIR/versions/node/v24.13.1/bin/node"
            chmod 0755 "$NVM_DIR/versions/node/v24.13.1/bin/node"
          fi
          return 0
        }
        NVM
        INSTALLER
        """,
    )
    _write_executable(
        fake_bin / "sha256sum",
        """
        #!/usr/bin/env bash
        printf '%s\\n' "$*" > "$CLOUD_TEST_SHA_ARGS"
        cat > "$CLOUD_TEST_SHA_INPUT"
        [[ "$*" == "--check --status" ]]
        """,
    )

    env = os.environ | {
        "HOME": str(home),
        "NVM_DIR": str(home / ".nvm"),
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "CLOUD_TEST_SHA_ARGS": str(sha_args),
        "CLOUD_TEST_SHA_INPUT": str(sha_input),
    }
    result = subprocess.run(
        ["bash", str(cloud_scripts / "cloud-install.sh")],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )

    assert result.returncode == 0, result.stderr
    assert (home / ".nvm" / "versions" / "node" / "v24.13.1" / "bin" / "node").is_file()
    assert sha_args.read_text(encoding="utf-8") == "--check --status\n"
    assert sha_input.read_text(encoding="utf-8").startswith(
        "2d8359a64a3cb07c02389ad88ceecd43f2fa469c06104f92f98df5b6f315275f  "
    )
    assert (
        'export PATH="$HOME/.nvm/versions/node/v24.13.1/bin:$HOME/.local/bin:$PATH"'
        in (home / ".cursor-cloud-tailscale.env").read_text(encoding="utf-8")
    )
