# RUN-3 transient scope permission note

RUN-3 Floor is expected to wrap each `run_command` execution worker in
`systemd-run --scope --uid agent_runtime --gid <agent_runtime gid>` with
resource-control properties such as `MemoryMax=`, `CPUQuota=`, `TasksMax=`,
`RuntimeMaxSec=`, `OOMPolicy=kill`, and `IPAddressDeny=any`. The scoped worker
then invokes `dfir-exec-launcher`; there is no inner sudo hop in the production
NoNewPrivileges path.

Wave 1 does not grant new privileges. During Wave 2, test first whether the
`sift-service` job worker can create the transient scope without interactive
authorization. If it cannot, grant only a narrow non-interactive permission for
the service account to start RUN-3 dfir-exec scope units. Prefer a polkit rule
limited to the systemd manage-units action, the `sift-service` subject, and
`dfir-exec`/`run-command` transient scope names and the fixed `--uid`/`--gid`
runtime identity. If sudoers is used instead, allow only `/usr/bin/systemd-run`
for the fixed RUN-3 scope wrapper shape; do not grant broad shell, editor, or
`ALL` command rights.

The native installer renders `configs/polkit/50-sift-run-command-systemd-run.rules`
to `/etc/polkit-1/rules.d/` for the configured service user. The rule authorizes
only `sift-run-command-*.scope` transient units.

Any grant must be validated with `visudo -c` or polkit syntax checks, a
non-interactive `sudo -n`/scope smoke, and a post-run `systemctl status` check.
The AppArmor profile remains complain-mode until this scope path and the
positive forensic matrix have both been exercised.
