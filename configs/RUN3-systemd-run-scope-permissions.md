# RUN-3 transient scope permission note

RUN-3 Floor is expected to wrap each `run_command` execution in
`systemd-run --scope` with resource-control properties such as `MemoryMax=`,
`CPUQuota=`, `TasksMax=`, `RuntimeMaxSec=`, `OOMPolicy=kill`, and
`IPAddressDeny=any`.

Wave 1 does not grant new privileges. During Wave 2, test first whether the
`sift-service` job worker can create the transient scope without interactive
authorization. If it cannot, grant only a narrow non-interactive permission for
the service account to start RUN-3 dfir-exec scope units. Prefer a polkit rule
limited to the systemd manage-units action, the `sift-service` subject, and
`dfir-exec`/`run-command` transient scope names. If sudoers is used instead,
allow only `/usr/bin/systemd-run` for the fixed RUN-3 scope wrapper shape; do
not grant broad shell, editor, or `ALL` command rights.

Any grant must be validated with `visudo -c` or polkit syntax checks, a
non-interactive `sudo -n`/scope smoke, and a post-run `systemctl status` check.
The AppArmor profile remains complain-mode until this scope path and the
positive forensic matrix have both been exercised.
