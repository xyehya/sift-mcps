# RUN-3 transient scope permission note

RUN-3 Floor wraps each `run_command` execution worker in
`systemd-run --scope --uid agent_runtime --gid <agent_runtime gid>` with
resource-control properties such as `MemoryMax=`, `CPUQuota=`, `TasksMax=`,
`RuntimeMaxSec=`, `OOMPolicy=kill`, and `IPAddressDeny=any`. The scoped worker
then invokes `dfir-exec-launcher`.

Live VM correction: on systemd 255, unprivileged `systemd-run --scope --uid`
cannot perform the UID/GID transition, and polkit does not expose transient
scope unit names in action details for a narrow unit-name rule. The production
path therefore uses a root-owned helper installed at
`/usr/local/sbin/sift-run-command-systemd-scope` and reached through
`/etc/sudoers.d/sift-run-command-systemd-scope`. The helper validates the unit
name, runtime user, resource-control properties, and exact worker argv before it
execs `/usr/bin/systemd-run` as root. Do not grant raw `/usr/bin/systemd-run`,
broad polkit `manage-units`, a shell, editor, or `ALL` root command rights.

The native installer runs
`scripts/setup-run-command-systemd-scope-sudoers.sh`, installs the helper
root:root 0755, validates the sudoers drop-in with `visudo -cf`, and configures
both gateway and job-worker units with
`SIFT_EXECUTE_SYSTEMD_SCOPE_HELPER=/usr/local/sbin/sift-run-command-systemd-scope`.

Any grant must be validated with `visudo -c`, a non-interactive helper/scope
smoke, and a post-run `systemctl status` check. The AppArmor profile remains
complain-mode until this scope path and the positive forensic matrix have both
been exercised.
