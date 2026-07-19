# Triage Labels

The skills speak in terms of five canonical triage roles. This file maps those roles to the actual label strings used in this repo's issue tracker.

| Label in mattpocock/skills | Label in our tracker | Meaning                                  |
| -------------------------- | -------------------- | ---------------------------------------- |
| `needs-triage`             | `needs-triage`       | Maintainer needs to evaluate this issue  |
| `needs-info`               | `needs-info`         | Waiting on reporter for more information |
| `ready-for-agent`          | `agent-ready`        | Fully specified, ready for an AFK agent  |
| `ready-for-human`          | `ready-for-human`    | Requires human implementation            |
| `wontfix`                  | `wontfix`            | Will not be actioned                     |

When a skill mentions a role (e.g. "apply the AFK-ready triage label"), use the corresponding label string from this table.

Edit the right-hand column to match whatever vocabulary you actually use.

## Repo-specific notes (2026-07-16)

- `agent-ready` and `wontfix` already exist on GitHub (`gh label list`); the mapping reuses
  `agent-ready` rather than creating a near-duplicate `ready-for-agent` that would split the queue.
- `needs-triage`, `needs-info`, and `ready-for-human` do not exist yet — create each on first use,
  e.g. `gh label create needs-triage --description "Maintainer needs to evaluate this issue"`.
- The existing orthogonal vocabularies (`component:*`, `gate:*`, `queue:*`) stay as-is; triage
  roles compose with them, they do not replace them.
- P4.23 sprint work items are NOT GitHub issues — see the scope exception in
  `issue-tracker.md`.
