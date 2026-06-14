# Agentic supply chain and governance review

Use this for ASI04 and ASI10 review.

## Inventory to require

- MCP servers: name, owner, repo, version, transport, auth mode, scopes, tools exposed, deployment location.
- Agent skills: name, version, source, checksum, installation scope, implicit invocation policy.
- Prompt templates: source, version, owner, allowed variables, review status.
- Models: provider, model ID, data handling mode, tool access allowed, retention settings.
- Dependencies: lockfiles, container images, base images, native forensic tools, parser plugins.
- Data/indexes: OpenSearch indexes, RAG collections, memory stores, vector stores, evidence vault roots.

## Minimum controls

- Pin dependencies and base images. Avoid floating `latest` in production-like deployments.
- Generate SBOM for code/runtime dependencies and AIBOM for agentic components.
- Review and checksum MCP tool manifests and skill folders before installation.
- Disable direct installation from public registries in production-like environments unless there is an intake review.
- Maintain a kill switch for MCP servers, individual tools, worker queues, and credentials.
- Add CI checks for secrets, unsafe subprocess patterns, RLS, tool policy, and dependency vulnerabilities.
- Log skill/tool version and checksum in every high-impact audit event.

## Skill-specific supply chain checks

- `SKILL.md` metadata should be concise and not contain prompt-injection bait.
- Bundled scripts should be readable, dependency-light, and non-networked unless absolutely required.
- Installation scope should be deliberate: repo-scoped for project-specific skills, user/admin-scoped only after trust review.
- Treat third-party skills as executable influence over the agent even when they contain only natural-language instructions.
