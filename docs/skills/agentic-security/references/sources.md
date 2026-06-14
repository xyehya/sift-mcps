# Sources and standards used

This skill was authored to follow these public references and the user-provided ASI table.

- OpenAI Codex Agent Skills documentation: https://developers.openai.com/codex/skills
- Agent Skills open specification: https://agentskills.io/specification
- Agent Skills best practices: https://agentskills.io/skill-creation/best-practices
- MCP Authorization specification: https://modelcontextprotocol.io/specification/draft/basic/authorization
- MCP Security Best Practices: https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices
- OWASP Top 10 for Agentic Applications 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP Top 10 for LLM Applications: https://owasp.org/www-project-top-10-for-large-language-model-applications/

Operational assumptions are tailored to Yehya Kar's DFIR/MCP environment: React/Vite operator portal, Starlette/FastAPI plus FastMCP gateway, Supabase/Postgres control plane, OpenSearch for timeline/artifact indexing, immutable evidence vault, and SIFT VM Python workers that claim jobs through Postgres.
