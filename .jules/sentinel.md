## 2023-10-27 - [OpenAI API Key Detection]
**Vulnerability:** The gateway's response guard regex for OpenAI API keys only detected the legacy format (`sk-...T3BlbkFJ...`), leaving newer project (`sk-proj-...`) and service account (`sk-svcacct-...`) keys undetected and potentially exposed in untrusted outputs.
**Learning:** Hardcoded regular expressions for third-party tokens must be actively maintained as vendors introduce new key formats. Relying on fixed substrings like base64-encoded provider names can create silent security gaps for newer key types.
**Prevention:** Regularly review and update secret detection regexes against current vendor documentation, ensuring coverage for all active key formats.
