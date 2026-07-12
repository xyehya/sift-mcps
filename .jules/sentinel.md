## 2025-02-28 - OpenCTI Remote Insecure Configuration
**Vulnerability:** OpenCTI token configuration allowed sending credentials in plaintext over remote HTTP connections. It only warned the user without enforcing security.
**Learning:** Configurations allowing credentials over plaintext connections should explicitly fail instead of merely warning the user, to prevent accidental leakage during setup or deployment.
**Prevention:** Enforce HTTPS for non-local connections by default and require an explicit "insecure" environment variable flag to bypass the protection for development or safe private networks.
