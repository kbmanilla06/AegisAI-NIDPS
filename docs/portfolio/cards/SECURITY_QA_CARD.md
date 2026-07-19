# Security and QA Evidence Card

- **Quality:** formatting, linting, typing, unit/integration, frontend, and
  health checks recorded in the completion report
- **Security:** Bandit, pip/npm audits, secret scan, simulation-only scan,
  Docker isolation, dependency/SBOM/CVE evidence, migration round trips, and
  backup/restore evidence
- **Supply chain:** ARM64 image/dependency identities and SBOM hashes are
  recorded; unavailable tools are identified as unavailable, never claimed as
  passing
- **Known residual:** the pre-existing WebSocket timing flake is documented;
  its targeted rerun passed
- **Privacy:** no credentials, raw dataset bytes, payloads, or unrestricted
  endpoint data are included in portfolio evidence
