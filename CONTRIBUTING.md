# Contributing to AegisAI NIDPS

Work only within the active approved sprint. Read the master prompt, implementation guide, PRD, architecture, threat model, and Definition of Done before changes.

Use a bounded issue with requirement IDs and acceptance criteria. Propose architecture/security-sensitive decisions before coding. Add tests and documentation with behavior. Record actual check results. Never use unreviewed bulk staging, bypass hooks/tests, commit secrets/data/models, or weaken simulation/RBAC/audit controls.

Suggested branches: `feature/<issue>-<name>`, `fix/<issue>-<name>`, `security/<issue>-<name>`, `ml/<issue>-<name>`, `docs/<issue>-<name>`. Use Conventional Commits. Prevention, authentication, model activation, migrations, and audit changes require focused security review.
