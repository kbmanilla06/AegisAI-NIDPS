# Repository Structure

The Sprint 0 foundation implements the minimal subset below. Future directories are created only when an approved sprint needs them.

```text
Aegis/
├── apps/{api,worker,dashboard}/
├── services/aegis_services/
├── infrastructure/docker/
├── scripts/
├── tests/unit/
├── docs/{architecture,api,threat-model}/
├── .github/workflows/
├── docker-compose.yml
├── Makefile
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
└── LICENSE
```

Logical services remain Python packages shared by the API and worker. ML, rules, monitoring, capture, and real prevention directories were intentionally not scaffolded.
