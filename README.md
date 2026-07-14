# AegisAI NIDPS

A defensive, portfolio-oriented network intrusion detection platform. Sprint 2 adds bounded, hostile-input telemetry ingestion and canonical flow normalization on top of the Sprint 1 identity/RBAC foundation. The Sprint 2 work is complete locally but remains uncommitted pending review.

## Safety status

- Prevention is compile/configuration constrained to `simulation`.
- There is no firewall adapter, live capture, model loader, dataset, privileged container, host networking, or automatic blocking.
- Use only synthetic, public, locally owned, or explicitly authorized telemetry.
- Supported offline inputs are canonical normalized JSONL, Zeek connection logs, Suricata EVE JSON flow events, and PCAP/PCAPNG files. Live interface capture is absent.

## Foundation stack

- Python 3.12, FastAPI, Celery, PostgreSQL, Redis
- React, TypeScript, Vite
- Docker Compose

## Local setup

1. Copy `.env.example` to `.env`.
2. Generate a unique local PostgreSQL password and place it only in `.env`.
3. Run `docker compose config --quiet`.
4. Run `docker compose up --build --wait`.
5. Create the first administrator interactively: `docker compose run --rm migrate python -m aegis_api.cli bootstrap-admin --email you@example.com`. The password is read from the terminal and must not be put in the command, environment, or a file.
6. Open `http://localhost:5173` and check `http://localhost:8000/api/v1/health/ready`.
7. Stop with `docker compose down`. Add `--volumes` only when intentionally deleting local development data.

Do not commit `.env`. Uploads are capped at 8 MiB and deleted after successful processing or within 24 hours. Flow metadata is retained for 30 days. Dataset acquisition is not part of Sprint 2; UNSW-NB15 terms are documented in `docs/DATASET_REVIEW_UNSW_NB15.md`.

## Checks

Backend checks run through `make backend-check`; frontend checks run through `make frontend-check`. The host macOS Python is older than the project requirement, so backend verification may be performed in the Python 3.12 container.

## Documentation

Start with `docs/PRD.md`, `docs/architecture/ARCHITECTURE.md`, `docs/threat-model/THREAT_MODEL.md`, and `docs/SPRINT_2_COMPLETION_REPORT.md`.
