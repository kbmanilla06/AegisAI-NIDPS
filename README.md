# AegisAI NIDPS

A defensive, portfolio-oriented network intrusion detection platform. The current repository contains the Sprint 0 foundation only.

## Safety status

- Prevention is compile/configuration constrained to `simulation`.
- There is no firewall adapter, live capture, model loader, dataset, privileged container, host networking, or automatic blocking.
- Use only synthetic, public, locally owned, or explicitly authorized telemetry.

## Foundation stack

- Python 3.12, FastAPI, Celery, PostgreSQL, Redis
- React, TypeScript, Vite
- Docker Compose

## Local setup

1. Copy `.env.example` to `.env`.
2. Generate a unique local PostgreSQL password and place it only in `.env`.
3. Run `docker compose config --quiet`.
4. Run `docker compose up --build --wait`.
5. Open `http://localhost:5173` and check `http://localhost:8000/api/v1/health/ready`.
6. Stop with `docker compose down`. Add `--volumes` only when intentionally deleting local development data.

Do not commit `.env`. Dataset acquisition is not part of Sprint 0; UNSW-NB15 terms are documented in `docs/DATASET_REVIEW_UNSW_NB15.md`.

## Checks

Backend checks run through `make backend-check`; frontend checks run through `make frontend-check`. The host macOS Python is older than the project requirement, so backend verification may be performed in the Python 3.12 container.

## Documentation

Start with `docs/PRD.md`, `docs/architecture/ARCHITECTURE.md`, `docs/threat-model/THREAT_MODEL.md`, and `docs/SPRINT_0_DESIGN_REVIEW.md`.
