# AegisAI NIDPS

A defensive, portfolio-oriented network intrusion detection platform. Sprint 4 is published at `72c97b1` with hosted CI Run #7 passing. Sprint 5 Gate 5S-C is implemented locally and uncommitted: it adds bounded project-generated synthetic canonical-flow evidence, reviewed synthetic registry metadata, and isolated aggregate-only offline scoring. UNSW-NB15 acquisition and publisher outreach remain blocked and cancelled; no real dataset or online model capability is present.

## Safety status

- Prevention is compile/configuration constrained to `simulation`.
- There is no firewall adapter, live capture, model loader, downloaded dataset, privileged container, host networking, or automatic blocking.
- Use only synthetic, public, locally owned, or explicitly authorized telemetry.
- Supported offline inputs are canonical normalized JSONL, Zeek connection logs, Suricata EVE flow/signature events, and PCAP/PCAPNG files. Live interface capture is absent.
- The initially active deterministic rules are port-scan indication, recognized Zeek connection failures, and high connection rate. They produce reviewable evidence, never enforcement.

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

Do not commit `.env`. Uploads are capped at 8 MiB and deleted after successful processing or within 24 hours. Flow/signature source metadata and feature artifacts are retained for 30 days; alerts/audit are retained for 180 days. UNSW-NB15 was investigated from the official publisher page only; no dataset was downloaded and its raw PCAP is excluded.

## Checks

Backend checks run through `make backend-check`; frontend checks run through `make frontend-check`. The host macOS Python is older than the project requirement, so backend verification may be performed in the Python 3.12 container.

## Documentation

Start with `docs/PRD.md`, `docs/architecture/ARCHITECTURE.md`, `docs/threat-model/THREAT_MODEL.md`, `docs/SPRINT_5_SYNTHETIC_ONLY_PLAN.md`, and `docs/SPRINT_5_GATE_5SA_COMPLETION_REPORT.md`. The publisher clarification draft is cancelled and must not be sent.
