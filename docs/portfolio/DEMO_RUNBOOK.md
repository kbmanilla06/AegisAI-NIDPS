# Gate P5 Synthetic-Only Demonstration Runbook

**Audience:** portfolio reviewer on the approved ARM64 development host
**Mode:** local, offline, simulation-only
**External services:** none required
**Media:** screenshots/recording not authorized in this checkpoint

## Preconditions

- Use a clean checkout at public-main baseline
  `2e4e3a6d9c927b731237de20847214e75f6a31e8`.
- Preserve inherited Sprint 10 planning/preflight files; do not stage or delete
  them.
- Use only synthetic project artifacts and non-secret validation values.
- Keep ports bound to `127.0.0.1`; do not expose the stack publicly.
- Do not open a dataset folder, publisher page, external URL, tokenized URL, or
  raw artifact payload.

## Start and health checks

```bash
export POSTGRES_PASSWORD=ci-validation-only
export AEGIS_API_PORT=18000
export AEGIS_DASHBOARD_PORT=15173
docker compose -p aegis-p5 up -d --build --force-recreate --wait
curl --fail --silent http://127.0.0.1:18000/api/v1/health/live
curl --fail --silent http://127.0.0.1:18000/api/v1/health/ready
curl --fail --silent --head http://127.0.0.1:15173/
```

Expected results are a healthy API with `prevention_mode=simulation`, healthy
PostgreSQL/Redis readiness, and dashboard HTTP 200. Do not paste the validation
password or any cookie/token into a report.

## Metadata-only evidence

The helper reads only its fixed documentation and contract allowlist. It does
not invoke Docker, a shell, a network client, a model runtime, a parser, or a
dataset reader.

```bash
PYTHONPATH=apps/api:apps/worker:services \
  .venv/bin/python scripts/create_p5_portfolio_evidence.py \
  --project-root . --output /tmp/aegis-p5-evidence-a.json
PYTHONPATH=apps/api:apps/worker:services \
  .venv/bin/python scripts/create_p5_portfolio_evidence.py \
  --project-root . --output /tmp/aegis-p5-evidence-b.json
cmp /tmp/aegis-p5-evidence-a.json /tmp/aegis-p5-evidence-b.json
shasum -a 256 /tmp/aegis-p5-evidence-a.json /tmp/aegis-p5-evidence-b.json
```

The two files must match byte-for-byte. The output is mode `0600`, aggregate
only, and contains accepted hashes, limitation hashes, claim statuses, and
false-capability flags. It contains no raw rows, vectors, addresses, paths,
credentials, model bytes, or dataset bytes.

## Review sequence

1. Read [`README_PORTFOLIO.md`](README_PORTFOLIO.md) and the limitation text.
2. Review [`CLAIMS_REVIEW.md`](CLAIMS_REVIEW.md) against the generated evidence.
3. Review the synthetic, feature, model/anomaly, monitoring, and prevention
   cards under [`cards/`](cards/).
4. Read [`DEMO_TRANSCRIPT.md`](DEMO_TRANSCRIPT.md) as the expected safe flow.
5. Verify the evidence identity and accepted hashes in `EVIDENCE_INDEX.md`.
6. Confirm no screenshot/recording was created without separate approval.

## Optional existing application views

If an authorized reviewer uses the existing local UI, use a least-privilege
demo account. The UI may display only the existing metadata and aggregate
surfaces. Do not activate a model, request online inference, mutate alerts or
incidents, or create prevention state beyond the existing simulation workflow.

## Teardown

```bash
docker compose -p aegis-p5 down -v --remove-orphans
rm -f /tmp/aegis-p5-evidence-a.json /tmp/aegis-p5-evidence-b.json
```

Only disposable P5 containers, volumes, and temporary evidence may be removed.
Never delete retained project evidence or inherited Sprint 10 files.

## Fail-closed conditions

Stop and mark the run `not_evaluable`/`failed_closed` on hash mismatch, missing
limitation text, unsafe container posture, public bind, external dependency,
unavailable required check, sensitive-data exposure, unhealthy dependency, or
any Critical/High security finding.
