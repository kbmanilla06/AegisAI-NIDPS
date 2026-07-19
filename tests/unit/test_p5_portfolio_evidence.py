import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "create_p5_portfolio_evidence", ROOT / "scripts/create_p5_portfolio_evidence.py"
)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

BASELINE = _MODULE.BASELINE
FALSE_CAPABILITY_FLAGS = _MODULE.FALSE_CAPABILITY_FLAGS
PortfolioEvidenceError = _MODULE.PortfolioEvidenceError
build_evidence = _MODULE.build_evidence
write_evidence = _MODULE.write_evidence


def test_evidence_is_hash_bound_and_synthetic_only() -> None:
    evidence = build_evidence(ROOT)
    identity = evidence["identity"]
    assert isinstance(identity, dict)
    assert identity["baseline"] == BASELINE
    assert identity["media"] == {"screenshots_authorized": False, "recording_authorized": False}
    assert identity["prevention_mode"] == "simulation"
    assert identity["external_services_required"] is False
    assert identity["sealed_test_reopened"] is False
    assert evidence["false_capability_flags"] == FALSE_CAPABILITY_FLAGS
    assert evidence["retention"]["exceptional_holds_enabled"] is False  # type: ignore[index]


def test_evidence_identity_is_deterministic() -> None:
    first = build_evidence(ROOT)
    second = build_evidence(ROOT)
    assert first["identity"] == second["identity"]
    assert first["identity_sha256"] == second["identity_sha256"]


def test_evidence_requires_limitation_constants(tmp_path: Path) -> None:
    for relative in (
        "docs/POST_MVP_GATE_P5_PLAN.md",
        "docs/POST_MVP_SYNTHETIC_ROADMAP.md",
        "docs/POST_MVP_GATE_P4_COMPLETION_REPORT.md",
        "docs/POST_MVP_GATE_P4_REPRODUCIBILITY_RUNBOOK.md",
        "README.md",
        "SECURITY.md",
        "docs/PRD.md",
        "docs/SCHEMAS.md",
        "docs/architecture/ARCHITECTURE.md",
        "docs/threat-model/THREAT_MODEL.md",
        "services/aegis_services/synthetic/schema.py",
        "services/aegis_services/monitoring/schema.py",
        "docs/portfolio/README_PORTFOLIO.md",
        "docs/portfolio/DEMO_RUNBOOK.md",
        "docs/portfolio/ARCHITECTURE_OVERVIEW.md",
        "docs/portfolio/THREAT_MODEL_SUMMARY.md",
        "docs/portfolio/SPRINT_HISTORY.md",
        "docs/portfolio/CLAIMS_REVIEW.md",
        "docs/portfolio/DEMO_TRANSCRIPT.md",
        "docs/portfolio/cards/SYNTHETIC_DATASET_CARD.md",
        "docs/portfolio/cards/FEATURE_SCHEMA_CARD.md",
        "docs/portfolio/cards/MODEL_ANOMALY_CARD.md",
        "docs/portfolio/cards/MONITORING_CARD.md",
        "docs/portfolio/cards/PREVENTION_SIMULATION_CARD.md",
        "docs/portfolio/cards/SECURITY_QA_CARD.md",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("control", encoding="utf-8")
    for relative in (
        "docs/SPRINT_5_GATE_5SA_COMPLETION_REPORT.md",
        "docs/SPRINT_5_GATE_5SB_COMPLETION_REPORT.md",
        "docs/SPRINT_5_GATE_5SC_COMPLETION_REPORT.md",
        "docs/POST_MVP_GATE_P1_COMPLETION_REPORT.md",
        "docs/POST_MVP_GATE_P2_COMPLETION_REPORT.md",
        "docs/POST_MVP_GATE_P3_COMPLETION_REPORT.md",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("evidence", encoding="utf-8")
    with pytest.raises(PortfolioEvidenceError, match="synthetic_limitation_constant_mismatch"):
        build_evidence(tmp_path)


def test_write_evidence_uses_restrictive_mode(tmp_path: Path) -> None:
    output = tmp_path / "portfolio.json"
    write_evidence(ROOT, output)
    assert output.stat().st_mode & 0o777 == 0o600
    assert "identity_sha256" in output.read_text(encoding="utf-8")
