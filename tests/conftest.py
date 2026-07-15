import asyncio
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from aegis_api.anomaly_dispatch import get_anomaly_fit_dispatcher, get_assessment_dispatcher
from aegis_api.config import Settings, get_settings
from aegis_api.database import get_db
from aegis_api.feature_dispatch import get_feature_dispatcher
from aegis_api.ingestion_dispatch import get_ingestion_dispatcher
from aegis_api.ingestion_throttle import get_ingestion_throttle
from aegis_api.main import create_app
from aegis_api.ml_dispatch import get_training_dispatcher
from aegis_api.models import Base, FeatureSchemaVersion, Permission, Role, RuleVersion, User
from aegis_api.security.passwords import password_service
from aegis_api.security.permissions import ROLE_PERMISSION_MATRIX
from aegis_api.security.throttle import LoginThrottle, get_login_throttle
from aegis_api.synthetic_dispatch import get_synthetic_dispatcher
from aegis_services.detection import DEFAULT_RULES, canonical_hash
from aegis_services.features import feature_schema

ORIGIN = "http://localhost:5173"
PASSWORD = "correct-horse-battery-staple"  # noqa: S105  # nosec B105 - test fixture


class AllowThrottle:
    async def check(self, _client_address: str) -> None:
        return None


@dataclass(frozen=True)
class AppHarness:
    client: TestClient
    session_factory: async_sessionmaker[AsyncSession]
    artifact_root: Path
    dispatched_jobs: list[str]
    dispatched_feature_jobs: list[str]
    dispatched_synthetic_jobs: list[str]
    dispatched_training_runs: list[str]
    dispatched_anomaly_fits: list[str]
    dispatched_assessments: list[str]

    def run(self, operation):  # type: ignore[no-untyped-def]
        async def execute():  # type: ignore[no-untyped-def]
            async with self.session_factory() as db:
                return await operation(db)

        return asyncio.run(execute())

    def login(self, role: str = "System Administrator") -> tuple[dict[str, object], str]:
        email = f"{role.lower().replace(' ', '.')}@example.com"
        response = self.client.post(
            "/api/v1/auth/login",
            headers={"Origin": ORIGIN},
            json={"email": email, "password": PASSWORD},
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        return payload, str(payload["csrf_token"])


@pytest.fixture
def app_harness(tmp_path: Path) -> Iterator[AppHarness]:
    database_path = tmp_path / "aegis-test.sqlite"
    test_engine = create_async_engine(f"sqlite+aiosqlite:///{database_path}")
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)

    async def prepare() -> None:
        async with test_engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with session_factory() as db:
            permissions = {
                permission.value: Permission(
                    key=permission.value, description=f"Allows {permission.value}"
                )
                for assigned in ROLE_PERMISSION_MATRIX.values()
                for permission in assigned
            }
            roles: dict[str, Role] = {}
            for role_name, assigned in ROLE_PERMISSION_MATRIX.items():
                role = Role(
                    name=role_name,
                    description=f"Built-in {role_name} role",
                    permissions=[permissions[item.value] for item in assigned],
                )
                roles[role_name] = role
                db.add(role)
            password_hash = password_service.hash(PASSWORD)
            for role_name, role in roles.items():
                db.add(
                    User(
                        email=f"{role_name.lower().replace(' ', '.')}@example.com",
                        password_hash=password_hash,
                        roles=[role],
                    )
                )
            for definition in DEFAULT_RULES:
                db.add(
                    RuleVersion(
                        rule_key=definition.rule_key,
                        version=1,
                        schema_version="behavioral-rule/v1",
                        name=definition.name,
                        description=definition.description,
                        category=definition.category,
                        evaluator_key=definition.evaluator_key,
                        parameters=definition.parameters,
                        window_seconds=definition.window_seconds,
                        severity=definition.severity,
                        mitre_mappings=[],
                        evidence_contract={"version": "alert-evidence/v1"},
                        false_positive_guidance=definition.false_positive_guidance,
                        investigation_guidance=definition.investigation_guidance,
                        prevention_recommendation=definition.prevention_recommendation,
                        change_rationale="Approved Sprint 3 test seed.",
                        definition_hash=canonical_hash(definition.canonical_definition()),
                        lifecycle_state="approved",
                        is_active=True,
                    )
                )
            # Match the immutable approved Sprint 4 schema exactly; changing only
            # code_version also changes the owner-accepted schema definition hash.
            schema = feature_schema(code_version="sprint4")
            db.add(
                FeatureSchemaVersion(
                    name=schema.name,
                    version=schema.version,
                    input_schema=schema.input_schema,
                    ordered_definition=schema.model_dump(mode="json"),
                    preprocessing_config={
                        "missing_token": schema.missing_token,
                        "unknown_token": schema.unknown_token,
                        "numeric_dtype": schema.numeric_dtype,
                        "fit_partition": "training_only",
                    },
                    banned_fields=list(schema.banned_fields),
                    definition_hash=schema.definition_hash,
                    code_version=schema.code_version,
                    lifecycle_state="approved",
                    review_reason="Owner-approved Sprint 4 test schema.",
                )
            )
            await db.commit()

    asyncio.run(prepare())
    artifact_root = tmp_path / "artifacts"
    test_settings = Settings(
        environment="test",
        database_url=f"sqlite+aiosqlite:///{database_path}",
        artifact_root=artifact_root,
        ingestion_max_upload_bytes=4096,
        ingestion_request_overhead_bytes=4096,
        ingestion_max_records=100,
        ingestion_max_unique_flows=50,
        ingestion_max_processing_seconds=10,
    )
    app = create_app(test_settings)
    app.state.session_factory = session_factory

    async def override_db() -> AsyncIterator[AsyncSession]:
        async with session_factory() as db:
            yield db

    throttle: LoginThrottle = AllowThrottle()
    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_settings] = lambda: test_settings
    app.dependency_overrides[get_login_throttle] = lambda: throttle
    app.dependency_overrides[get_ingestion_throttle] = lambda: throttle
    dispatched_jobs: list[str] = []
    dispatched_feature_jobs: list[str] = []
    dispatched_synthetic_jobs: list[str] = []
    dispatched_training_runs: list[str] = []
    dispatched_anomaly_fits: list[str] = []
    dispatched_assessments: list[str] = []
    app.dependency_overrides[get_ingestion_dispatcher] = lambda: dispatched_jobs.append
    app.dependency_overrides[get_feature_dispatcher] = lambda: dispatched_feature_jobs.append
    app.dependency_overrides[get_synthetic_dispatcher] = lambda: dispatched_synthetic_jobs.append
    app.dependency_overrides[get_training_dispatcher] = lambda: dispatched_training_runs.append
    app.dependency_overrides[get_anomaly_fit_dispatcher] = lambda: dispatched_anomaly_fits.append
    app.dependency_overrides[get_assessment_dispatcher] = lambda: dispatched_assessments.append
    with TestClient(app, base_url="https://testserver") as client:
        yield AppHarness(
            client,
            session_factory,
            artifact_root,
            dispatched_jobs,
            dispatched_feature_jobs,
            dispatched_synthetic_jobs,
            dispatched_training_runs,
            dispatched_anomaly_fits,
            dispatched_assessments,
        )
    asyncio.run(test_engine.dispose())
