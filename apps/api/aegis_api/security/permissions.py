from enum import StrEnum


class PermissionKey(StrEnum):
    USERS_READ = "users:read"
    USERS_MANAGE = "users:manage"
    ROLES_READ = "roles:read"
    ASSETS_READ = "assets:read"
    ASSETS_MANAGE = "assets:manage"
    SENSORS_READ = "sensors:read"
    SENSORS_MANAGE = "sensors:manage"
    AUDIT_READ = "audit:read"
    TELEMETRY_READ = "telemetry:read"
    INGESTION_SUBMIT = "ingestion:submit"
    INGESTION_REPLAY = "ingestion:replay"
    RULES_READ = "rules:read"
    RULES_WRITE = "rules:write"
    RULES_REVIEW = "rules:review"
    RULES_ACTIVATE = "rules:activate"
    ALERTS_READ = "alerts:read"
    ALERTS_READ_SENSITIVE = "alerts:read_sensitive"
    DETECTIONS_READ_METRICS = "detections:read_metrics"
    FEATURES_READ = "features:read"
    FEATURES_MATERIALIZE = "features:materialize"
    FEATURES_REVIEW = "features:review"
    DATASETS_READ = "datasets:read"
    DATASETS_MANAGE = "datasets:manage"
    DATASETS_ACQUIRE = "datasets:acquire"
    DATASETS_ACCEPT = "datasets:accept"
    SYNTHETIC_DATASETS_READ = "synthetic_datasets:read"
    SYNTHETIC_DATASETS_GENERATE = "synthetic_datasets:generate"
    SYNTHETIC_DATASETS_REVIEW = "synthetic_datasets:review"
    MODELS_READ = "models:read"
    MODELS_TRAIN_SYNTHETIC = "models:train_synthetic"
    MODELS_REVIEW_SYNTHETIC = "models:review_synthetic"
    MODELS_SCORE_SYNTHETIC = "models:score_synthetic"
    PREDICTIONS_READ = "predictions:read"
    ANOMALY_FIT = "anomaly:fit"
    ANOMALY_EVALUATE = "anomaly:evaluate"
    ENSEMBLE_REVIEW = "ensemble:review"
    ENSEMBLE_EVALUATE = "ensemble:evaluate"
    EXPLANATIONS_READ = "explanations:read"
    EXPLANATIONS_GENERATE = "explanations:generate"
    EXPLANATIONS_REVIEW = "explanations:review"
    INTELLIGENCE_READ = "intelligence:read"
    INTELLIGENCE_IMPORT = "intelligence:import"
    INTELLIGENCE_REVIEW = "intelligence:review"
    INTELLIGENCE_MATCH = "intelligence:match"
    MITRE_READ = "mitre:read"
    ALERTS_TRIAGE = "alerts:triage"
    INCIDENTS_READ = "incidents:read"
    INCIDENTS_CORRELATE = "incidents:correlate"
    INCIDENTS_MANAGE = "incidents:manage"
    PREVENTION_READ = "prevention:read"
    PREVENTION_MANAGE = "prevention:manage"


ROLE_PERMISSION_MATRIX: dict[str, frozenset[PermissionKey]] = {
    "Viewer": frozenset(
        {PermissionKey.ASSETS_READ, PermissionKey.RULES_READ, PermissionKey.ALERTS_READ}
    ),
    "SOC Analyst": frozenset(
        {
            PermissionKey.ASSETS_READ,
            PermissionKey.SENSORS_READ,
            PermissionKey.TELEMETRY_READ,
            PermissionKey.RULES_READ,
            PermissionKey.ALERTS_READ,
            PermissionKey.ALERTS_READ_SENSITIVE,
            PermissionKey.DETECTIONS_READ_METRICS,
            PermissionKey.FEATURES_READ,
            PermissionKey.INTELLIGENCE_READ,
            PermissionKey.MITRE_READ,
            PermissionKey.ALERTS_TRIAGE,
            PermissionKey.INCIDENTS_READ,
        }
    ),
    "Senior Analyst": frozenset(
        {
            PermissionKey.ASSETS_READ,
            PermissionKey.SENSORS_READ,
            PermissionKey.TELEMETRY_READ,
            PermissionKey.PREVENTION_READ,
            PermissionKey.RULES_READ,
            PermissionKey.ALERTS_READ,
            PermissionKey.ALERTS_READ_SENSITIVE,
            PermissionKey.DETECTIONS_READ_METRICS,
            PermissionKey.FEATURES_READ,
            PermissionKey.DATASETS_READ,
            PermissionKey.SYNTHETIC_DATASETS_READ,
            PermissionKey.MODELS_READ,
            PermissionKey.MODELS_SCORE_SYNTHETIC,
            PermissionKey.PREDICTIONS_READ,
            PermissionKey.ANOMALY_EVALUATE,
            PermissionKey.ENSEMBLE_EVALUATE,
            PermissionKey.EXPLANATIONS_READ,
            PermissionKey.INTELLIGENCE_READ,
            PermissionKey.INTELLIGENCE_MATCH,
            PermissionKey.MITRE_READ,
            PermissionKey.ALERTS_TRIAGE,
            PermissionKey.INCIDENTS_READ,
            PermissionKey.INCIDENTS_MANAGE,
        }
    ),
    "Security Administrator": frozenset(
        {
            PermissionKey.ROLES_READ,
            PermissionKey.ASSETS_READ,
            PermissionKey.ASSETS_MANAGE,
            PermissionKey.SENSORS_READ,
            PermissionKey.SENSORS_MANAGE,
            PermissionKey.AUDIT_READ,
            PermissionKey.TELEMETRY_READ,
            PermissionKey.INGESTION_SUBMIT,
            PermissionKey.INGESTION_REPLAY,
            PermissionKey.RULES_READ,
            PermissionKey.RULES_WRITE,
            PermissionKey.RULES_REVIEW,
            PermissionKey.RULES_ACTIVATE,
            PermissionKey.ALERTS_READ,
            PermissionKey.ALERTS_READ_SENSITIVE,
            PermissionKey.DETECTIONS_READ_METRICS,
            PermissionKey.PREVENTION_READ,
            PermissionKey.PREVENTION_MANAGE,
            PermissionKey.FEATURES_READ,
            PermissionKey.FEATURES_MATERIALIZE,
            PermissionKey.FEATURES_REVIEW,
            PermissionKey.DATASETS_READ,
            PermissionKey.DATASETS_MANAGE,
            PermissionKey.DATASETS_ACCEPT,
            PermissionKey.SYNTHETIC_DATASETS_READ,
            PermissionKey.SYNTHETIC_DATASETS_REVIEW,
            PermissionKey.MODELS_READ,
            PermissionKey.MODELS_REVIEW_SYNTHETIC,
            PermissionKey.MODELS_SCORE_SYNTHETIC,
            PermissionKey.PREDICTIONS_READ,
            PermissionKey.ANOMALY_EVALUATE,
            PermissionKey.ENSEMBLE_EVALUATE,
            PermissionKey.ENSEMBLE_REVIEW,
            PermissionKey.EXPLANATIONS_READ,
            PermissionKey.EXPLANATIONS_REVIEW,
            PermissionKey.INTELLIGENCE_READ,
            PermissionKey.INTELLIGENCE_IMPORT,
            PermissionKey.INTELLIGENCE_REVIEW,
            PermissionKey.INTELLIGENCE_MATCH,
            PermissionKey.MITRE_READ,
            PermissionKey.ALERTS_TRIAGE,
            PermissionKey.INCIDENTS_READ,
            PermissionKey.INCIDENTS_CORRELATE,
            PermissionKey.INCIDENTS_MANAGE,
        }
    ),
    "System Administrator": frozenset(
        set(PermissionKey)
        - {
            PermissionKey.FEATURES_REVIEW,
            PermissionKey.DATASETS_MANAGE,
            PermissionKey.DATASETS_ACCEPT,
            PermissionKey.SYNTHETIC_DATASETS_REVIEW,
            PermissionKey.MODELS_REVIEW_SYNTHETIC,
            PermissionKey.ENSEMBLE_REVIEW,
            PermissionKey.EXPLANATIONS_REVIEW,
            PermissionKey.INTELLIGENCE_IMPORT,
            PermissionKey.INTELLIGENCE_REVIEW,
            PermissionKey.ALERTS_TRIAGE,
            PermissionKey.INCIDENTS_MANAGE,
        }
    ),
    "Auditor": frozenset(
        {
            PermissionKey.ROLES_READ,
            PermissionKey.ASSETS_READ,
            PermissionKey.SENSORS_READ,
            PermissionKey.AUDIT_READ,
            PermissionKey.TELEMETRY_READ,
            PermissionKey.RULES_READ,
            PermissionKey.ALERTS_READ,
            PermissionKey.ALERTS_READ_SENSITIVE,
            PermissionKey.DETECTIONS_READ_METRICS,
            PermissionKey.PREVENTION_READ,
            PermissionKey.FEATURES_READ,
            PermissionKey.DATASETS_READ,
            PermissionKey.SYNTHETIC_DATASETS_READ,
            PermissionKey.MODELS_READ,
            PermissionKey.MODELS_SCORE_SYNTHETIC,
            PermissionKey.PREDICTIONS_READ,
            PermissionKey.EXPLANATIONS_READ,
            PermissionKey.INTELLIGENCE_READ,
            PermissionKey.MITRE_READ,
            PermissionKey.INCIDENTS_READ,
        }
    ),
}
