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
        }
    ),
    "System Administrator": frozenset(
        set(PermissionKey)
        - {
            PermissionKey.FEATURES_REVIEW,
            PermissionKey.DATASETS_MANAGE,
            PermissionKey.DATASETS_ACCEPT,
            PermissionKey.SYNTHETIC_DATASETS_REVIEW,
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
        }
    ),
}
