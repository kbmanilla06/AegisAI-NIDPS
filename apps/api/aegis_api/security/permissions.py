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
        }
    ),
    "System Administrator": frozenset(PermissionKey),
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
        }
    ),
}
