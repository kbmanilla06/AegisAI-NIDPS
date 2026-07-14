from aegis_api.security.permissions import ROLE_PERMISSION_MATRIX, PermissionKey


def test_only_explicit_administrators_can_manage_prevention() -> None:
    managers = {
        role
        for role, permissions in ROLE_PERMISSION_MATRIX.items()
        if PermissionKey.PREVENTION_MANAGE in permissions
    }
    assert managers == {"Security Administrator", "System Administrator"}


def test_viewer_has_no_mutating_permission() -> None:
    assert all(
        not permission.value.endswith(":manage") for permission in ROLE_PERMISSION_MATRIX["Viewer"]
    )
