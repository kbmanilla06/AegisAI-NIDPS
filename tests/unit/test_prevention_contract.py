from uuid import uuid4

from aegis_services.prevention import PreventionPreview


def test_preview_mode_can_only_be_simulation() -> None:
    preview = PreventionPreview(
        request_id=uuid4(),
        mode="simulation",
        action_type="temporary_block_preview",
        target_type="external_ip",
        target_display="203.0.113.10",
        duration_seconds=300,
        rollback_summary="Remove the simulated temporary rule",
    )
    assert preview.mode == "simulation"
