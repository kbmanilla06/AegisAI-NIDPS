from __future__ import annotations

from aegis_services.soc import AlertRef, correlate_alerts, correlation_key


def test_correlation_groups_by_category_deterministically() -> None:
    alerts = [
        AlertRef(alert_id="a3", category="port_scan"),
        AlertRef(alert_id="a1", category="port_scan"),
        AlertRef(alert_id="a2", category="brute_force"),
    ]
    groups = correlate_alerts(alerts)
    by_category = {group.category: group for group in groups}
    assert set(by_category) == {"port_scan", "brute_force"}
    # Members are sorted for a stable, replayable grouping.
    assert by_category["port_scan"].alert_ids == ("a1", "a3")
    assert by_category["brute_force"].alert_ids == ("a2",)
    # Correlation key is a pure function of category.
    assert by_category["port_scan"].correlation_key == correlation_key("port_scan")


def test_correlation_is_stable_across_runs() -> None:
    alerts = [AlertRef(alert_id=f"a{i}", category="port_scan") for i in range(5)]
    assert correlate_alerts(alerts) == correlate_alerts(list(reversed(alerts)))


def test_correlation_empty_input() -> None:
    assert correlate_alerts([]) == ()
