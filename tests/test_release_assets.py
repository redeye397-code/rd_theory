import json
from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_release_version_and_changelog_are_consistent():
    assert 'version = "11.4.0"' in (ROOT / "pyproject.toml").read_text()
    assert '__version__ = "11.4.0"' in (ROOT / "__init__.py").read_text()
    assert '# RD Theory V11.4.0' in (ROOT / "README.md").read_text()
    changelog = (ROOT / "CHANGELOG.md").read_text()
    assert "## Unreleased\n\n## 11.4.0 — October 25, 2026" in changelog
    assert '"V11.4.0 LIVE"' in (ROOT / "realworld.py").read_text()
    assert (ROOT / "RELEASE_V11.4.0.md").is_file()
    assert '__version__ = "11.4.0"' in (
        ROOT / "rd_guard/v11/__init__.py"
    ).read_text()


def test_container_monitoring_assets_are_present_and_linked():
    compose = (ROOT / "docker-compose.yml").read_text()
    assert "prometheus-compose.yml" in compose
    assert "prometheus-data:/prometheus" in compose
    assert "app:9090" in (
        ROOT / "examples/prometheus/prometheus-compose.yml"
    ).read_text()
    assert (ROOT / "Dockerfile").is_file()
    assert "localhost:9090" in (
        ROOT / "examples/prometheus/prometheus.yml"
    ).read_text()
    alerts = (ROOT / "examples/prometheus/alerts.yml").read_text()
    assert "rd_guard_state_transitions_total" in alerts
    assert "rd_guard_action_decisions_total" in alerts
    assert json.loads(
        (ROOT / "examples/grafana/rd_guard_dashboard.json").read_text()
    )["title"] == "RD Guard"
