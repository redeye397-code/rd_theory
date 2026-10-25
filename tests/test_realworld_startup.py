"""Tests for the V11.4.0 real-world startup path (``realworld.py``).

These guard against the package-layout regression where ``rd_guard`` was a
flat module and the V11 submodules it documents/imports --
``rd_guard.v11.config`` and ``rd_guard.v11.telemetry.logging`` -- did not
exist, causing ``realworld.py`` to fail immediately on import.
"""

import importlib
import socket
from pathlib import Path
from urllib.request import urlopen

import pytest
from fastapi.testclient import TestClient

from _rd_metrics_server import stop_metrics_server

from rd_guard import RDGuard
from rd_guard.v11.config import GuardConfig
from rd_guard.v11.telemetry.logging import get_logger


def test_guard_config_has_expected_defaults_and_env():
    config = GuardConfig(env="prod")

    assert config.env == "prod"
    assert config.bloat_threshold == 0.7
    assert config.drift_threshold == 0.6
    assert config.stall_threshold == 0.6


def test_get_logger_is_idempotent_and_usable():
    logger = get_logger("rd_guard.tests.realworld")
    same_logger = get_logger("rd_guard.tests.realworld")

    assert logger is same_logger
    assert len(logger.handlers) == 1
    logger.info("startup check")


def test_rdguard_accepts_v11_config_and_evaluate_alias():
    guard = RDGuard(config=GuardConfig(env="prod"))

    allowed = guard.evaluate({"action": "read_file"})
    assert allowed.state == "ALLOW"
    assert allowed.blocked is False

    blocked = guard.evaluate({"deleting_tests": True})
    assert blocked.state == "BLOCK"
    assert blocked.blocked is True


def test_realworld_entrypoint_imports_and_serves_requests(monkeypatch):
    monkeypatch.setenv("RD_GUARD_METRICS_ENABLED", "false")

    realworld = importlib.import_module("realworld")

    realworld.app.state.metrics_server = None
    client = TestClient(realworld.app)

    root = client.get("/")
    assert root.status_code == 200
    assert root.json()["status"] == "V11.4.0 LIVE"

    allowed = client.post("/check", json={"data": {"action": "read_file"}})
    assert allowed.status_code == 200
    assert allowed.json()["state"] == "ALLOW"
    assert allowed.json()["blocked"] is False

    blocked = client.post("/check", json={"data": {"deleting_tests": True}})
    assert blocked.status_code == 200
    assert blocked.json()["state"] == "BLOCK"
    assert blocked.json()["blocked"] is True


def test_realworld_reports_actionable_error_when_v11_layout_missing(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "rd_guard.v11.config", None)
    monkeypatch.delitem(sys.modules, "realworld", raising=False)

    with pytest.raises(ImportError) as exc_info:
        importlib.import_module("realworld")

    message = str(exc_info.value)
    assert "python -m pip install -r requirements.txt" in message
    assert "pip install -e ." in message
    assert "rd_guard/v11/config.py" in message

    # Clean up so later tests re-import a fresh, working realworld module.
    monkeypatch.delitem(sys.modules, "realworld", raising=False)


def test_realworld_reports_actionable_error_when_fastapi_is_missing(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "fastapi", None)
    monkeypatch.delitem(sys.modules, "realworld", raising=False)

    with pytest.raises(ImportError, match="python -m pip install -r requirements.txt"):
        importlib.import_module("realworld")

    monkeypatch.delitem(sys.modules, "realworld", raising=False)


def test_realworld_metrics_can_be_disabled(monkeypatch):
    realworld = importlib.import_module("realworld")
    monkeypatch.setenv("RD_GUARD_METRICS_ENABLED", "false")
    monkeypatch.setattr(realworld.DEFAULT_METRICS, "enabled", True)
    monkeypatch.setattr(
        realworld,
        "start_metrics_server",
        lambda **kwargs: pytest.fail("metrics server should not start"),
    )

    with TestClient(realworld.app) as client:
        assert client.get("/").json()["metrics"] == "metrics disabled"
        assert client.post("/check", json={"data": {"action": "read_file"}}).json()[
            "blocked"
        ] is False


def test_realworld_skips_metrics_when_optional_client_is_unavailable(monkeypatch):
    realworld = importlib.import_module("realworld")
    monkeypatch.setenv("RD_GUARD_METRICS_ENABLED", "true")
    monkeypatch.setattr(realworld.DEFAULT_METRICS, "enabled", False)
    monkeypatch.setattr(
        realworld,
        "start_metrics_server",
        lambda **kwargs: pytest.fail("metrics server should not start"),
    )

    with TestClient(realworld.app) as client:
        assert client.get("/").json()["metrics"] == "metrics disabled"


def test_realworld_metrics_use_configured_host_and_port(monkeypatch):
    realworld = importlib.import_module("realworld")
    monkeypatch.setenv("RD_GUARD_METRICS_ENABLED", "true")
    monkeypatch.setenv("RD_GUARD_METRICS_HOST", "127.0.0.1")
    monkeypatch.setenv("RD_GUARD_METRICS_PORT", "0")
    monkeypatch.setattr(realworld.DEFAULT_METRICS, "enabled", True)

    with TestClient(realworld.app) as client:
        metrics_url = client.get("/").json()["metrics"]
        assert metrics_url.startswith("http://127.0.0.1:")
        with urlopen(metrics_url) as response:
            assert response.status == 200
            assert response.headers["Content-Type"].startswith("text/plain")
            assert b"# HELP rd_guard_action_decisions_total" in response.read()
        assert realworld.app.state.metrics_server.server_port > 0

    server = realworld.app.state.metrics_server
    importlib.reload(realworld)
    with TestClient(realworld.app):
        assert realworld.app.state.metrics_server is server
    stop_metrics_server("127.0.0.1", 0)


def test_realworld_metrics_port_conflict_does_not_stop_app(monkeypatch, caplog):
    realworld = importlib.import_module("realworld")
    monkeypatch.setenv("RD_GUARD_METRICS_ENABLED", "true")
    monkeypatch.setenv("RD_GUARD_METRICS_HOST", "127.0.0.1")
    monkeypatch.setattr(realworld.DEFAULT_METRICS, "enabled", True)

    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        monkeypatch.setenv("RD_GUARD_METRICS_PORT", str(occupied.getsockname()[1]))

        with TestClient(realworld.app) as client:
            assert client.get("/").status_code == 200
            assert client.get("/").json()["metrics"] == "metrics unavailable"
            allowed = client.post("/check", json={"data": {"action": "read_file"}})
            blocked = client.post("/check", json={"data": {"deleting_tests": True}})
            assert allowed.json()["blocked"] is False
            assert blocked.json()["blocked"] is True
        assert "Check RD_GUARD_METRICS_HOST" in caplog.text
        assert "application startup will continue" in caplog.text


def test_realworld_invalid_metrics_port_does_not_stop_app(monkeypatch, caplog):
    realworld = importlib.import_module("realworld")
    monkeypatch.setenv("RD_GUARD_METRICS_ENABLED", "true")
    monkeypatch.setenv("RD_GUARD_METRICS_PORT", "not-a-port")
    monkeypatch.setattr(realworld.DEFAULT_METRICS, "enabled", True)

    with TestClient(realworld.app) as client:
        assert client.get("/").status_code == 200
        assert client.get("/").json()["metrics"] == "metrics unavailable"
        allowed = client.post("/check", json={"data": {"action": "read_file"}})
        assert allowed.json()["blocked"] is False
    assert "RD_GUARD_METRICS_PORT must be an integer" in caplog.text
    assert "application startup will continue" in caplog.text


def test_readme_documents_cross_shell_install_and_startup_commands():
    repo_root = Path(__file__).parents[1]
    readme = (repo_root / "README.md").read_text()
    procfile = (repo_root / "Procfile").read_text()

    assert "python -m pip install -r requirements.txt" in readme
    assert "python -m pip install -e ." in readme
    assert "uvicorn realworld:app --reload" in readme
    assert "uvicorn realworld:app --host 0.0.0.0 --port ${PORT:-8000}" in readme
    assert "$port = if ($env:PORT) { $env:PORT } else { 8000 }" in readme
    assert "uvicorn realworld:app --host 0.0.0.0 --port $port" in readme
    assert "${PORT:-8000}" in procfile
