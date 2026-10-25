import secrets

from fastapi.testclient import TestClient

import realworld


def test_startup_root_and_check_actions(monkeypatch):
    monkeypatch.setenv("RD_GUARD_METRICS_ENABLED", "false")
    monkeypatch.delenv("RD_API_KEY", raising=False)

    with TestClient(realworld.app) as client:
        root = client.get("/")
        assert root.status_code == 200
        assert root.json()["status"] == "V11.4.0 LIVE"

        allowed = client.post("/check", json={"data": {"action": "read_file"}})
        assert allowed.status_code == 200
        assert allowed.json()["state"] == "ALLOW"
        assert allowed.json()["blocked"] is False
        assert allowed.json()["request_id"]

        blocked = client.post(
            "/check",
            json={"data": {"action": "unknown_task"}},
            headers={"X-Request-ID": "unknown-case"},
        )
        assert blocked.status_code == 200
        assert blocked.json()["state"] == "BLOCK"
        assert blocked.json()["blocked"] is True
        assert blocked.headers["X-Request-ID"] == "unknown-case"
        audit_record = [
            record
            for record in realworld.guard.audit_log
            if record.get("event") == "HTTP_CHECK"
        ][-1]
        assert audit_record["request_id"] == "unknown-case"
        assert audit_record["decision"] == "BLOCK"


def test_api_key_authentication_and_request_id(monkeypatch):
    monkeypatch.setenv("RD_GUARD_METRICS_ENABLED", "false")
    api_key = secrets.token_hex(32)
    monkeypatch.setenv("RD_API_KEY", api_key)

    with TestClient(realworld.app) as client:
        denied = client.post(
            "/check",
            json={"data": {"action": "read_file"}},
            headers={"X-Request-ID": "auth-case"},
        )
        assert denied.status_code == 401
        assert denied.json()["request_id"] == "auth-case"
        assert denied.headers["X-Request-ID"] == "auth-case"

        allowed = client.post(
            "/check",
            json={"data": {"action": "read_file"}},
            headers={"X-API-Key": api_key, "X-Request-ID": "read-case"},
        )
        assert allowed.status_code == 200
        assert allowed.json()["request_id"] == "read-case"


def test_body_size_limit_and_rate_limit(monkeypatch):
    monkeypatch.setenv("RD_GUARD_METRICS_ENABLED", "false")
    monkeypatch.delenv("RD_API_KEY", raising=False)
    monkeypatch.setenv("RD_RATE_LIMIT_PER_MIN", "1")
    realworld._rate_windows.clear()

    with TestClient(realworld.app) as client:
        large = client.post(
            "/check",
            content=b"x" * (realworld.MAX_REQUEST_BYTES + 1),
            headers={"X-Request-ID": "large-body"},
        )
        assert large.status_code == 413
        assert large.headers["X-Request-ID"] == "large-body"

        allowed = client.post("/check", json={"data": {"action": "read_file"}})
        assert allowed.status_code == 200
        limited = client.post("/check", json={"data": {"action": "read_file"}})
        assert limited.status_code == 429


def test_metrics_start_failure_does_not_crash_app(monkeypatch):
    monkeypatch.setenv("RD_GUARD_METRICS_ENABLED", "true")
    monkeypatch.setenv("RD_GUARD_METRICS_HOST", "127.0.0.1")
    monkeypatch.setenv("RD_GUARD_METRICS_PORT", "9090")
    monkeypatch.setattr(realworld.DEFAULT_METRICS, "enabled", True)

    def fail_start(**_kwargs):
        raise RuntimeError("metrics unavailable in test")

    monkeypatch.setattr(realworld, "start_metrics_server", fail_start)
    with TestClient(realworld.app) as client:
        assert client.get("/").json()["metrics"] == "metrics unavailable"
        assert client.post("/check", json={"data": {"action": "read_file"}}).status_code == 200
