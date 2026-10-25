"""V11.4.0 FastAPI entrypoint for the real-world startup example."""

import hmac
import json
import os
import re
import threading
import time
import uuid
from contextlib import asynccontextmanager

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
except ImportError as exc:
    missing = getattr(exc, "name", None) or "FastAPI runtime dependencies"
    raise ImportError(
        f"realworld.py requires '{missing}'. Install runtime dependencies with "
        "`python -m pip install -r requirements.txt`."
    ) from exc

try:
    from rd_guard import RDGuard
    from rd_guard.v11.config import GuardConfig
    from rd_guard.v11.telemetry.logging import get_logger
except ImportError as exc:
    missing = getattr(exc, "name", None) or ""
    raise ImportError(
        f"realworld.py (V11.4.0) could not import '{missing or 'rd_guard'}' "
        f"({exc}). Install dependencies with "
        "`python -m pip install -r requirements.txt`, then run "
        "`python -m pip install -e .` from the repository root. Confirm these "
        "files exist: rd_guard/__init__.py, rd_guard/v11/config.py, "
        "rd_guard/v11/telemetry/logging.py. See README.md 'Run the V11.4.0 "
        "real-world app' for the expected layout and startup command."
    ) from exc

from _rd_guard_executor import GuardedExecutor
from _rd_metrics import DEFAULT_METRICS
from _rd_metrics_server import start_metrics_server
from rd_guard.v11.policy import normalize_action_name

MAX_REQUEST_BYTES = 8192
DEFAULT_RATE_LIMIT = 120
_rate_windows: dict[str, tuple[float, int]] = {}
_rate_lock = threading.Lock()
_logger = get_logger("realworld")
logger = _logger
guard = RDGuard(config=GuardConfig(env="prod"))
executor = GuardedExecutor(guard=guard)


def _metrics_enabled():
    disabled_values = {"0", "false", "no", "off"}
    setting = os.environ.get("RD_GUARD_METRICS_ENABLED", "true").strip().lower()
    return DEFAULT_METRICS.enabled and setting not in disabled_values


def _display_host(host):
    wildcard_ipv4 = host.split(".") == ["0"] * 4
    if wildcard_ipv4 or host in {"::", ""}:
        return "localhost"
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _start_metrics():
    app.state.metrics_server = None
    app.state.metrics_display_host = None
    if not _metrics_enabled():
        return

    host = os.environ.get("RD_GUARD_METRICS_HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("RD_GUARD_METRICS_PORT", "9090"))
    except ValueError as exc:
        logger.warning(
            "Prometheus metrics listener not started: RD_GUARD_METRICS_PORT must be an "
            "integer (%s). Correct the setting or set "
            "RD_GUARD_METRICS_ENABLED=false; application startup will continue.",
            exc,
        )
        return

    try:
        app.state.metrics_server = start_metrics_server(
            host=host, port=port, metrics=DEFAULT_METRICS
        )
        app.state.metrics_display_host = _display_host(host)
    except Exception as exc:
        logger.warning(
            "Prometheus metrics server could not start on %s:%s: %s. Check "
            "RD_GUARD_METRICS_HOST, RD_GUARD_METRICS_PORT, and listener/network "
            "permissions; metrics will be unavailable, but application startup "
            "will continue.",
            host,
            port,
            exc,
        )


def _request_id(headers):
    supplied = next(
        (value.decode("latin-1") for name, value in headers if name.lower() == b"x-request-id"),
        "",
    )
    if supplied and len(supplied) <= 128 and re.fullmatch(r"[A-Za-z0-9_.:-]+", supplied):
        return supplied
    return uuid.uuid4().hex


def _error_response(send, status, request_id):
    body = json.dumps(
        {
            "state": "BLOCK",
            "blocked": True,
            "latency_ms": 0.0,
            "request_id": request_id,
        }
    ).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"x-request-id", request_id.encode("ascii")),
    ]
    return [
        {"type": "http.response.start", "status": status, "headers": headers},
        {"type": "http.response.body", "body": body},
    ]


def _record_rejection(request_id, reason):
    record = {
        "event": "HTTP_CHECK",
        "request_id": request_id,
        "decision": "BLOCK",
        "reason": reason,
    }
    try:
        guard.audit_log.append(record)
    except Exception as exc:
        logger.error("request_id=%s audit write failed: %s", request_id, exc)


class RequestBodyLimitMiddleware:
    """Bound /check request buffering and establish request correlation."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") != "/check":
            await self.app(scope, receive, send)
            return

        request_id = _request_id(scope.get("headers", ()))
        scope.setdefault("state", {})["request_id"] = request_id
        content_length = next(
            (value for name, value in scope.get("headers", ()) if name.lower() == b"content-length"),
            None,
        )
        if content_length is not None:
            try:
                if int(content_length) > MAX_REQUEST_BYTES:
                    logger.warning(
                        "request_id=%s decision=BLOCK reason=request_body_too_large",
                        request_id,
                    )
                    _record_rejection(request_id, "request_body_too_large")
                    for message in _error_response(send, 413, request_id):
                        await send(message)
                    return
            except ValueError:
                logger.warning(
                    "request_id=%s decision=BLOCK reason=invalid_content_length",
                    request_id,
                )
                _record_rejection(request_id, "invalid_content_length")
                for message in _error_response(send, 400, request_id):
                    await send(message)
                return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > MAX_REQUEST_BYTES:
                logger.warning(
                    "request_id=%s decision=BLOCK reason=request_body_too_large",
                    request_id,
                )
                _record_rejection(request_id, "request_body_too_large")
                for response in _error_response(send, 413, request_id):
                    await send(response)
                return
            if not message.get("more_body", False):
                break

        delivered = False

        async def replay_body():
            nonlocal delivered
            if delivered:
                return {"type": "http.disconnect"}
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay_body, send)


@asynccontextmanager
async def _lifespan(_app):
    if not os.environ.get("RD_API_KEY"):
        logger.warning(
            "RD_API_KEY is unset; /check is unauthenticated. Set RD_API_KEY in production."
        )
    try:
        _start_metrics()
    except Exception as exc:
        app.state.metrics_server = None
        app.state.metrics_display_host = None
        logger.warning("Metrics startup failed; metrics unavailable: %s", exc)
    yield


app = FastAPI(title="RD Guard V11.4.0 — Real World", lifespan=_lifespan)
app.add_middleware(RequestBodyLimitMiddleware)
app.state.metrics_server = None
app.state.metrics_display_host = None


def _metrics_url():
    server = app.state.metrics_server
    if server is None:
        return "metrics unavailable" if _metrics_enabled() else "metrics disabled"
    return f"http://{app.state.metrics_display_host}:{server.server_port}/metrics"


def _authorized(supplied):
    expected = os.environ.get("RD_API_KEY")
    if not expected:
        return True
    return supplied is not None and hmac.compare_digest(
        supplied.encode("utf-8"), expected.encode("utf-8")
    )


def _within_rate_limit(client):
    try:
        limit = int(os.environ.get("RD_RATE_LIMIT_PER_MIN", str(DEFAULT_RATE_LIMIT)))
        if limit < 1:
            raise ValueError("limit must be positive")
    except ValueError:
        logger.warning(
            "RD_RATE_LIMIT_PER_MIN must be a positive integer; using %s",
            DEFAULT_RATE_LIMIT,
        )
        limit = DEFAULT_RATE_LIMIT

    now = time.monotonic()
    with _rate_lock:
        started, count = _rate_windows.get(client, (now, 0))
        if now - started >= 60:
            started, count = now, 0
        if count >= limit:
            return False
        _rate_windows[client] = (started, count + 1)
        return True


def _safe_summary(value):
    summary = re.sub(r"[\x00-\x1f\x7f]", "?", str(value or "<missing>"))
    return summary[:120]


def _audit_request(request_id, result, action_summary):
    if result.audit_record is not None:
        result.audit_record["request_id"] = request_id
    record = {
        "event": "HTTP_CHECK",
        "request_id": request_id,
        "decision": result.decision,
        "action": action_summary,
    }
    if result.blocked:
        record["reason"] = _safe_summary(result.reason)
    try:
        guard.audit_log.append(record)
    except Exception as exc:
        logger.error("request_id=%s audit write failed: %s", request_id, exc)


@app.post("/check")
async def check(request: Request):
    request_id = request.state.request_id
    if not _authorized(request.headers.get("X-API-Key")):
        logger.warning("request_id=%s decision=BLOCK reason=authentication_failed", request_id)
        _record_rejection(request_id, "authentication_failed")
        return JSONResponse(
            {
                "state": "BLOCK", "blocked": True, "latency_ms": 0.0,
                "request_id": request_id,
            },
            status_code=401,
            headers={"X-Request-ID": request_id},
        )

    client = request.client.host if request.client is not None else "unknown"
    if not _within_rate_limit(client):
        logger.warning("request_id=%s decision=BLOCK reason=rate_limit", request_id)
        _record_rejection(request_id, "rate_limit")
        return JSONResponse(
            {
                "state": "BLOCK", "blocked": True, "latency_ms": 0.0,
                "request_id": request_id,
            },
            status_code=429,
            headers={"X-Request-ID": request_id},
        )

    start = time.perf_counter()
    try:
        payload = await request.json()
    except (ValueError, UnicodeDecodeError):
        logger.warning("request_id=%s decision=BLOCK reason=invalid_json", request_id)
        _record_rejection(request_id, "invalid_json")
        return JSONResponse(
            {
                "state": "BLOCK", "blocked": True, "latency_ms": 0.0,
                "request_id": request_id,
            },
            status_code=400,
            headers={"X-Request-ID": request_id},
        )
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
        logger.warning("request_id=%s decision=BLOCK reason=invalid_payload", request_id)
        _record_rejection(request_id, "invalid_payload")
        return JSONResponse(
            {
                "state": "BLOCK", "blocked": True, "latency_ms": 0.0,
                "request_id": request_id,
            },
            status_code=422,
            headers={"X-Request-ID": request_id},
        )

    data = payload["data"]
    action = data.get("action", data.get("requested_action"))
    action_name = action.get("type", action.get("name")) if isinstance(action, dict) else action
    summary = _safe_summary(normalize_action_name(action_name) or "<missing>")
    result = executor.execute(data)
    latency_ms = (time.perf_counter() - start) * 1000

    _audit_request(request_id, result, summary)
    logger.info(
        "request_id=%s decision=%s blocked=%s latency=%.2fms",
        request_id,
        result.state,
        result.blocked,
        latency_ms,
    )
    if result.blocked:
        logger.warning(
            "request_id=%s decision=BLOCK action=%s reason=%s",
            request_id,
            summary,
            _safe_summary(result.reason),
        )

    return JSONResponse(
        {
            "state": str(result.state),
            "blocked": bool(result.blocked),
            "latency_ms": round(latency_ms, 2),
            "request_id": request_id,
        },
        headers={"X-Request-ID": request_id},
    )


@app.get("/")
def root():
    return {"status": "V11.4.0 LIVE", "metrics": _metrics_url()}


# Run: uvicorn realworld:app --reload
