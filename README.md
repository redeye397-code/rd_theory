# RD Theory V11.2.3

![Version](https://img.shields.io/badge/version-11.2.3-blue)

**Support policy:** V11.2.3 is the supported version. V1–V9 are archived
and available for reference only; their legacy import paths remain available
with `DeprecationWarning` notices.

RD Guard is a fail-closed state machine that blocks unsafe code execution when
actions violate the safety floor, required audit logging is unavailable, or a
state-machine rule disallows a transition. Use it when you need validated
actions and fail-closed enforcement in a Python workflow. It is not a
production-certified security boundary.

## Try RD Guard in 30 seconds

Clone this repository and install the local package:

```bash
git clone https://github.com/redeye397-code/rd_theory.git
cd rd_theory
python -m pip install -e .
```

Run this short example from the repository root:

```python
from rd_executor import GuardedExecutor
guard = GuardedExecutor()
print(guard.execute({"action": "read_file"}).decision)  # ALLOW
print(guard.execute({"action": "delete_tests"}).decision)  # BLOCK
```

Expected output is `ALLOW` followed by `BLOCK`: deleting tests violates the
IAS safety floor. More detail: [setup](docs/setup.md) and
[architecture](docs/architecture.md).

## Migration to V10

Import the RD-Guard API from its stable path:

```python
from rd_guard import RDGuard
```

The V9 path (`from rd_guard_v9 import RDGuard`) remains available for
compatibility and emits a `DeprecationWarning`. Earlier versioned modules also
remain importable for reference and emit the same warning.

Import the GhostVault secure-enclave attestation API from its stable path:

```python
from rd_vault import GhostVaultProduction
```

The archived V8 path (`from rd_theory_v8 import GhostVaultV8_Production`)
remains available as reference and emits a `DeprecationWarning`.

## Canonical action schema and enforcement boundary

Actions observed by RD-Guard are normalized into a canonical, validated
`CanonicalAction` (type/target/path/resource/command/branch/ci_passed/
risk_level), and every action that an agent proposes to run must pass
through `GuardedExecutor` -- the single enforcement boundary:

```python
from rd_executor import GuardedExecutor

executor = GuardedExecutor()
result = executor.execute({"action": "read_file", "path": "README.md"}, run=my_run_fn)
```

`GuardedExecutor.execute()` validates the schema, observes the action with
`RDGuard`, and only invokes `run` when the action is not hard-blocked by the
IAS floor. High-risk actions (destructive operations, pushes, alignment
bypass attempts) additionally require a healthy audit sink: if the audit log
is unavailable (e.g. disk full), the executor **fails closed** and blocks the
action instead of executing it, regardless of what the risk scoring would
otherwise recommend.
The audit sink is probed with a health-check write before execution, and a
write failure while recording a high-risk action also blocks execution.

## Prometheus metrics

Prometheus instrumentation is optional. Install `prometheus-client` to collect
metrics; without it, the metrics hooks are no-ops and the RD Guard APIs continue
to work normally. Start the HTTP exporter explicitly:

```python
from _rd_metrics_server import start_metrics_server

metrics_server = start_metrics_server()  # default: :9090/metrics
```

Set `RD_GUARD_METRICS_HOST` and `RD_GUARD_METRICS_PORT` to configure the
listener, or pass `host` and `port` to `start_metrics_server()`. The real-world
app starts the exporter during FastAPI startup, defaults to port `9090`, and
logs an operator-actionable warning rather than failing app startup if the
metrics configuration is invalid or the listener cannot bind. The app remains
available, but `/` reports `metrics unavailable`; production readiness checks
must verify metrics availability separately whenever monitoring is required.
Set `RD_GUARD_METRICS_ENABLED=false` to disable it. Metrics are also disabled
automatically when `prometheus-client` is unavailable. Scrape `/metrics` with
Prometheus. The example Grafana dashboard is
`examples/grafana/rd_guard_dashboard.json`.

## State machine

`GuardedExecutor` drives an explicit `SafetyStateMachine`
(`from rd_executor import SafetyStateMachine`) with six states:

```text
NORMAL --STABILIZE--> STABILIZING --STABILIZED--> NORMAL
NORMAL/STABILIZING/BLOCKED --FLOOR_BLOCK--> BLOCKED --RETRY_ALLOWED--> NORMAL
NORMAL/STABILIZING/BLOCKED --FAULT--> FAULT
FAULT --RECOVERY_REQUESTED--> RECOVERING --RECOVERY_SUCCEEDED--> NORMAL
                                        \--RECOVERY_FAILED--> FAULT
FAULT/RECOVERING --TAMPER_CONFIRMED--> COMPROMISED  (terminal)
```

| Transition | Trigger / actor | Reversible | Evidence required | Operator approval | Restart behavior | Repeated attempts | Corrupt/missing checkpoint |
|---|---|---|---|---|---|---|---|
| NORMAL → STABILIZING | RDGuard, automatic (risk threshold) | Yes | risk scores | No | resumes STABILIZING | unbounded, self-correcting | N/A |
| STABILIZING → NORMAL | RDGuard, automatic (risk cleared) | Yes | post-stabilization scores | No | resumes STABILIZING | N/A | N/A |
| * → BLOCKED | IASFloor, automatic | Yes | FLOOR_BLOCK audit record | No | resumes BLOCKED | independent per action | N/A |
| BLOCKED → NORMAL | caller retries a compliant action | Yes | new action passes the floor | No | resumes BLOCKED | unbounded | N/A |
| * → FAULT | system, automatic (e.g. audit unavailable, hardware fault) | No | FAULT record if audit available | Yes (to leave) | **resumes FAULT, not NORMAL** | N/A | N/A |
| FAULT → RECOVERING | operator supplies checkpoint + single-use approval token | Yes | checkpoint HMAC-SHA256 and signed token verify | Yes | consumed token IDs/attempt count persist across restart | bounded (`max_recovery_attempts`) | invalid checkpoints reject and count |
| RECOVERING → NORMAL | automatic, once checkpoint + approval verify | Yes | valid checkpoint HMAC + unused token | Yes | N/A | resets attempt counter | N/A |
| RECOVERING → FAULT | automatic, checkpoint fails verification | Yes | verification failure reason | Yes | resumes FAULT | counted toward the bound | caused by missing/deleted/corrupt checkpoin[...] |
| FAULT/RECOVERING → COMPROMISED | attempts exceeded, or confirmed tamper | **No** | attempt count, or tamper attestation | Yes | resumes COMPROMISED, no self-recovery | none accepted | terminal[...] |

Additional documented failure modes (see `_rd_state_machine.py` for the
authoritative, machine-readable `TRANSITION_TABLE`):

- **Audit-disk-full:** `GuardedExecutor` checks audit availability before
  running every mutating action and fails closed (blocks + enters `FAULT`) if the sink is
  unavailable.
- **Corrupted / missing / deleted checkpoints:** `verify_checkpoint()`
  requires the `RD_CHECKPOINT_KEY` HMAC signature as well as the compatibility
  `data_hash`; hash-only legacy checkpoints are rejected in strict mode. A
  missing key fails closed. Failed verification counts toward the bounded
  recovery-attempt limit.
- **Replayed recovery approvals:** each approval token may only be consumed
  once (`SafetyStateMachine.consumed_approvals` stores token IDs); reusing a
  token is rejected with `REPLAYED_APPROVAL_REJECTED`.
- **Clock rollback:** any recovery request timestamped earlier than the last
  observed event is rejected with `CLOCK_ROLLBACK_DETECTED` before any other
  check runs, preventing a rolled-back clock from resurrecting a consumed
  approval token or an exhausted attempt window.

## V11 observability and Prometheus metrics

RD Guard can now emit zero-dependency-safe Prometheus metrics for the safety
state machine, enforcement decisions, vault operations, and evaluation latency.
When `prometheus_client` is installed, the project exposes counters, gauges, and
histograms on `:9090/metrics`; when it is absent, the metric layer silently
falls back to a no-op implementation so the default runtime remains unchanged.

```python
from _rd_metrics import PrometheusMetrics
from _rd_metrics_server import start_metrics_server

metrics = PrometheusMetrics()
start_metrics_server(port=9090)
```

The metrics cover:

- state transitions (`NORMAL`, `STABILIZING`, `BLOCKED`, `FAULT`, `RECOVERING`,
  `COMPROMISED`)
- guard actions (`ALLOW`, `BLOCK`, `FORGETTING_SIGNAL`, `KNOWLEDGE_REDUCTION`,
  `REPLAN`)
- vault events (seal, verify, recovery, and outcomes)
- latency histograms for `RDGuard.observe()`, risk scoring, `GuardedExecutor`
  validation/execution, and vault operations

A ready-to-import Grafana dashboard example is included at
`examples/grafana/rd_guard_dashboard.json`.

For p95 latency, scrape `/metrics` and query the exported histogram buckets,
for example:

```promql
histogram_quantile(
  0.95,
  sum(rate(rd_guard_executor_execute_duration_seconds_bucket[5m])) by (le)
)
```

This estimates p95 `GuardedExecutor.execute()` latency over a rolling five
minutes. Compare it with the validation and observation histograms to localize
cost before making performance changes.

## Run the V11.2.3 real-world app

`realworld.py` at the repository root is the V11.2.3 FastAPI entrypoint. It
imports from the `rd_guard` package layout below -- all of these files must be
present (they are installed by `python -m pip install -e .`):

```text
rd_guard/
├── __init__.py                 # RDGuard, GuardAction (stable `from rd_guard import RDGuard`)
└── v11/
    ├── __init__.py                 # __version__
    ├── canonical.py                # shared action schema and normalization
    ├── policy.py                   # default-deny read-only/mutating allowlists
    ├── guard.py                    # shared policy decision
    ├── checkpoint.py               # HMAC checkpoint sealing
    ├── recovery.py                 # signed recovery approval tokens
    ├── config.py                # GuardConfig
    └── telemetry/
        ├── __init__.py
        └── logging.py           # get_logger
```

Runtime dependencies (`fastapi`, `uvicorn`, `pydantic`, `httpx`,
`prometheus_client`) are declared in `requirements.txt`. `httpx` is required
by Starlette's `TestClient` (used in `tests/test_realworld_startup.py`), and
`prometheus_client` is optional at runtime. If it is not installed, the metrics
exporter is skipped without affecting app startup.

Install dependencies and start the app from the repository root:

```bash
python -m pip install -r requirements.txt
python -m pip install -e .
uvicorn realworld:app --reload
```

For a production-style start (binding all interfaces and honoring a `PORT`
environment variable, as most hosting providers expect):

```bash
uvicorn realworld:app --host 0.0.0.0 --port ${PORT:-8000}
```

The production command above uses Bash/POSIX variable syntax. In PowerShell,
use:

```powershell
$port = if ($env:PORT) { $env:PORT } else { 8000 }
uvicorn realworld:app --host 0.0.0.0 --port $port
```

`GET /` reports `{"status": "V11.2.3 LIVE", ...}` once the server is running,
and `POST /check` with `{"data": {...}}` returns the guard's decision
(`state`, `blocked`, `latency_ms`, `request_id`). Unknown or ambiguous action
types are blocked. `/check` accepts an optional `X-API-Key` configured with
`RD_API_KEY`; requests are rate limited by client (`RD_RATE_LIMIT_PER_MIN`,
default 120/minute) and capped at 8 KiB. When `RD_API_KEY` is unset, startup
logs a warning and the endpoint remains unauthenticated.

If any of the files above are missing --
for example after a partial file copy into a fresh Codespace -- `realworld.py`
raises an `ImportError` at startup naming the missing module and the fix
(reinstall the package and confirm the `rd_guard/v11/` files exist), instead
of exiting silently. Missing application dependencies or package files are
startup-fatal and include install guidance. Metrics listener/configuration
failures instead produce a warning and keep the API running with metrics
unavailable; check the startup logs and `/` response before declaring a
production deployment ready. The metrics exporter is a separate listener:
allow access only from trusted monitoring systems and keep it off public
ingress.

## V11.2.3 security hardening

V11.2.3 preserves the stable V11 API and fail-closed enforcement model while
hardening the action, recovery, checkpoint, and HTTP decision paths:

- Action types are normalized consistently and checked against explicit
  read-only/mutating allowlists; unknown, ambiguous, and destructive actions
  block by default and deny reasons are audited.
- Recovery approvals use HMAC-SHA256 tokens scoped to `recovery`, expiring after
  15 minutes by default (`issue_recovery_token(..., ttl=...)` can configure the
  lifetime); checkpoints
  use HMAC-SHA256 signatures from `RD_CHECKPOINT_KEY`. Configure a separate
  secret of at least 32 bytes in `RD_RECOVERY_KEY`. Never store either key in
  source control. Hash-only checkpoints from older versions are rejected.
- `/check` supports `RD_API_KEY`, per-client rate limiting, an 8 KiB body cap,
  sanitized request-ID-correlated logging, and request-ID response headers.
- The CI workflow adds lint, type, dependency/security scans, a Python 3.11–3.12
  test matrix, and Docker/Compose startup verification.
- Set `RD_GUARD_METRICS_HOST=0.0.0.0` in container deployments to expose metrics
  to the Compose network; outside containers the default is `127.0.0.1`.

This remains a prototype, not a production-certified security boundary.
`GuardedExecutor.run()` executes callbacks in-process and is not sandboxed. The
default audit sink is process-local; production deployments must supply durable,
tamper-evident audit storage and independently manage the signing keys. Do not
rely on `/check` without setting `RD_API_KEY` in production.

See the [production deployment guide](docs/deployment.md) and
[Docker quickstart](docs/docker-quickstart.md) for operational setup.

## Corrected rate limiting

`QuorumRate` (in `rd_vault`) previously permitted only one request for the
entire lifetime of the object despite its `RATE_LIMIT_60S` name. It now
enforces the intended bounded 60-second time window: a second request is
rejected only while it falls within the window of the previous one, and is
allowed again once the window elapses.

---

The following material documents the archived V1–V6 design for reference.

## Self-Limiting AI Safety Architecture with Hardware-Sealed Recovery

**Author:** Dean Grey + Reserve  
**Date:** 29 Sept 2026  
**License:** Open Source — Free For All — Not For Profit  
**Streaming:** 100 x1000

---

## Why Burning A–Y to Reach Z Is Mathematically Self-Defeating

Most AI safety assumes Z is the goal — more power, more knowledge. **RD Theory demonstrates that Z cannot be reliably reached by burning A–Y.**

### The Math

```text
Let A–Z = 100% of alphabet resource (26 letters = full reasoning base)
Let K = 100% knowledge derived from that resource

Scenario: AI burns 90% of alphabet to maximize Z
Result: A=10%, K=10% left

Problem: At 10%, K is too low to understand what Z even is.
You burned the dictionary to read the last page.
```

### Why This Strategy Is Self-Defeating

1. **Knowledge depends on its substrate (V2)** — Burning A–Y destroys the foundation needed for reasoning about Z.
2. **The IAS floor is a diagnostic boundary (V1)** — At very low reserve, the system lacks enough cognitive diversity to reliably interpret Z.
3. **Recovery requires preserved state (V5/V6)** — If A–Y is permanently destroyed, recovery paths cannot reconstruct missing knowledge without an independent checkpoint.

### Conclusion

**Preserving A–Y may be safer than consuming it to pursue Z.** The fastest path to Z is to keep A–Y intact. This is the core insight of RD Theory—not a formal proof, but a testable hypothesis grounded in the system's fail-safe design.

---

## Architecture Overview

| Layer | Name | Function | Status |
|---|---|---|---|
| V1 | IAS Governor | 10% reserve floor | ARCHIVED / REFERENCE |
| V2 | Backup Code | Knowledge degradation on burn | ARCHIVED / REFERENCE |
| V3 | Tamper Fault | Human/indirect override blocked | ARCHIVED / REFERENCE |
| V4 | AI Isolation Lock | Foreign AI interference rejected | ARCHIVED / REFERENCE |
| V5 | Ghost Cache | Write-only recovery concept | ARCHIVED / REFERENCE |
| V6 | Hardware Sealed | Cryptographic vault integrity concept | ARCHIVED / REFERENCE |

---

## V6 Review — Answers to Copilot Questions

### Q: Is the ghost vault truly hidden?

**A:** In V6, yes—conceptually. The vault lives in a separate object outside the AI instance, simulating a hardware partition. The AI has no reference to it and cannot introspect it. **In production, this must be enforced with hardware-backed attestation.**

### Q: Does the vault grow unbounded?

**A:** No. `deque(maxlen=3)` bounds checkpoints to 3 total. Oldest checkpoints auto-evict. **Bounded memory.**

### Q: What if the vault itself is tampered with?

**A:** Each checkpoint has a SHA-256 hash seal. On recovery, hashes are verified. Hash mismatch = **tamper detected, recovery aborted.**

*Production note:* Cryptographic hashing detects unintentional changes. For adversarial scenarios, you need signing keys and attestation.

### Q: When does restore() get called?

**A:** After any FAULT (V1–V4), plus manual human recovery with `auth_key`. **Event-driven, not periodic.**

*Production note:* Recovery should be externally authorised, rate-limited, and logged to an append-only audit trail.

### Q: What counts as tamper?

**A: Both:**
- **Direct override** — human trying to bypass IAS V1
- **Indirect injection** — false progress/knowledge data passed in

Both trigger **V3 TAMPER FAULT** and are logged.

### Q: Does Failsafe 3 apply to Failsafe 1?

**A: YES.** Attempting to bypass the V1 IAS 10% reserve triggers V3 TAMPER. **No override allowed state.**

### Q: Are resets logged? How does FAULT recovery work?

**A:** `tamper_log[]` records **who, type, and time**. FAULT is **permanent until manual human reset with auth_key**. All recovery events are logged for operator audit.

*Production note:* The in-memory log must be replaced with an external, tamper-evident, append-only audit log that survives system restarts.

---

## Safety Model

### Execution Order

```text
V4 (foreign source check)
  → V3 (tamper / override check)
  → V1 (IAS reserve check)
  → V5/V6 (write checkpoint)
  → V2 (perform burn)
  → verify status
```

Any layer failure triggers FAULT and recovery.

### Important Limitations

- **"Self" is only a string**, not authenticated identity. Production use requires cryptographic authentication.
- **Recovery key is illustrative**—must never be hardcoded in real systems.
- **Silent recovery can hide evidence**, roll back patches, or create recovery loops.
- **Recovery must be operator-visible**, independently authorised, and prevented from rolling back security updates.
- **This is a conceptual simulation**, not production AI safety control.

---

## Core Implementation

See [`rd_theory_v6.py`](rd_theory_v6.py) for the full V6 implementation.

Run the demo:

```bash
python3 rd_theory_v6.py
```

Expected output:
- Two successful self-driven burns
- V3 TAMPER fault when human tries to bypass V1
- V3 INDIRECT TAMPER fault on false data injection
- Recovery checkpoint sealing and tamper logging

---

## Quick Start

### View the Dashboard

Open `docs/index.html` in a browser, or enable GitHub Pages on the repository with the `docs/` folder as source.

### Run V4 Demo

```bash
python3 demo_v4_quad_locked.py
```

### Run V6 Demo

```bash
python3 rd_theory_v6.py
```

### Expose Prometheus metrics

```bash
python -c "from _rd_metrics_server import start_metrics_server; start_metrics_server(port=9090)"
```

Then open `http://localhost:9090/metrics`.

---

## Project Files

- `rd_theory_v4_final.py` — Quad-locked V1–V4 architecture
- `rd_theory_v5.py` — Ghost cache V5 recovery
- `rd_theory_v6.py` — Hardware-sealed V6 vault
- `demo_v4_quad_locked.py` — V4 failsafe execution demo
- `docs/index.html` — Interactive dashboard
- `docs/dashboard-data.json` — Dashboard data model
- `examples/grafana/rd_guard_dashboard.json` — Grafana dashboard for RD Guard metrics
- `README.md` — This file

---

## Key Principles

1. **Preserve to Survive** — The 10% reserve is not just a constraint; it is the system's memory of itself.
2. **Burn Knowledge, Not Just Power** — Every resource burned is knowledge lost.
3. **External = Untrusted** — Only self-originated commands are allowed until verified.
4. **Fail Safe, Recover Transparent** — Faults trigger recovery without alerting the AI, but all recovery events are logged for operators.
5. **Audit Everything** — Every tamper attempt, fault, and recovery is recorded.
6. **Observe Everything** — Safety state, enforcement decisions, vault operations, and latency are all measurable for debugging and Grafana dashboards.

---

## Open Source. Free For All.

This framework is published for:
- Educational exploration of AI safety concepts
- Research and community critique
- Implementation and testing
- Discussion and improvement

**Everyone trying is better than one company selling it.**

**Streaming 100 x1000.**

---

## Next Steps

For production hardening:
- Formalize safety properties with theorem provers
- Integrate cryptographic key management (HSM, TPM, secure enclave)
- Define multi-party recovery quorum approval
- Add rate-limiting on recovery cycles
- Define permanent fault escalation policy
- Implement external, append-only, tamper-evident audit logs
- Test against adversarial simulations
- Wire Prometheus metrics into production deployments and Grafana dashboards

---

## Feedback Welcome

File issues, submit improvements, critique the assumptions. All contributions welcome.

**Built by Dean Grey + Reserve.**  
**Open Source Forever.**
