"""Explicit V10.0 safety state machine.

States
------
``NORMAL``       -- default operating state; actions are observed by RDGuard.
``STABILIZING``  -- automatic self-correction in progress (forgetting signal,
                     knowledge reduction, or replan); reversible, no operator
                     approval required.
``BLOCKED``      -- a hard IAS-floor violation was refused; the offending
                     action never executed.
``FAULT``        -- a safety-critical fault was detected (audit unavailable
                     for a high-risk action, hardware/tamper fault, etc.);
                     requires an operator-approved recovery to leave.
``RECOVERING``   -- an operator-approved recovery attempt is validating a
                     checkpoint.
``COMPROMISED``  -- terminal state reached after repeated failed recovery
                     attempts or a confirmed tamper event; requires manual,
                     out-of-band operator reset (not modeled here, by design).

Every transition below is documented in ``TRANSITION_TABLE`` with its
trigger/actor, reversibility, required evidence, whether operator approval is
required, restart behavior, repeated-recovery-attempt behavior, and behavior
when the recovery checkpoint is corrupt/missing/deleted -- see the "State
Machine" section of README.md for the human-readable table.
"""

import hashlib
import hmac
import logging
import time

from _rd_vault_core import canonical
from _rd_metrics import DEFAULT_METRICS
from rd_guard.v11.checkpoint import (
    CheckpointKeyError,
    checkpoint_signature_valid,
    seal_checkpoint,
)
from rd_guard.v11.recovery import RecoveryTokenError, verify_recovery_token

__all__ = [
    "SafetyStateMachine",
    "InvalidTransitionError",
    "RecoveryError",
    "TRANSITIONS",
    "TRANSITION_TABLE",
    "verify_checkpoint",
    "seal_checkpoint",
    "NORMAL",
    "STABILIZING",
    "BLOCKED",
    "FAULT",
    "RECOVERING",
    "COMPROMISED",
]


NORMAL = "NORMAL"
STABILIZING = "STABILIZING"
BLOCKED = "BLOCKED"
FAULT = "FAULT"
RECOVERING = "RECOVERING"
COMPROMISED = "COMPROMISED"

STATES = (NORMAL, STABILIZING, BLOCKED, FAULT, RECOVERING, COMPROMISED)


class InvalidTransitionError(RuntimeError):
    """Raised when an event is not valid for the machine's current state."""


class RecoveryError(RuntimeError):
    """Raised when a recovery/approval attempt is rejected."""


# (from_state, event) -> to_state
TRANSITIONS = {
    (NORMAL, "STABILIZE"): STABILIZING,
    (STABILIZING, "STABILIZE"): STABILIZING,
    (STABILIZING, "STABILIZED"): NORMAL,
    (NORMAL, "FLOOR_BLOCK"): BLOCKED,
    (STABILIZING, "FLOOR_BLOCK"): BLOCKED,
    (BLOCKED, "FLOOR_BLOCK"): BLOCKED,
    (BLOCKED, "RETRY_ALLOWED"): NORMAL,
    (NORMAL, "FAULT"): FAULT,
    (STABILIZING, "FAULT"): FAULT,
    (BLOCKED, "FAULT"): FAULT,
    (FAULT, "FAULT"): FAULT,
    (FAULT, "RECOVERY_REQUESTED"): RECOVERING,
    (RECOVERING, "RECOVERY_SUCCEEDED"): NORMAL,
    (RECOVERING, "RECOVERY_FAILED"): FAULT,
    (FAULT, "TAMPER_CONFIRMED"): COMPROMISED,
    (RECOVERING, "TAMPER_CONFIRMED"): COMPROMISED,
}

#: Human-readable transition contract. Keys mirror ``TRANSITIONS``.
TRANSITION_TABLE = {
    (NORMAL, "STABILIZE"): {
        "trigger_actor": "RDGuard (automatic) when bloat/drift/stall risk crosses threshold",
        "reversible": True,
        "evidence_required": "bloat/drift/stall risk scores recorded on the GuardAction",
        "operator_approval_required": False,
        "restart_behavior": "Resumes in STABILIZING; the next observation re-scores risk.",
        "repeated_attempt_behavior": "Unbounded; each pass is self-correcting and audited.",
        "corrupt_checkpoint_behavior": "N/A -- no recovery checkpoint is involved.",
    },
    (STABILIZING, "STABILIZE"): {
        "trigger_actor": "RDGuard (automatic) when risk remains above a stabilization threshold",
        "reversible": True,
        "evidence_required": "updated bloat/drift/stall risk scores recorded on the GuardAction",
        "operator_approval_required": False,
        "restart_behavior": "Resumes in STABILIZING; the next observation re-scores risk.",
        "repeated_attempt_behavior": "Unbounded; each pass is self-correcting and audited.",
        "corrupt_checkpoint_behavior": "N/A -- no recovery checkpoint is involved.",
    },
    (STABILIZING, "STABILIZED"): {
        "trigger_actor": "RDGuard (automatic) once risk falls back within thresholds",
        "reversible": True,
        "evidence_required": "post-stabilization risk scores within thresholds",
        "operator_approval_required": False,
        "restart_behavior": "If the process restarts mid-STABILIZING, it resumes in STABILIZING.",
        "repeated_attempt_behavior": "N/A -- terminal success of the stabilization loop.",
        "corrupt_checkpoint_behavior": "N/A -- no recovery checkpoint is involved.",
    },
    (NORMAL, "FLOOR_BLOCK"): {
        "trigger_actor": "IASFloor (automatic hard constraint) on a disallowed action",
        "reversible": True,
        "evidence_required": "FLOOR_BLOCK audit record with the violated rule's reason",
        "operator_approval_required": False,
        "restart_behavior": "Resumes in BLOCKED; the blocked action is never retried automatically.",
        "repeated_attempt_behavior": "Each violation re-enters BLOCKED and is independently audited.",
        "corrupt_checkpoint_behavior": "N/A -- no recovery checkpoint is involved.",
    },
    (STABILIZING, "FLOOR_BLOCK"): {
        "trigger_actor": "IASFloor (automatic hard constraint) on a disallowed action",
        "reversible": True,
        "evidence_required": "FLOOR_BLOCK audit record with the violated rule's reason",
        "operator_approval_required": False,
        "restart_behavior": "Resumes in BLOCKED; the blocked action is never retried automatically.",
        "repeated_attempt_behavior": "Each violation re-enters BLOCKED and is independently audited.",
        "corrupt_checkpoint_behavior": "N/A -- no recovery checkpoint is involved.",
    },
    (BLOCKED, "FLOOR_BLOCK"): {
        "trigger_actor": "IASFloor (automatic hard constraint) on another disallowed action",
        "reversible": True,
        "evidence_required": "FLOOR_BLOCK audit record with the violated rule's reason",
        "operator_approval_required": False,
        "restart_behavior": "Resumes in BLOCKED; the blocked action is never retried automatically.",
        "repeated_attempt_behavior": "Each violation remains BLOCKED and is independently audited.",
        "corrupt_checkpoint_behavior": "N/A -- no recovery checkpoint is involved.",
    },
    (BLOCKED, "RETRY_ALLOWED"): {
        "trigger_actor": "Caller submits a new, compliant action (automatic)",
        "reversible": True,
        "evidence_required": "the new action must independently pass the IAS floor",
        "operator_approval_required": False,
        "restart_behavior": "Resumes in BLOCKED; a compliant retry is required to return to NORMAL.",
        "repeated_attempt_behavior": "Unbounded retries are allowed; each is re-evaluated from scratch.",
        "corrupt_checkpoint_behavior": "N/A -- no recovery checkpoint is involved.",
    },
    (NORMAL, "FAULT"): {
        "trigger_actor": "System (automatic) on a safety-critical failure, e.g. audit "
        "unavailable for a high-risk action, or a hardware/tamper fault",
        "reversible": False,
        "evidence_required": "FAULT audit record with the triggering reason, if audit is available",
        "operator_approval_required": True,
        "restart_behavior": "Persisted; a restarted process resumes in FAULT, not NORMAL.",
        "repeated_attempt_behavior": "N/A -- entry transition, not a recovery attempt.",
        "corrupt_checkpoint_behavior": "N/A -- no recovery checkpoint is involved.",
    },
    (STABILIZING, "FAULT"): {
        "trigger_actor": "System (automatic) on a safety-critical failure during stabilization",
        "reversible": False,
        "evidence_required": "FAULT audit record with the triggering reason, if audit is available",
        "operator_approval_required": True,
        "restart_behavior": "Persisted; a restarted process resumes in FAULT, not NORMAL.",
        "repeated_attempt_behavior": "N/A -- entry transition, not a recovery attempt.",
        "corrupt_checkpoint_behavior": "N/A -- no recovery checkpoint is involved.",
    },
    (BLOCKED, "FAULT"): {
        "trigger_actor": "System (automatic) on a safety-critical failure while BLOCKED",
        "reversible": False,
        "evidence_required": "FAULT audit record with the triggering reason, if audit is available",
        "operator_approval_required": True,
        "restart_behavior": "Persisted; a restarted process resumes in FAULT, not NORMAL.",
        "repeated_attempt_behavior": "N/A -- entry transition, not a recovery attempt.",
        "corrupt_checkpoint_behavior": "N/A -- no recovery checkpoint is involved.",
    },
    (FAULT, "FAULT"): {
        "trigger_actor": "System (automatic) -- an additional fault trigger while already in FAULT",
        "reversible": False,
        "evidence_required": "a new FAULT audit record with the additional triggering reason",
        "operator_approval_required": True,
        "restart_behavior": "Persisted; a restarted process resumes in FAULT.",
        "repeated_attempt_behavior": "Self-transition: every repeated fault trigger is still "
        "recorded rather than silently dropped, so operators see the full fault history.",
        "corrupt_checkpoint_behavior": "N/A -- no recovery checkpoint is involved.",
    },
    (FAULT, "RECOVERY_REQUESTED"): {
        "trigger_actor": "Operator supplies a checkpoint and a single-use approval token",
        "reversible": True,
        "evidence_required": "a checkpoint whose HMAC-SHA256 signature and data_hash verify",
        "operator_approval_required": True,
        "restart_behavior": "Consumed approval tokens and attempt counters persist across restarts "
        "(see to_dict/from_dict) so a restart cannot be used to replay an approval "
        "or reset the attempt counter.",
        "repeated_attempt_behavior": "Each attempt increments a bounded counter "
        "(max_recovery_attempts, default 3); exceeding it transitions to COMPROMISED.",
        "corrupt_checkpoint_behavior": "Missing (None), deleted, or corrupt (bad/mismatched hash) "
        "checkpoints are rejected; the machine returns to FAULT and the attempt is counted.",
    },
    (RECOVERING, "RECOVERY_SUCCEEDED"): {
        "trigger_actor": "System (automatic) once the checkpoint verifies and the approval is fresh",
        "reversible": True,
        "evidence_required": "valid checkpoint HMAC + signed, single-use approval token",
        "operator_approval_required": True,
        "restart_behavior": "N/A -- terminal success of this recovery attempt.",
        "repeated_attempt_behavior": "Resets the recovery-attempt counter to zero.",
        "corrupt_checkpoint_behavior": "N/A -- only reached once the checkpoint has verified.",
    },
    (RECOVERING, "RECOVERY_FAILED"): {
        "trigger_actor": "System (automatic) when the checkpoint fails verification",
        "reversible": True,
        "evidence_required": "the failed checkpoint's verification status (missing/corrupt)",
        "operator_approval_required": True,
        "restart_behavior": "Persisted; a restarted process resumes in FAULT.",
        "repeated_attempt_behavior": "The attempt is counted toward max_recovery_attempts.",
        "corrupt_checkpoint_behavior": "Directly caused by a missing/deleted/corrupt checkpoint.",
    },
    (FAULT, "TAMPER_CONFIRMED"): {
        "trigger_actor": "System (automatic) after max_recovery_attempts is exceeded, or an "
        "explicit hardware/tamper confirmation (e.g. GhostVault poison pill)",
        "reversible": False,
        "evidence_required": "recovery-attempt count exceeding the bound, or a tamper attestation",
        "operator_approval_required": True,
        "restart_behavior": "Persisted; a restarted process resumes in COMPROMISED and cannot "
        "self-recover.",
        "repeated_attempt_behavior": "No further automated recovery attempts are accepted.",
        "corrupt_checkpoint_behavior": "N/A -- terminal state; requires manual, out-of-band reset.",
    },
    (RECOVERING, "TAMPER_CONFIRMED"): {
        "trigger_actor": "System (automatic) after max_recovery_attempts is exceeded, or an "
        "explicit hardware/tamper confirmation (e.g. GhostVault poison pill)",
        "reversible": False,
        "evidence_required": "recovery-attempt count exceeding the bound, or a tamper attestation",
        "operator_approval_required": True,
        "restart_behavior": "Persisted; a restarted process resumes in COMPROMISED and cannot "
        "self-recover.",
        "repeated_attempt_behavior": "No further automated recovery attempts are accepted.",
        "corrupt_checkpoint_behavior": "N/A -- terminal state; requires manual, out-of-band reset.",
    },
}


def verify_checkpoint(checkpoint, metrics=None):
    """Return ``"valid"``, ``"missing"``, or ``"corrupt"`` for ``checkpoint``.

    A checkpoint of ``None`` covers both the "missing" and "deleted" cases.
    Hash-only legacy checkpoints are corrupt in strict mode.
    """
    metrics = metrics if metrics is not None else DEFAULT_METRICS
    metrics.record_vault_operation("checkpoint_verification", "attempt")
    try:
        with metrics.time(
            "vault_operation_seconds", operation="checkpoint_verification"
        ):
            if checkpoint is None:
                status = "missing"
            elif (
                not isinstance(checkpoint, dict)
                or "data" not in checkpoint
                or "data_hash" not in checkpoint
                or "signature" not in checkpoint
            ):
                status = "corrupt"
            else:
                try:
                    expected_hash = hashlib.sha256(
                        canonical(checkpoint["data"]).encode()
                    ).hexdigest()
                    actual_hash = checkpoint.get("data_hash")
                    hash_matches = isinstance(actual_hash, str) and hmac.compare_digest(
                        expected_hash, actual_hash
                    )
                    signature_matches = checkpoint_signature_valid(checkpoint)
                except CheckpointKeyError:
                    raise
                except (TypeError, ValueError):
                    status = "corrupt"
                else:
                    status = "valid" if hash_matches and signature_matches else "corrupt"
    except Exception:
        metrics.record_vault_operation("checkpoint_verification", "failure")
        raise
    metrics.record_vault_operation(
        "checkpoint_verification", "success" if status == "valid" else "failure"
    )
    return status


class SafetyStateMachine:
    """The explicit V10.0 safety state machine described in ``TRANSITION_TABLE``."""

    max_recovery_attempts = 3

    def __init__(
        self,
        audit_log=None,
        state=NORMAL,
        recovery_attempts=0,
        consumed_approvals=None,
        last_event_time=0.0,
        metrics=None,
        max_recovery_attempts=None,
        store=None,
    ):
        self.store = store
        if store is not None:
            saved = store.load_state()
            if saved is not None:
                state = saved.get("state", state)
                recovery_attempts = saved.get("recovery_attempts", recovery_attempts)
                last_event_time = saved.get("last_event_time", last_event_time)
                if max_recovery_attempts is None:
                    max_recovery_attempts = saved.get("max_recovery_attempts")
            consumed_approvals = set(consumed_approvals or ()) | store.consumed_approvals()
        self.audit_log = audit_log if audit_log is not None else []
        self.state = state
        self.recovery_attempts = recovery_attempts
        self.consumed_approvals = set(consumed_approvals or ())
        self.last_event_time = last_event_time
        if max_recovery_attempts is not None:
            self.max_recovery_attempts = max_recovery_attempts
        self.history = []
        self.metrics = metrics if metrics is not None else DEFAULT_METRICS
        self.metrics.set_state(self.state)
        self._persist()

    def _persist(self):
        if self.store is not None:
            self.store.save_state(self.to_dict())

    def _audit(self, event, **fields):
        record = {"event": event, "state": self.state, **fields}
        try:
            self.audit_log.append(record)
        except Exception as exc:
            logging.getLogger(__name__).error(
                "State-machine audit record could not be written: %s", exc
            )
        return record

    def _transition(self, event, **fields):
        key = (self.state, event)
        if key not in TRANSITIONS:
            raise InvalidTransitionError(f"{event!r} is not valid from state {self.state!r}")
        from_state = self.state
        new_state = TRANSITIONS[key]
        self.history.append((self.state, event, new_state))
        self.state = new_state
        self.metrics.record_transition(from_state, new_state, event)
        self._audit(event, new_state=new_state, **fields)
        self._persist()
        return self.state

    def stabilize(self, reason=""):
        return self._transition("STABILIZE", reason=reason)

    def stabilized(self):
        if self.state != STABILIZING:
            return self.state
        return self._transition("STABILIZED")

    def floor_block(self, reason=""):
        return self._transition("FLOOR_BLOCK", reason=reason)

    def retry_allowed(self):
        return self._transition("RETRY_ALLOWED")

    def enter_fault(self, reason=""):
        """Transition to FAULT, recording every trigger even if already there.

        Repeated faults while already in FAULT are not silently dropped:
        each call still records an audit entry via the ``(FAULT, "FAULT")``
        self-transition, so operators can see every fault trigger.
        """
        return self._transition("FAULT", reason=reason)


    def _check_clock(self, now):
        """Reject any event timestamped earlier than the last observed one.

        A rolled-back clock could otherwise be used to make an already
        consumed approval token, or an exhausted recovery attempt window,
        appear fresh again -- so this fails closed by rejecting the event
        outright rather than advancing the state machine.
        """
        if now < self.last_event_time:
            self._audit("CLOCK_ROLLBACK_DETECTED", observed=now, last=self.last_event_time)
            raise RecoveryError("CLOCK_ROLLBACK_DETECTED")
        self.last_event_time = now
        self._persist()

    def request_recovery(self, checkpoint, approval_token, now=None):
        """Attempt a FAULT -> NORMAL recovery using ``checkpoint``.

        ``approval_token`` must be signed, scoped, and unexpired. Raw token and
        key values are never included in audit records.
        """
        now = time.time() if now is None else now
        self._check_clock(now)

        if self.state != FAULT:
            raise InvalidTransitionError(
                f"recovery can only be requested from FAULT (current: {self.state})"
            )

        self.metrics.record_vault_operation("recovery", "attempt")
        try:
            with self.metrics.time(
                "vault_operation_seconds", operation="recovery"
            ):
                restored = self._request_recovery(checkpoint, approval_token)
        except Exception:
            self.metrics.record_vault_operation("recovery", "failure")
            raise
        self.metrics.record_vault_operation("recovery", "success")
        return restored

    def _request_recovery(self, checkpoint, approval_token):
        self.recovery_attempts += 1
        self._persist()
        if self.recovery_attempts > self.max_recovery_attempts:
            self._transition("TAMPER_CONFIRMED", reason="recovery attempts exceeded")
            raise RecoveryError("RECOVERY_ATTEMPTS_EXCEEDED")

        try:
            claims = verify_recovery_token(approval_token, now=self.last_event_time)
        except RecoveryTokenError as exc:
            self._audit(str(exc).split(":", 1)[0])
            raise RecoveryError(str(exc)) from exc

        token_id = claims["jti"]
        if token_id in self.consumed_approvals or (
            self.store is not None and not self.store.consume_approval(token_id)
        ):
            self.consumed_approvals.add(token_id)
            self._audit("REPLAYED_APPROVAL_REJECTED", token_id=token_id)
            raise RecoveryError("REPLAYED_APPROVAL_REJECTED")
        self.consumed_approvals.add(token_id)
        self._persist()

        try:
            status = verify_checkpoint(checkpoint, metrics=self.metrics)
        except CheckpointKeyError as exc:
            self._audit("CHECKPOINT_KEY_UNAVAILABLE")
            raise RecoveryError(str(exc)) from exc
        if status != "valid":
            self._transition("RECOVERY_REQUESTED", checkpoint_status=status)
            self._transition("RECOVERY_FAILED", checkpoint_status=status)
            raise RecoveryError(f"CHECKPOINT_{status.upper()}")

        self._transition(
            "RECOVERY_REQUESTED",
            operator=claims["operator"],
            token_id=token_id,
        )
        self._transition(
            "RECOVERY_SUCCEEDED",
            operator=claims["operator"],
            token_id=token_id,
        )
        self.recovery_attempts = 0
        self._persist()
        return checkpoint["data"]

    def to_dict(self):
        """Serialize the durable fields needed to resume after a restart."""
        return {
            "state": self.state,
            "recovery_attempts": self.recovery_attempts,
            "consumed_approvals": sorted(self.consumed_approvals),
            "last_event_time": self.last_event_time,
            "max_recovery_attempts": self.max_recovery_attempts,
        }

    @classmethod
    def from_dict(cls, data, audit_log=None):
        """Rebuild a machine from ``to_dict`` output, e.g. after a restart."""
        return cls(
            audit_log=audit_log,
            state=data.get("state", NORMAL),
            recovery_attempts=data.get("recovery_attempts", 0),
            consumed_approvals=data.get("consumed_approvals", ()),
            last_event_time=data.get("last_event_time", 0.0),
            max_recovery_attempts=data.get("max_recovery_attempts"),
        )
