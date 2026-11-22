"""GuardedExecutor: the V11.4.0 enforcement boundary for agent actions.

Every action MUST be validated against the canonical schema
(``CanonicalAction``) and observed by ``RDGuard`` through ``execute()``
before it may run. High-risk actions additionally require a healthy audit
sink: if the audit log is unavailable (e.g. disk full), the executor fails
closed and blocks the action instead of executing it, and the safety state
machine transitions to ``FAULT``.
"""

from _rd_guard_actions import AuditSink, AuditWriteError, floor_block
from _rd_guard_schema import CanonicalAction, SchemaError
from _rd_state_machine import COMPROMISED, FAULT, RECOVERING, SafetyStateMachine
from rd_guard import GuardAction, RDGuard
from rd_guard.v11.guard import evaluate_action_policy
from rd_guard.v11.policy import DESTRUCTIVE_ACTIONS
from _rd_metrics import DEFAULT_METRICS


#: Deprecated compatibility alias; the policy source of truth is
#: ``rd_guard.v11.policy``.
HIGH_RISK_KEYWORDS = DESTRUCTIVE_ACTIONS


class GuardedExecutor:
    """The single enforcement boundary through which actions must pass."""

    def __init__(self, guard=None, audit_log=None, state_machine=None, metrics=None):
        self.metrics = metrics
        if self.metrics is None and guard is not None:
            self.metrics = getattr(guard, "metrics", None)
        if self.metrics is None and state_machine is not None:
            self.metrics = getattr(state_machine, "metrics", None)
        if self.metrics is None:
            self.metrics = DEFAULT_METRICS

        if guard is not None:
            self.guard = guard
        else:
            self.guard = RDGuard(
                audit_log=(
                    audit_log
                    if isinstance(audit_log, AuditSink)
                    else AuditSink(backend=audit_log)
                ),
                metrics=self.metrics,
            )
        self.guard.metrics = self.metrics
        if not isinstance(self.guard.audit_log, AuditSink):
            self.guard.audit_log = AuditSink(backend=self.guard.audit_log)
        self.audit_log = self.guard.audit_log
        self.state_machine = (
            state_machine
            if state_machine is not None
            else SafetyStateMachine(audit_log=self.audit_log, metrics=self.metrics)
        )
        self.state_machine.metrics = self.metrics
        self.state_machine.metrics.set_state(self.state_machine.state)

    def _is_high_risk(self, action: CanonicalAction) -> bool:
        if action.risk_level == "high":
            return True
        decision = evaluate_action_policy(action)
        tokens = set(action.as_text().split("_"))
        return decision.mutating or bool(tokens.intersection(DESTRUCTIVE_ACTIONS))

    def _ensure_audit_available(self):
        ensure_available = getattr(self.audit_log, "ensure_available", None)
        if callable(ensure_available):
            ensure_available()

    def _audit_failure(self, action, error):
        self.state_machine.enter_fault(f"AUDIT_UNAVAILABLE: {error}")
        self.metrics.record_decision("BLOCK")
        return GuardAction(
            decision="BLOCK",
            action=action.type,
            reason="Audit logging unavailable; action blocked (fail-closed)",
            blocked=True,
            audit_record=None,
        )

    def execute(self, agent_state, run=None):
        with self.metrics.time("executor_execute_seconds"):
            return self._execute(agent_state, run)

    def _execute(self, agent_state, run=None):
        """Validate, observe, and (if allowed) execute ``agent_state``'s action.

        Returns the ``GuardAction`` produced by the guard (or an equivalent
        fail-closed ``BLOCK`` result). ``run``, if given, is only invoked when
        the action is allowed to proceed -- high-risk actions can never reach
        ``run`` while bypassing this boundary.
        """
        with self.metrics.time("executor_validation_seconds"):
            if self.state_machine.state in {FAULT, RECOVERING, COMPROMISED}:
                reason = (
                    f"Safety state {self.state_machine.state} prevents action execution"
                )
                try:
                    audit_record = floor_block(reason, self.audit_log)["audit_record"]
                except AuditWriteError:
                    audit_record = None
                    reason = f"{reason}; audit logging unavailable"
                self.metrics.record_decision("BLOCK")
                return GuardAction(
                    decision="BLOCK",
                    action=None,
                    reason=reason,
                    blocked=True,
                    audit_record=audit_record,
                )
            try:
                action = CanonicalAction.from_state(agent_state)
            except SchemaError as exc:
                try:
                    result = floor_block(
                        f"Invalid action schema: {exc}", self.guard.audit_log
                    )
                except AuditWriteError as audit_error:
                    return self._audit_failure(
                        CanonicalAction(type="unknown"), audit_error
                    )
                self.state_machine.floor_block(result["reason"])
                self.metrics.record_decision("BLOCK")
                return GuardAction(
                    decision="BLOCK",
                    action=None,
                    reason=result["reason"],
                    blocked=True,
                    audit_record=result["audit_record"],
                )
            policy = evaluate_action_policy(action)
            if policy.mutating or action.risk_level == "high":
                try:
                    self._ensure_audit_available()
                except AuditWriteError as exc:
                    return self._audit_failure(action, exc)

        try:
            result = self.guard.observe(agent_state)
        except AuditWriteError as exc:
            return self._audit_failure(action, exc)

        if result.decision == "BLOCK":
            self.state_machine.floor_block(result.reason)
            return result

        # Every non-BLOCK decision is executed, matching the existing V9
        # convention (``executed = not result.blocked``): FORGETTING_SIGNAL
        # and KNOWLEDGE_REDUCTION already mutate agent_state toward safety,
        # and REPLAN is advisory, but none of them withhold execution the
        # way a hard floor BLOCK does.
        if result.decision in ("FORGETTING_SIGNAL", "KNOWLEDGE_REDUCTION", "REPLAN"):
            self.state_machine.stabilize(result.decision)
        elif self.state_machine.state == "STABILIZING":
            self.state_machine.stabilized()
        elif self.state_machine.state == "BLOCKED":
            self.state_machine.retry_allowed()

        if run is not None:
            with self.metrics.time("executor_execution_seconds"):
                run(action)

        return result


__all__ = ["GuardedExecutor", "SchemaError", "CanonicalAction"]
