"""Durability tests for the SQLite-backed state store."""

import pytest

from rd_executor import FAULT, NORMAL, RecoveryError, SafetyStateMachine, seal_checkpoint
from rd_guard.v11.recovery import issue_recovery_token
from rd_guard.v11.store import SQLiteStateStore


def test_state_and_replay_protection_survive_restart(tmp_path):
    path = str(tmp_path / "state.db")
    checkpoint = seal_checkpoint({"a": 1})
    token = issue_recovery_token("op", ttl=900, now=100.0)

    sm = SafetyStateMachine(audit_log=[], store=SQLiteStateStore(path))
    sm.enter_fault("fault")
    sm.request_recovery(checkpoint, token, now=100.0)
    sm.enter_fault("again")
    sm.store.close()

    restarted = SafetyStateMachine(audit_log=[], store=SQLiteStateStore(path))
    assert restarted.state == FAULT
    assert restarted.last_event_time == 100.0
    with pytest.raises(RecoveryError, match="REPLAYED_APPROVAL_REJECTED"):
        restarted.request_recovery(checkpoint, token, now=200.0)


def test_second_instance_cannot_replay_token(tmp_path):
    path = str(tmp_path / "state.db")
    store_a, store_b = SQLiteStateStore(path), SQLiteStateStore(path)
    assert store_a.consume_approval("jti") is True
    assert store_b.consume_approval("jti") is False


def test_fresh_store_starts_normal(tmp_path):
    sm = SafetyStateMachine(audit_log=[], store=SQLiteStateStore(str(tmp_path / "s.db")))
    assert sm.state == NORMAL
