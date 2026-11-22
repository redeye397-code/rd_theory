import base64

import pytest

from rd_guard.v11.recovery import (
    RecoveryTokenError,
    issue_recovery_token,
    verify_recovery_token,
)

KEY = "k" * 40
NOW = 1_000_000.0


def _token():
    return issue_recovery_token("alice", key=KEY, now=NOW)


def test_missing_key_fails_before_hmac(monkeypatch):
    token = _token()
    monkeypatch.delenv("RD_RECOVERY_KEY", raising=False)

    def boom(*a, **k):
        raise AssertionError("HMAC computed before key validation")

    monkeypatch.setattr("rd_guard.v11.recovery.hmac.new", boom)
    with pytest.raises(RecoveryTokenError) as exc:
        verify_recovery_token(token, now=NOW)
    assert "RD_RECOVERY_KEY is missing" in str(exc.value)
    assert "INVALID_APPROVAL_SIGNATURE" not in str(exc.value)


def test_missing_key_error_does_not_leak_secrets(monkeypatch):
    token = _token()
    monkeypatch.delenv("RD_RECOVERY_KEY", raising=False)
    with pytest.raises(RecoveryTokenError) as exc:
        verify_recovery_token(token, now=NOW)
    assert KEY not in str(exc.value)
    assert token not in str(exc.value)


def test_valid_token_verifies_with_env_key(monkeypatch):
    monkeypatch.setenv("RD_RECOVERY_KEY", KEY)
    assert verify_recovery_token(_token(), now=NOW + 1)["operator"] == "alice"


def test_wrong_key_rejected():
    with pytest.raises(RecoveryTokenError, match="INVALID_APPROVAL_SIGNATURE"):
        verify_recovery_token(_token(), now=NOW, key="z" * 40)


def test_non_canonical_signature_tail_rejected():
    encoded, sig = _token().split(".")
    original = base64.urlsafe_b64decode(sig + "=")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    checked = 0
    for ch in alphabet:
        if ch == sig[-1]:
            continue
        tampered = sig[:-1] + ch
        if base64.urlsafe_b64decode(tampered + "=") != original:
            continue
        checked += 1
        with pytest.raises(RecoveryTokenError, match="INVALID_APPROVAL_SIGNATURE"):
            verify_recovery_token(f"{encoded}.{tampered}", now=NOW, key=KEY)
    assert checked == 3  # 2 unused bits in final char


def test_padded_signature_rejected():
    encoded, sig = _token().split(".")
    with pytest.raises(RecoveryTokenError, match="INVALID_APPROVAL_SIGNATURE"):
        verify_recovery_token(f"{encoded}.{sig}=", now=NOW, key=KEY)
