from pathlib import Path

import _rd_guard_executor
import rd_guard.v11 as v11
from rd_guard.v11 import policy

ROOT = Path(__file__).resolve().parent.parent


def test_version_is_consistent():
    assert v11.__version__ == "11.4.0"
    assert 'version = "11.4.0"' in (ROOT / "pyproject.toml").read_text()
    for name in ("realworld.py", "Dockerfile", "docker-compose.yml"):
        text = (ROOT / name).read_text()
        assert "11.2.2" not in text, name
    assert "V11.4.0 LIVE" in (ROOT / "realworld.py").read_text()


def test_high_risk_keywords_is_deprecated_alias_of_policy():
    assert _rd_guard_executor.HIGH_RISK_KEYWORDS is policy.DESTRUCTIVE_ACTIONS
