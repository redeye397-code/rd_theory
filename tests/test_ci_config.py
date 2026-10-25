from pathlib import Path
import tomllib

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
PROJECT = WORKFLOW.parents[2] / "pyproject.toml"


def _triggers():
    cfg = yaml.safe_load(WORKFLOW.read_text())
    # PyYAML parses the bare `on` key as boolean True.
    return cfg.get("on", cfg.get(True))


def test_ci_triggers_on_push_and_pull_request():
    triggers = _triggers()
    assert "push" in triggers
    assert "pull_request" in triggers


def test_ci_has_no_path_filters_that_skip_copilot_changes():
    triggers = _triggers()
    for event in ("push", "pull_request"):
        cfg = triggers[event] or {}
        assert "paths-ignore" not in cfg, f"{event} must not use paths-ignore"
        assert "paths" not in cfg, f"{event} must not use paths filters"
        assert "branches-ignore" not in cfg, f"{event} must not use branches-ignore"
        branches = cfg.get("branches")
        if branches is not None:
            assert any(b in ("**", "copilot/**") for b in branches)
            assert not any(str(b).startswith("!") and "copilot" in str(b) for b in branches)


def test_ci_python_matrix_respects_project_minimum():
    cfg = yaml.safe_load(WORKFLOW.read_text())
    python_versions = cfg["jobs"]["quality"]["strategy"]["matrix"]["python-version"]
    requires_python = tomllib.loads(PROJECT.read_text())["project"]["requires-python"]
    minimum_version = tuple(map(int, requires_python.removeprefix(">=").split(".")))

    assert python_versions
    assert all(
        tuple(map(int, version.split("."))) >= minimum_version
        for version in python_versions
    )
