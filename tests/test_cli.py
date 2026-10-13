import json
from pathlib import Path

import pytest

from solidity_guard.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


# --- --help / --version ---

def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "solidity-guard" in capsys.readouterr().out


def test_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    assert "usage:" in capsys.readouterr().out.lower()


# --- Usage errors ---

def test_nonexistent_path(tmp_path, capsys):
    code = main([str(tmp_path / "nope")])
    assert code == 2
    assert "does not exist" in capsys.readouterr().err


def test_directory_without_sol(tmp_path, capsys):
    code = main([str(tmp_path)])
    assert code == 2
    assert "no .sol files" in capsys.readouterr().err


# --- Real integration ---

def test_single_vulnerable_file(capsys):
    code = main([str(FIXTURES / "vulnerable" / "reentrancy.sol")])
    assert code == 0
    out = capsys.readouterr().out
    assert "SG-001" in out
    assert "1 issue" in out


def test_safe_file(capsys):
    code = main([str(FIXTURES / "safe" / "clean.sol")])
    assert code == 0
    assert "no issues found" in capsys.readouterr().out.lower()


def test_directory_scan(capsys):
    code = main([str(FIXTURES / "vulnerable")])
    assert code == 0
    out = capsys.readouterr().out
    for rule in ("SG-001", "SG-002", "SG-003", "SG-004"):
        assert rule in out


def test_json_output_shape(capsys):
    code = main([
        str(FIXTURES / "vulnerable" / "reentrancy.sol"),
        "--format", "json",
    ])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert "scanner_version" in payload
    assert len(payload["results"]) == 1
    r0 = payload["results"][0]
    assert r0["status"] == "completed_with_findings"
    assert r0["path"].endswith("reentrancy.sol")
    assert r0["findings"][0]["rule_id"] == "SG-001"


# --- --fail-on ---

def test_fail_on_high_with_high_finding(capsys):
    code = main([
        str(FIXTURES / "vulnerable" / "reentrancy.sol"),
        "--fail-on", "high",
    ])
    assert code == 1


def test_fail_on_critical_no_critical_finding(capsys):
    code = main([
        str(FIXTURES / "vulnerable" / "unchecked_call.sol"),
        "--fail-on", "critical",
    ])
    assert code == 0


def test_fail_on_high_on_safe(capsys):
    code = main([
        str(FIXTURES / "safe" / "clean.sol"),
        "--fail-on", "high",
    ])
    assert code == 0


# --- Failure paths ---

def test_invalid_solidity_exits_3(tmp_path, capsys):
    bad = tmp_path / "bad.sol"
    bad.write_text("this is not solidity")
    code = main([str(bad)])
    assert code == 3
    assert "analysis failed" in capsys.readouterr().out.lower()


def test_empty_file_exits_3(tmp_path, capsys):
    empty = tmp_path / "empty.sol"
    empty.write_text("   \n")
    code = main([str(empty)])
    assert code == 3
