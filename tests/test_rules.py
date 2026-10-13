from pathlib import Path

import pytest

from solidity_guard.engine import scan
from solidity_guard.models import Confidence, Finding, Severity, Status


def _scan(path: Path):
    return scan(path.read_text(encoding="utf-8"))


# --- Positive: each rule fires on its vulnerable fixture ---

@pytest.mark.parametrize(
    "fixture,expected_rule",
    [
        ("reentrancy.sol", "SG-001"),
        ("tx_origin.sol", "SG-002"),
        ("unchecked_call.sol", "SG-003"),
        ("old_pragma.sol", "SG-004"),
    ],
)
def test_rule_fires_on_vulnerable_fixture(vulnerable_dir, fixture, expected_rule):
    result = _scan(vulnerable_dir / fixture)
    assert result.status == Status.COMPLETED_WITH_FINDINGS
    assert expected_rule in {f.rule_id for f in result.findings}


# --- Negative: safe fixtures produce no findings ---

@pytest.mark.parametrize("fixture", ["clean.sol", "guarded.sol"])
def test_safe_fixture_produces_no_findings(safe_dir, fixture):
    result = _scan(safe_dir / fixture)
    assert result.status == Status.COMPLETED_NO_FINDINGS
    assert result.findings == []


# --- Finding structure ---

def test_finding_has_all_required_fields(vulnerable_dir):
    result = _scan(vulnerable_dir / "reentrancy.sol")
    assert result.findings, "expected at least one finding"
    f = result.findings[0]
    assert isinstance(f, Finding)
    assert f.rule_id.startswith("SG-")
    assert isinstance(f.title, str) and f.title
    assert isinstance(f.severity, Severity)
    assert isinstance(f.confidence, Confidence)
    assert isinstance(f.line, int) and f.line > 0
    assert isinstance(f.snippet, str) and f.snippet
    assert isinstance(f.description, str) and f.description
    assert isinstance(f.rationale, str) and f.rationale
    assert isinstance(f.remediation, str) and f.remediation


def test_finding_to_dict_shape(vulnerable_dir):
    result = _scan(vulnerable_dir / "reentrancy.sol")
    d = result.findings[0].to_dict()
    expected_keys = {
        "rule_id", "title", "severity", "confidence",
        "line", "snippet", "description", "rationale", "remediation",
    }
    assert set(d.keys()) == expected_keys
    assert d["severity"] in {s.value for s in Severity}
    assert d["confidence"] in {c.value for c in Confidence}


# --- Determinism ---

def test_findings_order_deterministic(vulnerable_dir):
    r1 = _scan(vulnerable_dir / "reentrancy.sol")
    r2 = _scan(vulnerable_dir / "reentrancy.sol")
    assert [f.to_dict() for f in r1.findings] == [f.to_dict() for f in r2.findings]
