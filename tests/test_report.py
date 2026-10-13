from pathlib import Path

from solidity_guard.engine import scan
from solidity_guard.models import ScanResult, Status
from solidity_guard.report import to_json, to_text


def _scan(path: Path):
    return scan(path.read_text(encoding="utf-8"))


def test_report_shows_finding_count(vulnerable_dir):
    text = to_text(_scan(vulnerable_dir / "reentrancy.sol"), "reentrancy.sol")
    assert "1 issue(s) found" in text
    assert "SG-001" in text
    assert "checks-effects-interactions" in text.lower()


def test_report_shows_disclaimer_on_clean(safe_dir):
    text = to_text(_scan(safe_dir / "clean.sol"), "clean.sol")
    assert "no issues found" in text.lower()
    assert "does not mean" in text.lower()


def test_report_shows_error_on_failure():
    result = ScanResult(
        status=Status.FAILED_PARSE,
        findings=[],
        scanner_version="0.1.0",
        error="solc rejected the source",
    )
    text = to_text(result, "broken.sol")
    assert "analysis failed" in text.lower()
    assert "solc rejected the source" in text


def test_to_json_is_valid_and_structured(vulnerable_dir):
    import json
    raw = to_json(_scan(vulnerable_dir / "reentrancy.sol"))
    parsed = json.loads(raw)
    assert parsed["status"] == "completed_with_findings"
    assert isinstance(parsed["findings"], list)
    assert parsed["findings"]
