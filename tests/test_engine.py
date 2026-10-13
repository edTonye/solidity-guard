from solidity_guard import engine
from solidity_guard.engine import scan
from solidity_guard.models import Status
from solidity_guard.parser import CompilerNotInstalledError

CLEAN = "pragma solidity ^0.8.20; contract T {}"
VULNERABLE = (
    "pragma solidity ^0.8.20; contract T {"
    "  function f(address payable to) external payable {"
    "    to.call{value: msg.value}(\"\");"
    "  }"
    "}"
)


def test_clean_source_status():
    r = scan(CLEAN)
    assert r.status == Status.COMPLETED_NO_FINDINGS
    assert r.error is None
    assert not r.is_clean is False  # is_clean should be True


def test_vulnerable_source_status():
    r = scan(VULNERABLE)
    assert r.status == Status.COMPLETED_WITH_FINDINGS
    assert any(f.rule_id == "SG-003" for f in r.findings)


def test_invalid_source_status():
    r = scan("this is not solidity at all")
    assert r.status == Status.FAILED_PARSE
    assert r.error is not None
    assert not r.is_clean


def test_empty_source_status():
    r = scan("")
    assert r.status == Status.FAILED_UNSUPPORTED
    assert r.error is not None


def test_whitespace_source_status():
    r = scan("   \n\t  ")
    assert r.status == Status.FAILED_UNSUPPORTED


def test_missing_compiler_status(monkeypatch):
    def fake_parse(source, solc_version=None):
        raise CompilerNotInstalledError("solc 9.9.9 is not installed")

    monkeypatch.setattr(engine, "parse", fake_parse)
    r = engine.scan(CLEAN)
    assert r.status == Status.FAILED_COMPILER_MISSING
    assert "9.9.9" in (r.error or "")


def test_scanner_version_present():
    r = scan(CLEAN)
    assert isinstance(r.scanner_version, str) and r.scanner_version


def test_to_dict_shape():
    r = scan(CLEAN)
    d = r.to_dict()
    assert set(d.keys()) == {"status", "scanner_version", "error", "findings"}
