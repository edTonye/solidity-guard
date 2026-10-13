from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Status(str, Enum):
    COMPLETED_NO_FINDINGS = "completed_no_findings"
    COMPLETED_WITH_FINDINGS = "completed_with_findings"
    FAILED_PARSE = "failed_parse"
    FAILED_UNSUPPORTED = "failed_unsupported"
    FAILED_COMPILER_MISSING = "failed_compiler_missing"
    FAILED_INTERNAL = "failed_internal"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    line: int
    snippet: str
    description: str
    rationale: str
    remediation: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "line": self.line,
            "snippet": self.snippet,
            "description": self.description,
            "rationale": self.rationale,
            "remediation": self.remediation,
        }


@dataclass
class ScanResult:
    status: Status
    findings: list[Finding]
    scanner_version: str
    error: Optional[str] = None

    @property
    def is_clean(self) -> bool:
        return self.status == Status.COMPLETED_NO_FINDINGS

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "scanner_version": self.scanner_version,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
        }
