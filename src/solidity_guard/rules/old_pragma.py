import re

from ..models import Confidence, Finding, Severity
from .base import Rule

PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
SIMPLE_VERSION_RE = re.compile(r"^\s*\^?\s*(\d+)\.(\d+)")


class OldPragmaRule(Rule):
    id = "SG-004"
    title = "Pragma targets Solidity <0.8 (unchecked arithmetic)"
    severity = Severity.INFO

    def check(self, ast: dict, source: str) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(source.splitlines(), start=1):
            m = PRAGMA_RE.search(line)
            if not m:
                continue
            expr = m.group(1).strip()
            # Ranges (`<`, `>`, `<=`, `>=`) are out of scope for v1 —
            # their semantics are not evaluated. See limitations.
            if any(op in expr for op in ("<", ">")):
                continue
            vm = SIMPLE_VERSION_RE.match(expr)
            if not vm:
                continue
            major, minor = int(vm.group(1)), int(vm.group(2))
            if major != 0 or minor >= 8:
                continue
            findings.append(Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.LOW,
                line=i,
                snippet=line,
                description=f"Pragma `{expr}` targets a Solidity version <0.8.",
                rationale=(
                    "Arithmetic in Solidity <0.8 is unchecked by default. "
                    "Overflow and underflow can silently wrap unless SafeMath "
                    "is used for all arithmetic."
                ),
                remediation=(
                    "Upgrade to Solidity >=0.8, or verify that SafeMath is "
                    "used for all arithmetic in the contract."
                ),
            ))
        return findings
