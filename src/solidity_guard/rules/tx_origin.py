from ..ast_utils import line_snippet, src_to_line, walk
from ..models import Confidence, Finding, Severity
from .base import Rule


class TxOriginRule(Rule):
    id = "SG-002"
    title = "Use of tx.origin"
    severity = Severity.HIGH

    def check(self, ast: dict, source: str) -> list[Finding]:
        findings: list[Finding] = []
        seen_lines: set[int] = set()
        for node in walk(ast):
            if node.get("nodeType") != "MemberAccess":
                continue
            if node.get("memberName") != "origin":
                continue
            expr = node.get("expression", {})
            if expr.get("nodeType") != "Identifier" or expr.get("name") != "tx":
                continue
            line = src_to_line(source, node)
            if line in seen_lines:
                continue
            seen_lines.add(line)
            findings.append(Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.MEDIUM,
                line=line,
                snippet=line_snippet(source, line, context=1),
                description="tx.origin is referenced in the contract.",
                rationale=(
                    "tx.origin refers to the original transaction sender. If "
                    "used for authorization, a malicious contract can trick a "
                    "user into invoking it, forwarding tx.origin and bypassing "
                    "the check. This rule flags any reference. Review whether "
                    "it is used for access control."
                ),
                remediation=(
                    "Use msg.sender for authorization. tx.origin should not "
                    "be used for access control."
                ),
            ))
        return findings
