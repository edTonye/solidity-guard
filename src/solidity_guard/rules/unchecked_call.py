from ..ast_utils import is_low_level_call_node, line_snippet, src_to_line, walk
from ..models import Confidence, Finding, Severity
from .base import Rule


class UncheckedCallRule(Rule):
    id = "SG-003"
    title = "Unchecked low-level call return value"
    severity = Severity.MEDIUM

    def check(self, ast: dict, source: str) -> list[Finding]:
        findings: list[Finding] = []
        for node in walk(ast):
            if node.get("nodeType") != "ExpressionStatement":
                continue
            call = node.get("expression")
            if not isinstance(call, dict):
                continue
            if not is_low_level_call_node(call):
                continue
            line = src_to_line(source, call)
            findings.append(Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.HIGH,
                line=line,
                snippet=line_snippet(source, line),
                description=(
                    "A low-level call is executed and its boolean return "
                    "value is discarded."
                ),
                rationale=(
                    "Low-level calls return a boolean success flag. If it is "
                    "not captured and checked, the call can fail silently and "
                    "execution continues as if it succeeded."
                ),
                remediation=(
                    "Capture the return value and check it, e.g. "
                    "`(bool ok, ) = target.call(...); require(ok, \"call failed\");`"
                ),
            ))
        return findings
