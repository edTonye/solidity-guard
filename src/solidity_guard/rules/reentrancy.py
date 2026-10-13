from ..ast_utils import (
    collect_state_var_ids,
    find_functions,
    function_has_nonreentrant,
    function_is_external,
    line_snippet,
    nodes_in_source_order,
    resolve_base_reference,
    src_to_line,
)
from ..models import Confidence, Finding, Severity
from .base import Rule

EXTERNAL_CALL_NAMES = {"call", "send", "transfer"}


class ReentrancyRule(Rule):
    id = "SG-001"
    title = "State change after external call (possible reentrancy)"
    severity = Severity.HIGH

    def check(self, ast: dict, source: str) -> list[Finding]:
        state_ids = collect_state_var_ids(ast)
        if not state_ids:
            return []
        findings: list[Finding] = []
        for fn in find_functions(ast):
            if not function_is_external(fn):
                continue
            if function_has_nonreentrant(fn):
                continue
            body = fn.get("body")
            if not body:
                continue
            ordered = nodes_in_source_order(body)
            call_node = None
            for node in ordered:
                if call_node is None:
                    if self._is_external_call(node):
                        call_node = node
                    continue
                if self._writes_state(node, state_ids):
                    line = src_to_line(source, node)
                    findings.append(Finding(
                        rule_id=self.id,
                        title=self.title,
                        severity=self.severity,
                        confidence=Confidence.MEDIUM,
                        line=line,
                        snippet=line_snippet(source, line, context=1),
                        description=(
                            f"Function `{fn.get('name') or '<fallback>'}` "
                            "writes state after performing an external call."
                        ),
                        rationale=(
                            "The function is externally reachable and has no "
                            "modifier whose name contains `nonReentrant`. "
                            "State is updated after an external call, which is "
                            "the ordering that enables a reentrancy attack if "
                            "the call target is attacker-controlled."
                        ),
                        remediation=(
                            "Apply checks-effects-interactions: update state "
                            "before the external call. Or add a reentrancy "
                            "guard (e.g. OpenZeppelin ReentrancyGuard)."
                        ),
                    ))
                    break
        return findings

    @staticmethod
    def _is_external_call(node: dict) -> bool:
        if node.get("nodeType") != "MemberAccess":
            return False
        return node.get("memberName") in EXTERNAL_CALL_NAMES

    @staticmethod
    def _writes_state(node: dict, state_ids: set[int]) -> bool:
        if node.get("nodeType") != "Assignment":
            return False
        target = resolve_base_reference(node.get("leftHandSide"))
        return target in state_ids
