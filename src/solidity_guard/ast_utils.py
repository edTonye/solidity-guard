from typing import Iterator, Optional


def walk(node) -> Iterator[dict]:
    """Yield every dict node in the AST, depth-first."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from walk(item)


def src_start(node: dict) -> int:
    return int(node.get("src", "0:0:0").split(":")[0])


def src_to_line(source: str, node: dict) -> int:
    return source[: src_start(node)].count("\n") + 1


def line_snippet(source: str, line: int, context: int = 0) -> str:
    lines = source.splitlines()
    if line < 1 or line > len(lines):
        return ""
    lo = max(0, line - 1 - context)
    hi = min(len(lines), line + context)
    return "\n".join(lines[lo:hi])


def find_functions(ast: dict) -> Iterator[dict]:
    for node in walk(ast):
        if node.get("nodeType") == "FunctionDefinition":
            yield node


def function_is_external(fn: dict) -> bool:
    return fn.get("visibility") in {"public", "external"}


def function_has_nonreentrant(fn: dict) -> bool:
    for mod in fn.get("modifiers", []) or []:
        name = mod.get("modifierName", {}).get("name")
        if name and "nonReentrant" in name:
            return True
    return False


def is_low_level_call_node(node: dict) -> bool:
    """True if `node` is a FunctionCall to a low-level call that returns
    a boolean success flag."""
    if node.get("nodeType") != "FunctionCall":
        return False
    expr = node.get("expression", {})
    if expr.get("nodeType") == "FunctionCallOptions":
        expr = expr.get("expression", {})
    if expr.get("nodeType") != "MemberAccess":
        return False
    return expr.get("memberName") in {"call", "delegatecall", "staticcall", "send"}


def collect_state_var_ids(ast: dict) -> set[int]:
    ids: set[int] = set()
    for node in walk(ast):
        if node.get("nodeType") == "VariableDeclaration" and node.get("stateVariable"):
            ids.add(node.get("id"))
    return ids


def resolve_base_reference(node: Optional[dict]) -> Optional[int]:
    """Follow IndexAccess / MemberAccess chains down to an Identifier's
    referencedDeclaration."""
    while isinstance(node, dict):
        nt = node.get("nodeType")
        if nt == "Identifier":
            return node.get("referencedDeclaration")
        if nt == "IndexAccess":
            node = node.get("baseExpression")
            continue
        if nt == "MemberAccess":
            node = node.get("expression")
            continue
        return None
    return None


def nodes_in_source_order(root) -> list[dict]:
    collected: list[dict] = []
    for n in walk(root):
        if "src" in n:
            collected.append(n)
    collected.sort(key=src_start)
    return collected
