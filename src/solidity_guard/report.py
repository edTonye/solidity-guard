import json

from .models import ScanResult, Status

NO_FINDINGS_DISCLAIMER = (
    "No issues detected by the implemented rules. This does NOT mean the "
    "contract is safe. Review manually or use a professional audit."
)


def to_text(result: ScanResult, filename: str = "<source>") -> str:
    lines: list[str] = []
    if result.status == Status.COMPLETED_NO_FINDINGS:
        lines.append(f"{filename}: no issues found.")
        lines.append(NO_FINDINGS_DISCLAIMER)
        return "\n".join(lines)
    if result.status != Status.COMPLETED_WITH_FINDINGS:
        lines.append(f"{filename}: analysis failed ({result.status.value}).")
        if result.error:
            lines.append(f"error: {result.error}")
        return "\n".join(lines)
    lines.append(f"{filename}: {len(result.findings)} issue(s) found")
    lines.append("")
    for f in result.findings:
        lines.append(
            f"[{f.severity.value.upper()} / {f.confidence.value}] "
            f"{f.rule_id} — {f.title}"
        )
        lines.append(f"  line {f.line}:")
        for sl in f.snippet.splitlines():
            lines.append(f"    {sl}")
        lines.append(f"  {f.description}")
        lines.append(f"  fix: {f.remediation}")
        lines.append("")
    return "\n".join(lines)


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)

def to_json_results(results: list[tuple[str, "ScanResult"]]) -> str:
    from . import __version__

    payload: dict = {"scanner_version": __version__, "results": []}
    for path, result in results:
        entry = result.to_dict()
        entry.pop("scanner_version", None)
        payload["results"].append({"path": path, **entry})
    return json.dumps(payload, indent=2)
