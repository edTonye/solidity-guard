from abc import ABC, abstractmethod

from ..models import Finding, Severity


class Rule(ABC):
    id: str
    title: str
    severity: Severity

    @abstractmethod
    def check(self, ast: dict, source: str) -> list[Finding]:
        ...
