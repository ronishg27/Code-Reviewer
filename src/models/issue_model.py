from dataclasses import dataclass
from typing import Literal, Optional

@dataclass
class Issue:
    filename: str
    line: int
    rule: str 
    function: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    message: str
    recommendation: str


def make_issue(
        filename: str,
        line: int, rule: str,
        function: str,
        severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"], 
        message: str, recommendation: str
        ) -> Issue:
    return Issue(
        filename=filename,
        line=line,
        rule=rule,
        function=function,
        severity=severity,
        message=message,
        recommendation=recommendation
    )