from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Literal, Optional
import uuid

@dataclass
class Issue:
    filename: str
    line: int
    rule: str
    function: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO", "ERROR"]
    message: str
    recommendation: str
    category: Literal["SECURITY", "CODE_QUALITY", "PERFORMANCE", "PARSING", "METRICS", "OTHER"]

    # NEW fields
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    confidence: float = 1.0  # 0.0 to 1.0
    code_snippet: Optional[str] = None
    column: Optional[int] = None
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    detector: Optional[str] = None  # Which detector found it
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """For JSON serialization."""
        return asdict(self)


def make_issue(
        filename: str,
        line: int, rule: str,
        function: str,
        severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"], 
        message: str, recommendation: str,
        category: Literal["SECURITY", "CODE_QUALITY", "PERFORMANCE"]
        ) -> Issue:
    return Issue(
        filename=filename,
        line=line,
        rule=rule,
        function=function,
        severity=severity,
        message=message,
        recommendation=recommendation,
        category=category
    )