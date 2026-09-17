from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class SecurityEvent:
    timestamp: datetime
    source_ip: str = ""
    destination_ip: str = ""
    source_port: int | None = None
    destination_port: int | None = None
    username: str = ""
    event_type: str = ""
    action: str = ""
    domain: str = ""
    url: str = ""
    hash: str = ""
    message: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class IOC:
    value: str
    type: str
    severity: str = "medium"
    source: str = "local"
    description: str = ""


@dataclass(slots=True)
class Finding:
    timestamp: datetime
    source_ip: str
    category: str
    score: int
    severity: str
    reasons: list[str]
    evidence: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "category": self.category,
            "score": self.score,
            "severity": self.severity,
            "reasons": self.reasons,
            "evidence": self.evidence,
        }
