from __future__ import annotations

SEVERITY_WEIGHTS = {
    "critical": 70,
    "high": 50,
    "medium": 30,
    "low": 10,
}


def score_to_severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def clamp_score(score: int) -> int:
    return max(0, min(score, 100))
