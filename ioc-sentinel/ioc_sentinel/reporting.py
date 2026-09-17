from __future__ import annotations

import csv
import json
from pathlib import Path

from .models import Finding


def findings_to_json(findings: list[Finding], output: str | Path) -> None:
    Path(output).write_text(json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8")


def findings_to_csv(findings: list[Finding], output: str | Path) -> None:
    with Path(output).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["timestamp", "source_ip", "category", "score", "severity", "reasons"])
        writer.writeheader()
        for finding in findings:
            writer.writerow({
                "timestamp": finding.timestamp.isoformat(),
                "source_ip": finding.source_ip,
                "category": finding.category,
                "score": finding.score,
                "severity": finding.severity,
                "reasons": " | ".join(finding.reasons),
            })


def terminal_report(findings: list[Finding]) -> str:
    lines = ["IOC SENTINEL REPORT", "=" * 60, f"Findings: {len(findings)}", ""]
    for finding in sorted(findings, key=lambda f: (-f.score, f.timestamp)):
        lines.extend([
            f"[{finding.severity.upper()}] {finding.source_ip} -> {finding.category}",
            f"Score: {finding.score}",
            "Reasons:",
        ])
        lines.extend(f"  - {reason}" for reason in finding.reasons)
        lines.append("")
    return "\n".join(lines)
