from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .models import IOC, SecurityEvent

DATETIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
)


def parse_timestamp(value: str) -> datetime:
    value = value.strip()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        for fmt in DATETIME_FORMATS:
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
    raise ValueError(f"Unsupported timestamp: {value}")


def _int_or_none(value: str) -> int | None:
    if not value or not value.strip():
        return None
    try:
        return int(value)
    except ValueError:
        return None


def row_to_event(row: dict[str, str]) -> SecurityEvent:
    return SecurityEvent(
        timestamp=parse_timestamp(row.get("timestamp", "")),
        source_ip=row.get("source_ip", "").strip(),
        destination_ip=row.get("destination_ip", "").strip(),
        source_port=_int_or_none(row.get("source_port", "")),
        destination_port=_int_or_none(row.get("destination_port", "")),
        username=row.get("username", "").strip(),
        event_type=row.get("event_type", "").strip().lower(),
        action=row.get("action", "").strip().lower(),
        domain=row.get("domain", "").strip().lower(),
        url=row.get("url", "").strip().lower(),
        hash=row.get("hash", "").strip().lower(),
        message=row.get("message", "").strip(),
        raw=row,
    )


def load_events(path: str | Path) -> list[SecurityEvent]:
    path = Path(path)
    if path.suffix.lower() != ".csv":
        raise ValueError("This version accepts CSV event files. Use a CSV with the documented fields.")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [row_to_event(row) for row in csv.DictReader(handle)]


def load_iocs(path: str | Path) -> list[IOC]:
    path = Path(path)
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        result: list[IOC] = []
        for row in csv.DictReader(handle):
            result.append(
                IOC(
                    value=row.get("ioc", "").strip().lower(),
                    type=row.get("type", "").strip().lower(),
                    severity=row.get("severity", "medium").strip().lower(),
                    source=row.get("source", "local").strip(),
                    description=row.get("description", "").strip(),
                )
            )
        return result
