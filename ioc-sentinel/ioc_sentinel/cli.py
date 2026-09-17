from __future__ import annotations

import argparse
import csv
from pathlib import Path

from .detections import correlate
from .parser import load_events, load_iocs
from .reporting import findings_to_csv, findings_to_json, terminal_report


def _write_demo_files(base: Path) -> tuple[Path, Path]:
    base.mkdir(parents=True, exist_ok=True)
    events = base / "security_events.csv"
    iocs = base / "iocs.csv"
    if not events.exists():
        rows = [
            {"timestamp":"2026-09-15T10:00:00","source_ip":"45.33.22.11","destination_ip":"10.0.0.10","source_port":"51220","destination_port":"22","username":"alice","event_type":"authentication","action":"failed_login","domain":"","url":"","hash":"","message":"SSH authentication failure"},
            {"timestamp":"2026-09-15T10:01:00","source_ip":"45.33.22.11","destination_ip":"10.0.0.10","source_port":"51221","destination_port":"22","username":"bob","event_type":"authentication","action":"failed_login","domain":"","url":"","hash":"","message":"SSH authentication failure"},
            {"timestamp":"2026-09-15T10:02:00","source_ip":"45.33.22.11","destination_ip":"10.0.0.10","source_port":"51222","destination_port":"22","username":"carol","event_type":"authentication","action":"failed_login","domain":"","url":"","hash":"","message":"SSH authentication failure"},
            {"timestamp":"2026-09-15T10:03:00","source_ip":"45.33.22.11","destination_ip":"10.0.0.10","source_port":"51223","destination_port":"22","username":"david","event_type":"authentication","action":"failed_login","domain":"","url":"","hash":"","message":"SSH authentication failure"},
            {"timestamp":"2026-09-15T10:04:00","source_ip":"45.33.22.11","destination_ip":"10.0.0.10","source_port":"51224","destination_port":"22","username":"admin","event_type":"authentication","action":"failed_login","domain":"","url":"","hash":"","message":"SSH authentication failure"},
            {"timestamp":"2026-09-15T10:04:30","source_ip":"45.33.22.11","destination_ip":"10.0.0.10","source_port":"51225","destination_port":"22","username":"admin","event_type":"authentication","action":"login_success","domain":"","url":"","hash":"","message":"Successful authentication"},
            {"timestamp":"2026-09-15T10:05:00","source_ip":"10.0.0.5","destination_ip":"10.0.0.30","source_port":"41000","destination_port":"4444","username":"","event_type":"network","action":"connection","domain":"","url":"","hash":"","message":"Outbound connection"},
        ]
        with events.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader(); writer.writerows(rows)
    if not iocs.exists():
        with iocs.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["ioc","type","severity","source","description"])
            writer.writerow(["45.33.22.11","ip","high","local-demo","Known malicious scanning source"])
    return events, iocs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ioc-sentinel", description="Threat-intelligence correlation and SOC triage engine")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a CSV security event file")
    scan.add_argument("input", help="Path to event CSV")
    scan.add_argument("--ioc-feed", required=True, help="Path to IOC CSV")
    scan.add_argument("--window", type=int, default=5, help="Behavior correlation window in minutes")
    scan.add_argument("--format", choices=["terminal", "json", "csv"], default="terminal")
    scan.add_argument("--output", help="Output path for json/csv")

    sub.add_parser("demo", help="Run the included demonstration dataset")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "demo":
        base = Path("data/demo")
        event_path, ioc_path = _write_demo_files(base)
        findings = correlate(load_events(event_path), load_iocs(ioc_path))
        print(terminal_report(findings))
        return 0

    events = load_events(args.input)
    iocs = load_iocs(args.ioc_feed)
    findings = correlate(events, iocs, window_minutes=args.window)

    if args.format == "terminal":
        print(terminal_report(findings))
    elif args.format == "json":
        output = args.output or "reports.json"
        findings_to_json(findings, output)
        print(f"Wrote {len(findings)} findings to {output}")
    else:
        output = args.output or "reports.csv"
        findings_to_csv(findings, output)
        print(f"Wrote {len(findings)} findings to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
