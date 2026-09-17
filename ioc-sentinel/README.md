# IOC Sentinel

**IOC Sentinel** is a lightweight Python threat-intelligence and SOC triage engine for correlating security logs with indicators of compromise (IOCs) and identifying suspicious behavior.

## Features

- Parse CSV security logs and simple Apache/auth-style text logs.
- Extract IPv4 addresses, domains, URLs, and hashes.
- Match extracted IOCs against local threat-intelligence feeds.
- Detect simple behaviors such as brute force, suspicious ports, and repeated targeting.
- Correlate events over a configurable time window.
- Assign an explainable risk score and severity.
- Export findings as JSON or CSV.
- Offline-first: works with local feeds and sample data.
- Clean CLI suitable for GitHub portfolio demonstrations.

## Quick start

Requires Python 3.10+.

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

Run the built-in demo:

```bash
python -m ioc_sentinel demo
```

Scan the included sample log:

```bash
python -m ioc_sentinel scan samples/security_events.csv --ioc-feed samples/iocs.csv --format json --output reports.json
```

View the terminal report:

```bash
python -m ioc_sentinel scan samples/security_events.csv --ioc-feed samples/iocs.csv
```

## Detection logic

The first version intentionally uses transparent rules rather than opaque machine learning.

| Signal | Score |
|---|---:|
| IOC match: critical | +70 |
| IOC match: high | +50 |
| IOC match: medium | +30 |
| IOC match: low | +10 |
| Failed-login brute force | +20 |
| Suspicious destination port | +15 |
| Same source attacks multiple accounts | +15 |
| Same source targets multiple hosts | +10 |
| Successful login after repeated failures | +10 |

The score is capped at 100 per finding.

Severity:

- **LOW:** 0–29
- **MEDIUM:** 30–59
- **HIGH:** 60–79
- **CRITICAL:** 80–100

## CSV input format

The scanner accepts a CSV with these fields:

```text
timestamp,source_ip,destination_ip,source_port,destination_port,username,event_type,action,domain,url,hash,message
```

Most fields are optional. Unknown fields are preserved where practical.

## IOC feed format

```text
ioc,type,severity,source,description
45.33.22.11,ip,high,local-demo,Known malicious scanning source
malicious.example.com,domain,critical,local-demo,Known phishing domain
```

Supported IOC types: `ip`, `domain`, `url`, `hash`.

## Project structure

```text
ioc-sentinel/
├── ioc_sentinel/
│   ├── cli.py
│   ├── detections.py
│   ├── extractor.py
│   ├── models.py
│   ├── parser.py
│   ├── reporting.py
│   ├── scoring.py
│   └── __main__.py
├── samples/
├── tests/
├── docs/
├── requirements.txt
└── README.md
```

## Example output

```text
IOC SENTINEL REPORT
============================================================
Findings: 3

[CRITICAL] 185.10.20.30 -> multiple accounts
Score: 100
Reasons:
  - Known malicious IP (local-demo)
  - Brute-force pattern: 7 failed logins in 5 minutes
  - Source targeted multiple accounts

[HIGH] 10.0.0.5 -> suspicious connection
Score: 65
Reasons:
  - Suspicious destination port: 4444
  - Source targeted multiple hosts
```

## Roadmap

1. Add live threat-intelligence API adapters (VirusTotal, MISP/OpenCTI).
2. Add Wazuh/Splunk ingestion adapters.
3. Add email/Slack/webhook alerting.
4. Add a small FastAPI REST service.
5. Add a dashboard with historical risk trends.
6. Add rule configuration through YAML.
7. Add Docker and CI/CD security checks.

## Portfolio positioning

A strong portfolio description is:

> Built IOC Sentinel, a Python-based security log correlation and threat-intelligence triage engine that extracts IOCs, correlates them with local intelligence, detects brute-force and suspicious-network behaviors, and produces explainable risk-scored SOC findings in JSON/CSV.

This project is designed for defensive security analysis and controlled lab data.
