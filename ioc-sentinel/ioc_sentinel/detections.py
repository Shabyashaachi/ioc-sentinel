from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Iterable

from .extractor import extract_all, normalize_ioc
from .models import Finding, IOC, SecurityEvent
from .scoring import SEVERITY_WEIGHTS, clamp_score, score_to_severity

SUSPICIOUS_PORTS = {23, 4444, 1337, 31337, 3389}
FAILED_ACTIONS = {"failed_login", "login_failed", "authentication_failure", "failure"}
SUCCESS_ACTIONS = {"login_success", "successful_login", "success"}


def _event_text(event: SecurityEvent) -> str:
    return " ".join(
        value for value in (
            event.source_ip,
            event.destination_ip,
            event.username,
            event.event_type,
            event.action,
            event.domain,
            event.url,
            event.hash,
            event.message,
        ) if value
    )


def _event_iocs(event: SecurityEvent) -> dict[str, set[str]]:
    extracted = {key: set(values) for key, values in extract_all(_event_text(event)).items()}
    if event.source_ip:
        extracted["ip"].add(event.source_ip.lower())
    if event.destination_ip:
        extracted["ip"].add(event.destination_ip.lower())
    if event.domain:
        extracted["domain"].add(event.domain.lower())
    if event.url:
        extracted["url"].add(normalize_ioc(event.url, "url"))
    if event.hash:
        extracted["hash"].add(event.hash.lower())
    return extracted


def correlate(events: Iterable[SecurityEvent], iocs: Iterable[IOC], window_minutes: int = 5) -> list[Finding]:
    events = sorted(events, key=lambda event: event.timestamp)
    ioc_map: dict[tuple[str, str], IOC] = {
        (ioc.type, normalize_ioc(ioc.value, ioc.type)): ioc for ioc in iocs
    }

    findings: list[Finding] = []
    by_source: dict[str, list[SecurityEvent]] = defaultdict(list)
    for event in events:
        if event.source_ip:
            by_source[event.source_ip].append(event)

    for event in events:
        if not event.source_ip:
            continue
        reasons: list[str] = []
        evidence: list[dict] = []
        score = 0

        for ioc_type, values in _event_iocs(event).items():
            for value in values:
                match = ioc_map.get((ioc_type, normalize_ioc(value, ioc_type)))
                if match:
                    weight = SEVERITY_WEIGHTS.get(match.severity, 30)
                    score += weight
                    reasons.append(f"Known malicious {ioc_type}: {match.value} ({match.source})")
                    evidence.append({"ioc": match.value, "type": ioc_type, "severity": match.severity, "source": match.source})
                    if match.description:
                        reasons.append(match.description)

        recent = [e for e in by_source[event.source_ip] if timedelta(minutes=0) <= event.timestamp - e.timestamp <= timedelta(minutes=window_minutes)]
        recent_failures = [e for e in recent if e.action in FAILED_ACTIONS or e.event_type in FAILED_ACTIONS]
        recent_successes = [e for e in recent if e.action in SUCCESS_ACTIONS or e.event_type in SUCCESS_ACTIONS]
        usernames = {e.username for e in recent_failures if e.username}
        destination_hosts = {e.destination_ip for e in recent if e.destination_ip}

        if len(recent_failures) >= 5:
            score += 20
            reasons.append(f"Brute-force pattern: {len(recent_failures)} failed logins in {window_minutes} minutes")
            evidence.append({"rule": "brute_force", "failed_logins": len(recent_failures)})

        if event.destination_port in SUSPICIOUS_PORTS:
            score += 15
            reasons.append(f"Suspicious destination port: {event.destination_port}")
            evidence.append({"rule": "suspicious_port", "destination_port": event.destination_port})

        if len(usernames) >= 3:
            score += 15
            reasons.append("Source targeted multiple accounts")
            evidence.append({"rule": "multi_account_targeting", "accounts": sorted(usernames)})

        if len(destination_hosts) >= 3:
            score += 10
            reasons.append("Source targeted multiple destination hosts")
            evidence.append({"rule": "multi_host_targeting", "hosts": sorted(destination_hosts)})

        if recent_failures and recent_successes:
            latest_failure = max(e.timestamp for e in recent_failures)
            if any(success.timestamp >= latest_failure for success in recent_successes):
                score += 10
                reasons.append("Successful login followed repeated authentication failures")
                evidence.append({"rule": "possible_account_compromise"})

        if not reasons:
            continue

        score = clamp_score(score)
        category = "ioc_match" if any("Known malicious" in reason for reason in reasons) else "behavioral_detection"
        findings.append(
            Finding(
                timestamp=event.timestamp,
                source_ip=event.source_ip,
                category=category,
                score=score,
                severity=score_to_severity(score),
                reasons=list(dict.fromkeys(reasons)),
                evidence=evidence,
            )
        )

    return findings
