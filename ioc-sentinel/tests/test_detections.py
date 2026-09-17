from ioc_sentinel.detections import correlate
from ioc_sentinel.models import IOC, SecurityEvent
from ioc_sentinel.parser import parse_timestamp


def event(ts, user, action, port=22):
    return SecurityEvent(
        timestamp=parse_timestamp(ts),
        source_ip="45.33.22.11",
        destination_ip="10.0.0.10",
        destination_port=port,
        username=user,
        event_type="authentication",
        action=action,
    )


def test_brute_force_and_ioc_correlation():
    events = [event(f"2026-09-15T10:0{i}:00", user, "failed_login") for i, user in enumerate(["a", "b", "c", "d", "e"])]
    events.append(event("2026-09-15T10:05:00", "admin", "login_success"))
    findings = correlate(events, [IOC("45.33.22.11", "ip", "high", "test")])
    assert findings
    assert any(f.severity == "critical" for f in findings)


def test_suspicious_port():
    findings = correlate([event("2026-09-15T10:00:00", "", "connection", port=4444)], [])
    assert findings[0].score == 15
    assert findings[0].severity == "low"
