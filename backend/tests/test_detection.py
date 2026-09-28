from datetime import datetime, timedelta, timezone

from app.services.detection import SecurityEvent, detect_brute_force, detect_public_exposure, run_detection


def event(**overrides):
    payload = {
        "timestamp": datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc),
        "event_type": "ConsoleLogin",
        "actor": "user@example.com",
        "source_ip": "203.0.113.10",
        "country": "GB",
        "resource": "aws-console",
        "status": "Failure",
        "user_agent": "browser",
        "metadata": {},
    }
    payload.update(overrides)
    return SecurityEvent(**payload)


def test_brute_force_detection_requires_repeated_failures():
    attempts = [event(timestamp=event().timestamp + timedelta(minutes=i)) for i in range(5)]
    findings = detect_brute_force(attempts)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].event_count == 5


def test_public_bucket_detection_is_critical():
    findings = detect_public_exposure([
        event(event_type="PutBucketAcl", status="Success", resource="exports", metadata={"public": True})
    ])
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_run_detection_orders_highest_risk_first():
    events = [
        event(event_type="PutBucketAcl", status="Success", resource="exports", metadata={"public": True}),
        event(event_type="CreateAccessKey", status="Success", actor="admin", resource="admin"),
    ]
    findings = run_detection(events)
    assert findings[0].score >= findings[-1].score
