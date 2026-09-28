from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Iterable


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: datetime
    event_type: str
    actor: str
    source_ip: str
    country: str
    resource: str
    status: str
    user_agent: str = ""
    metadata: dict | None = None


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str
    score: int
    category: str
    actor: str
    first_seen: str
    last_seen: str
    event_count: int
    summary: str
    evidence: list[dict]
    recommended_actions: list[str]


SEVERITY_WEIGHT = {"low": 25, "medium": 50, "high": 75, "critical": 95}


def _serialise(event: SecurityEvent) -> dict:
    payload = asdict(event)
    payload["timestamp"] = event.timestamp.isoformat()
    return payload


def _finding(
    *,
    fid: str,
    title: str,
    severity: str,
    category: str,
    actor: str,
    events: list[SecurityEvent],
    summary: str,
    actions: list[str],
) -> Finding:
    ordered = sorted(events, key=lambda item: item.timestamp)
    return Finding(
        id=fid,
        title=title,
        severity=severity,
        score=SEVERITY_WEIGHT[severity],
        category=category,
        actor=actor,
        first_seen=ordered[0].timestamp.isoformat(),
        last_seen=ordered[-1].timestamp.isoformat(),
        event_count=len(ordered),
        summary=summary,
        evidence=[_serialise(item) for item in ordered[-8:]],
        recommended_actions=actions,
    )


def detect_brute_force(events: Iterable[SecurityEvent]) -> list[Finding]:
    grouped: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == "ConsoleLogin" and event.status == "Failure":
            grouped[(event.actor, event.source_ip)].append(event)

    findings: list[Finding] = []
    for (actor, ip), attempts in grouped.items():
        attempts = sorted(attempts, key=lambda item: item.timestamp)
        window: list[SecurityEvent] = []
        for event in attempts:
            window = [item for item in window if event.timestamp - item.timestamp <= timedelta(minutes=10)]
            window.append(event)
            if len(window) >= 5:
                findings.append(
                    _finding(
                        fid=f"brute-{actor}-{ip}".replace(".", "-"),
                        title="Repeated failed console logins",
                        severity="high",
                        category="credential-access",
                        actor=actor,
                        events=window,
                        summary=f"{len(window)} failed console logins from {ip} occurred within 10 minutes.",
                        actions=[
                            "Confirm whether the source IP belongs to the user.",
                            "Reset credentials and revoke active sessions if activity is unauthorised.",
                            "Require MFA and review authentication logs for successful follow-on activity.",
                        ],
                    )
                )
                break
    return findings


def detect_suspicious_geo(events: Iterable[SecurityEvent]) -> list[Finding]:
    actor_events: dict[str, list[SecurityEvent]] = defaultdict(list)
    for event in events:
        if event.status == "Success" and event.event_type in {"ConsoleLogin", "AssumeRole"}:
            actor_events[event.actor].append(event)

    findings: list[Finding] = []
    for actor, items in actor_events.items():
        items = sorted(items, key=lambda item: item.timestamp)
        for previous, current in zip(items, items[1:]):
            if previous.country != current.country and current.timestamp - previous.timestamp <= timedelta(hours=2):
                findings.append(
                    _finding(
                        fid=f"geo-{actor}-{int(current.timestamp.timestamp())}",
                        title="Rapid geographic login change",
                        severity="high",
                        category="identity-anomaly",
                        actor=actor,
                        events=[previous, current],
                        summary=f"Successful access moved from {previous.country} to {current.country} within two hours.",
                        actions=[
                            "Validate both sessions with the account owner.",
                            "Revoke suspicious sessions and rotate credentials if unrecognised.",
                            "Check for VPN, proxy or corporate egress explanations before escalation.",
                        ],
                    )
                )
    return findings


def detect_privilege_escalation(events: Iterable[SecurityEvent]) -> list[Finding]:
    privileged = {"AttachUserPolicy", "PutUserPolicy", "CreateAccessKey", "AddUserToGroup"}
    findings: list[Finding] = []
    for event in events:
        if event.event_type in privileged and event.status == "Success":
            severity = "critical" if event.event_type in {"AttachUserPolicy", "PutUserPolicy"} else "high"
            findings.append(
                _finding(
                    fid=f"priv-{event.actor}-{int(event.timestamp.timestamp())}",
                    title="Sensitive IAM change",
                    severity=severity,
                    category="privilege-escalation",
                    actor=event.actor,
                    events=[event],
                    summary=f"{event.actor} performed {event.event_type} against {event.resource}.",
                    actions=[
                        "Confirm the IAM change is linked to an approved change request.",
                        "Review the resulting permissions for excessive privilege.",
                        "Revert unauthorised policy or access-key changes and inspect adjacent activity.",
                    ],
                )
            )
    return findings


def detect_public_exposure(events: Iterable[SecurityEvent]) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        metadata = event.metadata or {}
        if event.event_type == "PutBucketAcl" and metadata.get("public") is True and event.status == "Success":
            findings.append(
                _finding(
                    fid=f"s3-public-{event.resource}-{int(event.timestamp.timestamp())}",
                    title="Storage bucket made public",
                    severity="critical",
                    category="data-exposure",
                    actor=event.actor,
                    events=[event],
                    summary=f"{event.resource} was configured for public access.",
                    actions=[
                        "Remove public access unless explicitly approved.",
                        "Review object access logs for unexpected downloads.",
                        "Enable block-public-access controls and assess exposed data classification.",
                    ],
                )
            )
    return findings


def detect_security_group_exposure(events: Iterable[SecurityEvent]) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        metadata = event.metadata or {}
        cidr = metadata.get("cidr")
        port = metadata.get("port")
        if event.event_type == "AuthorizeSecurityGroupIngress" and event.status == "Success" and cidr == "0.0.0.0/0" and port in {22, 3389}:
            findings.append(
                _finding(
                    fid=f"sg-open-{event.resource}-{int(event.timestamp.timestamp())}",
                    title="Remote administration port exposed to the internet",
                    severity="critical",
                    category="network-exposure",
                    actor=event.actor,
                    events=[event],
                    summary=f"Port {port} on {event.resource} was opened to 0.0.0.0/0.",
                    actions=[
                        "Restrict the rule to approved management networks immediately.",
                        "Inspect connection logs for unauthorised access attempts.",
                        "Prefer a managed bastion or session-management service for administration.",
                    ],
                )
            )
    return findings


def run_detection(events: list[SecurityEvent]) -> list[Finding]:
    findings: list[Finding] = []
    for detector in [
        detect_brute_force,
        detect_suspicious_geo,
        detect_privilege_escalation,
        detect_public_exposure,
        detect_security_group_exposure,
    ]:
        findings.extend(detector(events))
    return sorted(findings, key=lambda item: (item.score, item.last_seen), reverse=True)


def dashboard_summary(events: list[SecurityEvent], findings: list[Finding]) -> dict:
    severity_counts = Counter(item.severity for item in findings)
    actors = Counter(item.actor for item in findings)
    countries = Counter(item.country for item in events)
    successful = sum(1 for item in events if item.status == "Success")
    failed = len(events) - successful
    return {
        "events": len(events),
        "findings": len(findings),
        "critical": severity_counts.get("critical", 0),
        "high": severity_counts.get("high", 0),
        "medium": severity_counts.get("medium", 0),
        "successful_events": successful,
        "failed_events": failed,
        "top_risky_actor": actors.most_common(1)[0][0] if actors else None,
        "countries_seen": len(countries),
        "risk_score": min(100, sum(item.score for item in findings) // max(1, len(findings))) if findings else 0,
    }
