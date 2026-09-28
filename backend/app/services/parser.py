from __future__ import annotations

import json
from datetime import datetime
from io import BytesIO
from pathlib import Path

from app.services.detection import SecurityEvent


def _parse_timestamp(value: str) -> datetime:
    normalised = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalised)


def parse_records(records: list[dict]) -> list[SecurityEvent]:
    events: list[SecurityEvent] = []
    for record in records:
        events.append(
            SecurityEvent(
                timestamp=_parse_timestamp(str(record["timestamp"])),
                event_type=str(record["event_type"]),
                actor=str(record["actor"]),
                source_ip=str(record["source_ip"]),
                country=str(record.get("country", "Unknown")),
                resource=str(record.get("resource", "-")),
                status=str(record.get("status", "Success")),
                user_agent=str(record.get("user_agent", "")),
                metadata=record.get("metadata") or {},
            )
        )
    return sorted(events, key=lambda item: item.timestamp)


def load_events(path: Path) -> list[SecurityEvent]:
    return parse_records(json.loads(path.read_text()))


def parse_upload(content: bytes) -> list[SecurityEvent]:
    raw = json.load(BytesIO(content))
    records = raw if isinstance(raw, list) else raw.get("events", [])
    if not records:
        raise ValueError("No events were found in the uploaded JSON file.")
    return parse_records(records)
