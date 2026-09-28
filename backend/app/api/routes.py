from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.services.detection import dashboard_summary, run_detection
from app.services.parser import load_events, parse_upload

router = APIRouter()
DATA_PATH = Path(__file__).resolve().parents[3] / "data" / "sample_cloud_events.json"


def build_dashboard(events):
    findings = run_detection(events)
    return {
        "summary": dashboard_summary(events, findings),
        "findings": [asdict(item) for item in findings],
        "events": [
            {
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "actor": event.actor,
                "source_ip": event.source_ip,
                "country": event.country,
                "resource": event.resource,
                "status": event.status,
                "metadata": event.metadata or {},
            }
            for event in sorted(events, key=lambda item: item.timestamp, reverse=True)[:100]
        ],
    }


@router.get("/health")
def health() -> dict:
    return {"status": "ok"}


@router.get("/dashboard")
def dashboard() -> dict:
    return build_dashboard(load_events(DATA_PATH))


@router.post("/dashboard/upload")
async def upload_logs(file: UploadFile = File(...)) -> dict:
    if not file.filename or not file.filename.lower().endswith(".json"):
        raise HTTPException(status_code=400, detail="Upload a JSON audit-log export.")
    try:
        return build_dashboard(parse_upload(await file.read()))
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Could not parse the uploaded security log.") from exc
