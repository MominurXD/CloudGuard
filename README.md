# CloudGuard

**Defensive cloud-security analytics for detecting suspicious identity, IAM, storage and network activity.**

CloudGuard is a full-stack security engineering project that ingests AWS-style audit events, runs transparent detection rules, assigns risk severity, and presents incidents in an investigation-focused dashboard.

## What it demonstrates

- Defensive security detection engineering
- Cloud audit-log analysis
- Python/FastAPI backend development
- React + TypeScript frontend engineering
- Incident triage and evidence timelines
- Automated testing and CI
- Dockerised deployment
- Security-focused architecture documentation

## Current detections

- Repeated failed console logins within a short window
- Rapid geographic changes in successful identity activity
- Sensitive IAM privilege changes
- Public object-storage exposure
- SSH/RDP security-group rules exposed to the internet

Every finding contains:

- Severity and numeric risk score
- Detection category
- Actor and event count
- First/last observed timestamps
- Supporting evidence
- Recommended incident-response actions

## Tech stack

| Layer | Technology |
| --- | --- |
| Frontend | React, TypeScript, Vite, Recharts |
| Backend | Python, FastAPI, Pydantic |
| Detection | Deterministic detection rules and event correlation |
| Testing | pytest, FastAPI TestClient |
| DevOps | Docker, Docker Compose, GitHub Actions |

## Demo dataset

`data/sample_cloud_events.json` contains more than 200 synthetic cloud-audit events and deliberately includes several security scenarios for the detectors to identify.

The format is intentionally straightforward:

```json
{
  "timestamp": "2026-09-26T11:32:00Z",
  "event_type": "AuthorizeSecurityGroupIngress",
  "actor": "admin@company.com",
  "source_ip": "13.40.55.71",
  "country": "GB",
  "resource": "sg-0ab12c-prod",
  "status": "Success",
  "metadata": { "cidr": "0.0.0.0/0", "port": 22 }
}
```

The dashboard also accepts your own JSON array of events in the same format.

## Run locally

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
PYTHONPATH=. uvicorn app.main:app --reload
```

API: `http://localhost:8000`  
Swagger: `http://localhost:8000/docs`

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Dashboard: `http://localhost:5173`

### Tests

```bash
cd backend
PYTHONPATH=. pytest -q
```

### Docker

```bash
docker compose up --build
```

## API

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/v1/health` | Service health check |
| GET | `/api/v1/dashboard` | Analyse the bundled demo audit log |
| POST | `/api/v1/dashboard/upload` | Analyse an uploaded JSON audit log |

## Security engineering decisions

CloudGuard's first version intentionally favours explainable rules over black-box anomaly models. A security analyst should be able to answer **why** a finding fired, inspect the underlying events, and verify the remediation advice. The detection layer is isolated from the API so new detectors or streaming inputs can be added without changing the frontend contract.

See [`docs/architecture.md`](docs/architecture.md) for the architecture and production roadmap.

## Future improvements

- PostgreSQL incident/event persistence
- User accounts and role-based access control
- Live AWS CloudTrail/EventBridge ingestion
- Finding assignment, status, analyst notes and audit history
- IP/ASN and threat-intelligence enrichment
- AWS ECS/RDS deployment with Terraform
- Slack/email alerting
- OpenTelemetry observability

## Licence

MIT
