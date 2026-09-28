from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_dashboard_contains_findings_and_events():
    response = client.get("/api/v1/dashboard")
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["events"] > 200
    assert body["summary"]["critical"] >= 2
    assert len(body["findings"]) >= 5
    assert len(body["events"]) <= 100
