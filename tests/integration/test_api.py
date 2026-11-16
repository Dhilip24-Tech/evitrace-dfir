from __future__ import annotations

from fastapi.testclient import TestClient

from evitrace.api import create_app
from evitrace.store import CaseStore


def test_health_needs_no_auth(workspace) -> None:
    client = TestClient(create_app(workspace, token="test-token"))
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["mode"] == "local-only"


def test_ask_requires_bearer_token(workspace, store: CaseStore) -> None:
    client = TestClient(create_app(workspace, token="test-token"))
    response = client.post(
        "/v1/cases/CASE-TEST-001/ask", json={"question": "Was x downloaded and executed on H?"}
    )
    assert response.status_code == 401


def test_ask_and_fetch_run(workspace, store: CaseStore) -> None:
    client = TestClient(create_app(workspace, token="test-token"))
    headers = {"Authorization": "Bearer test-token"}
    response = client.post(
        "/v1/cases/CASE-TEST-001/ask",
        headers=headers,
        json={"question": "Was invoice_q4.exe downloaded and executed on WKSTN-04?"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["proof"]["verdict"] == "ABSTAIN_INSUFFICIENT_EVIDENCE"
    run = client.get(f"/v1/cases/CASE-TEST-001/runs/{body['run_id']}", headers=headers)
    assert run.status_code == 200
    assert run.json()["certificate_id"] == body["certificate_id"]


def test_ask_rejects_unknown_fields(workspace, store: CaseStore) -> None:
    client = TestClient(create_app(workspace, token="test-token"))
    response = client.post(
        "/v1/cases/CASE-TEST-001/ask",
        headers={"Authorization": "Bearer test-token"},
        json={
            "question": "Was invoice_q4.exe downloaded and executed on WKSTN-04?",
            "unexpected": True,
        },
    )
    assert response.status_code == 422


def test_unknown_case_is_404(workspace, store: CaseStore) -> None:
    client = TestClient(create_app(workspace, token="test-token"))
    response = client.post(
        "/v1/cases/NOPE/ask",
        headers={"Authorization": "Bearer test-token"},
        json={"question": "Was x downloaded and executed on H?"},
    )
    assert response.status_code == 404
