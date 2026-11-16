"""Optional loopback FastAPI service with bearer-token auth."""

from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import Field

from evitrace.claims import prove_claim
from evitrace.cpc import issue_certificate
from evitrace.models import RunRecord, StrictModel
from evitrace.planner import plan_question
from evitrace.store import CaseStore, StoreError


class AskRequest(StrictModel):
    question: str = Field(min_length=3, max_length=2_000)
    alpha: float = Field(default=0.05, gt=0, lt=1)


def create_app(workspace: Path | None = None, token: str | None = None) -> FastAPI:
    root = (workspace or Path(os.environ.get("EVITRACE_WORKSPACE", "./workspace"))).resolve()
    expected = token or os.environ.get("EVITRACE_API_TOKEN", "")
    if not expected:
        raise RuntimeError("EVITRACE_API_TOKEN must be set; no default bearer token is allowed")
    app = FastAPI(title="EviTrace-DFIR local API", version="0.1.0")

    def auth(authorization: str = Header(default="")) -> None:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(value, expected):
            raise HTTPException(status_code=401, detail="invalid bearer token")

    def store_for(case_id: str) -> CaseStore:
        try:
            return CaseStore.open(root, case_id)
        except StoreError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": "local-only"}

    @app.post("/v1/cases/{case_id}/ask", dependencies=[Depends(auth)])
    def ask(case_id: str, request: AskRequest) -> dict[str, Any]:
        store = store_for(case_id)
        calibration = store.latest_calibration(request.alpha)
        if calibration is None:
            raise HTTPException(status_code=409, detail="case has no calibration for alpha")
        claim = plan_question(request.question, store)
        proof = prove_claim(claim, store, qhat=calibration.qhat, alpha=request.alpha)
        run_id = f"api-{claim.claim_id}"
        certificate = issue_certificate(store, run_id, proof)
        store.save_run(
            RunRecord(
                run_id=run_id,
                case_id=case_id,
                question_id="API",
                question=request.question,
                verdict=proof.verdict,
                certificate_id=certificate.certificate_id,
            ),
            certificate,
        )
        return certificate.model_dump(mode="json")

    @app.get("/v1/cases/{case_id}/runs/{run_id}", dependencies=[Depends(auth)])
    def run(case_id: str, run_id: str) -> dict[str, Any]:
        store = store_for(case_id)
        certificate = store.certificate(run_id)
        if certificate is None:
            raise HTTPException(status_code=404, detail="unknown run")
        return certificate.model_dump(mode="json")

    return app


app = FastAPI(title="EviTrace-DFIR local API", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "local-only"}
