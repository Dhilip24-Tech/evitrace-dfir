"""Signed JSON Claim Proof Certificates (CPC) using per-case HMAC keys."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import UTC, datetime

from evitrace.models import Certificate, ProofPackage, Signature
from evitrace.store import CaseStore

SAFE = re.compile(r"[^A-Za-z0-9_.\-]")


def _canonical(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:16]


def issue_certificate(store: CaseStore, run_id: str, proof: ProofPackage) -> Certificate:
    key = store.key_bytes()
    certificate_id = f"cpc-{SAFE.sub('-', store.config.case_id)}-{SAFE.sub('-', run_id)}"
    unsigned = Certificate(
        certificate_id=certificate_id,
        case_id=store.config.case_id,
        run_id=run_id,
        issued_at=datetime.now(UTC),
        proof=proof,
        signature=None,
    )
    payload = unsigned.model_dump(mode="json", exclude={"signature"})
    digest = hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()
    return unsigned.model_copy(update={"signature": Signature(key_id=_key_id(key), value=digest)})


def verify_certificate(certificate: Certificate, key: bytes) -> bool:
    if certificate.signature is None:
        return False
    payload = certificate.model_dump(mode="json", exclude={"signature"})
    expected = hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, certificate.signature.value)


def certificate_json(certificate: Certificate) -> str:
    return certificate.model_dump_json(indent=2)
