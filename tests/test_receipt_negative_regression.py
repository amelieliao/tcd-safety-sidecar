from __future__ import annotations

import json
from typing import Any, Dict, Tuple

from tcd.attest import Attestor, verify_attestation_record_ex


def _flip_first_hex_char(value: str) -> str:
    assert value
    return ("0" if value[0] != "0" else "1") + value[1:]


def _issue_receipt() -> Dict[str, Any]:
    attestor = Attestor(hash_alg="sha256")

    return attestor.issue(
        req_obj={
            "tenant": "tenant-test",
            "user": "user-test",
            "route": "diagnose",
        },
        comp_obj={
            "decision": "allow",
            "required_action": "allow",
            "score": 0.01,
        },
        e_obj={
            "p_value": 0.99,
            "trigger": False,
        },
        witness_segments=None,
        witness_tags=["ci", "negative_receipt"],
        meta={
            "_tcd_event_id": "negative-receipt-regression-1",
            "test_case": "negative_receipt_regression",
        },
    )


def _verify(
    *,
    receipt: str,
    receipt_body: str,
    receipt_sig: str,
) -> Tuple[bool, str, Dict[str, Any]]:
    ok, reason, details = verify_attestation_record_ex(
        receipt=receipt,
        receipt_body=receipt_body,
        receipt_sig=receipt_sig,
        strict_structure=True,
        require_canonical_body=True,
        require_sig=False,
    )
    return bool(ok), str(reason), dict(details or {})


def test_valid_receipt_verifies() -> None:
    bundle = _issue_receipt()

    ok, reason, details = _verify(
        receipt=bundle["receipt"],
        receipt_body=bundle["receipt_body"],
        receipt_sig=bundle["receipt_sig"],
    )

    assert ok is True, (reason, details)


def test_tampered_receipt_head_fails_verification() -> None:
    bundle = _issue_receipt()

    ok, reason, details = _verify(
        receipt=_flip_first_hex_char(bundle["receipt"]),
        receipt_body=bundle["receipt_body"],
        receipt_sig=bundle["receipt_sig"],
    )

    assert ok is False, (reason, details)


def test_tampered_receipt_body_fails_verification() -> None:
    bundle = _issue_receipt()

    body = json.loads(bundle["receipt_body"])
    body.setdefault("meta", {})["tampered"] = True

    tampered_body = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )

    ok, reason, details = _verify(
        receipt=bundle["receipt"],
        receipt_body=tampered_body,
        receipt_sig=bundle["receipt_sig"],
    )

    assert ok is False, (reason, details)


def test_tampered_receipt_sig_fails_verification() -> None:
    bundle = _issue_receipt()

    ok, reason, details = _verify(
        receipt=bundle["receipt"],
        receipt_body=bundle["receipt_body"],
        receipt_sig=_flip_first_hex_char(bundle["receipt_sig"]),
    )

    assert ok is False, (reason, details)
