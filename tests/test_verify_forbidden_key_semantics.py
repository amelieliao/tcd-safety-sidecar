
import json

from tcd.verify import (
    R_BODY_SECURITY_INVALID,
    ReceiptVerifyReport,
    _scan_forbidden_keys,
    _tcd_v2_contract_rewrite,
    _tcd_v2_report_copy,
    _validate_body_security,
)


def test_verify_structural_keys_do_not_trigger_forbidden_key_scan():
    payload = {
        "receipt_body_json": "{}",
        "receipt_sig_hex": "00",
        "receipt_verify_key": "test-key",
        "verify_key": "test-key",
        "verify_key_id": "kid",
        "verify_key_fp": "sha256:" + "a" * 64,
        "expected_policy_ref": "policy@v1",
        "expected_cfg_fp": "hcfg3:sha256:" + "a" * 64,
        "body_digest": "sha256:" + "b" * 64,
        "payload_digest": "sha256:" + "c" * 64,
        "request_id": "req-123",
        "auth_mode": "hmac",
    }

    found = _scan_forbidden_keys(payload, max_depth=8)

    assert found == []


def test_attestation_signature_block_is_structural_not_raw_auth():
    body = {
        "v": 2,
        "schema": "tcd.attest.body.v2",
        "ts_ns": 1,
        "nonce": "n",
        "attestor": {
            "id": "att",
            "hash_alg": "sha256",
            "hash_ctx": "tcd:attest",
            "digest_size": 32,
        },
        "claims": {
            "policy_ref": "policy@v1",
            "cfg_fp": "hcfg3:sha256:" + "a" * 64,
        },
        "auth_sig": {
            "alg": "ed25519",
            "key_id": "kid",
            "val": "AA==",
        },
    }

    found = _scan_forbidden_keys(body, max_depth=8)

    assert found == []
    ok, errs = _validate_body_security(body, strict=True)
    assert ok is True
    assert "forbidden_key_present" not in errs


def test_real_content_keys_still_trigger_forbidden_key_scan():
    payload = {
        "meta": {
            "prompt": "do not leak this",
            "request_body": "raw body",
            "authorization": "Bearer definitely-not-safe",
        }
    }

    found = _scan_forbidden_keys(payload, max_depth=8)

    assert found
    assert any("prompt" in x for x in found)
    assert any("request_body" in x for x in found)
    assert any("authorization" in x for x in found)


def test_forbidden_key_present_is_blocking_not_compat_relaxed():
    body = json.dumps(
        {
            "v": 2,
            "schema": "tcd.attest.body.v2",
            "prompt": "raw prompt must not be in receipt",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    report = ReceiptVerifyReport(
        ok=False,
        reason=R_BODY_SECURITY_INVALID,
        strict=True,
        head_verified=True,
        integrity_hash_verified=True,
        integrity_ok=False,
        integrity_errors=("forbidden_key_present", "forbidden_key:prompt"),
    )

    out = _tcd_v2_contract_rewrite(report, receipt_body_json=body)

    assert out.ok is False
    assert "forbidden_key_present" in tuple(out.errors)


def test_report_copy_clears_integrity_errors_when_marking_ok():
    report = ReceiptVerifyReport(
        ok=False,
        reason=R_BODY_SECURITY_INVALID,
        strict=True,
        integrity_ok=False,
        integrity_errors=("e_value_invalid",),
    )

    out = _tcd_v2_report_copy(report, ok=True, errors=[], warnings=["compat"])

    assert out.ok is True
    assert out.integrity_ok is True
    assert tuple(out.integrity_errors) == ()
    assert out.to_dict()["errors"] == []
