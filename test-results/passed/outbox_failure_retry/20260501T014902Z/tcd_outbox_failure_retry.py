from __future__ import annotations

import hashlib
import inspect
import json
import multiprocessing as mp
import os
import sqlite3
import tempfile
import time
from typing import Any, Mapping


class LedgerUnavailable(RuntimeError):
    pass


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_hex_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class FakeLedger:
    def __init__(self) -> None:
        self.available = False
        self.rows: list[dict[str, Any]] = []

    def append(self, record: Mapping[str, Any]) -> dict[str, Any]:
        if not self.available:
            raise LedgerUnavailable("ledger unavailable")
        payload_json = canonical_json(record)
        head = hashlib.sha256(("ledger:" + payload_json).encode("utf-8")).hexdigest()
        row = dict(record)
        row["ledger_head"] = head
        self.rows.append(row)
        return {"head": head, "stored": True}


def verify_receipt_pack(pack: Mapping[str, Any]) -> bool:
    try:
        from tcd.verify import verify_receipt
    except Exception:
        return False

    kwargs = {
        "receipt_head_hex": pack.get("receipt"),
        "receipt_body_json": pack.get("receipt_body"),
        "verify_key_hex": pack.get("verify_key"),
        "receipt_sig_hex": pack.get("receipt_sig"),
        "req_obj": pack.get("req_obj"),
        "comp_obj": pack.get("comp_obj"),
        "e_obj": pack.get("e_obj"),
        "witness_segments": pack.get("witness_segments"),
        "strict": True,
    }

    try:
        sig = inspect.signature(verify_receipt)
        accepts_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
        call_kwargs = kwargs if accepts_kwargs else {k: v for k, v in kwargs.items() if k in sig.parameters}
        return bool(verify_receipt(**call_kwargs))
    except TypeError:
        try:
            kwargs.pop("strict", None)
            sig = inspect.signature(verify_receipt)
            accepts_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
            call_kwargs = kwargs if accepts_kwargs else {k: v for k, v in kwargs.items() if k in sig.parameters}
            return bool(verify_receipt(**call_kwargs))
        except Exception:
            return False
    except Exception:
        return False


def issue_receipt(request_id: str, event_id: str) -> dict[str, Any]:
    from tcd.attest import Attestor

    req_obj = {
        "request_id": request_id,
        "event_id": event_id,
        "tenant": "tenant-a",
        "user": "user-a",
        "session": "sess-a",
    }
    comp_obj = {
        "action": "reload_config",
        "ok": True,
        "test": "outbox_failure_retry",
    }
    e_obj = {
        "e_value": 1.0,
        "alpha_alloc": 0.0,
        "alpha_spent": 0.0,
    }
    witness_segments = ([1, 2, 3], [4, 5, 6], [7, 8, 9])

    attestor = Attestor()
    issue = getattr(attestor, "issue")
    kwargs = {
        "req_obj": req_obj,
        "comp_obj": comp_obj,
        "e_obj": e_obj,
        "witness_segments": witness_segments,
        "witness_tags": ("req", "comp", "e"),
        "meta": {
            "request_id": request_id,
            "event_id": event_id,
            "test": "outbox_failure_retry",
        },
    }
    sig = inspect.signature(issue)
    accepts_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
    call_kwargs = kwargs if accepts_kwargs else {k: v for k, v in kwargs.items() if k in sig.parameters}
    out = issue(**call_kwargs)

    if not isinstance(out, Mapping):
        raise RuntimeError("attestor.issue did not return a mapping")

    pack = {
        "receipt": out.get("receipt") or out.get("head"),
        "receipt_body": out.get("receipt_body") or out.get("body"),
        "receipt_sig": out.get("receipt_sig") or out.get("sig"),
        "verify_key": out.get("verify_key"),
        "receipt_ref": out.get("receipt_ref") or out.get("receipt") or out.get("head"),
        "audit_ref": out.get("audit_ref"),
        "req_obj": req_obj,
        "comp_obj": comp_obj,
        "e_obj": e_obj,
        "witness_segments": witness_segments,
    }
    pack["receipt_verified"] = verify_receipt_pack(pack)
    return pack


def child_put_outbox(path: str, kind: str, dedupe_key: str, payload_json: str, payload_digest: str, result_path: str) -> None:
    result: dict[str, Any] = {"ok": False, "status": None, "error": None}
    try:
        from tcd.service_grpc import _SQLiteOutbox

        outbox = _SQLiteOutbox(
            path,
            max_rows=1000,
            max_db_bytes=64 * 1024 * 1024,
            max_payload_bytes=512 * 1024,
            drop_policy="drop_oldest",
        )
        status = outbox.put(
            kind=kind,
            dedupe_key=dedupe_key,
            payload_json=payload_json,
            payload_digest=payload_digest,
        )
        result = {"ok": True, "status": status, "error": None}
    except Exception as exc:
        result = {"ok": False, "status": None, "error": str(exc)}
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, sort_keys=True)


def put_outbox_with_timeout(path: str, kind: str, dedupe_key: str, payload_json: str, payload_digest: str, timeout_s: float = 8.0) -> dict[str, Any]:
    result_path = path + ".put-result-" + os.urandom(4).hex() + ".json"
    ctx = mp.get_context("spawn")
    proc = ctx.Process(
        target=child_put_outbox,
        args=(path, kind, dedupe_key, payload_json, payload_digest, result_path),
    )
    proc.start()
    proc.join(timeout_s)
    if proc.is_alive():
        proc.terminate()
        proc.join(1.0)
        if proc.is_alive():
            try:
                proc.kill()
            except Exception:
                pass
        return {"ok": False, "status": "timeout", "error": "outbox_put_timeout", "returncode": None}
    if not os.path.exists(result_path):
        return {"ok": False, "status": None, "error": "missing_child_result", "returncode": proc.exitcode}
    with open(result_path, "r", encoding="utf-8") as f:
        result = json.load(f)
    result["returncode"] = proc.exitcode
    try:
        os.remove(result_path)
    except Exception:
        pass
    return result


def read_outbox_rows(path: str) -> list[dict[str, Any]]:
    if not os.path.exists(path):
        return []
    conn = sqlite3.connect(path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        rows = list(
            conn.execute(
                "SELECT id, kind, dedupe_key, payload_json, payload_digest, attempts FROM outbox ORDER BY id ASC"
            )
        )
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def delete_outbox_row(path: str, row_id: int) -> None:
    conn = sqlite3.connect(path, timeout=5.0)
    try:
        conn.execute("DELETE FROM outbox WHERE id=?", (int(row_id),))
        conn.commit()
    finally:
        conn.close()


def flush_outbox(path: str, ledger: FakeLedger) -> dict[str, Any]:
    rows = read_outbox_rows(path)
    flushed = 0
    committed = 0
    verified = 0
    errors: list[str] = []
    receipt_refs: list[str] = []
    ledger_heads: list[str] = []

    for row in rows:
        try:
            payload_json = row["payload_json"]
            expected_digest = row["payload_digest"]
            actual_digest = sha256_hex_text(payload_json)
            if actual_digest != expected_digest:
                errors.append("payload_digest_mismatch")
                continue
            payload = json.loads(payload_json)
            receipt_pack = payload.get("receipt_pack") if isinstance(payload, dict) else None
            if not isinstance(receipt_pack, Mapping):
                errors.append("missing_receipt_pack")
                continue
            receipt_ok = verify_receipt_pack(receipt_pack)
            if not receipt_ok:
                errors.append("receipt_verify_failed")
                continue
            verified += 1
            payload["outbox_status"] = "flushed"
            payload["ledger_stage"] = "committed"
            payload["delivery_attempts"] = int(payload.get("delivery_attempts") or 0) + 1
            commit = ledger.append(payload)
            committed += 1
            flushed += 1
            if payload.get("receipt_ref"):
                receipt_refs.append(str(payload.get("receipt_ref")))
            if commit.get("head"):
                ledger_heads.append(str(commit.get("head")))
            delete_outbox_row(path, int(row["id"]))
        except Exception as exc:
            errors.append(str(exc))

    return {
        "flushed": flushed,
        "committed": committed,
        "verified": verified,
        "errors": errors,
        "receipt_refs": receipt_refs,
        "ledger_heads": ledger_heads,
        "remaining_rows": len(read_outbox_rows(path)),
    }


def main() -> int:
    root = tempfile.mkdtemp(prefix="tcd-outbox-failure-retry-")
    outbox_path = os.path.join(root, "outbox.sqlite3")
    request_id = "outbox-failure-retry"
    idempotency_key = "idem-outbox-failure-retry"
    event_id = "evt:" + sha256_hex_text(idempotency_key)[:32]
    dedupe_key = "ledger:" + idempotency_key
    ledger = FakeLedger()

    receipt_pack = issue_receipt(request_id, event_id)
    request_payload = {
        "schema": "tcd.test.outbox_failure_retry.v1",
        "request_id": request_id,
        "event_id": event_id,
        "idempotency_key": idempotency_key,
        "action": "reload_config",
        "tenant": "tenant-a",
        "user": "user-a",
        "receipt_ref": receipt_pack.get("receipt_ref"),
        "receipt_pack": receipt_pack,
        "ledger_stage": "outboxed",
        "outbox_status": "queued",
        "outbox_dedupe_key": dedupe_key,
        "delivery_attempts": 0,
        "created_ts": time.time(),
    }
    payload_json = canonical_json(request_payload)
    payload_digest = sha256_hex_text(payload_json)

    ledger_unavailable_forced = False
    try:
        ledger.append(request_payload)
    except LedgerUnavailable:
        ledger_unavailable_forced = True

    put_result_1 = put_outbox_with_timeout(outbox_path, "ledger", dedupe_key, payload_json, payload_digest)
    put_result_2 = put_outbox_with_timeout(outbox_path, "ledger", dedupe_key, payload_json, payload_digest)

    rows_after_queue = read_outbox_rows(outbox_path)
    queued_payloads = []
    for row in rows_after_queue:
        try:
            queued_payloads.append(json.loads(row["payload_json"]))
        except Exception:
            pass

    ledger.available = True
    flush_result = flush_outbox(outbox_path, ledger)
    rows_after_flush = read_outbox_rows(outbox_path)

    committed_rows = list(ledger.rows)
    committed_payload = committed_rows[0] if committed_rows else {}
    receipt_verified_after_flush = False
    if committed_payload:
        receipt_verified_after_flush = verify_receipt_pack(committed_payload.get("receipt_pack") or {})

    checks = {
        "ledger_unavailable_forced": bool(ledger_unavailable_forced),
        "receipt_ref_present": bool(receipt_pack.get("receipt_ref")),
        "receipt_verified_at_issue": bool(receipt_pack.get("receipt_verified")),
        "outbox_put_completed": bool(put_result_1.get("ok")),
        "outbox_put_status_queued": bool(put_result_1.get("status") == "queued"),
        "duplicate_put_ignored": bool(put_result_2.get("status") == "ignored"),
        "outbox_status_queued": bool(len(rows_after_queue) == 1 and queued_payloads and queued_payloads[0].get("outbox_status") == "queued"),
        "no_duplicate_outbox_rows": bool(len(rows_after_queue) == 1),
        "ledger_restored": bool(ledger.available),
        "flush_verified": bool(flush_result.get("verified") == 1),
        "flush_committed": bool(flush_result.get("committed") == 1 and len(committed_rows) == 1),
        "outbox_status_flushed_or_committed": bool(committed_payload.get("outbox_status") in {"flushed", "committed"} and committed_payload.get("ledger_stage") == "committed"),
        "outbox_empty_after_flush": bool(len(rows_after_flush) == 0),
        "receipt_verified_after_flush": bool(receipt_verified_after_flush),
        "same_receipt_ref": bool((committed_payload.get("receipt_ref") or None) == (receipt_pack.get("receipt_ref") or None)),
        "payload_digest_stable": bool(rows_after_queue and rows_after_queue[0].get("payload_digest") == payload_digest),
    }

    report = {
        "ok": all(checks.values()),
        "checks": checks,
        "failed_checks": [k for k, v in checks.items() if not v],
        "root": root,
        "outbox_path": outbox_path,
        "request_id": request_id,
        "idempotency_key": idempotency_key,
        "event_id": event_id,
        "dedupe_key": dedupe_key,
        "put_result_1": put_result_1,
        "put_result_2": put_result_2,
        "outbox_rows_after_queue": rows_after_queue,
        "outbox_rows_after_flush": rows_after_flush,
        "flush_result": flush_result,
        "ledger_rows_after_flush": committed_rows,
        "receipt_ref": receipt_pack.get("receipt_ref"),
        "receipt_verified_at_issue": bool(receipt_pack.get("receipt_verified")),
        "receipt_verified_after_flush": receipt_verified_after_flush,
    }

    print(json.dumps(report, sort_keys=True, ensure_ascii=False))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    mp.freeze_support()
    raise SystemExit(main())
