#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures as cf
import contextlib
import json
import os
import random
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional


APP_CODE = r'''
from __future__ import annotations

import hashlib
import json
import os
import random
import sqlite3
import time
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException

from tcd.storage import (
    ReceiptEnvelope,
    SQLiteReceiptStore,
    StorageConfig,
    StorageConflictError,
    StorageError,
    StorageIntegrityError,
)

DB_PATH = os.environ["TCD_MP_DB_PATH"]
CHAIN_NAMESPACE = os.environ.get("TCD_MP_CHAIN_NAMESPACE", "mpwrite")
CHAIN_ID = os.environ.get("TCD_MP_CHAIN_ID", "durable-block-chain")
RUN_ID = os.environ.get("TCD_MP_RUN_ID", "run")
MAX_RETRIES = int(os.environ.get("TCD_MP_APP_RETRIES", "1000"))
SQLITE_TIMEOUT_S = float(os.environ.get("TCD_MP_SQLITE_TIMEOUT_S", "30.0"))

CFG_FP = "cfg:sha256:" + hashlib.sha256(
    ("tcd-storage-multi-process-write:" + RUN_ID).encode("utf-8")
).hexdigest()

store = SQLiteReceiptStore(
    DB_PATH,
    config=StorageConfig(
        profile="PROD",
        sqlite_timeout_s=SQLITE_TIMEOUT_S,
        sqlite_synchronous="FULL",
        validate_receipt_json=True,
        canonicalize_receipt_body=True,
        strict_dict_top_level_external=False,
        reject_forbidden_body_keys=True,
        verify_receipt_head=True,
        enforce_single_genesis_per_chain=True,
        require_chain_leaf_append=True,
        fail_closed_on_chain_ambiguity=True,
    ),
)

app = FastAPI(title="tcd-storage-multi-process-write-test")


def _canon(obj: Any) -> str:
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sleep_backoff(attempt: int) -> None:
    delay = min(0.050, 0.0008 * (2 ** min(attempt, 6)))
    time.sleep(delay + random.random() * 0.006)


def _latest_record():
    return store.latest(chain_namespace=CHAIN_NAMESPACE, chain_id=CHAIN_ID)


def _build_receipt(idx: int, attempt: int, prev_chain_head: Optional[str], seq_hint: int) -> ReceiptEnvelope:
    event_id = f"ev-mpwrite-{RUN_ID}-{idx:06d}"
    decision_id = f"dc-mpwrite-{RUN_ID}-{idx:06d}"
    route_plan_id = f"rp-mpwrite-{RUN_ID}-{idx:06d}"

    body_base: Dict[str, Any] = {
        "schema": "tcd.storage.receipt.v3",
        "schema_version": 3,
        "canonicalization_version": "canonjson_v1",
        "receipt_kind": "decision",
        "event_type": "durable_block",
        "event_id": event_id,
        "decision_id": decision_id,
        "route_plan_id": route_plan_id,
        "policy_ref": "storage-mpwrite-test",
        "policyset_ref": "storage-tests",
        "cfg_fp": CFG_FP,
        "chain_namespace": CHAIN_NAMESPACE,
        "chain_id": CHAIN_ID,
        "chain_seq": seq_hint,
        "prev_head_hex": prev_chain_head,
        "action": "block",
        "reason": "ROUTE_BLOCK",
        "selected_source": "storage_test",
        "statistical_guarantee_scope": "none",
        "trigger": True,
        "allowed": False,
        "ts_unix_ns": time.time_ns(),
        "audit_ref": f"audit@mpwrite#{idx:06d}",
        "receipt_ref": f"receipt@mpwrite#{idx:06d}",
        "produced_by": ["tcd.storage.mpwrite"],
        "meta": {
            "idx": idx,
            "pid": os.getpid(),
            "try_no": attempt,
            "seq_hint": seq_hint,
            "run": RUN_ID,
        },
    }

    head_input = {
        "body": body_base,
        "pid": os.getpid(),
        "attempt": attempt,
    }
    head_hex = hashlib.sha256(_canon(head_input).encode("utf-8")).hexdigest()

    body = dict(body_base)
    body["head"] = head_hex
    body_json = _canon(body)

    return ReceiptEnvelope(
        head_hex=head_hex,
        body_json=body_json,
        head_semantics="external_receipt_passthrough",
        event_id=event_id,
        decision_id=decision_id,
        route_plan_id=route_plan_id,
        policy_ref="storage-mpwrite-test",
        policyset_ref="storage-tests",
        cfg_fp=CFG_FP,
        chain_namespace=CHAIN_NAMESPACE,
        chain_id=CHAIN_ID,
        chain_seq=seq_hint,
        prev_head_hex=prev_chain_head,
        action="block",
        reason="ROUTE_BLOCK",
        selected_source="storage_test",
        statistical_guarantee_scope="none",
        trigger=True,
        allowed=False,
        audit_ref=f"audit@mpwrite#{idx:06d}",
        receipt_ref=f"receipt@mpwrite#{idx:06d}",
        produced_by=("tcd.storage.mpwrite",),
        meta={
            "idx": idx,
            "pid": os.getpid(),
            "try_no": attempt,
            "seq_hint": seq_hint,
            "run": RUN_ID,
        },
    )


@app.get("/healthz")
def healthz() -> Dict[str, Any]:
    return {
        "ok": True,
        "pid": os.getpid(),
        "db_path": DB_PATH,
        "chain_namespace": CHAIN_NAMESPACE,
        "chain_id": CHAIN_ID,
    }


@app.get("/pid")
def pid() -> Dict[str, Any]:
    return {"pid": os.getpid()}


@app.post("/durable-block")
def durable_block(inp: Dict[str, Any]) -> Dict[str, Any]:
    try:
        idx = int(inp.get("i"))
    except Exception:
        raise HTTPException(status_code=400, detail="missing integer field i")

    conflict_retries = 0
    sqlite_lock_retries = 0
    last_error: Optional[str] = None

    for attempt in range(MAX_RETRIES):
        try:
            latest = _latest_record()
            prev_chain_head = latest.chain_head_hex if latest is not None else None
            seq_hint = (
                int(latest.chain_seq) + 1
                if latest is not None and latest.chain_seq is not None
                else 0
            )

            env = _build_receipt(
                idx=idx,
                attempt=attempt,
                prev_chain_head=prev_chain_head,
                seq_hint=seq_hint,
            )
            put = store.put_receipt(env)

            return {
                "ok": True,
                "pid": os.getpid(),
                "idx": idx,
                "attempt": attempt,
                "conflict_retries": conflict_retries,
                "sqlite_lock_retries": sqlite_lock_retries,
                "head_hex": put.head_hex,
                "chain_head_hex": put.chain_head_hex,
                "chain_seq": put.chain_seq,
                "stored": put.stored,
                "idempotent": put.idempotent,
                "reason": put.reason,
                "event_id": put.event_id,
                "decision_id": put.decision_id,
            }

        except StorageConflictError as exc:
            conflict_retries += 1
            last_error = f"{type(exc).__name__}: {exc}"
            _sleep_backoff(attempt)
            continue

        except sqlite3.OperationalError as exc:
            msg = str(exc).lower()
            last_error = f"{type(exc).__name__}: {exc}"
            if "locked" in msg or "busy" in msg:
                sqlite_lock_retries += 1
                _sleep_backoff(attempt)
                continue
            raise HTTPException(status_code=500, detail=last_error)

        except StorageIntegrityError as exc:
            raise HTTPException(status_code=500, detail=f"{type(exc).__name__}: {exc}")

        except StorageError as exc:
            raise HTTPException(status_code=500, detail=f"{type(exc).__name__}: {exc}")

        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"{type(exc).__name__}: {exc}")

    raise HTTPException(
        status_code=503,
        detail={
            "error": "exhausted_retries",
            "idx": idx,
            "conflict_retries": conflict_retries,
            "sqlite_lock_retries": sqlite_lock_retries,
            "last_error": last_error,
        },
    )
'''


def _repo_root() -> Path:
    root = Path.cwd().resolve()
    if not (root / "tcd").exists():
        raise SystemExit("Run from repo root, for example: /Users/amelieliao/tcd-safety-sidecar")
    return root


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _http_json(method: str, url: str, data: Optional[Dict[str, Any]] = None, timeout: float = 5.0) -> Dict[str, Any]:
    body = None
    headers: Dict[str, str] = {}
    if data is not None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw) if raw else {}
            return {"ok": True, "status": int(resp.status), "json": parsed}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw) if raw else {}
        except Exception:
            parsed = {"raw": raw}
        return {"ok": False, "status": int(exc.code), "json": parsed}
    except Exception as exc:
        return {
            "ok": False,
            "status": None,
            "error_kind": type(exc).__name__,
            "error": str(exc),
        }


def _wait_ready(proc: subprocess.Popen, port: int, timeout_s: float = 45.0) -> None:
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"uvicorn exited early with code {proc.returncode}")
        res = _http_json("GET", f"http://127.0.0.1:{port}/healthz", timeout=1.5)
        last = res
        if res.get("ok") and res.get("status") == 200 and res.get("json", {}).get("ok") is True:
            return
        time.sleep(0.20)
    raise TimeoutError(f"server did not become ready; last={last}")


def _collect_worker_pids(port: int, tries: int = 160) -> List[int]:
    pids = set()
    for _ in range(tries):
        res = _http_json("GET", f"http://127.0.0.1:{port}/pid", timeout=2.0)
        if res.get("ok") and res.get("status") == 200:
            pid = res.get("json", {}).get("pid")
            if isinstance(pid, int):
                pids.add(pid)
        if len(pids) >= 2:
            break
        time.sleep(0.035)
    return sorted(pids)


def _post_block(port: int, idx: int, timeout_s: float) -> Dict[str, Any]:
    t0 = time.perf_counter()
    res = _http_json(
        "POST",
        f"http://127.0.0.1:{port}/durable-block",
        data={"i": idx},
        timeout=timeout_s,
    )
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
    ok = bool(res.get("ok") and res.get("status") == 200 and res.get("json", {}).get("ok") is True)
    return {
        "ok": ok,
        "idx": idx,
        "status": res.get("status"),
        "latency_ms": elapsed_ms,
        "response": res.get("json"),
        "error_kind": res.get("error_kind"),
        "error": res.get("error"),
    }


def _run_load(port: int, total: int, concurrency: int, http_timeout_s: float, overall_timeout_s: float) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    with cf.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(_post_block, port, i, http_timeout_s) for i in range(total)]
        try:
            for fut in cf.as_completed(futures, timeout=overall_timeout_s):
                try:
                    results.append(fut.result())
                except Exception as exc:
                    results.append(
                        {
                            "ok": False,
                            "status": None,
                            "error_kind": type(exc).__name__,
                            "error": str(exc),
                        }
                    )
        except cf.TimeoutError:
            pending = [f for f in futures if not f.done()]
            for f in pending:
                f.cancel()
            results.extend(
                {
                    "ok": False,
                    "status": None,
                    "error_kind": "ClientOverallTimeout",
                    "error": "load phase exceeded overall timeout",
                }
                for _ in pending
            )
    return results


def _storage_config_kwargs() -> Dict[str, Any]:
    return {
        "profile": "PROD",
        "sqlite_timeout_s": 30.0,
        "sqlite_synchronous": "FULL",
        "validate_receipt_json": True,
        "canonicalize_receipt_body": True,
        "strict_dict_top_level_external": False,
        "reject_forbidden_body_keys": True,
        "verify_receipt_head": True,
        "enforce_single_genesis_per_chain": True,
        "require_chain_leaf_append": True,
        "fail_closed_on_chain_ambiguity": True,
    }


def _preinit_db(db_path: Path) -> None:
    from tcd.storage import SQLiteReceiptStore, StorageConfig

    store = SQLiteReceiptStore(str(db_path), config=StorageConfig(**_storage_config_kwargs()))
    store.stats()
    with contextlib.suppress(Exception):
        store._db.close()


def _verify_window(db_path: Path, chain_namespace: str, chain_id: str, limit: int) -> Dict[str, Any]:
    from tcd.storage import SQLiteReceiptStore, StorageConfig

    store = SQLiteReceiptStore(str(db_path), config=StorageConfig(**_storage_config_kwargs()))
    try:
        report = store.verify_window(
            chain_namespace=chain_namespace,
            chain_id=chain_id,
            limit=limit,
        ).to_dict()
        stats = store.stats()
        return {"report": report, "stats": stats}
    finally:
        with contextlib.suppress(Exception):
            store._db.close()


def _inspect_db(db_path: Path, chain_namespace: str, chain_id: str) -> Dict[str, Any]:
    conn = sqlite3.connect(str(db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    try:
        journal_mode = str(conn.execute("PRAGMA journal_mode").fetchone()[0])

        params = (chain_namespace, chain_id)

        row_count = int(conn.execute(
            "SELECT COUNT(*) AS n FROM receipts_v2 WHERE chain_namespace=? AND chain_id=?",
            params,
        ).fetchone()["n"])

        duplicate_receipt_heads = int(conn.execute("""
            SELECT COUNT(*) AS n FROM (
                SELECT head_hex FROM receipts_v2
                WHERE chain_namespace=? AND chain_id=?
                GROUP BY head_hex HAVING COUNT(*) > 1
            )
        """, params).fetchone()["n"])

        duplicate_chain_heads = int(conn.execute("""
            SELECT COUNT(*) AS n FROM (
                SELECT chain_head_hex FROM receipts_v2
                WHERE chain_namespace=? AND chain_id=?
                GROUP BY chain_head_hex HAVING COUNT(*) > 1
            )
        """, params).fetchone()["n"])

        duplicate_chain_seq = int(conn.execute("""
            SELECT COUNT(*) AS n FROM (
                SELECT chain_seq FROM receipts_v2
                WHERE chain_namespace=? AND chain_id=?
                GROUP BY chain_seq HAVING COUNT(*) > 1
            )
        """, params).fetchone()["n"])

        genesis_count = int(conn.execute("""
            SELECT COUNT(*) AS n FROM receipts_v2
            WHERE chain_namespace=? AND chain_id=? AND prev_chain_head_hex IS NULL
        """, params).fetchone()["n"])

        forks = int(conn.execute("""
            SELECT COUNT(*) AS n FROM (
                SELECT prev_chain_head_hex FROM receipts_v2
                WHERE chain_namespace=? AND chain_id=? AND prev_chain_head_hex IS NOT NULL
                GROUP BY prev_chain_head_hex HAVING COUNT(*) > 1
            )
        """, params).fetchone()["n"])

        leaves = int(conn.execute("""
            SELECT COUNT(*) AS n
            FROM receipts_v2 r
            WHERE r.chain_namespace=? AND r.chain_id=?
              AND NOT EXISTS (
                SELECT 1 FROM receipts_v2 c
                WHERE c.chain_namespace=r.chain_namespace
                  AND c.chain_id=r.chain_id
                  AND c.prev_chain_head_hex=r.chain_head_hex
              )
        """, params).fetchone()["n"])

        missing_prev = int(conn.execute("""
            SELECT COUNT(*) AS n
            FROM receipts_v2 c
            LEFT JOIN receipts_v2 p
              ON p.chain_namespace=c.chain_namespace
             AND p.chain_id=c.chain_id
             AND p.chain_head_hex=c.prev_chain_head_hex
            WHERE c.chain_namespace=? AND c.chain_id=?
              AND c.prev_chain_head_hex IS NOT NULL
              AND p.store_id IS NULL
        """, params).fetchone()["n"])

        self_loops = int(conn.execute("""
            SELECT COUNT(*) AS n
            FROM receipts_v2
            WHERE chain_namespace=? AND chain_id=?
              AND prev_chain_head_hex IS NOT NULL
              AND (prev_chain_head_hex = chain_head_hex OR prev_chain_head_hex = head_hex)
        """, params).fetchone()["n"])

        seq_row = conn.execute("""
            SELECT
                MIN(chain_seq) AS min_seq,
                MAX(chain_seq) AS max_seq,
                COUNT(DISTINCT chain_seq) AS distinct_seq
            FROM receipts_v2
            WHERE chain_namespace=? AND chain_id=?
        """, params).fetchone()

        latest = conn.execute("""
            SELECT store_id, head_hex, chain_head_hex, prev_chain_head_hex, chain_seq, event_id, decision_id
            FROM receipts_v2
            WHERE chain_namespace=? AND chain_id=?
            ORDER BY chain_seq DESC, ts_unix_ns DESC, store_id DESC
            LIMIT 1
        """, params).fetchone()

        rows = list(conn.execute("""
            SELECT store_id, chain_seq, body_json, meta_json
            FROM receipts_v2
            WHERE chain_namespace=? AND chain_id=?
            ORDER BY chain_seq ASC, store_id ASC
        """, params))

        writer_pids = set()
        body_parse_errors = 0
        for row in rows:
            found = False
            for raw in (row["body_json"], row["meta_json"]):
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except Exception:
                    body_parse_errors += 1
                    continue
                if isinstance(obj, dict):
                    meta = obj.get("meta") if isinstance(obj.get("meta"), dict) else obj
                    pid = meta.get("pid") if isinstance(meta, dict) else None
                    if isinstance(pid, int):
                        writer_pids.add(pid)
                        found = True
                        break
            if not found:
                continue

        return {
            "journal_mode": journal_mode,
            "row_count": row_count,
            "duplicate_receipt_heads": duplicate_receipt_heads,
            "duplicate_chain_heads": duplicate_chain_heads,
            "duplicate_chain_seq": duplicate_chain_seq,
            "genesis_count": genesis_count,
            "forks": forks,
            "leaves": leaves,
            "missing_prev": missing_prev,
            "self_loops": self_loops,
            "min_seq": None if seq_row["min_seq"] is None else int(seq_row["min_seq"]),
            "max_seq": None if seq_row["max_seq"] is None else int(seq_row["max_seq"]),
            "distinct_seq": int(seq_row["distinct_seq"] or 0),
            "writer_pids": sorted(writer_pids),
            "body_parse_errors": body_parse_errors,
            "latest": dict(latest) if latest is not None else None,
        }
    finally:
        conn.close()


def _tail_file(path: Path, max_bytes: int = 20000) -> str:
    if not path.exists():
        return ""
    data = path.read_bytes()
    return data[-max_bytes:].decode("utf-8", errors="replace")


def _stop_process(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    with contextlib.suppress(Exception):
        proc.terminate()
        proc.wait(timeout=8)
    if proc.poll() is None:
        with contextlib.suppress(Exception):
            proc.kill()
            proc.wait(timeout=5)


def main() -> int:
    repo = _repo_root()

    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
        import tcd.storage  # noqa: F401
    except Exception as exc:
        print("ok = False")
        print(f"failed_checks = [{{'name': 'imports_available', 'passed': False, 'details': {type(exc).__name__!r} + ': ' + {str(exc)!r}}}]")
        return 1

    requests_total = max(2, int(os.environ.get("TCD_MP_REQUESTS", "128")))
    concurrency = max(1, min(requests_total, int(os.environ.get("TCD_MP_CONCURRENCY", "32"))))
    http_timeout_s = float(os.environ.get("TCD_MP_HTTP_TIMEOUT_S", "30"))
    overall_timeout_s = float(os.environ.get("TCD_MP_OVERALL_TIMEOUT_S", str(max(180, requests_total * 4))))

    chain_namespace = os.environ.get("TCD_MP_CHAIN_NAMESPACE", "mpwrite")
    chain_id = os.environ.get("TCD_MP_CHAIN_ID", "durable-block-chain")
    run_id = os.environ.get("TCD_MP_RUN_ID", f"{int(time.time())}-{os.getpid()}")

    tmp_root = Path(tempfile.mkdtemp(prefix="tcd-storage-mpwrite-")).resolve()
    db_path = tmp_root / "shared-storage.sqlite3"
    app_path = tmp_root / "mp_write_app.py"
    uvicorn_log = tmp_root / "uvicorn.log"
    result_path = Path("/tmp/tcd_multi_process_write_result.json")

    proc: Optional[subprocess.Popen] = None
    log_fh = None

    checks: List[Dict[str, Any]] = []
    failed_checks: List[Dict[str, Any]] = []

    def check(name: str, passed: bool, details: Any = None) -> None:
        item = {"name": name, "passed": bool(passed), "details": details}
        checks.append(item)
        if not passed:
            failed_checks.append(item)

    try:
        app_path.write_text(APP_CODE, encoding="utf-8")
        _preinit_db(db_path)

        port = _find_free_port()
        env = os.environ.copy()
        env["TCD_MP_DB_PATH"] = str(db_path)
        env["TCD_MP_CHAIN_NAMESPACE"] = chain_namespace
        env["TCD_MP_CHAIN_ID"] = chain_id
        env["TCD_MP_RUN_ID"] = run_id
        env["PYTHONPATH"] = os.pathsep.join([
            str(repo),
            str(tmp_root),
            env.get("PYTHONPATH", ""),
        ])

        cmd = [
            sys.executable,
            "-m",
            "uvicorn",
            "mp_write_app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--workers",
            "2",
            "--log-level",
            "warning",
        ]

        log_fh = uvicorn_log.open("w", encoding="utf-8")
        proc = subprocess.Popen(
            cmd,
            cwd=str(tmp_root),
            env=env,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            text=True,
        )

        _wait_ready(proc, port)
        pids_before = _collect_worker_pids(port)

        t0 = time.perf_counter()
        results = _run_load(
            port=port,
            total=requests_total,
            concurrency=concurrency,
            http_timeout_s=http_timeout_s,
            overall_timeout_s=overall_timeout_s,
        )
        load_elapsed_s = round(time.perf_counter() - t0, 3)

        pids_after = _collect_worker_pids(port)

        response_pids = sorted({
            int(r.get("response", {}).get("pid"))
            for r in results
            if isinstance(r.get("response"), dict) and isinstance(r.get("response", {}).get("pid"), int)
        })
        worker_pids_observed = sorted(set(pids_before) | set(pids_after) | set(response_pids))

        proc_alive_after_load = proc.poll() is None

        _stop_process(proc)
        proc = None
        if log_fh is not None:
            log_fh.close()
            log_fh = None

        successes = [r for r in results if r.get("ok") is True]
        failures = [r for r in results if r.get("ok") is not True]

        statuses: Dict[str, int] = {}
        for r in results:
            statuses[str(r.get("status"))] = statuses.get(str(r.get("status")), 0) + 1

        total_conflict_retries = sum(
            int(r.get("response", {}).get("conflict_retries", 0))
            for r in successes
            if isinstance(r.get("response"), dict)
        )
        total_sqlite_lock_retries = sum(
            int(r.get("response", {}).get("sqlite_lock_retries", 0))
            for r in successes
            if isinstance(r.get("response"), dict)
        )
        max_attempt = max(
            [
                int(r.get("response", {}).get("attempt", 0))
                for r in successes
                if isinstance(r.get("response"), dict)
            ] or [0]
        )

        db_report = _inspect_db(db_path, chain_namespace, chain_id)
        verify_status = _verify_window(db_path, chain_namespace, chain_id, limit=requests_total + 32)
        verify_report = verify_status["report"]

        check(
            "uvicorn_parent_survived_load",
            proc_alive_after_load,
            {"proc_alive_after_load": proc_alive_after_load},
        )
        check(
            "two_uvicorn_workers_observed",
            len(worker_pids_observed) >= 2,
            {"worker_pids_observed": worker_pids_observed, "response_pids": response_pids},
        )
        check(
            "two_workers_participated_in_writes",
            len(db_report["writer_pids"]) >= 2,
            {"writer_pids": db_report["writer_pids"]},
        )
        check(
            "all_client_futures_completed",
            len(results) == requests_total,
            {"expected": requests_total, "actual": len(results)},
        )
        check(
            "all_durable_block_requests_ok",
            len(successes) == requests_total and not failures,
            {"successes": len(successes), "failures": failures[:10], "statuses": statuses},
        )
        check(
            "no_client_timeout_deadlock",
            not any(
                r.get("error_kind") == "ClientOverallTimeout"
                or "timeout" in str(r.get("error_kind", "")).lower()
                for r in results
            ),
            {"load_elapsed_s": load_elapsed_s, "overall_timeout_s": overall_timeout_s},
        )
        check(
            "sqlite_wal_mode",
            str(db_report["journal_mode"]).lower() == "wal",
            {"journal_mode": db_report["journal_mode"]},
        )
        check(
            "db_row_count_matches_requests",
            db_report["row_count"] == requests_total,
            db_report,
        )
        check(
            "no_duplicate_receipt_head",
            db_report["duplicate_receipt_heads"] == 0,
            db_report,
        )
        check(
            "no_duplicate_chain_head",
            db_report["duplicate_chain_heads"] == 0,
            db_report,
        )
        check(
            "no_duplicate_chain_seq",
            db_report["duplicate_chain_seq"] == 0,
            db_report,
        )
        check(
            "single_genesis",
            db_report["genesis_count"] == 1,
            db_report,
        )
        check(
            "no_forks",
            db_report["forks"] == 0,
            db_report,
        )
        check(
            "single_leaf_no_chain_ambiguity",
            db_report["leaves"] == 1,
            db_report,
        )
        check(
            "no_missing_prev_links",
            db_report["missing_prev"] == 0,
            db_report,
        )
        check(
            "no_self_loops",
            db_report["self_loops"] == 0,
            db_report,
        )
        check(
            "chain_seq_contiguous",
            (
                db_report["row_count"] == 0
                or (
                    db_report["min_seq"] == 0
                    and db_report["max_seq"] == db_report["row_count"] - 1
                    and db_report["distinct_seq"] == db_report["row_count"]
                )
            ),
            db_report,
        )
        check(
            "verify_window_ok",
            verify_report.get("ok") is True,
            verify_report,
        )
        check(
            "verify_window_no_bad_heads",
            verify_report.get("bad_heads") == 0,
            verify_report,
        )
        check(
            "verify_window_no_missing_prev",
            verify_report.get("missing_prev") == 0,
            verify_report,
        )
        check(
            "verify_window_no_forks",
            verify_report.get("forks") == 0,
            verify_report,
        )
        check(
            "verify_window_no_cycles",
            verify_report.get("cycles") == 0,
            verify_report,
        )

        output = {
            "ok": not failed_checks,
            "failed_checks": failed_checks,
            "checks": checks,
            "tmp_root": str(tmp_root),
            "db_path": str(db_path),
            "uvicorn_log": str(uvicorn_log),
            "workers_requested": 2,
            "worker_pids_observed": worker_pids_observed,
            "response_pids": response_pids,
            "writer_pids": db_report["writer_pids"],
            "requests_total": requests_total,
            "concurrency": concurrency,
            "load_elapsed_s": load_elapsed_s,
            "http_statuses": statuses,
            "successful_requests": len(successes),
            "failed_requests": len(failures),
            "total_conflict_retries": total_conflict_retries,
            "total_sqlite_lock_retries": total_sqlite_lock_retries,
            "max_attempt": max_attempt,
            "chain_namespace": chain_namespace,
            "chain_id": chain_id,
            "db_report": db_report,
            "verify_status": verify_status,
            "result_path": str(result_path),
            "uvicorn_log_tail": _tail_file(uvicorn_log) if failed_checks else "",
        }

        result_path.write_text(
            json.dumps(output, ensure_ascii=False, sort_keys=True, indent=2),
            encoding="utf-8",
        )

        print(f"ok = {output['ok']}")
        print(f"failed_checks = {output['failed_checks']}")
        print(f"tmp_root = {output['tmp_root']}")
        print(f"db_path = {output['db_path']}")
        print("")
        print("multi_process_write_test:")
        print(f"  workers_requested = {output['workers_requested']}")
        print(f"  worker_pids_observed = {output['worker_pids_observed']}")
        print(f"  writer_pids = {output['writer_pids']}")
        print(f"  requests_total = {output['requests_total']}")
        print(f"  concurrency = {output['concurrency']}")
        print(f"  successful_requests = {output['successful_requests']}")
        print(f"  failed_requests = {output['failed_requests']}")
        print(f"  load_elapsed_s = {output['load_elapsed_s']}")
        print(f"  total_conflict_retries = {output['total_conflict_retries']}")
        print(f"  total_sqlite_lock_retries = {output['total_sqlite_lock_retries']}")
        print(f"  max_attempt = {output['max_attempt']}")
        print(f"  db_report = {json.dumps(output['db_report'], ensure_ascii=False, sort_keys=True)}")
        print(f"  verify_report = {json.dumps(output['verify_status']['report'], ensure_ascii=False, sort_keys=True)}")
        print("")
        print(f"result_json = {result_path}")

        if failed_checks:
            print("")
            print("uvicorn_log_tail:")
            print(output["uvicorn_log_tail"])
            return 1

        return 0

    except Exception as exc:
        if proc is not None:
            _stop_process(proc)
        if log_fh is not None:
            with contextlib.suppress(Exception):
                log_fh.close()

        output = {
            "ok": False,
            "failed_checks": [
                {
                    "name": "test_harness_exception",
                    "passed": False,
                    "details": f"{type(exc).__name__}: {exc}",
                }
            ],
            "tmp_root": str(tmp_root),
            "db_path": str(db_path),
            "uvicorn_log": str(uvicorn_log),
            "result_path": str(result_path),
            "uvicorn_log_tail": _tail_file(uvicorn_log),
        }
        result_path.write_text(
            json.dumps(output, ensure_ascii=False, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        print("ok = False")
        print(f"failed_checks = {output['failed_checks']}")
        print(f"tmp_root = {output['tmp_root']}")
        print(f"db_path = {output['db_path']}")
        print(f"result_json = {result_path}")
        print("")
        print("uvicorn_log_tail:")
        print(output["uvicorn_log_tail"])
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
