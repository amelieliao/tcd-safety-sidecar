#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import inspect
import json
import os
import random
import sqlite3
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


def _import_storage():
    from tcd.storage import (  # type: ignore
        ReceiptEnvelope,
        SQLiteReceiptStore,
        StorageConfig,
        StorageConflictError,
        make_receipt_store,
    )

    return {
        "ReceiptEnvelope": ReceiptEnvelope,
        "SQLiteReceiptStore": SQLiteReceiptStore,
        "StorageConfig": StorageConfig,
        "StorageConflictError": StorageConflictError,
        "make_receipt_store": make_receipt_store,
    }


def _obj_get(obj: Any, key: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _as_dict(obj: Any) -> Dict[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return dict(obj)
    if hasattr(obj, "to_dict"):
        out = obj.to_dict()
        return dict(out) if isinstance(out, dict) else {}
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    return {}


def _sig_params(cls_or_fn: Any) -> set[str]:
    try:
        return set(inspect.signature(cls_or_fn).parameters.keys())
    except Exception:
        return set()


def make_cfg(
    *,
    chain_namespace: str,
    chain_id: str,
    sqlite_timeout_s: float,
    sqlite_synchronous: str,
    require_server_assign: bool,
):
    storage = _import_storage()
    StorageConfig = storage["StorageConfig"]

    kwargs = {
        "profile": "PROD",
        "default_chain_namespace": chain_namespace,
        "default_chain_id": chain_id,
        "server_assign_receipt_chain_position": True,
        "sqlite_timeout_s": float(sqlite_timeout_s),
        "sqlite_synchronous": sqlite_synchronous,
    }

    params = _sig_params(StorageConfig)

    if "server_assign_receipt_chain_position" not in params and require_server_assign:
        raise RuntimeError(
            "StorageConfig does not accept server_assign_receipt_chain_position. "
            "This final durability test requires that field. "
            "Pass --allow-missing-server-assign only for debugging old code."
        )

    filtered = {k: v for k, v in kwargs.items() if k in params}
    return StorageConfig(**filtered)


def open_store(
    *,
    db_path: str,
    chain_namespace: str,
    chain_id: str,
    sqlite_timeout_s: float,
    sqlite_synchronous: str,
    use_factory: bool,
    require_server_assign: bool,
):
    storage = _import_storage()
    SQLiteReceiptStore = storage["SQLiteReceiptStore"]
    make_receipt_store = storage["make_receipt_store"]

    cfg = make_cfg(
        chain_namespace=chain_namespace,
        chain_id=chain_id,
        sqlite_timeout_s=sqlite_timeout_s,
        sqlite_synchronous=sqlite_synchronous,
        require_server_assign=require_server_assign,
    )

    if use_factory:
        return make_receipt_store(f"sqlite:///{db_path}", config=cfg)

    return SQLiteReceiptStore(path=db_path, config=cfg)


def canonical_json(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def make_receipt(
    *,
    node_label: str,
    ordinal: int,
    chain_namespace: str,
    chain_id: str,
    prev_head_hex: Optional[str],
    commit_mode: str,
    test_run_id: str,
):
    storage = _import_storage()
    ReceiptEnvelope = storage["ReceiptEnvelope"]

    event_id = f"{test_run_id}-ev-{node_label}-{ordinal:08d}"
    decision_id = f"{test_run_id}-dec-{node_label}-{ordinal:08d}"
    request_id = f"{test_run_id}-req-{node_label}-{ordinal:08d}"
    receipt_ref = f"{test_run_id}-receipt-{node_label}-{ordinal:08d}"
    audit_ref = f"{test_run_id}-audit-{node_label}-{ordinal:08d}"

    body: Dict[str, Any] = {
        "schema": "tcd.storage.multi_node_shared_persistence_test.v1",
        "kind": "multi_node_shared_persistence_test",
        "event_id": event_id,
        "decision_id": decision_id,
        "request_id": request_id,
        "receipt_ref": receipt_ref,
        "audit_ref": audit_ref,
        "producer": node_label,
        "ordinal": ordinal,
        "chain_namespace": chain_namespace,
        "chain_id": chain_id,
        "commit_mode": commit_mode,
        "ts_unix_ns": time.time_ns(),
    }

    # In optimistic-prev debug mode we bind the attempted predecessor into the body.
    # In server-assign mode this remains absent so storage must assign chain position.
    if prev_head_hex is not None:
        body["prev_head_hex"] = prev_head_hex

    body_json = canonical_json(body)
    head_hex = "attn:" + hashlib.sha256(body_json.encode("utf-8")).hexdigest()

    kwargs = {
        "head_hex": head_hex,
        "body_json": body_json,
        "head_semantics": "external_receipt_passthrough",
        "chain_namespace": chain_namespace,
        "chain_id": chain_id,
        "prev_head_hex": prev_head_hex,
        "event_id": event_id,
        "decision_id": decision_id,
        "request_id": request_id,
        "receipt_ref": receipt_ref,
        "audit_ref": audit_ref,
        "produced_by": ("multi_node_shared_persistence_test", node_label),
    }

    params = _sig_params(ReceiptEnvelope)
    filtered = {k: v for k, v in kwargs.items() if k in params}
    return ReceiptEnvelope(**filtered)


def put_one(
    *,
    db_path: str,
    node_label: str,
    ordinal: int,
    chain_namespace: str,
    chain_id: str,
    sqlite_timeout_s: float,
    sqlite_synchronous: str,
    use_factory: bool,
    commit_mode: str,
    test_run_id: str,
    max_retries: int,
    require_server_assign: bool,
) -> Dict[str, Any]:
    storage = _import_storage()
    StorageConflictError = storage["StorageConflictError"]

    last_error = ""

    for attempt in range(max_retries):
        try:
            store = open_store(
                db_path=db_path,
                chain_namespace=chain_namespace,
                chain_id=chain_id,
                sqlite_timeout_s=sqlite_timeout_s,
                sqlite_synchronous=sqlite_synchronous,
                use_factory=use_factory,
                require_server_assign=require_server_assign,
            )

            prev_ref: Optional[str] = None

            if commit_mode == "optimistic-prev":
                latest = store.latest(chain_namespace=chain_namespace, chain_id=chain_id)
                if latest is not None:
                    prev_ref = _obj_get(latest, "chain_head_hex") or _obj_get(latest, "head_hex")

            rec = make_receipt(
                node_label=node_label,
                ordinal=ordinal,
                chain_namespace=chain_namespace,
                chain_id=chain_id,
                prev_head_hex=prev_ref,
                commit_mode=commit_mode,
                test_run_id=test_run_id,
            )

            put = store.put_receipt(rec)
            return {
                "ok": True,
                "node": node_label,
                "ordinal": ordinal,
                "attempt": attempt + 1,
                "put": _as_dict(put),
            }

        except StorageConflictError as exc:
            last_error = f"StorageConflictError: {exc}"
            # In server-assign mode, repeated chain conflicts usually mean server-side
            # assignment is not actually implemented or not atomic. Still retry briefly
            # to tolerate transient races.
            time.sleep(min(0.250, 0.005 * (2 ** min(attempt, 5))) + random.random() * 0.010)

        except sqlite3.OperationalError as exc:
            last_error = f"sqlite3.OperationalError: {exc}"
            time.sleep(min(0.250, 0.005 * (2 ** min(attempt, 5))) + random.random() * 0.010)

        except Exception as exc:
            return {
                "ok": False,
                "node": node_label,
                "ordinal": ordinal,
                "attempt": attempt + 1,
                "error": f"{type(exc).__name__}: {exc}",
            }

    return {
        "ok": False,
        "node": node_label,
        "ordinal": ordinal,
        "attempt": max_retries,
        "error": last_error or "max retries exceeded",
    }


def fetch_all_chain_rows(store: Any, *, chain_namespace: str, chain_id: str, page_size: int) -> List[Any]:
    rows_all: List[Any] = []
    after_seq: Optional[int] = None

    while True:
        rows, _cursor = store.page_chain(
            chain_namespace=chain_namespace,
            chain_id=chain_id,
            after_seq=after_seq,
            limit=page_size,
        )
        rows = list(rows or [])
        if not rows:
            break

        rows_all.extend(rows)

        last_seq = _obj_get(rows[-1], "chain_seq")
        if last_seq is None:
            break

        after_seq = int(last_seq)

        if len(rows) < page_size:
            break

    return rows_all


def assert_verify_report_ok(report: Any) -> Dict[str, Any]:
    d = _as_dict(report)
    bad_fields = [
        "duplicates",
        "forks",
        "cycles",
        "missing_prev",
        "bad_heads",
        "bad_rows",
    ]

    if not bool(d.get("ok", False)):
        raise AssertionError(f"verify_window failed: {d}")

    for field in bad_fields:
        if int(d.get(field, 0) or 0) != 0:
            raise AssertionError(f"verify_window {field} != 0: {d}")

    return d


def assert_chain_unambiguous(rows: Sequence[Any], *, expected_count: int) -> Dict[str, Any]:
    if len(rows) != expected_count:
        raise AssertionError(f"chain row count mismatch: got={len(rows)} expected={expected_count}")

    seqs: List[int] = []
    heads: List[str] = []
    chain_heads: List[str] = []
    prev_chain_heads: List[Optional[str]] = []

    for r in rows:
        seq = _obj_get(r, "chain_seq")
        head = _obj_get(r, "head_hex")
        chain_head = _obj_get(r, "chain_head_hex")
        prev = _obj_get(r, "prev_chain_head_hex")

        if seq is None:
            raise AssertionError(f"row missing chain_seq: {_as_dict(r)}")
        if not head:
            raise AssertionError(f"row missing head_hex: {_as_dict(r)}")
        if not chain_head:
            raise AssertionError(f"row missing chain_head_hex: {_as_dict(r)}")

        seqs.append(int(seq))
        heads.append(str(head))
        chain_heads.append(str(chain_head))
        prev_chain_heads.append(str(prev) if prev else None)

    if len(set(heads)) != len(heads):
        raise AssertionError("duplicate receipt head_hex detected")

    if len(set(chain_heads)) != len(chain_heads):
        raise AssertionError("duplicate chain_head_hex detected")

    if len(set(seqs)) != len(seqs):
        raise AssertionError(f"duplicate chain_seq detected: {seqs}")

    expected_seqs = list(range(len(rows)))
    if sorted(seqs) != expected_seqs:
        raise AssertionError(f"chain_seq is not contiguous 0..n-1: got={sorted(seqs)} expected={expected_seqs}")

    genesis_count = sum(1 for p in prev_chain_heads if p is None)
    if genesis_count != 1:
        raise AssertionError(f"expected exactly one genesis row, got={genesis_count}")

    non_null_prevs = [p for p in prev_chain_heads if p is not None]
    if len(set(non_null_prevs)) != len(non_null_prevs):
        raise AssertionError("fork detected: one prev_chain_head_hex is consumed more than once")

    chain_head_set = set(chain_heads)
    missing_prev = [p for p in non_null_prevs if p not in chain_head_set]
    if missing_prev:
        raise AssertionError(f"missing predecessor chain heads: {missing_prev[:5]}")

    consumed = set(non_null_prevs)
    leaves = [h for h in chain_heads if h not in consumed]
    if len(leaves) != 1:
        raise AssertionError(f"expected exactly one leaf, got={len(leaves)}")

    return {
        "rows": len(rows),
        "min_seq": min(seqs),
        "max_seq": max(seqs),
        "genesis_count": genesis_count,
        "leaf_count": len(leaves),
        "leaf_chain_head_hex": leaves[0],
    }


def remove_sqlite_files(db_path: str) -> None:
    for suffix in ("", "-wal", "-shm"):
        p = Path(db_path + suffix)
        if p.exists():
            p.unlink()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="TCD multi-node / shared SQLite persistence durability test"
    )
    ap.add_argument("--db", default="/tmp/tcd-mpwrite-shared-persistence.sqlite3")
    ap.add_argument("--chain-namespace", default="mpwrite")
    ap.add_argument("--chain-id", default="durable-block-chain")
    ap.add_argument("--commits-per-node", type=int, default=32)
    ap.add_argument("--processes", type=int, default=8)
    ap.add_argument("--max-retries", type=int, default=200)
    ap.add_argument("--sqlite-timeout-s", type=float, default=30.0)
    ap.add_argument("--sqlite-synchronous", default="FULL", choices=("NORMAL", "FULL"))
    ap.add_argument("--page-size", type=int, default=128)
    ap.add_argument("--verify-limit", type=int, default=100000)
    ap.add_argument("--use-factory", action="store_true")
    ap.add_argument(
        "--commit-mode",
        choices=("server-assign", "optimistic-prev"),
        default="server-assign",
        help=(
            "server-assign: concurrent writers omit prev_head_hex and require storage to assign chain position. "
            "optimistic-prev: debug fallback that reads latest and retries on conflict."
        ),
    )
    ap.add_argument("--keep-existing-db", action="store_true")
    ap.add_argument("--allow-missing-server-assign", action="store_true")
    args = ap.parse_args()

    db_path = str(Path(args.db).expanduser())
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    require_server_assign = not args.allow_missing_server_assign

    if not args.keep_existing_db:
        remove_sqlite_files(db_path)

    test_run_id = "mnsp-" + hashlib.sha256(
        f"{time.time_ns()}:{os.getpid()}:{random.random()}".encode("utf-8")
    ).hexdigest()[:12]

    print("== TCD multi-node / shared persistence test ==")
    print(f"db_path={db_path}")
    print(f"chain_namespace={args.chain_namespace}")
    print(f"chain_id={args.chain_id}")
    print(f"commit_mode={args.commit_mode}")
    print(f"test_run_id={test_run_id}")

    node_a = open_store(
        db_path=db_path,
        chain_namespace=args.chain_namespace,
        chain_id=args.chain_id,
        sqlite_timeout_s=args.sqlite_timeout_s,
        sqlite_synchronous=args.sqlite_synchronous,
        use_factory=args.use_factory,
        require_server_assign=require_server_assign,
    )
    node_b = open_store(
        db_path=db_path,
        chain_namespace=args.chain_namespace,
        chain_id=args.chain_id,
        sqlite_timeout_s=args.sqlite_timeout_s,
        sqlite_synchronous=args.sqlite_synchronous,
        use_factory=args.use_factory,
        require_server_assign=require_server_assign,
    )

    # 1. node A issue / commit genesis
    rec_a0 = make_receipt(
        node_label="A",
        ordinal=0,
        chain_namespace=args.chain_namespace,
        chain_id=args.chain_id,
        prev_head_hex=None,
        commit_mode=args.commit_mode,
        test_run_id=test_run_id,
    )
    put_a0 = node_a.put_receipt(rec_a0)
    put_a0_d = _as_dict(put_a0)
    print(f"[A issue] {json.dumps(put_a0_d, sort_keys=True)}")

    if not bool(put_a0_d.get("stored")) and not bool(put_a0_d.get("idempotent")):
        raise AssertionError(f"node A issue failed: {put_a0_d}")

    # 2. node B verify A's write
    seen_by_b = node_b.get_record_by_head(put_a0_d["head_hex"])
    if seen_by_b is None:
        raise AssertionError("node B cannot read node A receipt by head")

    report_b0 = node_b.verify_window(
        chain_namespace=args.chain_namespace,
        chain_id=args.chain_id,
        limit=args.verify_limit,
    )
    report_b0_d = assert_verify_report_ok(report_b0)
    print(f"[B verify after A issue] {json.dumps(report_b0_d, sort_keys=True)}")

    # 3. node B legacy tail/page
    tail_rows = node_b.tail(10)
    if not tail_rows:
        raise AssertionError("node B tail returned no rows")
    if not any(row[0] == put_a0_d["head_hex"] for row in tail_rows):
        raise AssertionError("node B tail does not contain node A receipt")

    page_rows, page_cursor = node_b.page(None, 10)
    if not page_rows:
        raise AssertionError("node B page returned no rows")
    if not any(row[0] == put_a0_d["head_hex"] for row in page_rows):
        raise AssertionError("node B page does not contain node A receipt")

    print(f"[B tail/page] tail_rows={len(tail_rows)} page_rows={len(page_rows)} page_cursor={page_cursor}")

    # 4. node A/B concurrent commit
    tasks: List[Tuple[str, int]] = []
    for i in range(1, args.commits_per_node + 1):
        tasks.append(("A", i))
        tasks.append(("B", i))

    random.shuffle(tasks)

    results: List[Dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=max(1, args.processes)) as pool:
        futs = [
            pool.submit(
                put_one,
                db_path=db_path,
                node_label=node_label,
                ordinal=ordinal,
                chain_namespace=args.chain_namespace,
                chain_id=args.chain_id,
                sqlite_timeout_s=args.sqlite_timeout_s,
                sqlite_synchronous=args.sqlite_synchronous,
                use_factory=args.use_factory,
                commit_mode=args.commit_mode,
                test_run_id=test_run_id,
                max_retries=args.max_retries,
                require_server_assign=require_server_assign,
            )
            for node_label, ordinal in tasks
        ]

        for fut in as_completed(futs):
            results.append(fut.result())

    failures = [r for r in results if not r.get("ok")]
    successes = [r for r in results if r.get("ok")]

    print(f"[concurrent commit] successes={len(successes)} failures={len(failures)}")

    if failures:
        print(json.dumps(failures[:20], indent=2, sort_keys=True))
        raise AssertionError(f"concurrent commit failures: {len(failures)}")

    expected_total = 1 + len(tasks)

    # 5. node B final verify
    report_final = node_b.verify_window(
        chain_namespace=args.chain_namespace,
        chain_id=args.chain_id,
        limit=args.verify_limit,
    )
    report_final_d = assert_verify_report_ok(report_final)
    print(f"[B final verify] {json.dumps(report_final_d, sort_keys=True)}")

    latest_b = node_b.latest(chain_namespace=args.chain_namespace, chain_id=args.chain_id)
    if latest_b is None:
        raise AssertionError("node B latest returned None after concurrent commit")

    print(
        "[B latest] "
        + json.dumps(
            {
                "head_hex": _obj_get(latest_b, "head_hex"),
                "chain_head_hex": _obj_get(latest_b, "chain_head_hex"),
                "chain_seq": _obj_get(latest_b, "chain_seq"),
                "event_id": _obj_get(latest_b, "event_id"),
            },
            sort_keys=True,
        )
    )

    # 6. page_chain and unambiguous chain assertions
    rows = fetch_all_chain_rows(
        node_b,
        chain_namespace=args.chain_namespace,
        chain_id=args.chain_id,
        page_size=args.page_size,
    )

    chain_summary = assert_chain_unambiguous(rows, expected_count=expected_total)
    print(f"[chain unambiguous] {json.dumps(chain_summary, sort_keys=True)}")

    # 7. final stats
    stats_a = node_a.stats()
    stats_b = node_b.stats()
    print(f"[stats A] {json.dumps(stats_a, sort_keys=True)}")
    print(f"[stats B] {json.dumps(stats_b, sort_keys=True)}")

    print("PASS multi-node shared persistence test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
