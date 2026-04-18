from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import inspect
import json
import math
import re
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Literal

try:
    from .attest import verify_attestation_record_ex as _attest_verify_ex  # type: ignore
except ImportError:  # pragma: no cover
    _attest_verify_ex = None  # type: ignore[assignment]

try:
    from .attest import _compute_head_from_body as _attest_compute_head_from_body  # type: ignore
except ImportError:  # pragma: no cover
    _attest_compute_head_from_body = None  # type: ignore[assignment]

try:
    from .schemas import ReceiptVerificationView  # type: ignore
except ImportError:  # pragma: no cover
    ReceiptVerificationView = None  # type: ignore[assignment]


__all__ = [
    "VerifyConfig",
    "VerifyPolicyBundle",
    "VerifyBundleDiagnostics",
    "VerifyPhaseResult",
    "VerifyReceiptInput",
    "VerifyChainInput",
    "ReceiptVerifyReport",
    "ChainVerifyReport",
    "VERIFY_IMPL_DIGEST",
    "compile_verify_bundle",
    "verify_receipt",
    "verify_receipt_ex",
    "verify_chain",
    "verify_chain_ex",
]


_SCHEMA = "tcd.verify.v3"
_COMPATIBILITY_EPOCH = "2026Q2"
_CANONICALIZATION_VERSION = "canonjson_v1"

_REQ_SCHEMA = "tcd.req.v1"
_COMP_SCHEMA = "tcd.comp.v1"
_E_SCHEMA = "tcd.e.v1"

_STRICT_PROFILES = frozenset({"PROD", "FINREG", "LOCKDOWN"})
_ALLOWED_PROFILES = frozenset({"DEV", "PROD", "FINREG", "LOCKDOWN"})

_MAX_RECEIPT_BODY_BYTES = 512 * 1024
_MAX_CHAIN_ITEMS = 4096
_MAX_CHAIN_TOTAL_BYTES = 16 * 1024 * 1024
_MAX_JSON_DEPTH = 128
_MAX_JSON_INT_DIGITS = 2048
_MAX_JSON_STRING_BYTES = 64 * 1024
_MAX_STRING_FIELD = 4096
_MAX_WITNESS_SEGMENTS = 512
_MAX_WITNESS_TAGS = 128

_FORBIDDEN_RECEIPT_KEYS = frozenset(
    {
        "prompt",
        "completion",
        "input_text",
        "output_text",
        "messages",
        "message",
        "content",
        "raw",
        "body",
        "payload",
        "request",
        "response",
        "headers",
        "header",
        "cookie",
        "cookies",
        "authorization",
        "auth",
        "token",
        "secret",
        "password",
        "api_key",
        "apikey",
        "private",
        "privatekey",
    }
)

_ALLOWED_TRUST_ZONES = frozenset({"internet", "internal", "partner", "admin", "ops", "unknown", "__config_error__"})
_ALLOWED_ROUTE_PROFILES = frozenset({"inference", "batch", "admin", "control", "metrics", "health", "restricted", "unknown"})
_ALLOWED_OVERRIDE_LEVELS = frozenset({"none", "break_glass", "maintenance"})
_ALLOWED_PQ_SCHEMES = frozenset({"", "dilithium2", "dilithium3", "falcon", "sphincs+"})
_ALLOWED_WITNESS_KINDS = frozenset(
    {"audit_ledger_head", "receipt_head", "tcd_chain_report", "zk_proof", "tpm_quote", "external", "other"}
)
_ALLOWED_ATTEST_HASH_ALGS = frozenset({"blake3", "sha256", "sha3_256", "blake2s"})

_DIGEST_HEX_RE = re.compile(r"^[0-9a-f]{16,256}$")
_DIGEST_HEX_0X_RE = re.compile(r"^0x[0-9a-f]{16,256}$")
_DIGEST_ALG_HEX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,31}:[0-9a-f]{16,256}$")
_CFG_FP_RE = re.compile(
    r"^(?:[A-Za-z0-9][A-Za-z0-9_.-]{1,15}:[A-Za-z0-9][A-Za-z0-9_.-]{1,15}:[0-9a-f]{16,256}|[A-Za-z0-9][A-Za-z0-9_.-]{1,15}:[0-9a-f]{16,256})$"
)
_RECEIPT_INTEGRITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{1,31}:[A-Za-z0-9][A-Za-z0-9_.:\-]{1,63}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-@#/+=]{0,255}$")
_SAFE_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9_.:\-]{0,63}$")
_SAFE_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,255}$")
_ASCII_CTRL_RE = re.compile(r"[\x00-\x1F\x7F]")


R_OK = "OK"
R_BAD_INPUT = "BAD_INPUT"
R_DEPENDENCY_CONTRACT = "DEPENDENCY_CONTRACT_INVALID"
R_PARSE_ERROR = "PARSE_ERROR"
R_BODY_SECURITY_INVALID = "BODY_SECURITY_INVALID"
R_BODY_NOT_CANONICAL = "BODY_NOT_CANONICAL"
R_HEAD_MISMATCH = "HEAD_MISMATCH"
R_INTEGRITY_MISMATCH = "INTEGRITY_MISMATCH"
R_SIGNATURE_INVALID = "SIGNATURE_INVALID"
R_SIGNATURE_MISSING = "SIGNATURE_MISSING"
R_VERIFY_KEY_DENIED = "VERIFY_KEY_DENIED"
R_VERIFY_KEY_BINDING = "VERIFY_KEY_BINDING_INVALID"
R_POLICY_BINDING_FAILED = "POLICY_BINDING_FAILED"
R_CFG_BINDING_FAILED = "CFG_BINDING_FAILED"
R_SUPPLY_CHAIN_VIOLATION = "SUPPLY_CHAIN_VIOLATION"
R_PQ_VIOLATION = "PQ_VIOLATION"
R_OBJECT_BINDING_FAILED = "OBJECT_BINDING_FAILED"
R_WITNESS_INVALID = "WITNESS_INVALID"
R_CHAIN_INVALID = "CHAIN_INVALID"
R_CHAIN_LINK_INVALID = "CHAIN_LINK_INVALID"
R_CHAIN_AMBIGUOUS = "CHAIN_AMBIGUOUS"


def _has_unsafe_unicode(s: str) -> bool:
    for ch in s:
        if ch in ("\u2028", "\u2029"):
            return True
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            return True
    return False


def _strip_unsafe_text(v: Any, *, max_len: int) -> str:
    if not isinstance(v, str):
        return ""
    s = unicodedata.normalize("NFC", v[:max_len])
    if s.isascii():
        if _ASCII_CTRL_RE.search(s):
            s = _ASCII_CTRL_RE.sub("", s)
        return s.strip()
    if not _ASCII_CTRL_RE.search(s) and not _has_unsafe_unicode(s):
        if any(0x80 <= ord(ch) <= 0x9F for ch in s):
            pass
        else:
            return s.strip()
    out: List[str] = []
    for ch in s:
        o = ord(ch)
        if ch in ("\u2028", "\u2029"):
            continue
        if o < 0x20 or o == 0x7F:
            continue
        if 0x80 <= o <= 0x9F:
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            continue
        out.append(ch)
    return "".join(out).strip()


def _safe_text(v: Any, *, max_len: int = 256) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return _strip_unsafe_text(v, max_len=max_len)
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return f"{v:.12g}" if math.isfinite(v) else ""
    if isinstance(v, (bytes, bytearray, memoryview)):
        return "<bytes>"
    return f"<{type(v).__name__}>"


def _safe_id(v: Any, *, max_len: int = 256) -> Optional[str]:
    s = _safe_text(v, max_len=max_len)
    if not s or not _SAFE_ID_RE.fullmatch(s):
        return None
    return s


def _safe_label(v: Any, *, default: str = "") -> str:
    s = _safe_text(v, max_len=64).lower()
    if not s or not _SAFE_LABEL_RE.fullmatch(s):
        return default
    return s


def _coerce_bool(v: Any) -> Optional[bool]:
    if type(v) is bool:
        return v
    if type(v) is int:
        if v == 0:
            return False
        if v == 1:
            return True
    if isinstance(v, str):
        s = v.strip().lower()
        if s in {"1", "true", "yes", "y", "on"}:
            return True
        if s in {"0", "false", "no", "n", "off"}:
            return False
    return None


def _coerce_float(v: Any) -> Optional[float]:
    if type(v) is bool:
        return None
    if isinstance(v, (int, float)):
        try:
            x = float(v)
        except Exception:
            return None
        return x if math.isfinite(x) else None
    if isinstance(v, str):
        s = v.strip()
        if not s or len(s) > 128:
            return None
        try:
            x = float(s)
        except Exception:
            return None
        return x if math.isfinite(x) else None
    return None


def _coerce_int(v: Any) -> Optional[int]:
    if type(v) is int:
        return int(v)
    if isinstance(v, str):
        s = v.strip()
        if not s or len(s) > 128:
            return None
        if s.startswith(("+", "-")):
            sign, digits = s[0], s[1:]
        else:
            sign, digits = "", s
        if not digits.isdigit():
            return None
        try:
            return int(sign + digits, 10)
        except Exception:
            return None
    return None


def _clamp_int(v: Any, *, default: int, lo: int, hi: int) -> int:
    x = _coerce_int(v)
    if x is None:
        return int(default)
    if x < lo:
        return int(lo)
    if x > hi:
        return int(hi)
    return int(x)


def _clamp_float(v: Any, *, default: float, lo: float, hi: float) -> float:
    x = _coerce_float(v)
    if x is None:
        return float(default)
    if x < lo:
        return float(lo)
    if x > hi:
        return float(hi)
    return float(x)


def _stable_jsonable(obj: Any) -> Any:
    if obj is None or isinstance(obj, (bool, int)):
        return obj
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise ValueError("non-finite float")
        return obj
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, Mapping):
        return {str(k): _stable_jsonable(obj[k]) for k in sorted(obj.keys(), key=lambda x: str(x))}
    if isinstance(obj, (list, tuple)):
        return [_stable_jsonable(x) for x in obj]
    return obj


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        _stable_jsonable(obj),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8", errors="strict")


def _canonical_json_text(obj: Any) -> str:
    return _canonical_json_bytes(obj).decode("utf-8", errors="strict")


def _json_depth_exceeds(raw: str | bytes, *, max_depth: int) -> bool:
    try:
        text = raw.decode("utf-8", errors="strict") if isinstance(raw, (bytes, bytearray)) else str(raw)
    except Exception:
        return True
    depth = 0
    in_str = False
    esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch in "{[":
            depth += 1
            if depth > max_depth:
                return True
        elif ch in "}]":
            depth = max(0, depth - 1)
    return False


def _json_loads_strict(raw: str | bytes, *, max_bytes: int, max_depth: int, max_int_digits: int) -> Any:
    data = raw.encode("utf-8", errors="strict") if isinstance(raw, str) else bytes(raw)
    if len(data) > max_bytes:
        raise ValueError("json payload too large")
    if _json_depth_exceeds(data, max_depth=max_depth):
        raise ValueError("json payload too deep")

    def _bad_const(_: str) -> Any:
        raise ValueError("non-finite JSON constant")

    def _parse_int(s: str) -> int:
        ss = s[1:] if s.startswith("-") else s
        if len(ss) > max_int_digits:
            raise ValueError("json integer too large")
        return int(s, 10)

    return json.loads(
        data.decode("utf-8", errors="strict"),
        parse_constant=_bad_const,
        parse_int=_parse_int,
    )


def _secure_compare_hex(a: str, b: str) -> bool:
    def _norm(s: Any) -> Optional[bytes]:
        if not isinstance(s, str):
            return None
        ss = s.strip()
        if ss.startswith(("0x", "0X")):
            ss = ss[2:]
        if not ss:
            return None
        if len(ss) % 2 == 1:
            ss = "0" + ss
        if not _HEX_RE.fullmatch(ss):
            return None
        try:
            return bytes.fromhex(ss.lower())
        except Exception:
            return None

    ba = _norm(a)
    bb = _norm(b)
    if ba is None or bb is None:
        return False
    return hmac.compare_digest(ba, bb)


def _normalize_digest(v: Any, *, kind: str = "any") -> Optional[str]:
    s = _safe_text(v, max_len=1024).strip()
    if not s:
        return None
    if kind == "cfg_fp":
        return s if _CFG_FP_RE.fullmatch(s) else None
    if kind == "integrity":
        return s if _RECEIPT_INTEGRITY_RE.fullmatch(s) else None
    if _DIGEST_HEX_RE.fullmatch(s):
        return s.lower()
    if _DIGEST_HEX_0X_RE.fullmatch(s):
        return s.lower()
    if _DIGEST_ALG_HEX_RE.fullmatch(s):
        algo, _, rest = s.partition(":")
        return f"{algo}:{rest.lower()}"
    return None


def _key_tokens(k: str) -> Tuple[str, ...]:
    s = _strip_unsafe_text(k, max_len=128)
    if not s:
        return tuple()
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", s)
    s = re.sub(r"(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])", " ", s)
    s = re.sub(r"[^A-Za-z0-9]+", " ", s).strip().lower()
    if not s:
        return tuple()
    parts = tuple(p for p in s.split(" ") if p)
    fused = "".join(parts)
    return parts + ((fused,) if fused and fused not in parts else tuple())


def _matches_forbidden_key(key: str) -> bool:
    tokens = _key_tokens(key)
    if not tokens:
        return False
    return any(t in _FORBIDDEN_RECEIPT_KEYS for t in tokens)


def _scan_forbidden_keys(obj: Any, *, max_depth: int, _depth: int = 0) -> List[str]:
    if _depth > max_depth:
        return []
    out: List[str] = []
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            if isinstance(k, str) and _matches_forbidden_key(k):
                out.append(k)
            out.extend(_scan_forbidden_keys(v, max_depth=max_depth, _depth=_depth + 1))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            out.extend(_scan_forbidden_keys(item, max_depth=max_depth, _depth=_depth + 1))
    return out


def _safe_hash_hex(data: bytes, *, alg: str, ctx: str, digest_size: int) -> str:
    algn = (alg or "").strip().lower()
    if algn == "sha256":
        h = hashlib.sha256()
        h.update(ctx.encode("utf-8", errors="strict"))
        h.update(b"\x00")
        h.update(data)
        return h.hexdigest()
    if algn == "sha3_256":
        h = hashlib.sha3_256()
        h.update(ctx.encode("utf-8", errors="strict"))
        h.update(b"\x00")
        h.update(data)
        return h.hexdigest()
    if algn == "blake2s":
        h = hashlib.blake2s(digest_size=max(1, min(32, int(digest_size))))
        h.update(ctx.encode("utf-8", errors="strict"))
        h.update(b"\x00")
        h.update(data)
        return h.hexdigest()
    try:
        from .crypto import Blake3Hash  # type: ignore
        return Blake3Hash().hex(data, ctx=ctx)
    except Exception:
        h = hashlib.sha256()
        h.update(b"compat:blake3:sha256")
        h.update(ctx.encode("utf-8", errors="strict"))
        h.update(b"\x00")
        h.update(data)
        return h.hexdigest()


def _local_attest_head(body_obj: Mapping[str, Any]) -> str:
    body = dict(body_obj)
    v = int(body.get("v", 1))
    ts_ns = int(body.get("ts_ns"))
    nonce = body.get("nonce")
    att = body.get("attestor", {}) or {}
    witness = body.get("witness", {}) or {}

    hash_alg = str(att.get("hash_alg") or "blake3").strip().lower()
    hash_ctx = str(att.get("hash_ctx") or "tcd:attest").strip() or "tcd:attest"
    digest_size = int(att.get("digest_size") or 32)

    attestor_subset = {
        "id": att.get("id"),
        "proc_id": att.get("proc_id"),
        "policy_digest": att.get("policy_digest"),
        "build_digest": att.get("build_digest"),
        "hw_root_id": att.get("hw_root_id"),
        "strict": bool(att.get("strict", False)),
        "hash_alg": hash_alg,
        "hash_ctx": hash_ctx,
        "digest_size": digest_size,
        "deployment_tier": att.get("deployment_tier"),
    }

    head_src = {
        "v": v,
        "ts_ns": ts_ns,
        "nonce": nonce,
        "attestor": attestor_subset,
        "meta": body.get("meta"),
        "req": body.get("req"),
        "comp": body.get("comp"),
        "e": body.get("e"),
        "witness_digest": witness.get("digest"),
        "witness_tags": witness.get("tags") or [],
        "policy_digest": att.get("policy_digest"),
    }
    raw = _canonical_json_bytes(head_src)
    return _safe_hash_hex(raw, alg=hash_alg, ctx=hash_ctx, digest_size=digest_size)


def _legacy_receipt_head(body_obj: Mapping[str, Any]) -> str:
    meta = {"body": dict(body_obj), "_schema": "tcd.receipt.v1"}
    raw = _canonical_json_bytes(meta)
    h = hashlib.blake2s(digest_size=16)
    h.update(b"domain:")
    h.update(b"tcd-receipt-head-v1")
    h.update(b"\x00")
    h.update(raw)
    return h.hexdigest()


def _compute_head_candidates(body_obj: Mapping[str, Any], *, allow_legacy: bool) -> List[str]:
    out: List[str] = []
    if _attest_compute_head_from_body is not None:
        try:
            h = _attest_compute_head_from_body(dict(body_obj))  # type: ignore[misc]
            if isinstance(h, str) and h:
                out.append(h)
        except Exception:
            pass
    try:
        out.append(_local_attest_head(body_obj))
    except Exception:
        pass
    if allow_legacy:
        try:
            out.append(_legacy_receipt_head(body_obj))
        except Exception:
            pass
    uniq: List[str] = []
    seen: set[str] = set()
    for item in out:
        if item and item not in seen:
            seen.add(item)
            uniq.append(item)
    return uniq


def _integrity_hash(head: str, body_bytes: bytes) -> str:
    h = hashlib.sha256()
    h.update(b"tcd:attest_sig")
    h.update(head.encode("utf-8", errors="strict"))
    h.update(body_bytes)
    return h.hexdigest()


def _legacy_commitment_hex(payload: Mapping[str, Any], *, schema: str, domain: str) -> str:
    meta = dict(payload)
    meta.setdefault("_schema", schema)
    raw = _canonical_json_bytes(meta)
    h = hashlib.blake2s(digest_size=16)
    h.update(b"domain:")
    h.update(domain.encode("utf-8", errors="ignore"))
    h.update(b"\x00")
    h.update(raw)
    return h.hexdigest()


def _commit_candidates(obj: Any, *, schema: str, domain: str) -> List[str]:
    out = [_legacy_commitment_hex({"value": obj}, schema=schema, domain=domain)]
    uniq: List[str] = []
    seen: set[str] = set()
    for item in out:
        if item not in seen:
            seen.add(item)
            uniq.append(item)
    return uniq


def _nested_get_first(d: Mapping[str, Any], paths: Sequence[Sequence[str]]) -> Any:
    for path in paths:
        cur: Any = d
        ok = True
        for part in path:
            if not isinstance(cur, Mapping) or part not in cur:
                ok = False
                break
            cur = cur[part]
        if ok:
            return cur
    return None


def _body_string_candidates(body_obj: Any) -> Tuple[bytes, str]:
    raw = _canonical_json_bytes(body_obj)
    return raw, raw.decode("utf-8", errors="strict")


def _find_prev_pointer(body: Mapping[str, Any]) -> Optional[str]:
    raw = _nested_get_first(
        body,
        (
            ("prev_head_hex",),
            ("prev_head",),
            ("prev_receipt_head",),
            ("prev_receipt",),
            ("prev",),
            ("meta", "prev_head_hex"),
            ("chain", "prev_head_hex"),
        ),
    )
    if raw in (None, ""):
        return None
    return _normalize_digest(raw, kind="receipt_head")


def _validate_supply_chain_section(supply: Mapping[str, Any], *, strict: bool) -> List[str]:
    errs: List[str] = []
    for k in ("build_id", "issuer", "runtime_env"):
        v = supply.get(k)
        if v is not None and not isinstance(v, str):
            errs.append(f"{k}_invalid")
        elif isinstance(v, str) and len(v) > 256:
            errs.append(f"{k}_oversize")
    for k in ("image_digest", "sbom_commit", "attestation_commit"):
        v = supply.get(k)
        if v is None:
            continue
        if not isinstance(v, str) or _normalize_digest(v, kind="any") is None:
            errs.append(f"{k}_invalid")
    for k in ("not_before", "not_after"):
        v = supply.get(k)
        if v is not None and _coerce_float(v) is None:
            errs.append(f"{k}_invalid")
    if strict and supply.get("attestation_commit") is None:
        errs.append("attestation_commit_missing")
    return errs


def _validate_witness_segments(witness_segments: Any, *, strict: bool) -> Tuple[bool, Tuple[str, ...]]:
    if witness_segments is None:
        return True, tuple()

    if isinstance(witness_segments, (list, tuple)) and len(witness_segments) == 3 and all(isinstance(seg, list) for seg in witness_segments):
        total = 0
        for seg in witness_segments:
            for x in seg:
                ix = _coerce_int(x)
                if ix is None:
                    return False, ("witness_non_int",)
                if ix < 0:
                    return False, ("witness_negative",)
                total += 1
        if total > _MAX_WITNESS_SEGMENTS * 16:
            return False, ("witness_oversize",)
        return True, tuple()

    if not isinstance(witness_segments, (list, tuple)):
        return False, ("witness_not_sequence",)
    if len(witness_segments) > _MAX_WITNESS_SEGMENTS:
        return False, ("witness_oversize",)

    for seg in witness_segments:
        if not isinstance(seg, Mapping):
            return False, ("witness_not_mapping",)
        kind = _safe_text(seg.get("kind"), max_len=64)
        if strict and (not kind or kind not in _ALLOWED_WITNESS_KINDS):
            return False, ("witness_kind_invalid",)
        if strict:
            sid = _safe_text(seg.get("id"), max_len=256)
            if not sid:
                return False, ("witness_id_missing",)
        dig = _normalize_digest(seg.get("digest") or seg.get("hash"), kind="any")
        if strict and not dig:
            return False, ("witness_digest_invalid",)
        meta = seg.get("meta")
        if meta is not None and not isinstance(meta, Mapping):
            return False, ("witness_meta_invalid",)
        if isinstance(meta, Mapping):
            try:
                _canonical_json_text(dict(meta))
            except Exception:
                return False, ("witness_meta_invalid",)
    return True, tuple()


def _extract_receipt_fields(body: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "policy_ref": _safe_id(_nested_get_first(body, (("policy_ref",), ("meta", "policy_ref"), ("policy", "auth_policy"))), max_len=256),
        "policyset_ref": _safe_id(_nested_get_first(body, (("policyset_ref",), ("meta", "policyset_ref"))), max_len=256),
        "policy_digest": _normalize_digest(
            _nested_get_first(body, (("policy_digest",), ("meta", "policy_digest"), ("attestor", "policy_digest"), ("policy", "cfg_digest"))),
            kind="any",
        ),
        "cfg_fp": _normalize_digest(
            _nested_get_first(body, (("cfg_fp",), ("config_hash",), ("meta", "cfg_fp"), ("meta", "config_hash"), ("policy", "cfg_digest"))),
            kind="cfg_fp",
        ),
        "event_id": _safe_id(_nested_get_first(body, (("event_id",), ("meta", "event_id"))), max_len=256),
        "decision_id": _safe_id(_nested_get_first(body, (("decision_id",), ("meta", "decision_id"))), max_len=256),
        "route_plan_id": _safe_id(_nested_get_first(body, (("route_plan_id",), ("route_id",), ("meta", "route_plan_id"))), max_len=256),
        "state_domain_id": _safe_id(_nested_get_first(body, (("state_domain_id",), ("meta", "state_domain_id"))), max_len=256),
        "adapter_registry_fp": _safe_id(_nested_get_first(body, (("adapter_registry_fp",), ("meta", "adapter_registry_fp"))), max_len=256),
        "verify_key_id": _safe_id(_nested_get_first(body, (("verify_key_id",), ("sig_key_id",), ("sig", "key_id"))), max_len=256),
        "verify_key_fp": _normalize_digest(_nested_get_first(body, (("verify_key_fp",), ("sig", "verify_key_fp"))), kind="any"),
        "receipt_integrity": _normalize_digest(_nested_get_first(body, (("receipt_integrity",),)), kind="integrity"),
        "body_kind": _safe_label(_nested_get_first(body, (("body_kind",),)), default=""),
        "pq_signature_required": _coerce_bool(_nested_get_first(body, (("pq_signature_required",), ("meta", "pq_signature_required")))),
        "pq_signature_ok": _coerce_bool(_nested_get_first(body, (("pq_signature_ok",), ("meta", "pq_signature_ok")))),
        "build_id": _safe_text(_nested_get_first(body, (("build_id",), ("meta", "build_id"), ("attestor", "build_digest"))), max_len=256),
        "image_digest": _safe_text(_nested_get_first(body, (("image_digest",), ("meta", "image_digest"))), max_len=256),
        "chain_id": _safe_text(_nested_get_first(body, (("chain_id",), ("meta", "chain_id"), ("chain", "chain_id"))), max_len=256),
        "chain_namespace": _safe_text(_nested_get_first(body, (("chain_namespace",), ("meta", "chain_namespace"), ("chain", "chain_namespace"))), max_len=256),
        "chain_seq": _coerce_int(_nested_get_first(body, (("chain_seq",), ("meta", "chain_seq"), ("chain", "chain_seq")))),
        "ts": _coerce_float(_nested_get_first(body, (("ts",), ("timestamp",)))),
        "ts_ns": _coerce_int(_nested_get_first(body, (("ts_ns",), ("ts_unix_ns",)))),
        "pq_required": _coerce_bool(_nested_get_first(body, (("pq_required",), ("meta", "pq_required"), ("components", "security", "pq_required")))),
        "pq_ok": _coerce_bool(_nested_get_first(body, (("pq_ok",), ("meta", "pq_ok"), ("components", "security", "pq_ok")))),
        "trust_zone": _safe_label(_nested_get_first(body, (("trust_zone",), ("meta", "trust_zone"), ("components", "security", "trust_zone"))), default=""),
        "route_profile": _safe_label(_nested_get_first(body, (("route_profile",), ("meta", "route_profile"), ("components", "security", "route_profile"))), default=""),
    }


def _validate_body_security(body: Mapping[str, Any], *, strict: bool) -> Tuple[bool, Tuple[str, ...]]:
    errs: List[str] = []
    forbidden = _scan_forbidden_keys(body, max_depth=8)
    if forbidden:
        errs.append("forbidden_key_present")

    fields = _extract_receipt_fields(body)
    tz = fields.get("trust_zone")
    if tz and tz not in _ALLOWED_TRUST_ZONES:
        errs.append("trust_zone_invalid")
    rp = fields.get("route_profile")
    if rp and rp not in _ALLOWED_ROUTE_PROFILES:
        errs.append("route_profile_invalid")

    override_applied = _coerce_bool(_nested_get_first(body, (("override_applied",), ("meta", "override_applied"))))
    if override_applied:
        actor = _safe_text(_nested_get_first(body, (("override_actor",), ("meta", "override_actor"))), max_len=128)
        if not actor:
            errs.append("override_actor_missing")
        level = _safe_label(_nested_get_first(body, (("override_level",), ("meta", "override_level"))), default="")
        if level and strict and level not in _ALLOWED_OVERRIDE_LEVELS:
            errs.append("override_level_invalid")

    pq_scheme = _safe_text(_nested_get_first(body, (("pq_scheme",), ("meta", "pq_scheme"), ("components", "security", "pq_scheme"))), max_len=64)
    if pq_scheme and strict and pq_scheme not in _ALLOWED_PQ_SCHEMES:
        errs.append("pq_scheme_invalid")

    for key_name in ("pq_pub_hex", "pq_sig_hex"):
        val = _nested_get_first(body, ((key_name,), ("components", "security", key_name), ("meta", key_name)))
        if val is not None and _normalize_digest(val, kind="any") is None and not (isinstance(val, str) and _HEX_RE.fullmatch(val.replace("0x", "").replace("0X", ""))):
            errs.append(f"{key_name}_invalid")

    e_val = _nested_get_first(body, (("e_value",), ("e", "e_value")))
    if e_val is not None:
        ef = _coerce_float(e_val)
        if ef is None or ef < 0.0:
            errs.append("e_value_invalid")

    supply = _nested_get_first(body, (("supply_chain",),))
    if supply is not None:
        if not isinstance(supply, Mapping):
            errs.append("supply_chain_invalid")
        else:
            errs.extend(_validate_supply_chain_section(dict(supply), strict=strict))

    chain_id = fields.get("chain_id")
    if chain_id is not None and fields.get("chain_seq") is not None and fields["chain_seq"] < 0:
        errs.append("chain_seq_invalid")
    if chain_id is not None and not chain_id:
        errs.append("chain_id_invalid")
    return len(errs) == 0, tuple(dict.fromkeys(errs))


def _verify_optional_commit_field(
    body: Mapping[str, Any],
    *,
    obj: Any,
    field_names: Sequence[str],
    schema: str,
    strict: bool,
) -> Tuple[bool, Optional[str]]:
    if obj is None:
        return True, None

    expected = _commit_candidates(obj, schema=schema, domain="tcd.obj.v1")
    present_val = None
    for name in field_names:
        if name in body:
            present_val = body.get(name)
            break
        meta_val = _nested_get_first(body, (("meta", name), ("components", name), ("components", "security", name)))
        if meta_val is not None:
            present_val = meta_val
            break

    if present_val is None:
        return (False, "missing_object_commit") if strict else (True, None)

    normalized = _normalize_digest(present_val, kind="any")
    if normalized is None:
        return False, "invalid_object_commit"

    for cand in expected:
        if _secure_compare_hex(cand, normalized):
            return True, None
    return False, "object_commit_mismatch"


def _parse_salt_bytes(label_salt_hex: Optional[str]) -> Optional[bytes]:
    if not isinstance(label_salt_hex, str) or not label_salt_hex.strip():
        return None
    s = label_salt_hex.strip()
    if s.startswith(("0x", "0X")):
        s = s[2:]
    if len(s) % 2 == 1 or not _HEX_RE.fullmatch(s):
        return None
    try:
        return bytes.fromhex(s)
    except Exception:
        return None


def _label_fingerprint(value: str, *, label_salt_hex: Optional[str]) -> str:
    raw = value.encode("utf-8", errors="ignore")
    salt = _parse_salt_bytes(label_salt_hex)
    if salt:
        dig = hmac.new(salt, b"tcd:verify:keyfp\x00" + raw, hashlib.sha256).hexdigest()
    else:
        dig = hashlib.sha256(b"tcd:verify:keyfp\x00" + raw).hexdigest()
    return dig


def _compute_verify_key_fp_candidates(raw: Optional[str], *, label_salt_hex: Optional[str]) -> List[str]:
    if not raw:
        return []
    dig = _label_fingerprint(raw, label_salt_hex=label_salt_hex)
    out = [dig, "0x" + dig, "sha256:" + dig]
    uniq: List[str] = []
    seen: set[str] = set()
    for item in out:
        if item not in seen:
            seen.add(item)
            uniq.append(item)
    return uniq


@dataclass(frozen=True)
class SignatureVerificationRequest:
    alg: str
    key_id: Optional[str]
    verify_key: Optional[str]
    verify_key_fp: Optional[str]
    body_bytes: bytes
    signature_bytes: bytes
    head: str
    receipt_sig: Optional[str]
    body: Mapping[str, Any]
    policy_digest: Optional[str]
    cfg_fp: Optional[str]


def _call_verify_sig_func(
    verify_sig_func: Callable[..., Any],
    req: SignatureVerificationRequest,
) -> bool:
    try:
        sig = inspect.signature(verify_sig_func)
    except Exception:
        return bool(verify_sig_func(req.alg, req.key_id, req.body_bytes, req.signature_bytes))

    params = list(sig.parameters.values())
    if len(params) == 1:
        return bool(verify_sig_func(req))

    kw = {
        "alg": req.alg,
        "key_id": req.key_id,
        "verify_key": req.verify_key,
        "verify_key_fp": req.verify_key_fp,
        "body_bytes": req.body_bytes,
        "signature_bytes": req.signature_bytes,
        "head": req.head,
        "receipt_sig": req.receipt_sig,
        "body": req.body,
        "policy_digest": req.policy_digest,
        "cfg_fp": req.cfg_fp,
    }
    filtered = {k: v for k, v in kw.items() if k in sig.parameters}
    if filtered:
        return bool(verify_sig_func(**filtered))
    return bool(verify_sig_func(req.alg, req.key_id, req.body_bytes, req.signature_bytes))


def _verify_signature_block(
    body: Mapping[str, Any],
    *,
    body_bytes: bytes,
    head: str,
    receipt_sig: Optional[str],
    verify_key: Optional[str],
    verify_key_fp: Optional[str],
    verify_sig_func: Optional[Callable[..., Any]],
    allowed_sig_algs: Tuple[str, ...],
    require_signature: bool,
) -> Tuple[Optional[bool], Optional[str]]:
    sig_block = body.get("sig")
    if sig_block is None:
        return (False, "signature_missing") if require_signature else (None, None)
    if not isinstance(sig_block, Mapping):
        return False, "signature_block_invalid"

    alg = _safe_text(sig_block.get("alg"), max_len=64)
    key_id = _safe_id(sig_block.get("key_id"), max_len=256)
    val = _safe_text(sig_block.get("val"), max_len=16 * 1024)
    if not alg or not val or not _BASE64_RE.fullmatch(val):
        return False, "signature_block_invalid"
    if allowed_sig_algs and alg.lower() not in {a.lower() for a in allowed_sig_algs}:
        return False, "signature_alg_forbidden"

    try:
        sig_bytes = base64.b64decode(val.encode("ascii"), validate=True)
    except Exception:
        return False, "signature_block_invalid"

    if require_signature and verify_sig_func is None:
        return False, "signature_verifier_missing"
    if verify_sig_func is None:
        return None, None

    req = SignatureVerificationRequest(
        alg=alg,
        key_id=key_id,
        verify_key=verify_key,
        verify_key_fp=verify_key_fp,
        body_bytes=body_bytes,
        signature_bytes=sig_bytes,
        head=head,
        receipt_sig=receipt_sig,
        body=body,
        policy_digest=_safe_text(_nested_get_first(body, (("policy_digest",), ("attestor", "policy_digest"))), max_len=256) or None,
        cfg_fp=_safe_text(_nested_get_first(body, (("cfg_fp",), ("config_hash",), ("policy", "cfg_digest"))), max_len=256) or None,
    )
    try:
        ok = bool(_call_verify_sig_func(verify_sig_func, req))
    except Exception:
        return False, "signature_verify_error"
    return ok, None if ok else "signature_invalid"


def _verify_verify_key_policy(
    *,
    provided_verify_key: Optional[str],
    body_verify_key: Optional[str],
    body_verify_key_id: Optional[str],
    body_verify_key_fp: Optional[str],
    allow_prefixes: Tuple[str, ...],
    deny_prefixes: Tuple[str, ...],
    label_salt_hex: Optional[str],
    strict: bool,
) -> Tuple[Optional[bool], Optional[str], Optional[bool], Optional[str]]:
    raw = provided_verify_key or body_verify_key
    if not raw and not body_verify_key_fp:
        return None, None, None, None

    fp_candidates = _compute_verify_key_fp_candidates(raw, label_salt_hex=label_salt_hex) if raw else []
    presented_fp = fp_candidates[0] if fp_candidates else body_verify_key_fp

    binding_ok: Optional[bool] = None
    if provided_verify_key and body_verify_key:
        binding_ok = (provided_verify_key == body_verify_key)
    elif provided_verify_key and body_verify_key_fp:
        norm_body_fp = _normalize_digest(body_verify_key_fp, kind="any") or body_verify_key_fp
        binding_ok = any(((_normalize_digest(c, kind="any") or c) == norm_body_fp) for c in fp_candidates)
    elif provided_verify_key and body_verify_key_id:
        binding_ok = None
    elif body_verify_key_fp or body_verify_key_id or body_verify_key:
        binding_ok = True if not strict else None

    def _match(prefixes: Tuple[str, ...], value: str) -> bool:
        vl = value.lower()
        for p in prefixes:
            pp = _safe_text(p, max_len=128).lower()
            if pp and vl.startswith(pp):
                return True
        return False

    decision_val = (presented_fp or raw or "")
    if decision_val:
        if deny_prefixes and _match(deny_prefixes, decision_val):
            return False, presented_fp, binding_ok, "verify_key_denied"
        if allow_prefixes and not _match(allow_prefixes, decision_val):
            return False, presented_fp, binding_ok, "verify_key_not_allowed"

    if strict and binding_ok is False:
        return False, presented_fp, binding_ok, "verify_key_binding_invalid"

    return True, presented_fp, binding_ok, None


def _verify_policy_bindings(
    fields: Mapping[str, Any],
    *,
    expected_policy_ref: Optional[str],
    expected_policyset_ref: Optional[str],
    expected_policy_digest: Optional[str],
    expected_cfg_fp: Optional[str],
    strict: bool,
) -> Tuple[Optional[bool], Optional[bool], List[str]]:
    errs: List[str] = []
    policy_ok: Optional[bool] = None
    cfg_ok: Optional[bool] = None

    if expected_policy_ref is not None or expected_policyset_ref is not None or expected_policy_digest is not None:
        policy_ok = True
        if expected_policy_ref is not None:
            got = _safe_text(fields.get("policy_ref"), max_len=256) or None
            if got is None:
                policy_ok = False
                errs.append("policy_ref_missing")
            elif got != expected_policy_ref:
                policy_ok = False
                errs.append("policy_ref_mismatch")
        if expected_policyset_ref is not None:
            got = _safe_text(fields.get("policyset_ref"), max_len=256) or None
            if got is None:
                policy_ok = False
                errs.append("policyset_ref_missing")
            elif got != expected_policyset_ref:
                policy_ok = False
                errs.append("policyset_ref_mismatch")
        if expected_policy_digest is not None:
            got = _normalize_digest(fields.get("policy_digest"), kind="any")
            exp = _normalize_digest(expected_policy_digest, kind="any")
            if got is None:
                policy_ok = False
                errs.append("policy_digest_missing")
            elif exp is None or got != exp:
                policy_ok = False
                errs.append("policy_digest_mismatch")

    if expected_cfg_fp is not None:
        cfg_ok = True
        got_cfg = _normalize_digest(fields.get("cfg_fp"), kind="cfg_fp")
        exp_cfg = _normalize_digest(expected_cfg_fp, kind="cfg_fp")
        if got_cfg is None:
            cfg_ok = False
            errs.append("cfg_fp_missing")
        elif exp_cfg is None or got_cfg != exp_cfg:
            cfg_ok = False
            errs.append("cfg_fp_mismatch")

    return policy_ok, cfg_ok, errs


def _verify_supply_chain(
    fields: Mapping[str, Any],
    *,
    expected_build_id: Optional[str],
    expected_image_digest: Optional[str],
    enforce: bool,
) -> Tuple[Optional[bool], List[str]]:
    errs: List[str] = []
    if expected_build_id is None and expected_image_digest is None and not enforce:
        return None, errs

    ok = True
    if expected_build_id is not None:
        got = _safe_text(fields.get("build_id"), max_len=256) or None
        if got is None:
            ok = False
            errs.append("build_id_missing")
        elif got != expected_build_id:
            ok = False
            errs.append("build_id_mismatch")
    if expected_image_digest is not None:
        got = _normalize_digest(fields.get("image_digest"), kind="any") or (_safe_text(fields.get("image_digest"), max_len=256) or None)
        exp = _normalize_digest(expected_image_digest, kind="any") or expected_image_digest
        if got is None:
            ok = False
            errs.append("image_digest_missing")
        elif got != exp:
            ok = False
            errs.append("image_digest_mismatch")
    return ok, errs


def _verify_pq(
    body: Mapping[str, Any],
    *,
    enforce_required: bool,
    enforce_signature: bool,
) -> Tuple[Optional[bool], List[str], Optional[bool], Optional[bool], Optional[bool], Optional[bool]]:
    fields = _extract_receipt_fields(body)
    pq_required = fields.get("pq_required")
    pq_ok = fields.get("pq_ok")
    pq_sig_required = fields.get("pq_signature_required")
    pq_sig_ok = fields.get("pq_signature_ok")
    errs: List[str] = []
    if enforce_required and pq_required and (pq_ok is not True):
        errs.append("pq_required_not_ok")
    if enforce_signature and pq_sig_required and (pq_sig_ok is not True):
        errs.append("pq_signature_required_not_ok")
    return (None if not (enforce_required or enforce_signature) else len(errs) == 0), errs, pq_required, pq_ok, pq_sig_required, pq_sig_ok


@dataclass(frozen=True)
class VerifyConfig:
    profile: str = "PROD"
    max_receipt_body_bytes: int = _MAX_RECEIPT_BODY_BYTES
    max_chain_items: int = _MAX_CHAIN_ITEMS
    max_chain_total_bytes: int = _MAX_CHAIN_TOTAL_BYTES
    max_json_depth: int = _MAX_JSON_DEPTH
    max_json_int_digits: int = _MAX_JSON_INT_DIGITS

    enforce_forbidden_keys: bool = True
    require_canonical_body_in_strict: bool = True
    require_signature_in_strict: bool = False
    enforce_attestation_integrity: bool = True
    enforce_pq_required_in_strict: bool = False
    enforce_pq_signature_in_strict: bool = False
    enforce_supply_chain_match: bool = False

    require_attest_contract_in_strict: bool = False
    use_attest_verifier_when_available: bool = True
    allow_local_attest_fallback: bool = True
    allow_legacy_head_fallback: bool = True

    include_verify_key_in_view: bool = True
    allowed_sig_algs: Tuple[str, ...] = ()


@dataclass(frozen=True)
class VerifyBundleDiagnostics:
    policy_digest: str
    profile: str
    utils_contract_ok: bool
    attest_contract_ok: bool
    schemas_contract_ok: bool
    compat_mode_used: bool
    warnings: Tuple[str, ...]
    errors: Tuple[str, ...]


@dataclass(frozen=True)
class VerifyPolicyBundle:
    schema: str
    compatibility_epoch: str
    canonicalization_version: str
    bundle_version: int
    config_fingerprint: str
    profile: str
    strict_profile: bool
    max_receipt_body_bytes: int
    max_chain_items: int
    max_chain_total_bytes: int
    max_json_depth: int
    max_json_int_digits: int
    enforce_forbidden_keys: bool
    require_canonical_body_in_strict: bool
    require_signature_in_strict: bool
    enforce_attestation_integrity: bool
    enforce_pq_required_in_strict: bool
    enforce_pq_signature_in_strict: bool
    enforce_supply_chain_match: bool
    require_attest_contract_in_strict: bool
    use_attest_verifier_when_available: bool
    allow_local_attest_fallback: bool
    allow_legacy_head_fallback: bool
    include_verify_key_in_view: bool
    allowed_sig_algs: Tuple[str, ...]
    diagnostics: VerifyBundleDiagnostics


@dataclass(frozen=True)
class VerifyPhaseResult:
    phase: str
    ok: bool
    reason_code: str = R_OK
    severity: str = "info"
    warnings: Tuple[str, ...] = ()
    details: Mapping[str, Any] = field(default_factory=dict)
    elapsed_ms: float = 0.0


@dataclass(frozen=True)
class VerifyReceiptInput:
    receipt_head_hex: str
    receipt_body_json: str
    verify_key_hex: Optional[str] = None
    receipt_sig_hex: Optional[str] = None
    req_obj: Any = None
    comp_obj: Any = None
    e_obj: Any = None
    witness_segments: Any = None
    strict: bool = True
    label_salt_hex: Optional[str] = None
    expected_policy_ref: Optional[str] = None
    expected_policyset_ref: Optional[str] = None
    expected_policy_digest: Optional[str] = None
    expected_cfg_fp: Optional[str] = None
    expected_build_id: Optional[str] = None
    expected_image_digest: Optional[str] = None
    verify_key_allowlist: Tuple[str, ...] = ()
    verify_key_denylist: Tuple[str, ...] = ()
    verify_sig_func: Optional[Callable[..., Any]] = None
    require_signature: Optional[bool] = None


@dataclass(frozen=True)
class VerifyChainInput:
    heads: Sequence[str]
    bodies: Sequence[str]
    strict: bool = True
    label_salt_hex: Optional[str] = None
    expected_policy_ref: Optional[str] = None
    expected_policyset_ref: Optional[str] = None
    expected_policy_digest: Optional[str] = None
    expected_cfg_fp: Optional[str] = None


@dataclass(frozen=True)
class ReceiptVerifyReport:
    ok: bool
    reason: str
    strict: bool
    schema: Optional[str] = None
    head: Optional[str] = None
    body: Optional[str] = None
    sig: Optional[str] = None
    verify_key: Optional[str] = None
    verify_key_id: Optional[str] = None
    verify_key_fp: Optional[str] = None
    receipt_integrity: Optional[str] = None
    body_kind: Optional[str] = None
    body_digest: Optional[str] = None
    policy_ref: Optional[str] = None
    policyset_ref: Optional[str] = None
    policy_digest: Optional[str] = None
    cfg_fp: Optional[str] = None
    state_domain_id: Optional[str] = None
    adapter_registry_fp: Optional[str] = None
    event_id: Optional[str] = None
    decision_id: Optional[str] = None
    route_plan_id: Optional[str] = None
    head_verified: Optional[bool] = None
    body_canonical_verified: Optional[bool] = None
    integrity_hash_verified: Optional[bool] = None
    signature_verified: Optional[bool] = None
    verify_key_allowed: Optional[bool] = None
    verify_key_binding_verified: Optional[bool] = None
    policy_binding_verified: Optional[bool] = None
    cfg_binding_verified: Optional[bool] = None
    pq_required: Optional[bool] = None
    pq_ok: Optional[bool] = None
    pq_signature_required: Optional[bool] = None
    pq_signature_ok: Optional[bool] = None
    integrity_ok: bool = True
    integrity_errors: Tuple[str, ...] = ()
    warnings: Tuple[str, ...] = ()
    compat_mode_used: bool = False
    phases: Tuple[VerifyPhaseResult, ...] = ()
    latency_ms: float = 0.0

    def to_dict(self, *, include_verify_key: bool = True, include_phases: bool = True) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "schema": self.schema,
            "head": self.head,
            "body": self.body,
            "sig": self.sig,
            "verify_key": self.verify_key if include_verify_key else None,
            "verify_key_id": self.verify_key_id,
            "verify_key_fp": self.verify_key_fp,
            "receipt_integrity": self.receipt_integrity,
            "body_kind": self.body_kind,
            "body_digest": self.body_digest,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "policy_digest": self.policy_digest,
            "cfg_fp": self.cfg_fp,
            "state_domain_id": self.state_domain_id,
            "adapter_registry_fp": self.adapter_registry_fp,
            "event_id": self.event_id,
            "decision_id": self.decision_id,
            "route_plan_id": self.route_plan_id,
            "head_verified": self.head_verified,
            "body_canonical_verified": self.body_canonical_verified,
            "integrity_hash_verified": self.integrity_hash_verified,
            "signature_verified": self.signature_verified,
            "verify_key_allowed": self.verify_key_allowed,
            "verify_key_binding_verified": self.verify_key_binding_verified,
            "policy_binding_verified": self.policy_binding_verified,
            "cfg_binding_verified": self.cfg_binding_verified,
            "pq_required": self.pq_required,
            "pq_ok": self.pq_ok,
            "pq_signature_required": self.pq_signature_required,
            "pq_signature_ok": self.pq_signature_ok,
            "integrity_ok": self.integrity_ok,
            "integrity_errors": list(self.integrity_errors),
            "warnings": list(self.warnings),
            "compat_mode_used": self.compat_mode_used,
            "ok": self.ok,
            "reason": self.reason,
            "strict": self.strict,
            "latency_ms": self.latency_ms,
        }
        if include_phases:
            out["phases"] = [
                {
                    "phase": p.phase,
                    "ok": p.ok,
                    "reason_code": p.reason_code,
                    "severity": p.severity,
                    "warnings": list(p.warnings),
                    "details": dict(p.details),
                    "elapsed_ms": p.elapsed_ms,
                }
                for p in self.phases
            ]
        return {k: v for k, v in out.items() if v is not None}

    def to_verification_view(self, *, include_verify_key: bool = True) -> Any:
        payload = {
            "schema": self.schema,
            "head": self.head,
            "body": self.body,
            "sig": self.sig,
            "verify_key": self.verify_key if include_verify_key else None,
            "verify_key_id": self.verify_key_id,
            "verify_key_fp": self.verify_key_fp,
            "receipt_integrity": self.receipt_integrity,
            "body_kind": self.body_kind,
            "body_digest": self.body_digest,
            "head_verified": self.head_verified,
            "body_canonical_verified": self.body_canonical_verified,
            "integrity_hash_verified": self.integrity_hash_verified,
            "signature_verified": self.signature_verified,
            "verify_key_allowed": self.verify_key_allowed,
            "policy_binding_verified": self.policy_binding_verified,
            "cfg_binding_verified": self.cfg_binding_verified,
            "integrity_ok": self.integrity_ok,
            "integrity_errors": list(self.integrity_errors),
        }
        if ReceiptVerificationView is not None:
            try:
                if hasattr(ReceiptVerificationView, "model_validate"):
                    return ReceiptVerificationView.model_validate(payload)  # type: ignore[attr-defined]
            except Exception:
                pass
        return payload


@dataclass(frozen=True)
class ChainVerifyReport:
    ok: bool
    reason: str
    strict: bool
    checked: int
    verified: int
    selected_chain_len: int
    selected_tip: Optional[str] = None
    tip_candidates: int = 0
    chain_id: Optional[str] = None
    chain_namespace: Optional[str] = None
    ts_monotonic: Optional[bool] = None
    pq_consistent: Optional[bool] = None
    integrity_ok: bool = True
    integrity_errors: Tuple[str, ...] = ()
    item_errors: Tuple[str, ...] = ()
    warnings: Tuple[str, ...] = ()
    compat_mode_used: bool = False
    phases: Tuple[VerifyPhaseResult, ...] = ()
    latency_ms: float = 0.0

    def to_dict(self, *, include_phases: bool = True) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "ok": self.ok,
            "reason": self.reason,
            "strict": self.strict,
            "checked": self.checked,
            "verified": self.verified,
            "selected_chain_len": self.selected_chain_len,
            "selected_tip": self.selected_tip,
            "tip_candidates": self.tip_candidates,
            "chain_id": self.chain_id,
            "chain_namespace": self.chain_namespace,
            "ts_monotonic": self.ts_monotonic,
            "pq_consistent": self.pq_consistent,
            "integrity_ok": self.integrity_ok,
            "integrity_errors": list(self.integrity_errors),
            "item_errors": list(self.item_errors),
            "warnings": list(self.warnings),
            "compat_mode_used": self.compat_mode_used,
            "latency_ms": self.latency_ms,
        }
        if include_phases:
            out["phases"] = [
                {
                    "phase": p.phase,
                    "ok": p.ok,
                    "reason_code": p.reason_code,
                    "severity": p.severity,
                    "warnings": list(p.warnings),
                    "details": dict(p.details),
                    "elapsed_ms": p.elapsed_ms,
                }
                for p in self.phases
            ]
        return {k: v for k, v in out.items() if v is not None}


def compile_verify_bundle(config: Optional[VerifyConfig] = None) -> VerifyPolicyBundle:
    cfg = config or VerifyConfig()
    profile = _safe_text(cfg.profile, max_len=32).upper() or "PROD"
    if profile not in _ALLOWED_PROFILES:
        profile = "PROD"
    strict_profile = profile in _STRICT_PROFILES

    allowed_sig_algs = tuple(sorted({_safe_text(x, max_len=64).lower() for x in cfg.allowed_sig_algs if _safe_text(x, max_len=64)}))

    utils_contract_ok = True
    attest_contract_ok = bool(_attest_verify_ex is not None and _attest_compute_head_from_body is not None)
    schemas_contract_ok = bool(ReceiptVerificationView is not None)

    warnings: List[str] = []
    errors: List[str] = []
    compat_mode_used = False

    if not attest_contract_ok:
        compat_mode_used = True
        warnings.append("attest_contract_missing")
        if strict_profile and bool(cfg.require_attest_contract_in_strict) and not bool(cfg.allow_local_attest_fallback):
            errors.append("attest_contract_required")

    payload = {
        "schema": _SCHEMA,
        "compatibility_epoch": _COMPATIBILITY_EPOCH,
        "canonicalization_version": _CANONICALIZATION_VERSION,
        "profile": profile,
        "max_receipt_body_bytes": int(cfg.max_receipt_body_bytes),
        "max_chain_items": int(cfg.max_chain_items),
        "max_chain_total_bytes": int(cfg.max_chain_total_bytes),
        "max_json_depth": int(cfg.max_json_depth),
        "max_json_int_digits": int(cfg.max_json_int_digits),
        "enforce_forbidden_keys": bool(cfg.enforce_forbidden_keys),
        "require_canonical_body_in_strict": bool(cfg.require_canonical_body_in_strict),
        "require_signature_in_strict": bool(cfg.require_signature_in_strict),
        "enforce_attestation_integrity": bool(cfg.enforce_attestation_integrity),
        "enforce_pq_required_in_strict": bool(cfg.enforce_pq_required_in_strict),
        "enforce_pq_signature_in_strict": bool(cfg.enforce_pq_signature_in_strict),
        "enforce_supply_chain_match": bool(cfg.enforce_supply_chain_match),
        "require_attest_contract_in_strict": bool(cfg.require_attest_contract_in_strict),
        "use_attest_verifier_when_available": bool(cfg.use_attest_verifier_when_available),
        "allow_local_attest_fallback": bool(cfg.allow_local_attest_fallback),
        "allow_legacy_head_fallback": bool(cfg.allow_legacy_head_fallback),
        "include_verify_key_in_view": bool(cfg.include_verify_key_in_view),
        "allowed_sig_algs": list(allowed_sig_algs),
        "attest_contract_ok": attest_contract_ok,
        "schemas_contract_ok": schemas_contract_ok,
    }
    config_fingerprint = "tcd.verify.bundle:" + hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()[:32]
    policy_digest = "tcd.verify.policy:" + hashlib.sha256(_canonical_json_bytes({**payload, "warnings": warnings, "errors": errors})).hexdigest()[:32]

    diagnostics = VerifyBundleDiagnostics(
        policy_digest=policy_digest,
        profile=profile,
        utils_contract_ok=utils_contract_ok,
        attest_contract_ok=attest_contract_ok,
        schemas_contract_ok=schemas_contract_ok,
        compat_mode_used=compat_mode_used,
        warnings=tuple(dict.fromkeys(warnings)),
        errors=tuple(dict.fromkeys(errors)),
    )

    return VerifyPolicyBundle(
        schema=_SCHEMA,
        compatibility_epoch=_COMPATIBILITY_EPOCH,
        canonicalization_version=_CANONICALIZATION_VERSION,
        bundle_version=3,
        config_fingerprint=config_fingerprint,
        profile=profile,
        strict_profile=strict_profile,
        max_receipt_body_bytes=max(1024, min(8 * 1024 * 1024, int(cfg.max_receipt_body_bytes))),
        max_chain_items=max(1, min(100_000, int(cfg.max_chain_items))),
        max_chain_total_bytes=max(1024, min(128 * 1024 * 1024, int(cfg.max_chain_total_bytes))),
        max_json_depth=max(8, min(1024, int(cfg.max_json_depth))),
        max_json_int_digits=max(64, min(100_000, int(cfg.max_json_int_digits))),
        enforce_forbidden_keys=bool(cfg.enforce_forbidden_keys),
        require_canonical_body_in_strict=bool(cfg.require_canonical_body_in_strict),
        require_signature_in_strict=bool(cfg.require_signature_in_strict),
        enforce_attestation_integrity=bool(cfg.enforce_attestation_integrity),
        enforce_pq_required_in_strict=bool(cfg.enforce_pq_required_in_strict),
        enforce_pq_signature_in_strict=bool(cfg.enforce_pq_signature_in_strict),
        enforce_supply_chain_match=bool(cfg.enforce_supply_chain_match),
        require_attest_contract_in_strict=bool(cfg.require_attest_contract_in_strict),
        use_attest_verifier_when_available=bool(cfg.use_attest_verifier_when_available),
        allow_local_attest_fallback=bool(cfg.allow_local_attest_fallback),
        allow_legacy_head_fallback=bool(cfg.allow_legacy_head_fallback),
        include_verify_key_in_view=bool(cfg.include_verify_key_in_view),
        allowed_sig_algs=allowed_sig_algs,
        diagnostics=diagnostics,
    )


VERIFY_IMPL_DIGEST = "verify3:" + hashlib.sha256(
    _canonical_json_bytes(
        {
            "schema": _SCHEMA,
            "compatibility_epoch": _COMPATIBILITY_EPOCH,
            "canonicalization_version": _CANONICALIZATION_VERSION,
            "attest_verify_present": bool(_attest_verify_ex is not None),
            "attest_head_present": bool(_attest_compute_head_from_body is not None),
            "schemas_present": bool(ReceiptVerificationView is not None),
        }
    )
).hexdigest()[:32]


def verify_receipt_ex(
    *,
    receipt_head_hex: str,
    receipt_body_json: str,
    verify_key_hex: Optional[str] = None,
    receipt_sig_hex: Optional[str] = None,
    req_obj: Any = None,
    comp_obj: Any = None,
    e_obj: Any = None,
    witness_segments: Any = None,
    strict: bool = True,
    label_salt_hex: Optional[str] = None,
    expected_policy_ref: Optional[str] = None,
    expected_policyset_ref: Optional[str] = None,
    expected_policy_digest: Optional[str] = None,
    expected_cfg_fp: Optional[str] = None,
    expected_build_id: Optional[str] = None,
    expected_image_digest: Optional[str] = None,
    verify_key_allowlist: Optional[Sequence[str]] = None,
    verify_key_denylist: Optional[Sequence[str]] = None,
    verify_sig_func: Optional[Callable[..., Any]] = None,
    require_signature: Optional[bool] = None,
    config: Optional[VerifyConfig] = None,
) -> ReceiptVerifyReport:
    bundle = compile_verify_bundle(config)
    return _verify_receipt_report(
        VerifyReceiptInput(
            receipt_head_hex=receipt_head_hex,
            receipt_body_json=receipt_body_json,
            verify_key_hex=verify_key_hex,
            receipt_sig_hex=receipt_sig_hex,
            req_obj=req_obj,
            comp_obj=comp_obj,
            e_obj=e_obj,
            witness_segments=witness_segments,
            strict=bool(strict),
            label_salt_hex=label_salt_hex,
            expected_policy_ref=expected_policy_ref,
            expected_policyset_ref=expected_policyset_ref,
            expected_policy_digest=expected_policy_digest,
            expected_cfg_fp=expected_cfg_fp,
            expected_build_id=expected_build_id,
            expected_image_digest=expected_image_digest,
            verify_key_allowlist=tuple(verify_key_allowlist or ()),
            verify_key_denylist=tuple(verify_key_denylist or ()),
            verify_sig_func=verify_sig_func,
            require_signature=require_signature,
        ),
        bundle=bundle,
    )


def verify_receipt(**kwargs: Any) -> bool:
    return bool(verify_receipt_ex(**kwargs).ok)


def _verify_receipt_report(inp: VerifyReceiptInput, *, bundle: VerifyPolicyBundle) -> ReceiptVerifyReport:
    started = time.perf_counter()
    strict = bool(inp.strict)
    phases: List[VerifyPhaseResult] = []
    errors: List[str] = []
    warnings: List[str] = list(bundle.diagnostics.warnings)

    require_signature = inp.require_signature
    if require_signature is None:
        require_signature = bool(strict and bundle.require_signature_in_strict)

    if bundle.diagnostics.errors and strict and bundle.strict_profile:
        errors.extend(bundle.diagnostics.errors)
        return ReceiptVerifyReport(
            ok=False,
            reason=R_DEPENDENCY_CONTRACT,
            strict=strict,
            integrity_ok=False,
            integrity_errors=tuple(dict.fromkeys(errors)),
            warnings=tuple(dict.fromkeys(warnings)),
            compat_mode_used=bundle.diagnostics.compat_mode_used,
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )

    t0 = time.perf_counter()
    head_input = _normalize_digest(inp.receipt_head_hex, kind="receipt_head")
    if head_input is None:
        phases.append(VerifyPhaseResult("input", False, R_BAD_INPUT, "fatal", details={"field": "receipt_head_hex"}, elapsed_ms=(time.perf_counter() - t0) * 1000.0))
        return ReceiptVerifyReport(
            ok=False,
            reason=R_BAD_INPUT,
            strict=strict,
            integrity_ok=False,
            integrity_errors=("invalid_receipt_head",),
            warnings=tuple(dict.fromkeys(warnings)),
            compat_mode_used=bundle.diagnostics.compat_mode_used,
            phases=tuple(phases),
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )
    if not isinstance(inp.receipt_body_json, str):
        phases.append(VerifyPhaseResult("input", False, R_BAD_INPUT, "fatal", details={"field": "receipt_body_json"}, elapsed_ms=(time.perf_counter() - t0) * 1000.0))
        return ReceiptVerifyReport(
            ok=False,
            reason=R_BAD_INPUT,
            strict=strict,
            head=head_input,
            integrity_ok=False,
            integrity_errors=("invalid_receipt_body",),
            warnings=tuple(dict.fromkeys(warnings)),
            compat_mode_used=bundle.diagnostics.compat_mode_used,
            phases=tuple(phases),
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )
    phases.append(VerifyPhaseResult("input", True, R_OK, elapsed_ms=(time.perf_counter() - t0) * 1000.0))

    t1 = time.perf_counter()
    try:
        body_obj = _json_loads_strict(
            inp.receipt_body_json,
            max_bytes=bundle.max_receipt_body_bytes,
            max_depth=bundle.max_json_depth,
            max_int_digits=bundle.max_json_int_digits,
        )
    except Exception as exc:
        phases.append(VerifyPhaseResult("parse", False, R_PARSE_ERROR, "fatal", details={"error": _safe_text(exc, max_len=128)}, elapsed_ms=(time.perf_counter() - t1) * 1000.0))
        return ReceiptVerifyReport(
            ok=False,
            reason=R_PARSE_ERROR,
            strict=strict,
            head=head_input,
            integrity_ok=False,
            integrity_errors=(f"body_parse:{_safe_text(exc, max_len=96)}",),
            warnings=tuple(dict.fromkeys(warnings)),
            compat_mode_used=bundle.diagnostics.compat_mode_used,
            phases=tuple(phases),
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )
    if not isinstance(body_obj, Mapping):
        phases.append(VerifyPhaseResult("parse", False, R_PARSE_ERROR, "fatal", details={"error": "body_not_mapping"}, elapsed_ms=(time.perf_counter() - t1) * 1000.0))
        return ReceiptVerifyReport(
            ok=False,
            reason=R_PARSE_ERROR,
            strict=strict,
            head=head_input,
            integrity_ok=False,
            integrity_errors=("body_not_mapping",),
            warnings=tuple(dict.fromkeys(warnings)),
            compat_mode_used=bundle.diagnostics.compat_mode_used,
            phases=tuple(phases),
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )
    body = dict(body_obj)
    phases.append(VerifyPhaseResult("parse", True, R_OK, elapsed_ms=(time.perf_counter() - t1) * 1000.0))

    fields = _extract_receipt_fields(body)

    t2 = time.perf_counter()
    ok_sec, sec_errs = _validate_body_security(body, strict=strict)
    if not ok_sec:
        errors.extend(sec_errs)
        phases.append(VerifyPhaseResult("body_security", False, R_BODY_SECURITY_INVALID, "fatal", details={"errors": list(sec_errs)}, elapsed_ms=(time.perf_counter() - t2) * 1000.0))
    else:
        phases.append(VerifyPhaseResult("body_security", True, R_OK, elapsed_ms=(time.perf_counter() - t2) * 1000.0))

    t3 = time.perf_counter()
    try:
        canonical_body_bytes, canonical_body_json = _body_string_candidates(body)
        body_canonical_verified = inp.receipt_body_json.encode("utf-8", errors="strict") == canonical_body_bytes
    except Exception as exc:
        canonical_body_bytes = inp.receipt_body_json.encode("utf-8", errors="strict")
        canonical_body_json = inp.receipt_body_json
        body_canonical_verified = False
        warnings.append(f"canonical_body_error:{_safe_text(exc, max_len=64)}")
    if strict and bundle.require_canonical_body_in_strict and not body_canonical_verified:
        errors.append("body_not_canonical")
        phases.append(VerifyPhaseResult("canonical_body", False, R_BODY_NOT_CANONICAL, "fatal", elapsed_ms=(time.perf_counter() - t3) * 1000.0))
    else:
        phases.append(VerifyPhaseResult("canonical_body", True, R_OK, warnings=("body_not_canonical",) if not body_canonical_verified else (), elapsed_ms=(time.perf_counter() - t3) * 1000.0))

    body_kind = fields.get("body_kind") or ("canonical_json" if body_canonical_verified else "opaque")
    body_digest = f"sha256:{hashlib.sha256(canonical_body_bytes).hexdigest()}"

    t_att = time.perf_counter()
    if bundle.use_attest_verifier_when_available and _attest_verify_ex is not None and inp.receipt_sig_hex is not None:
        try:
            ok_att, reason_att, details_att = _attest_verify_ex(
                receipt=head_input,
                receipt_body=inp.receipt_body_json,
                receipt_sig=inp.receipt_sig_hex,
                max_body_bytes=bundle.max_receipt_body_bytes,
                max_json_depth=bundle.max_json_depth,
                max_nodes=8192,
                max_list_items=512,
                max_dict_items=512,
                max_string_bytes=_MAX_JSON_STRING_BYTES,
                max_key_bytes=2048,
                strict_structure=bool(strict),
                require_canonical_body=bool(strict and bundle.require_canonical_body_in_strict),
                require_sig=bool(require_signature),
                verify_sig_func=inp.verify_sig_func,
            )
            if not ok_att:
                errors.append(f"attest:{reason_att}")
                if details_att:
                    warnings.append(_safe_text(details_att, max_len=256))
                phases.append(VerifyPhaseResult("attest_contract", False, R_DEPENDENCY_CONTRACT, "fatal", details={"reason": reason_att}, elapsed_ms=(time.perf_counter() - t_att) * 1000.0))
            else:
                phases.append(VerifyPhaseResult("attest_contract", True, R_OK, elapsed_ms=(time.perf_counter() - t_att) * 1000.0))
        except Exception as exc:
            if strict and bundle.strict_profile and not bundle.allow_local_attest_fallback:
                errors.append("attest_contract_exception")
                phases.append(VerifyPhaseResult("attest_contract", False, R_DEPENDENCY_CONTRACT, "fatal", details={"error": _safe_text(exc, max_len=128)}, elapsed_ms=(time.perf_counter() - t_att) * 1000.0))
            else:
                warnings.append(f"attest_contract_exception:{_safe_text(exc, max_len=64)}")
                phases.append(VerifyPhaseResult("attest_contract", True, R_OK, warnings=("local_attest_fallback",), elapsed_ms=(time.perf_counter() - t_att) * 1000.0))
    elif strict and bundle.strict_profile and bundle.require_attest_contract_in_strict and not bundle.allow_local_attest_fallback:
        errors.append("attest_contract_missing")
        phases.append(VerifyPhaseResult("attest_contract", False, R_DEPENDENCY_CONTRACT, "fatal", details={"error": "attest_contract_missing"}, elapsed_ms=(time.perf_counter() - t_att) * 1000.0))
    else:
        extra_warns = []
        if bundle.diagnostics.compat_mode_used:
            extra_warns.append("local_attest_fallback")
        if inp.receipt_sig_hex is None:
            extra_warns.append("attest_crosscheck_skipped_no_receipt_sig")
        phases.append(VerifyPhaseResult("attest_contract", True, R_OK, warnings=tuple(extra_warns), elapsed_ms=(time.perf_counter() - t_att) * 1000.0))

    t4 = time.perf_counter()
    head_candidates = _compute_head_candidates(body, allow_legacy=bundle.allow_legacy_head_fallback)
    head_verified = any(_secure_compare_hex(c, head_input) for c in head_candidates)
    declared_head = _normalize_digest(_nested_get_first(body, (("head",), ("receipt",), ("receipt_head",))), kind="receipt_head")
    if declared_head is not None and not _secure_compare_hex(declared_head, head_input):
        errors.append("body_declared_head_mismatch")
    if not head_verified:
        errors.append("head_mismatch")
        phases.append(VerifyPhaseResult("head", False, R_HEAD_MISMATCH, "fatal", details={"candidates": head_candidates[:4]}, elapsed_ms=(time.perf_counter() - t4) * 1000.0))
    else:
        phases.append(VerifyPhaseResult("head", True, R_OK, elapsed_ms=(time.perf_counter() - t4) * 1000.0))

    t5 = time.perf_counter()
    receipt_integrity = fields.get("receipt_integrity") or "sha256:tcd:attest_sig"
    integrity_hash_verified: Optional[bool] = None
    if inp.receipt_sig_hex is not None:
        sig_norm = _normalize_digest(inp.receipt_sig_hex, kind="any")
        if sig_norm is None:
            integrity_hash_verified = False
            errors.append("invalid_receipt_sig")
        else:
            expect = _integrity_hash(head_input, canonical_body_bytes)
            integrity_hash_verified = _secure_compare_hex(sig_norm, expect)
            if not integrity_hash_verified:
                errors.append("receipt_integrity_hash_mismatch")
            if strict and bundle.enforce_attestation_integrity and receipt_integrity != "sha256:tcd:attest_sig":
                errors.append("receipt_integrity_mismatch")
    elif require_signature:
        errors.append("receipt_sig_missing")
        integrity_hash_verified = False
    if integrity_hash_verified is False:
        phases.append(VerifyPhaseResult("integrity_hash", False, R_INTEGRITY_MISMATCH, "fatal", elapsed_ms=(time.perf_counter() - t5) * 1000.0))
    else:
        phases.append(VerifyPhaseResult("integrity_hash", True, R_OK, elapsed_ms=(time.perf_counter() - t5) * 1000.0))

    t6 = time.perf_counter()
    verify_key_allowed, verify_key_fp, verify_key_binding_ok, verify_key_err = _verify_verify_key_policy(
        provided_verify_key=_safe_text(inp.verify_key_hex, max_len=8192) or None,
        body_verify_key=_safe_text(_nested_get_first(body, (("verify_key",),)), max_len=8192) or None,
        body_verify_key_id=fields.get("verify_key_id"),
        body_verify_key_fp=fields.get("verify_key_fp"),
        allow_prefixes=tuple(inp.verify_key_allowlist or ()),
        deny_prefixes=tuple(inp.verify_key_denylist or ()),
        label_salt_hex=inp.label_salt_hex,
        strict=strict,
    )
    if verify_key_err:
        errors.append(verify_key_err)
        phase_reason = R_VERIFY_KEY_BINDING if "binding" in verify_key_err else R_VERIFY_KEY_DENIED
        phases.append(VerifyPhaseResult("verify_key", False, phase_reason, "fatal", elapsed_ms=(time.perf_counter() - t6) * 1000.0))
    else:
        phases.append(VerifyPhaseResult("verify_key", True, R_OK, elapsed_ms=(time.perf_counter() - t6) * 1000.0))

    t7 = time.perf_counter()
    signature_verified, sig_err = _verify_signature_block(
        body,
        body_bytes=canonical_body_bytes,
        head=head_input,
        receipt_sig=inp.receipt_sig_hex,
        verify_key=_safe_text(inp.verify_key_hex, max_len=8192) or None,
        verify_key_fp=verify_key_fp,
        verify_sig_func=inp.verify_sig_func,
        allowed_sig_algs=bundle.allowed_sig_algs,
        require_signature=bool(require_signature),
    )
    if sig_err:
        errors.append(sig_err)
        reason = R_SIGNATURE_MISSING if sig_err == "signature_missing" else R_SIGNATURE_INVALID
        phases.append(VerifyPhaseResult("signature", False, reason, "fatal", details={"error": sig_err}, elapsed_ms=(time.perf_counter() - t7) * 1000.0))
    else:
        phases.append(VerifyPhaseResult("signature", True, R_OK, elapsed_ms=(time.perf_counter() - t7) * 1000.0))

    t8 = time.perf_counter()
    policy_binding_verified, cfg_binding_verified, bind_errs = _verify_policy_bindings(
        fields,
        expected_policy_ref=inp.expected_policy_ref,
        expected_policyset_ref=inp.expected_policyset_ref,
        expected_policy_digest=inp.expected_policy_digest,
        expected_cfg_fp=inp.expected_cfg_fp,
        strict=strict,
    )
    if bind_errs:
        errors.extend(bind_errs)
        phase_reason = R_CFG_BINDING_FAILED if any(e.startswith("cfg_") for e in bind_errs) else R_POLICY_BINDING_FAILED
        phases.append(VerifyPhaseResult("bindings", False, phase_reason, "fatal", details={"errors": list(bind_errs)}, elapsed_ms=(time.perf_counter() - t8) * 1000.0))
    else:
        phases.append(VerifyPhaseResult("bindings", True, R_OK, elapsed_ms=(time.perf_counter() - t8) * 1000.0))

    t9 = time.perf_counter()
    supply_ok, supply_errs = _verify_supply_chain(
        fields,
        expected_build_id=inp.expected_build_id,
        expected_image_digest=inp.expected_image_digest,
        enforce=bool(bundle.enforce_supply_chain_match and strict),
    )
    if supply_errs:
        errors.extend(supply_errs)
        phases.append(VerifyPhaseResult("supply_chain", False, R_SUPPLY_CHAIN_VIOLATION, "fatal", details={"errors": list(supply_errs)}, elapsed_ms=(time.perf_counter() - t9) * 1000.0))
    else:
        phases.append(VerifyPhaseResult("supply_chain", True, R_OK, elapsed_ms=(time.perf_counter() - t9) * 1000.0))

    t10 = time.perf_counter()
    _pq_ok, pq_errs, pq_required, pq_ok, pq_sig_required, pq_sig_ok = _verify_pq(
        body,
        enforce_required=bool(strict and bundle.enforce_pq_required_in_strict),
        enforce_signature=bool(strict and bundle.enforce_pq_signature_in_strict),
    )
    if pq_errs:
        errors.extend(pq_errs)
        phases.append(VerifyPhaseResult("pq", False, R_PQ_VIOLATION, "fatal", details={"errors": list(pq_errs)}, elapsed_ms=(time.perf_counter() - t10) * 1000.0))
    else:
        phases.append(VerifyPhaseResult("pq", True, R_OK, elapsed_ms=(time.perf_counter() - t10) * 1000.0))

    t11 = time.perf_counter()
    ok_req, req_err = _verify_optional_commit_field(body, obj=inp.req_obj, field_names=("req_commit", "req_digest", "req_obj_commit", "req_obj_digest"), schema=_REQ_SCHEMA, strict=strict)
    ok_comp, comp_err = _verify_optional_commit_field(body, obj=inp.comp_obj, field_names=("comp_commit", "comp_digest", "comp_obj_commit", "comp_obj_digest"), schema=_COMP_SCHEMA, strict=strict)
    ok_e, e_err = _verify_optional_commit_field(body, obj=inp.e_obj, field_names=("e_commit", "e_digest", "e_obj_commit", "e_obj_digest"), schema=_E_SCHEMA, strict=strict)
    obj_errs = [e for e in (req_err, comp_err, e_err) if e]
    if obj_errs:
        errors.extend(obj_errs)
        phases.append(VerifyPhaseResult("object_commitments", False, R_OBJECT_BINDING_FAILED, "fatal", details={"errors": obj_errs}, elapsed_ms=(time.perf_counter() - t11) * 1000.0))
    else:
        phases.append(VerifyPhaseResult("object_commitments", True, R_OK, elapsed_ms=(time.perf_counter() - t11) * 1000.0))

    t12 = time.perf_counter()
    witness_to_check = inp.witness_segments if inp.witness_segments is not None else _nested_get_first(body, (("witness_segments",), ("witness", "segments"), ("witness",)))
    witness_ok, witness_errs = _validate_witness_segments(witness_to_check, strict=strict)
    if witness_ok:
        wt = _nested_get_first(body, (("witness_tags",), ("witness", "tags")))
        if wt is not None and not isinstance(wt, (list, tuple, set, frozenset)):
            witness_ok = False
            witness_errs = ("witness_tags_invalid",)
        elif isinstance(wt, (list, tuple, set, frozenset)) and len(list(wt)) > _MAX_WITNESS_TAGS:
            witness_ok = False
            witness_errs = ("witness_tags_oversize",)
    if not witness_ok:
        errors.extend(witness_errs)
        phases.append(VerifyPhaseResult("witness", False, R_WITNESS_INVALID, "fatal", details={"errors": list(witness_errs)}, elapsed_ms=(time.perf_counter() - t12) * 1000.0))
    else:
        phases.append(VerifyPhaseResult("witness", True, R_OK, elapsed_ms=(time.perf_counter() - t12) * 1000.0))

    ok = len(errors) == 0
    if not ok:
        if any(e == "signature_missing" for e in errors):
            reason = R_SIGNATURE_MISSING
        elif any(e.startswith("verify_key_") for e in errors):
            reason = R_VERIFY_KEY_DENIED if any("denied" in e or "not_allowed" in e for e in errors) else R_VERIFY_KEY_BINDING
        elif any(e.startswith("policy_") or e.startswith("policyset_") for e in errors):
            reason = R_POLICY_BINDING_FAILED
        elif any(e.startswith("cfg_") for e in errors):
            reason = R_CFG_BINDING_FAILED
        elif any("head" in e for e in errors):
            reason = R_HEAD_MISMATCH
        elif any("integrity" in e or e in {"receipt_sig_missing", "invalid_receipt_sig"} for e in errors):
            reason = R_INTEGRITY_MISMATCH
        elif any("witness" in e for e in errors):
            reason = R_WITNESS_INVALID
        elif any("object_commit" in e or e == "missing_object_commit" for e in errors):
            reason = R_OBJECT_BINDING_FAILED
        elif any("pq_" in e for e in errors):
            reason = R_PQ_VIOLATION
        elif any("build_id" in e or "image_digest" in e for e in errors):
            reason = R_SUPPLY_CHAIN_VIOLATION
        elif any("canonical" in e for e in errors):
            reason = R_BODY_NOT_CANONICAL
        elif any("body" in e or "forbidden_key" in e or "route_profile" in e or "trust_zone" in e for e in errors):
            reason = R_BODY_SECURITY_INVALID
        elif any("attest_contract" in e for e in errors):
            reason = R_DEPENDENCY_CONTRACT
        else:
            reason = R_PARSE_ERROR
    else:
        reason = R_OK

    return ReceiptVerifyReport(
        ok=ok,
        reason=reason,
        strict=strict,
        schema=_safe_text(body.get("schema"), max_len=128) or _SCHEMA,
        head=head_input,
        body=canonical_body_json,
        sig=_safe_text(inp.receipt_sig_hex, max_len=8192) or None,
        verify_key=_safe_text(inp.verify_key_hex, max_len=8192) or _safe_text(_nested_get_first(body, (("verify_key",),)), max_len=8192) or None,
        verify_key_id=fields.get("verify_key_id"),
        verify_key_fp=verify_key_fp or fields.get("verify_key_fp"),
        receipt_integrity=receipt_integrity,
        body_kind=body_kind,
        body_digest=body_digest,
        policy_ref=fields.get("policy_ref"),
        policyset_ref=fields.get("policyset_ref"),
        policy_digest=fields.get("policy_digest"),
        cfg_fp=fields.get("cfg_fp"),
        state_domain_id=fields.get("state_domain_id"),
        adapter_registry_fp=fields.get("adapter_registry_fp"),
        event_id=fields.get("event_id"),
        decision_id=fields.get("decision_id"),
        route_plan_id=fields.get("route_plan_id"),
        head_verified=head_verified,
        body_canonical_verified=body_canonical_verified,
        integrity_hash_verified=integrity_hash_verified,
        signature_verified=signature_verified,
        verify_key_allowed=verify_key_allowed,
        verify_key_binding_verified=verify_key_binding_ok,
        policy_binding_verified=policy_binding_verified,
        cfg_binding_verified=cfg_binding_verified,
        pq_required=pq_required,
        pq_ok=pq_ok,
        pq_signature_required=pq_sig_required,
        pq_signature_ok=pq_sig_ok,
        integrity_ok=ok,
        integrity_errors=tuple(dict.fromkeys(errors)),
        warnings=tuple(dict.fromkeys(warnings)),
        compat_mode_used=bundle.diagnostics.compat_mode_used,
        phases=tuple(phases),
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


@dataclass(frozen=True)
class _ChainNode:
    head: str
    body: Mapping[str, Any]
    report: ReceiptVerifyReport
    prev: Optional[str]
    chain_id: Optional[str]
    chain_namespace: Optional[str]
    chain_seq: Optional[int]
    ts: Optional[float]
    pq_required: Optional[bool]
    pq_ok: Optional[bool]


def verify_chain_ex(
    heads: Sequence[str],
    bodies: Sequence[str],
    *,
    strict: bool = True,
    label_salt_hex: Optional[str] = None,
    config: Optional[VerifyConfig] = None,
    expected_policy_ref: Optional[str] = None,
    expected_policyset_ref: Optional[str] = None,
    expected_policy_digest: Optional[str] = None,
    expected_cfg_fp: Optional[str] = None,
) -> ChainVerifyReport:
    bundle = compile_verify_bundle(config)
    return _verify_chain_report(
        VerifyChainInput(
            heads=heads,
            bodies=bodies,
            strict=bool(strict),
            label_salt_hex=label_salt_hex,
            expected_policy_ref=expected_policy_ref,
            expected_policyset_ref=expected_policyset_ref,
            expected_policy_digest=expected_policy_digest,
            expected_cfg_fp=expected_cfg_fp,
        ),
        bundle=bundle,
    )


def verify_chain(
    heads: Sequence[str],
    bodies: Sequence[str],
    *,
    strict: bool = True,
    label_salt_hex: Optional[str] = None,
    config: Optional[VerifyConfig] = None,
    expected_policy_ref: Optional[str] = None,
    expected_policyset_ref: Optional[str] = None,
    expected_policy_digest: Optional[str] = None,
    expected_cfg_fp: Optional[str] = None,
) -> bool:
    return bool(
        verify_chain_ex(
            heads,
            bodies,
            strict=strict,
            label_salt_hex=label_salt_hex,
            config=config,
            expected_policy_ref=expected_policy_ref,
            expected_policyset_ref=expected_policyset_ref,
            expected_policy_digest=expected_policy_digest,
            expected_cfg_fp=expected_cfg_fp,
        ).ok
    )


def _select_best_chain(nodes: Mapping[str, _ChainNode]) -> Tuple[List[_ChainNode], List[str], int]:
    if not nodes:
        return [], [], 0

    referenced: Dict[str, int] = {}
    for n in nodes.values():
        if n.prev:
            referenced[n.prev] = referenced.get(n.prev, 0) + 1

    tips = [n for n in nodes.values() if referenced.get(n.head, 0) == 0]
    if not tips:
        tips = list(nodes.values())

    def _backtrack(tip: _ChainNode) -> Tuple[List[_ChainNode], List[str]]:
        chain: List[_ChainNode] = []
        errs: List[str] = []
        cur = tip
        seen: set[str] = set()
        while True:
            if cur.head in seen:
                errs.append("cycle_detected")
                break
            seen.add(cur.head)
            chain.append(cur)
            if not cur.prev:
                break
            nxt = nodes.get(cur.prev)
            if nxt is None:
                errs.append("missing_prev")
                break
            cur = nxt
        chain.reverse()
        return chain, errs

    best_chain: List[_ChainNode] = []
    best_errs: List[str] = []
    for tip in tips:
        chain, errs = _backtrack(tip)

        def _score(ns: List[_ChainNode]) -> Tuple[int, int, float, str]:
            last = ns[-1]
            seq = last.chain_seq if last.chain_seq is not None else -1
            ts = last.ts if last.ts is not None else -1.0
            return (len(ns), seq, ts, last.head)

        if _score(chain) > _score(best_chain):
            best_chain = chain
            best_errs = errs

    return best_chain, best_errs, len(tips)


def _verify_chain_report(inp: VerifyChainInput, *, bundle: VerifyPolicyBundle) -> ChainVerifyReport:
    started = time.perf_counter()
    strict = bool(inp.strict)
    phases: List[VerifyPhaseResult] = []
    warnings: List[str] = list(bundle.diagnostics.warnings)
    errs: List[str] = []
    item_errs: List[str] = []

    if bundle.diagnostics.errors and strict and bundle.strict_profile:
        errs.extend(bundle.diagnostics.errors)
        return ChainVerifyReport(
            ok=False,
            reason=R_DEPENDENCY_CONTRACT,
            strict=strict,
            checked=len(inp.heads),
            verified=0,
            selected_chain_len=0,
            integrity_ok=False,
            integrity_errors=tuple(dict.fromkeys(errs)),
            warnings=tuple(dict.fromkeys(warnings)),
            compat_mode_used=bundle.diagnostics.compat_mode_used,
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )

    t0 = time.perf_counter()
    if not isinstance(inp.heads, Sequence) or not isinstance(inp.bodies, Sequence):
        phases.append(VerifyPhaseResult("input", False, R_CHAIN_INVALID, "fatal", details={"error": "chain_not_sequence"}, elapsed_ms=(time.perf_counter() - t0) * 1000.0))
        return ChainVerifyReport(
            ok=False,
            reason=R_CHAIN_INVALID,
            strict=strict,
            checked=0,
            verified=0,
            selected_chain_len=0,
            integrity_ok=False,
            integrity_errors=("chain_not_sequence",),
            warnings=tuple(dict.fromkeys(warnings)),
            compat_mode_used=bundle.diagnostics.compat_mode_used,
            phases=tuple(phases),
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )
    if len(inp.heads) != len(inp.bodies) or len(inp.heads) == 0:
        phases.append(VerifyPhaseResult("input", False, R_CHAIN_INVALID, "fatal", details={"error": "chain_length_invalid"}, elapsed_ms=(time.perf_counter() - t0) * 1000.0))
        return ChainVerifyReport(
            ok=False,
            reason=R_CHAIN_INVALID,
            strict=strict,
            checked=len(inp.heads),
            verified=0,
            selected_chain_len=0,
            integrity_ok=False,
            integrity_errors=("chain_length_invalid",),
            warnings=tuple(dict.fromkeys(warnings)),
            compat_mode_used=bundle.diagnostics.compat_mode_used,
            phases=tuple(phases),
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )
    if len(inp.heads) > bundle.max_chain_items:
        phases.append(VerifyPhaseResult("input", False, R_CHAIN_INVALID, "fatal", details={"error": "chain_window_too_large"}, elapsed_ms=(time.perf_counter() - t0) * 1000.0))
        return ChainVerifyReport(
            ok=False,
            reason=R_CHAIN_INVALID,
            strict=strict,
            checked=len(inp.heads),
            verified=0,
            selected_chain_len=0,
            integrity_ok=False,
            integrity_errors=("chain_window_too_large",),
            warnings=tuple(dict.fromkeys(warnings)),
            compat_mode_used=bundle.diagnostics.compat_mode_used,
            phases=tuple(phases),
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )
    phases.append(VerifyPhaseResult("input", True, R_OK, elapsed_ms=(time.perf_counter() - t0) * 1000.0))

    total_bytes = 0
    nodes_by_head: Dict[str, _ChainNode] = {}
    duplicate_head_total = 0

    t1 = time.perf_counter()
    for idx, (h, b) in enumerate(zip(inp.heads, inp.bodies)):
        if not isinstance(h, str) or not isinstance(b, str):
            errs.append("chain_item_type_invalid")
            item_errs.append(f"idx={idx}:type")
            continue

        total_bytes += len(h.encode("utf-8", errors="ignore")) + len(b.encode("utf-8", errors="ignore"))
        if total_bytes > bundle.max_chain_total_bytes:
            errs.append("chain_total_bytes_exceeded")
            item_errs.append(f"idx={idx}:size")
            break

        rep = _verify_receipt_report(
            VerifyReceiptInput(
                receipt_head_hex=h,
                receipt_body_json=b,
                strict=strict,
                label_salt_hex=inp.label_salt_hex,
                expected_policy_ref=inp.expected_policy_ref,
                expected_policyset_ref=inp.expected_policyset_ref,
                expected_policy_digest=inp.expected_policy_digest,
                expected_cfg_fp=inp.expected_cfg_fp,
            ),
            bundle=bundle,
        )

        try:
            parsed = _json_loads_strict(b, max_bytes=bundle.max_receipt_body_bytes, max_depth=bundle.max_json_depth, max_int_digits=bundle.max_json_int_digits)
            body = parsed if isinstance(parsed, Mapping) else {}
        except Exception:
            body = {}

        if not rep.ok:
            errs.append(f"receipt[{idx}]={rep.reason}")
            item_errs.extend([f"idx={idx}:{e}" for e in rep.integrity_errors[:8]])
            continue

        head_norm = _normalize_digest(h, kind="receipt_head")
        if head_norm is None:
            errs.append("invalid_head")
            item_errs.append(f"idx={idx}:invalid_head")
            continue

        if head_norm in nodes_by_head:
            duplicate_head_total += 1
            item_errs.append(f"idx={idx}:duplicate_head")
            if strict:
                errs.append("duplicate_head")
            continue

        fields = _extract_receipt_fields(body)
        node = _ChainNode(
            head=head_norm,
            body=body,
            report=rep,
            prev=_find_prev_pointer(body),
            chain_id=_safe_text(fields.get("chain_id"), max_len=256) or None,
            chain_namespace=_safe_text(fields.get("chain_namespace"), max_len=256) or None,
            chain_seq=fields.get("chain_seq"),
            ts=(fields.get("ts_ns") / 1_000_000_000.0) if fields.get("ts_ns") is not None else fields.get("ts"),
            pq_required=fields.get("pq_required"),
            pq_ok=fields.get("pq_ok"),
        )
        nodes_by_head[head_norm] = node
    phases.append(
        VerifyPhaseResult(
            "receipt_verify",
            len(nodes_by_head) > 0,
            R_OK if nodes_by_head else R_CHAIN_INVALID,
            "fatal" if not nodes_by_head else "info",
            details={"verified_receipts": len(nodes_by_head)},
            elapsed_ms=(time.perf_counter() - t1) * 1000.0,
        )
    )

    t2 = time.perf_counter()
    chain, backtrack_errs, tip_candidates = _select_best_chain(nodes_by_head)
    selected_tip = chain[-1].head if chain else None
    chain_id = None
    chain_namespace = None
    ts_monotonic = True
    pq_consistent = True

    if chain:
        for idx, node in enumerate(chain):
            if chain_id is None and node.chain_id:
                chain_id = node.chain_id
            elif node.chain_id and chain_id and node.chain_id != chain_id:
                errs.append("chain_id_mismatch")
                item_errs.append(f"head={node.head}:chain_id")
            if chain_namespace is None and node.chain_namespace:
                chain_namespace = node.chain_namespace
            elif node.chain_namespace and chain_namespace and node.chain_namespace != chain_namespace:
                errs.append("chain_namespace_mismatch")
                item_errs.append(f"head={node.head}:chain_namespace")
            if idx > 0 and node.ts is not None and chain[idx - 1].ts is not None and node.ts < chain[idx - 1].ts:
                ts_monotonic = False
                errs.append("chain_timestamp_non_monotonic")
                item_errs.append(f"head={node.head}:ts")
            if idx > 0 and node.chain_seq is not None and chain[idx - 1].chain_seq is not None and node.chain_seq <= chain[idx - 1].chain_seq:
                errs.append("chain_seq_non_monotonic")
                item_errs.append(f"head={node.head}:chain_seq")
        pq_seen: Optional[bool] = None
        for node in chain:
            if node.pq_required:
                if pq_seen is None:
                    pq_seen = node.pq_ok
                elif node.pq_ok != pq_seen:
                    pq_consistent = False
                    errs.append("pq_consistency_violation")
                    item_errs.append(f"head={node.head}:pq")

    for err in backtrack_errs:
        errs.append(err)

    referenced: Dict[str, List[str]] = {}
    for node in nodes_by_head.values():
        if node.prev:
            referenced.setdefault(node.prev, []).append(node.head)
    forks = sum(1 for children in referenced.values() if len(children) > 1)
    if forks:
        errs.append("fork_detected")

    phases.append(
        VerifyPhaseResult(
            "chain_graph",
            len(chain) > 0,
            R_OK if chain else R_CHAIN_INVALID,
            "fatal" if not chain else "info",
            details={
                "selected_chain_len": len(chain),
                "tip_candidates": tip_candidates,
                "forks": forks,
                "backtrack_errors": list(backtrack_errs),
            },
            elapsed_ms=(time.perf_counter() - t2) * 1000.0,
        )
    )

    if strict:
        if duplicate_head_total > 0:
            errs.append("duplicate_head")
        if tip_candidates > 1:
            errs.append("multiple_tips")
        if len(chain) != len(nodes_by_head):
            errs.append("window_contains_unselected_nodes")
    else:
        if tip_candidates > 1:
            warnings.append("multiple_tips")
        if len(chain) != len(nodes_by_head):
            warnings.append("window_contains_unselected_nodes")

    ok = len(errs) == 0 and len(chain) > 0
    reason = R_OK
    if not ok:
        if any("prev" in e or "cycle" in e or "fork" in e or "tip" in e or "window_contains_unselected_nodes" in e for e in errs):
            reason = R_CHAIN_LINK_INVALID if len(chain) > 0 else R_CHAIN_AMBIGUOUS
        else:
            reason = R_CHAIN_INVALID

    return ChainVerifyReport(
        ok=ok,
        reason=reason,
        strict=strict,
        checked=len(inp.heads),
        verified=len(nodes_by_head),
        selected_chain_len=len(chain),
        selected_tip=selected_tip,
        tip_candidates=tip_candidates,
        chain_id=chain_id,
        chain_namespace=chain_namespace,
        ts_monotonic=ts_monotonic if chain else None,
        pq_consistent=pq_consistent if chain else None,
        integrity_ok=ok,
        integrity_errors=tuple(dict.fromkeys(errs)),
        item_errors=tuple(dict.fromkeys(item_errs)),
        warnings=tuple(dict.fromkeys(warnings)),
        compat_mode_used=bundle.diagnostics.compat_mode_used,
        phases=tuple(phases),
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )