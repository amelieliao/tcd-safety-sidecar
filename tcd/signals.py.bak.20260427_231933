from __future__ import annotations

"""
tcd/signals.py

Governed, content-agnostic signal / evidence bus for TCD.

This module is intentionally not a generic event bus. It is the deterministic,
bounded, policy-aware signal surface that sits between:

- routing.py strong route contracts
- security_router.py security decisions / evidence identities / artifacts
- risk_av.py e-process / controller outputs
- attest.py receipt issuance / verification
- audit.py / ledger.py append-only persistence
- service_http.py / service_grpc.py transport adapters
- schemas.py public / audit / verification views

Design goals
------------
1. Content-agnostic
   No raw prompts, completions, request/response bodies, or direct PII are
   allowed to cross this surface.

2. Deterministic
   Canonical JSON, bounded normalization, stable IDs, no background threads in
   the bus, no async, no implicit remote I/O.

3. Contract-closed
   Signal payloads align with:
     - EvidenceIdentityView / ArtifactRefsView
     - RouteContractView
     - ReceiptPublicView / ReceiptAuditView / ReceiptVerificationView
     - risk_av controller_mode / statistical_guarantee_scope / state_domain_id /
       adapter_registry_fp / selected_source / audit_ref / receipt_ref
     - security_router route_plan_id / decision_id / signal_digest /
       context_digest / artifacts / evidence_identity

4. Strong boundary hygiene
   Safe text / ID helpers are explicit and separate:
     - _safe_text
     - _safe_text_or_none
     - _safe_text_for_log
     - _safe_text_for_id

5. Synchronous core, external side-effects isolated
   Sinks are synchronous and in-process. Remote I/O should happen via durable
   local sinks (for example, outbox) outside the bus critical path.

6. Auditability
   Every important signal can project into public / audit / internal views and
   can be translated into attestation / audit / ledger payloads.
"""

import base64
import hashlib
import hmac
import json
import logging
import math
import os
import re
import threading
import time
import unicodedata
from collections import OrderedDict, deque
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from types import MappingProxyType
from typing import (
    Any,
    Callable,
    Deque,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
    Literal,
)

logger = logging.getLogger(__name__)

try:  # optional, stronger hashing when available
    from .crypto import Blake3Hash  # type: ignore
except Exception:  # pragma: no cover
    Blake3Hash = None  # type: ignore[assignment]

# Optional strong views from schemas.py. We keep these soft to avoid tight import cycles.
try:  # pragma: no cover
    from .schemas import (  # type: ignore
        EvidenceIdentityView,
        ArtifactRefsView,
        RouteContractView,
        ReceiptPublicView,
        ReceiptAuditView,
        ReceiptVerificationView,
        EProcessStateView,
    )
except Exception:  # pragma: no cover
    EvidenceIdentityView = None  # type: ignore[assignment]
    ArtifactRefsView = None  # type: ignore[assignment]
    RouteContractView = None  # type: ignore[assignment]
    ReceiptPublicView = None  # type: ignore[assignment]
    ReceiptAuditView = None  # type: ignore[assignment]
    ReceiptVerificationView = None  # type: ignore[assignment]
    EProcessStateView = None  # type: ignore[assignment]

__all__ = [
    # contract / diagnostics
    "SignalContractVersion",
    "ProducerBundle",
    "ProducerActivation",
    "SignalIntegrityIssue",
    "SignalIntegrityReport",
    "SignalBusConfig",
    "SignalEmitResult",
    "SinkDiagnostics",
    "SignalBusPublicConfigView",
    "SignalBusDiagnosticsView",
    # common identity / context
    "EvidenceIdentity",
    "ArtifactRefs",
    "SignalEnvelope",
    "SubjectContext",
    "ModelContext",
    "SecurityContext",
    "StreamContext",
    # signals
    "GovernedSignal",
    "RiskDecisionSignal",
    "SecurityDecisionSignal",
    "RouteDecisionSignal",
    "ReceiptSignal",
    "ReceiptPreparedSignal",
    "ReceiptCommittedSignal",
    "LedgerPreparedSignal",
    "LedgerCommittedSignal",
    "OutboxQueuedSignal",
    "OutboxFlushedSignal",
    "PQHealthSignal",
    "BundleLifecycleSignal",
    # provider / sinks / translator / bus
    "SignalSink",
    "SignalProvider",
    "LoggingSink",
    "InMemorySink",
    "OutboxBackendProtocol",
    "OutboxSignalSink",
    "SignalEvidenceTranslator",
    "SignalBus",
    "DefaultSignalProvider",
    "DefaultLLMSignals",
    # builders / time
    "make_contract_version",
    "make_producer_bundle",
    "make_producer_activation",
    "make_evidence_identity",
    "make_artifact_refs",
    "make_signal_envelope",
    "make_subject_context",
    "make_model_context",
    "make_security_context",
    "make_stream_context",
    "now_ts",
    "now_unix_ns",
    "now_monotonic_ns",
]

# =============================================================================
# Constants / versions / vocabularies
# =============================================================================

_SCHEMA = "tcd.signals.v4"
_SIGNAL_VERSION = "4.0.0"
_COMPATIBILITY_EPOCH = "2026Q2"
_CANONICALIZATION_VERSION = "canonjson_v1"
_DEFAULT_DEPRECATION_POLICY = "append_only_fields__compat_epoch_required"

Profile = Literal["DEV", "PROD", "FINREG", "LOCKDOWN"]

_ALLOWED_PROFILES: FrozenSet[str] = frozenset({"DEV", "PROD", "FINREG", "LOCKDOWN"})
_ALLOWED_SIGNAL_KINDS: FrozenSet[str] = frozenset(
    {
        "risk_decision",
        "security_decision",
        "route_decision",
        "receipt",
        "receipt_prepared",
        "receipt_committed",
        "ledger_prepared",
        "ledger_committed",
        "outbox_queued",
        "outbox_flushed",
        "pq_health",
        "bundle_lifecycle",
    }
)
_ALLOWED_PHASES: FrozenSet[str] = frozenset(
    {
        "observed",
        "normalized",
        "evaluated",
        "materialized",
        "prepared",
        "committed",
        "queued",
        "flushed",
        "verified",
        "replayed",
        "degraded",
    }
)
_ALLOWED_SOURCE_CLASSIFICATION: FrozenSet[str] = frozenset(
    {
        "control_plane_produced",
        "data_plane_observed",
        "reconstructed",
        "replayed",
        "imported",
        "synthetic",
        "degraded",
    }
)
_ALLOWED_TRUST_ZONES: FrozenSet[str] = frozenset(
    {"internet", "internal", "partner", "admin", "ops", "unknown", "__config_error__"}
)
_ALLOWED_ROUTE_PROFILES: FrozenSet[str] = frozenset(
    {"inference", "batch", "admin", "control", "metrics", "health", "restricted", "unknown"}
)
_ALLOWED_RISK_LABELS: FrozenSet[str] = frozenset({"low", "normal", "elevated", "high", "critical", "unknown"})
_ALLOWED_ACTIONS: FrozenSet[str] = frozenset(
    {"allow", "degrade", "block", "deny", "advisory", "log_only", "none", "degraded_allow", "degraded_block"}
)
_ALLOWED_REQUIRED_ACTIONS: FrozenSet[str] = frozenset({"allow", "degrade", "block"})
_ALLOWED_ENFORCEMENT: FrozenSet[str] = frozenset({"advisory", "must_enforce", "fail_closed"})
_ALLOWED_ROUTER_MODES: FrozenSet[str] = frozenset({"normal", "last_known_good", "fail_closed", "disabled", "degraded"})
_ALLOWED_SIGNAL_TRUST: FrozenSet[str] = frozenset({"trusted", "advisory", "untrusted"})
_ALLOWED_RECEIPT_OPS: FrozenSet[str] = frozenset({"issue", "verify"})
_ALLOWED_LEDGER_STAGE: FrozenSet[str] = frozenset({"prepared", "committed", "outboxed", "skipped", "failed"})
_ALLOWED_OUTBOX_STATUS: FrozenSet[str] = frozenset({"queued", "flushed", "dropped", "disabled", "none"})
_ALLOWED_CRITICALITY: FrozenSet[str] = frozenset({"required", "optional", "best_effort"})
_ALLOWED_TIMEOUT_BEHAVIOR: FrozenSet[str] = frozenset({"disable", "degrade", "raise"})
_ALLOWED_ON_SINK_ERROR: FrozenSet[str] = frozenset({"log_and_continue", "raise", "disable_sink"})
_ALLOWED_CONSISTENCY_LEVELS: FrozenSet[str] = frozenset(
    {"local_sync", "local_prepare_commit", "local_outbox_first", "best_effort"}
)
_ALLOWED_DELIVERY_SEMANTICS: FrozenSet[str] = frozenset(
    {"sync_in_process", "sync_with_outbox", "local_prepare_commit", "best_effort"}
)
_ALLOWED_GUARANTEE_SCOPES: FrozenSet[str] = frozenset(
    {"strict_direct_p", "predictable_calibrated_p", "heuristic_only", "none"}
)
_ALLOWED_CONTROLLER_MODES: FrozenSet[str] = frozenset(
    {"normal", "last_known_good", "fail_closed", "degraded_identity", "degraded_state_backend", "degraded_calibration"}
)
_ALLOWED_DECISION_MODES: FrozenSet[str] = frozenset(
    {"strict_only", "controller_only", "prefer_current_strict", "dual_track"}
)
_ALLOWED_RECEIPT_BODY_KINDS: FrozenSet[str] = frozenset({"canonical_json", "blob_ref", "compact_receipt", "opaque"})
_ALLOWED_BUNDLE_EVENTS: FrozenSet[str] = frozenset(
    {
        "bundle_activated",
        "bundle_rejected",
        "bundle_last_known_good",
        "bundle_fail_closed",
        "bundle_disabled",
        "config_rotated",
        "policy_rotated",
        "sink_topology_changed",
        "key_rotation",
        "profile_changed",
    }
)

_ALLOWED_REASON_CODES: FrozenSet[str] = frozenset(
    {
        "ROUTER_DISABLED",
        "ROUTER_LAST_KNOWN_GOOD",
        "ROUTER_FAIL_CLOSED",
        "CFG_ERROR",
        "CFG_ERROR_LKG",
        "INVALID_TRUST_ZONE",
        "UNKNOWN_TRUST_ZONE",
        "INVALID_ROUTE_PROFILE",
        "UNKNOWN_ROUTE_PROFILE",
        "INVALID_RISK_LABEL",
        "UNKNOWN_RISK_LABEL",
        "UNKNOWN_THREAT_DROPPED",
        "UNKNOWN_AV_LABEL_DROPPED",
        "UNTRUSTED_STRICT_SIGNAL_DOWNGRADED",
        "UNSIGNED_BLOCK_SIGNAL_DOWNGRADED",
        "STALE_SIGNAL_DOWNGRADED",
        "BASELINE_ZONE_ELEVATED",
        "BASELINE_ZONE_STRICT",
        "BASELINE_PROFILE_ELEVATED",
        "BASELINE_PROFILE_STRICT",
        "BASELINE_RISK_ELEVATED",
        "BASELINE_RISK_STRICT",
        "SIGNAL_DECISION_FAIL",
        "SIGNAL_E_TRIGGER",
        "SIGNAL_AV_TRIGGER",
        "SIGNAL_AV_LABEL_STRICT",
        "SIGNAL_RISK_SCORE_HIGH",
        "SIGNAL_RISK_SCORE_CRITICAL",
        "SIGNAL_RISK_LABEL_HIGH",
        "SIGNAL_RISK_LABEL_CRITICAL",
        "SIGNAL_THREAT_APT",
        "SIGNAL_THREAT_INSIDER",
        "SIGNAL_THREAT_SUPPLY_CHAIN",
        "SIGNAL_PQ_UNHEALTHY",
        "ROUTE_NORMAL",
        "ROUTE_ELEVATED",
        "ROUTE_STRICT",
        "CRITICAL_BASIS_BLOCK",
        "BALANCED_ROUTE",
        "DERIVED_PQ_REQUIRED",
        "DERIVED_STRICT_TRUST_ZONE",
        "DERIVED_STRICT_ROUTE_PROFILE",
        "OUTBOX_QUEUED",
        "OUTBOX_FLUSHED",
        "OUTBOX_QUEUE_FAILED",
        "LEDGER_PREPARED",
        "LEDGER_COMMITTED",
        "RECEIPT_PREPARED",
        "RECEIPT_COMMITTED",
        "INTEGRITY_ERROR",
        "REPLAY_SUPPRESSED",
    }
)

_ALLOWED_FORBIDDEN_KEY_TOKENS: FrozenSet[str] = frozenset(
    {
        "prompt",
        "completion",
        "messages",
        "message",
        "content",
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
        "apikey",
        "api_key",
        "private",
        "privatekey",
    }
)
_ALLOWED_TAG_NAMESPACES: FrozenSet[str] = frozenset(
    {"routing", "security", "receipt", "lifecycle", "diagnostics", "misc", "signal", "producer", "bus"}
)

_ASCII_CTRL_RE = re.compile(r"[\x00-\x1F\x7F]")
_SAFE_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9_.:\-]{0,63}$")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:\-]{0,127}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-@#/+=]{0,255}$")
_SAFE_REASON_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
_SAFE_TOKEN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,255}$")
_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DIGEST_HEX_RE = re.compile(r"^[0-9a-f]{16,256}$")
_DIGEST_HEX_0X_RE = re.compile(r"^0x[0-9a-f]{16,256}$")
_DIGEST_ALG_HEX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,31}:[0-9a-f]{16,256}$")
_CFG_FP_RE = re.compile(
    r"^(?:[A-Za-z0-9][A-Za-z0-9_.-]{1,15}:[A-Za-z0-9][A-Za-z0-9_.-]{1,15}:[0-9a-f]{16,256}|[A-Za-z0-9][A-Za-z0-9_.-]{1,15}:[0-9a-f]{16,256})$"
)
_RECEIPT_INTEGRITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{1,31}:[A-Za-z0-9][A-Za-z0-9_.:\-]{1,63}$")
_BASE64ISH_RE = re.compile(r"^[A-Za-z0-9+/=_:\-.,]{1,16384}$")
_TAGLIKE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,255}$")
_UUID_RE = re.compile(
    r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

# secret detectors
_JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_PRIVKEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----", re.IGNORECASE)
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._\-~=+/]+\b", re.IGNORECASE)
_BASIC_RE = re.compile(r"\bBasic\s+[A-Za-z0-9+/=]{16,}\b", re.IGNORECASE)
_OPENAI_SK_RE = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")
_AWS_AKIA_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GOOGLE_AIZA_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
_KV_SECRET_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|apikey|token|secret|password|passwd|pwd)\s*[:=]\s*([^\s,;]{8,})"
)
_ENTROPY_B64URL_RE = re.compile(r"\b[A-Za-z0-9_-]{60,}\b")

_MAX_JSON_NODES = 4096
_MAX_JSON_ITEMS = 256
_MAX_JSON_DEPTH = 8
_MAX_JSON_STR_TOTAL = 128_000
_MAX_JSON_STR_LEN = 4096
_MAX_SIGNAL_INTERNAL_BYTES = 512_000
_MAX_ENVELOPE_INTERNAL_BYTES = 64_000


# =============================================================================
# Low-level helpers
# =============================================================================


def now_ts() -> float:
    return float(time.time())


def now_unix_ns() -> int:
    return int(time.time_ns())


def now_monotonic_ns() -> int:
    return int(time.monotonic_ns())


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


def _scalar_text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if not math.isfinite(v):
            return ""
        return f"{v:.12g}"
    if isinstance(v, (bytes, bytearray, memoryview)):
        return "<bytes>"
    return f"<{type(v).__name__}>"


def _looks_like_secret_token(s: str) -> bool:
    if not s:
        return False
    if _JWT_RE.search(s):
        return True
    if _PRIVKEY_RE.search(s):
        return True
    if _BEARER_RE.search(s):
        return True
    if _BASIC_RE.search(s):
        return True
    if _OPENAI_SK_RE.search(s):
        return True
    if _AWS_AKIA_RE.search(s):
        return True
    if _GOOGLE_AIZA_RE.search(s):
        return True
    if _KV_SECRET_RE.search(s):
        return True
    return False


def _looks_like_high_entropy(s: str) -> bool:
    return bool(s) and (_ENTROPY_B64URL_RE.search(s) is not None)


def _safe_text(v: Any, *, max_len: int = 256, redact_mode: str = "none") -> str:
    s = _strip_unsafe_text(_scalar_text(v), max_len=max_len)
    if not s:
        return ""
    mode = (redact_mode or "none").lower()
    if mode in {"token", "log", "strict"} and _looks_like_secret_token(s):
        return "[redacted]"
    if mode == "strict" and _looks_like_high_entropy(s):
        return "[redacted]"
    if len(s) > max_len:
        s = s[:max_len]
    return s


def _safe_text_or_none(v: Any, *, max_len: int = 256, redact_mode: str = "none") -> Optional[str]:
    s = _safe_text(v, max_len=max_len, redact_mode=redact_mode)
    return s or None


def _safe_text_for_log(v: Any, *, max_len: int = 256) -> str:
    return _safe_text(v, max_len=max_len, redact_mode="strict")


def _safe_text_for_id(v: Any, *, max_len: int = 256, default: Optional[str] = None) -> Optional[str]:
    s = _safe_text(v, max_len=max_len, redact_mode="token")
    if not s or s == "[redacted]":
        return default
    if not _SAFE_ID_RE.fullmatch(s):
        return default
    return s


def _safe_label(v: Any, *, default: str) -> str:
    s = _safe_text(v, max_len=64, redact_mode="token").lower()
    if not s or s == "[redacted]" or not _SAFE_LABEL_RE.fullmatch(s):
        return default
    return s


def _safe_name(v: Any, *, default: str) -> str:
    s = _safe_text(v, max_len=128, redact_mode="token")
    if not s or s == "[redacted]" or not _SAFE_NAME_RE.fullmatch(s):
        return default
    return s


def _safe_reason_code(v: Any, *, default: Optional[str] = None) -> Optional[str]:
    s = _safe_text(v, max_len=128, redact_mode="token").upper()
    if not s or s == "[REDACTED]" or not _SAFE_REASON_CODE_RE.fullmatch(s):
        return default
    return s if s in _ALLOWED_REASON_CODES else default


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


def _clamp_int(v: Any, *, default: int, lo: int, hi: int) -> int:
    x = _coerce_int(v)
    if x is None:
        return int(default)
    return min(max(int(x), lo), hi)


def _clamp_float(v: Any, *, default: float, lo: float, hi: float) -> float:
    x = _coerce_float(v)
    if x is None:
        return float(default)
    return min(max(float(x), lo), hi)


def _stable_float(x: float) -> str:
    if not math.isfinite(float(x)):
        return "0"
    s = f"{float(x):.12f}".rstrip("0").rstrip(".")
    return s or "0"


def _stable_jsonable(obj: Any) -> Any:
    if obj is None or isinstance(obj, (bool, int)):
        return obj
    if isinstance(obj, float):
        return _stable_float(obj)
    if isinstance(obj, str):
        return obj
    if isinstance(obj, Mapping):
        return {str(k): _stable_jsonable(obj[k]) for k in sorted(obj.keys(), key=lambda x: str(x))}
    if isinstance(obj, (list, tuple)):
        return [_stable_jsonable(x) for x in obj]
    if isinstance(obj, (set, frozenset)):
        xs = [_stable_jsonable(x) for x in obj]
        try:
            return sorted(xs)
        except Exception:
            return xs
    return _safe_name(type(obj).__name__, default="object")


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        _stable_jsonable(obj),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8", errors="strict")


def _canonical_json_str(obj: Any) -> str:
    return _canonical_json_bytes(obj).decode("utf-8", errors="strict")


def _hash_hex(*, ctx: str, payload: Mapping[str, Any], out_hex: int = 32) -> str:
    raw = ctx.encode("utf-8", errors="strict") + b"\x00" + _canonical_json_bytes(payload)
    if Blake3Hash is not None:
        with contextlib.suppress(Exception):
            return Blake3Hash().hex(raw, ctx=ctx)[:out_hex]
    return hashlib.sha256(raw).hexdigest()[:out_hex]


def _hash_bytes(*, ctx: str, payload: bytes, out_hex: int = 32) -> str:
    raw = ctx.encode("utf-8", errors="strict") + b"\x00" + payload
    if Blake3Hash is not None:
        with contextlib.suppress(Exception):
            return Blake3Hash().hex(raw, ctx=ctx)[:out_hex]
    return hashlib.sha256(raw).hexdigest()[:out_hex]


def _parse_key_material(v: Any) -> Optional[bytes]:
    if isinstance(v, bytes):
        return bytes(v) if 1 <= len(v) <= 4096 else None
    if not isinstance(v, str):
        return None
    s = _strip_unsafe_text(v, max_len=4096)
    if not s:
        return None
    if s.lower().startswith("hex:"):
        hx = s[4:].strip()
        if len(hx) % 2 != 0 or not _HEX_RE.fullmatch(hx):
            return None
        with contextlib.suppress(Exception):
            return bytes.fromhex(hx)
        return None
    if s.lower().startswith("b64:"):
        raw = s[4:].strip()
        try:
            pad = "=" * ((4 - (len(raw) % 4)) % 4)
            return base64.urlsafe_b64decode((raw + pad).encode("utf-8", errors="strict"))
        except Exception:
            return None
    if s.lower().startswith("raw:"):
        return s[4:].encode("utf-8", errors="ignore")
    if _HEX_RE.fullmatch(s) and len(s) % 2 == 0:
        with contextlib.suppress(Exception):
            return bytes.fromhex(s)
    try:
        pad = "=" * ((4 - (len(s) % 4)) % 4)
        return base64.urlsafe_b64decode((s + pad).encode("utf-8", errors="strict"))
    except Exception:
        return None


_SUBJECT_HASH_KEY = _parse_key_material(os.getenv("TCD_SIGNAL_SUBJECT_HASH_KEY"))
_SUBJECT_HASH_KEY_ID = _safe_text_for_id(os.getenv("TCD_SIGNAL_SUBJECT_HASH_KEY_ID"), max_len=32, default=None)


def _subject_hash(tenant: str, user: str, session: str, *, out_hex: int = 32) -> str:
    payload = f"{tenant}|{user}|{session}".encode("utf-8", errors="ignore")
    if _SUBJECT_HASH_KEY:
        dig = hmac.new(_SUBJECT_HASH_KEY, b"tcd:signals:subject\x00" + payload, hashlib.sha256).hexdigest()[:out_hex]
        kid = _SUBJECT_HASH_KEY_ID or "hmac"
        return f"sub1:{kid}:{dig}"
    return f"sub1:sha256:{hashlib.sha256(b'tcd:signals:subject\x00' + payload).hexdigest()[:out_hex]}"


def _safe_oneof(v: Any, *, allowed: Iterable[str], default: str, lower: bool = True) -> str:
    s = _safe_text(v, max_len=64, redact_mode="token")
    if lower:
        s = s.lower()
        aset = {x.lower() for x in allowed}
    else:
        aset = set(allowed)
    return s if s in aset else default


def _normalize_namespaced_tags(values: Any, *, max_items: int = 32) -> Tuple[str, ...]:
    if values is None:
        return tuple()
    if isinstance(values, str):
        seq: Sequence[Any] = [values]
    elif isinstance(values, (list, tuple, set, frozenset)):
        seq = list(values)
    else:
        return tuple()
    out: List[str] = []
    seen = set()
    for item in seq:
        if len(out) >= max_items:
            break
        raw = _safe_text(item, max_len=128, redact_mode="token")
        if not raw or raw == "[redacted]":
            continue
        tag = raw if ":" in raw else f"misc:{raw}"
        ns, _, suffix = tag.partition(":")
        ns = _safe_label(ns, default="misc")
        suffix = _safe_text(suffix, max_len=96, redact_mode="token")
        if not suffix:
            continue
        fixed = f"{ns}:{suffix}"
        if ns not in _ALLOWED_TAG_NAMESPACES:
            fixed = f"misc:{suffix}"
        if fixed in seen:
            continue
        seen.add(fixed)
        out.append(fixed)
    return tuple(out)


def _normalize_reason_codes(values: Any, *, max_items: int = 32) -> Tuple[str, ...]:
    if values is None:
        return tuple()
    if isinstance(values, str):
        seq: Sequence[Any] = [values]
    elif isinstance(values, (list, tuple, set, frozenset)):
        seq = list(values)
    else:
        return tuple()
    out: List[str] = []
    seen = set()
    for item in seq:
        if len(out) >= max_items:
            break
        code = _safe_reason_code(item, default=None)
        if not code or code in seen:
            continue
        seen.add(code)
        out.append(code)
    return tuple(out)


def _normalize_digest_token(v: Any, *, kind: str = "any", default: Optional[str] = None) -> Optional[str]:
    s = _safe_text(v, max_len=1024, redact_mode="token")
    if not s or s == "[redacted]":
        return default
    if kind == "cfg_fp":
        return s if _CFG_FP_RE.fullmatch(s) else default
    if kind == "integrity":
        return s if _RECEIPT_INTEGRITY_RE.fullmatch(s) else default
    if _DIGEST_HEX_RE.fullmatch(s):
        return s.lower()
    if _DIGEST_HEX_0X_RE.fullmatch(s):
        return s.lower()
    if _DIGEST_ALG_HEX_RE.fullmatch(s):
        return s
    return default


class _JsonBudget:
    __slots__ = ("max_nodes", "max_items", "max_depth", "max_str_total", "nodes", "str_used")

    def __init__(self, *, max_nodes: int, max_items: int, max_depth: int, max_str_total: int) -> None:
        self.max_nodes = max_nodes
        self.max_items = max_items
        self.max_depth = max_depth
        self.max_str_total = max_str_total
        self.nodes = 0
        self.str_used = 0

    def take_node(self) -> bool:
        self.nodes += 1
        return self.nodes <= self.max_nodes

    def take_str(self, n: int) -> bool:
        self.str_used += n
        return self.str_used <= self.max_str_total


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


def _sanitize_json_like(
    obj: Any,
    *,
    budget: _JsonBudget,
    depth: int,
    max_str_len: int,
    drop_forbidden_keys: bool,
    allowed_keys: Optional[Set[str]] = None,
) -> Any:
    if not budget.take_node():
        return "[truncated]"
    t = type(obj)
    if obj is None:
        return None
    if t is bool:
        return bool(obj)
    if t is int:
        if obj.bit_length() > 256:
            return "[int:oversize]"
        return int(obj)
    if t is float:
        return float(obj) if math.isfinite(obj) else None
    if t is str:
        s = _safe_text(obj, max_len=max_str_len, redact_mode="strict")
        if not budget.take_str(len(s)):
            return "[truncated]"
        return s
    if t in (bytes, bytearray, memoryview):
        return f"[bytes:{len(obj)}]"
    if depth >= budget.max_depth:
        return "[truncated-depth]"
    if isinstance(obj, Mapping):
        out: Dict[str, Any] = {}
        n = 0
        try:
            items = obj.items()
        except Exception:
            return {"_type": type(obj).__name__}
        for k, v in items:
            if n >= budget.max_items:
                out["_tcd_truncated"] = True
                break
            kk = _safe_text_for_id(k, max_len=128, default=None)
            if kk is None:
                continue
            kl = kk.lower()
            if allowed_keys is not None and kl not in allowed_keys:
                continue
            if drop_forbidden_keys:
                toks = _key_tokens(kk)
                if any(tok in _ALLOWED_FORBIDDEN_KEY_TOKENS for tok in toks):
                    continue
            out[kk] = _sanitize_json_like(
                v,
                budget=budget,
                depth=depth + 1,
                max_str_len=max_str_len,
                drop_forbidden_keys=drop_forbidden_keys,
                allowed_keys=None,
            )
            n += 1
        return out
    if t in (list, tuple):
        out: List[Any] = []
        for i, item in enumerate(obj):
            if i >= budget.max_items:
                out.append("[truncated]")
                break
            out.append(
                _sanitize_json_like(
                    item,
                    budget=budget,
                    depth=depth + 1,
                    max_str_len=max_str_len,
                    drop_forbidden_keys=drop_forbidden_keys,
                    allowed_keys=None,
                )
            )
        return out
    if t in (set, frozenset):
        out_set = []
        for i, item in enumerate(sorted(list(obj), key=lambda x: _safe_text_for_log(type(x).__name__, max_len=32) + ":" + _safe_text_for_log(x, max_len=128))):
            if i >= budget.max_items:
                out_set.append("[truncated]")
                break
            out_set.append(
                _sanitize_json_like(
                    item,
                    budget=budget,
                    depth=depth + 1,
                    max_str_len=max_str_len,
                    drop_forbidden_keys=drop_forbidden_keys,
                    allowed_keys=None,
                )
            )
        return out_set
    return f"[type:{type(obj).__name__}]"


def _sanitize_mapping(
    obj: Any,
    *,
    max_nodes: int = _MAX_JSON_NODES,
    max_items: int = _MAX_JSON_ITEMS,
    max_depth: int = _MAX_JSON_DEPTH,
    max_str_total: int = _MAX_JSON_STR_TOTAL,
    max_str_len: int = _MAX_JSON_STR_LEN,
    drop_forbidden_keys: bool = True,
    allowed_keys: Optional[Set[str]] = None,
) -> Mapping[str, Any]:
    if not isinstance(obj, Mapping):
        return MappingProxyType({})
    budget = _JsonBudget(max_nodes=max_nodes, max_items=max_items, max_depth=max_depth, max_str_total=max_str_total)
    out = _sanitize_json_like(
        obj,
        budget=budget,
        depth=0,
        max_str_len=max_str_len,
        drop_forbidden_keys=drop_forbidden_keys,
        allowed_keys=allowed_keys,
    )
    return MappingProxyType(out if isinstance(out, dict) else {})


def _deep_freeze(obj: Any) -> Any:
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, Mapping):
        return MappingProxyType({str(k): _deep_freeze(v) for k, v in obj.items()})
    if isinstance(obj, (list, tuple)):
        return tuple(_deep_freeze(x) for x in obj)
    if isinstance(obj, (set, frozenset)):
        return tuple(sorted((_deep_freeze(x) for x in obj), key=lambda z: _safe_text_for_log(type(z).__name__, max_len=32) + ":" + _safe_text_for_log(z, max_len=128)))
    return _safe_name(type(obj).__name__, default="object")


def _to_primitive(obj: Any) -> Any:
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if is_dataclass(obj):
        return {f.name: _to_primitive(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, Mapping):
        return {str(k): _to_primitive(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_primitive(x) for x in obj]
    if isinstance(obj, (set, frozenset)):
        return [_to_primitive(x) for x in obj]
    return _safe_name(type(obj).__name__, default="object")


def _view_instance(view_cls: Any, payload: Dict[str, Any]) -> Any:
    if view_cls is None:
        return dict(payload)
    try:
        return view_cls(**payload)
    except Exception:
        return dict(payload)


# =============================================================================
# Contract / producer metadata / integrity
# =============================================================================


@dataclass(frozen=True)
class SignalContractVersion:
    schema_version: str = _SCHEMA
    signal_version: str = _SIGNAL_VERSION
    compatibility_epoch: str = _COMPATIBILITY_EPOCH
    canonicalization_version: str = _CANONICALIZATION_VERSION
    field_deprecation_policy: str = _DEFAULT_DEPRECATION_POLICY
    producer_capabilities: Tuple[str, ...] = field(default_factory=tuple)
    consumer_capabilities: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "schema_version", _safe_text(self.schema_version, max_len=64) or _SCHEMA)
        object.__setattr__(self, "signal_version", _safe_text(self.signal_version, max_len=32) or _SIGNAL_VERSION)
        object.__setattr__(self, "compatibility_epoch", _safe_text(self.compatibility_epoch, max_len=32) or _COMPATIBILITY_EPOCH)
        object.__setattr__(self, "canonicalization_version", _safe_text(self.canonicalization_version, max_len=32) or _CANONICALIZATION_VERSION)
        object.__setattr__(self, "field_deprecation_policy", _safe_text(self.field_deprecation_policy, max_len=96) or _DEFAULT_DEPRECATION_POLICY)
        object.__setattr__(self, "producer_capabilities", _normalize_namespaced_tags(self.producer_capabilities, max_items=64))
        object.__setattr__(self, "consumer_capabilities", _normalize_namespaced_tags(self.consumer_capabilities, max_items=64))

    def to_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


@dataclass(frozen=True)
class ProducerBundle:
    producer_name: str = "tcd.signals"
    producer_instance_id: Optional[str] = None
    producer_cfg_fp: Optional[str] = None
    producer_bundle_version: Optional[int] = None
    producer_mode: str = "normal"
    using_last_known_good: Optional[bool] = None
    build_id: Optional[str] = None
    image_digest: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "producer_name", _safe_name(self.producer_name, default="tcd.signals"))
        object.__setattr__(self, "producer_instance_id", _safe_text_for_id(self.producer_instance_id, max_len=128, default=None))
        object.__setattr__(self, "producer_cfg_fp", _normalize_digest_token(self.producer_cfg_fp, kind="cfg_fp", default=None))
        bv = _coerce_int(self.producer_bundle_version)
        object.__setattr__(self, "producer_bundle_version", max(0, bv) if bv is not None else None)
        object.__setattr__(self, "producer_mode", _safe_label(self.producer_mode, default="normal"))
        object.__setattr__(self, "using_last_known_good", _coerce_bool(self.using_last_known_good) if self.using_last_known_good is not None else None)
        object.__setattr__(self, "build_id", _safe_text_for_id(self.build_id, max_len=128, default=None))
        object.__setattr__(self, "image_digest", _safe_text(self.image_digest, max_len=256, redact_mode="token") or None)

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "producer_name": self.producer_name,
            "producer_cfg_fp": self.producer_cfg_fp,
            "producer_bundle_version": self.producer_bundle_version,
            "producer_mode": self.producer_mode,
            "using_last_known_good": self.using_last_known_good,
        }

    def to_internal_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


@dataclass(frozen=True)
class ProducerActivation:
    producer_activation_id: Optional[str] = None
    patch_id: Optional[str] = None
    change_ticket_id: Optional[str] = None
    activated_by_hash: Optional[str] = None
    approved_by_hashes: Tuple[str, ...] = field(default_factory=tuple)
    approval_count: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "producer_activation_id", _safe_text_for_id(self.producer_activation_id, max_len=256, default=None))
        object.__setattr__(self, "patch_id", _safe_text_for_id(self.patch_id, max_len=128, default=None))
        object.__setattr__(self, "change_ticket_id", _safe_text_for_id(self.change_ticket_id, max_len=128, default=None))
        object.__setattr__(self, "activated_by_hash", _safe_text_for_id(self.activated_by_hash, max_len=128, default=None))
        hashes = _normalize_str_tuple(self.approved_by_hashes, max_len=128, max_items=64)
        object.__setattr__(self, "approved_by_hashes", hashes)
        ac = _coerce_int(self.approval_count)
        object.__setattr__(self, "approval_count", max(0, ac) if ac is not None else max(0, len(hashes)))

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "producer_activation_id": self.producer_activation_id,
            "patch_id": self.patch_id,
            "change_ticket_id": self.change_ticket_id,
            "approval_count": self.approval_count,
        }

    def to_internal_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


@dataclass(frozen=True)
class SignalIntegrityIssue:
    code: str
    severity: Literal["warning", "error"] = "error"
    field: Optional[str] = None
    message: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _safe_reason_code(self.code, default="INTEGRITY_ERROR") or "INTEGRITY_ERROR")
        sev = _safe_label(self.severity, default="error")
        object.__setattr__(self, "severity", "warning" if sev == "warning" else "error")
        object.__setattr__(self, "field", _safe_text_or_none(self.field, max_len=128, redact_mode="token"))
        object.__setattr__(self, "message", _safe_text_or_none(self.message, max_len=256, redact_mode="strict"))

    def to_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


@dataclass(frozen=True)
class SignalIntegrityReport:
    ok: bool
    errors: Tuple[SignalIntegrityIssue, ...] = field(default_factory=tuple)
    warnings: Tuple[SignalIntegrityIssue, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": [x.to_dict() for x in self.errors],
            "warnings": [x.to_dict() for x in self.warnings],
        }


# =============================================================================
# Common identity / context objects
# =============================================================================


@dataclass(frozen=True)
class EvidenceIdentity:
    event_id: Optional[str] = None
    event_id_kind: str = "event"
    decision_id: Optional[str] = None
    decision_id_kind: str = "decision"
    route_plan_id: Optional[str] = None
    route_id: Optional[str] = None
    route_id_kind: str = "plan"

    config_fingerprint: Optional[str] = None
    bundle_version: Optional[int] = None

    policy_ref: Optional[str] = None
    policyset_ref: Optional[str] = None
    policy_digest: Optional[str] = None

    state_domain_id: Optional[str] = None
    activation_id: Optional[str] = None
    patch_id: Optional[str] = None
    change_ticket_id: Optional[str] = None

    controller_mode: Optional[str] = None
    statistical_guarantee_scope: Optional[str] = None
    adapter_registry_fp: Optional[str] = None
    selected_source: Optional[str] = None
    state_revision: Optional[int] = None
    identity_status: Optional[str] = None

    audit_ref: Optional[str] = None
    receipt_ref: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "event_id", _safe_text_for_id(self.event_id, max_len=256, default=None))
        object.__setattr__(self, "event_id_kind", _safe_label(self.event_id_kind, default="event"))
        object.__setattr__(self, "decision_id", _safe_text_for_id(self.decision_id, max_len=256, default=None))
        object.__setattr__(self, "decision_id_kind", _safe_label(self.decision_id_kind, default="decision"))
        object.__setattr__(self, "route_plan_id", _safe_text_for_id(self.route_plan_id, max_len=256, default=None))
        route_id = _safe_text_for_id(self.route_id, max_len=256, default=None) or _safe_text_for_id(self.route_plan_id, max_len=256, default=None)
        object.__setattr__(self, "route_id", route_id)
        object.__setattr__(self, "route_id_kind", _safe_label(self.route_id_kind, default="plan"))
        object.__setattr__(self, "config_fingerprint", _normalize_digest_token(self.config_fingerprint, kind="cfg_fp", default=None))
        bv = _coerce_int(self.bundle_version)
        object.__setattr__(self, "bundle_version", max(0, bv) if bv is not None else None)
        object.__setattr__(self, "policy_ref", _safe_text_for_id(self.policy_ref, max_len=128, default=None))
        object.__setattr__(self, "policyset_ref", _safe_text_for_id(self.policyset_ref, max_len=128, default=None))
        object.__setattr__(self, "policy_digest", _normalize_digest_token(self.policy_digest, kind="any", default=None))
        object.__setattr__(self, "state_domain_id", _safe_text_for_id(self.state_domain_id, max_len=256, default=None))
        object.__setattr__(self, "activation_id", _safe_text_for_id(self.activation_id, max_len=256, default=None))
        object.__setattr__(self, "patch_id", _safe_text_for_id(self.patch_id, max_len=128, default=None))
        object.__setattr__(self, "change_ticket_id", _safe_text_for_id(self.change_ticket_id, max_len=128, default=None))
        object.__setattr__(self, "controller_mode", _safe_oneof(self.controller_mode, allowed=_ALLOWED_CONTROLLER_MODES, default="normal"))
        object.__setattr__(self, "statistical_guarantee_scope", _safe_oneof(self.statistical_guarantee_scope, allowed=_ALLOWED_GUARANTEE_SCOPES, default="none"))
        object.__setattr__(self, "adapter_registry_fp", _safe_text_for_id(self.adapter_registry_fp, max_len=256, default=None))
        object.__setattr__(self, "selected_source", _safe_label(self.selected_source, default="") or None if self.selected_source is not None else None)
        rev = _coerce_int(self.state_revision)
        object.__setattr__(self, "state_revision", max(0, rev) if rev is not None else None)
        object.__setattr__(self, "identity_status", _safe_label(self.identity_status, default="") or None if self.identity_status is not None else None)
        object.__setattr__(self, "audit_ref", _safe_text_for_id(self.audit_ref, max_len=256, default=None))
        object.__setattr__(self, "receipt_ref", _safe_text_for_id(self.receipt_ref, max_len=256, default=None))

    def to_evidence_identity_view(self, *, strict: bool = True) -> Any:
        payload = {
            "event_id": self.event_id,
            "event_id_kind": self.event_id_kind,
            "decision_id": self.decision_id,
            "decision_id_kind": self.decision_id_kind,
            "route_plan_id": self.route_plan_id,
            "route_id": self.route_id,
            "route_id_kind": self.route_id_kind,
            "config_fingerprint": self.config_fingerprint,
            "bundle_version": self.bundle_version,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "state_domain_id": self.state_domain_id,
            "activation_id": self.activation_id,
            "patch_id": self.patch_id,
            "change_ticket_id": self.change_ticket_id,
            "audit_ref": self.audit_ref,
            "receipt_ref": self.receipt_ref,
        }
        return _view_instance(EvidenceIdentityView, payload)

    def to_public_dict(self) -> Dict[str, Any]:
        return _to_primitive(self.to_evidence_identity_view(strict=False))

    def to_internal_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


@dataclass(frozen=True)
class ArtifactRefs:
    audit_ref: Optional[str] = None
    receipt_ref: Optional[str] = None
    ledger_ref: Optional[str] = None
    attestation_ref: Optional[str] = None

    event_digest: Optional[str] = None
    body_digest: Optional[str] = None
    payload_digest: Optional[str] = None

    prepare_ref: Optional[str] = None
    commit_ref: Optional[str] = None
    ledger_stage: Optional[str] = None

    outbox_ref: Optional[str] = None
    outbox_status: Optional[str] = None
    outbox_dedupe_key: Optional[str] = None
    delivery_attempts: Optional[int] = None

    chain_id: Optional[str] = None
    chain_head: Optional[str] = None

    produced_by: Tuple[str, ...] = field(default_factory=tuple)
    provenance_path_digest: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "audit_ref", _safe_text_for_id(self.audit_ref, max_len=256, default=None))
        object.__setattr__(self, "receipt_ref", _safe_text_for_id(self.receipt_ref, max_len=256, default=None))
        object.__setattr__(self, "ledger_ref", _safe_text_for_id(self.ledger_ref, max_len=256, default=None))
        object.__setattr__(self, "attestation_ref", _safe_text_for_id(self.attestation_ref, max_len=256, default=None))
        object.__setattr__(self, "event_digest", _normalize_digest_token(self.event_digest, kind="any", default=None))
        object.__setattr__(self, "body_digest", _normalize_digest_token(self.body_digest, kind="any", default=None))
        object.__setattr__(self, "payload_digest", _normalize_digest_token(self.payload_digest, kind="any", default=None))
        object.__setattr__(self, "prepare_ref", _safe_text_for_id(self.prepare_ref, max_len=256, default=None))
        object.__setattr__(self, "commit_ref", _safe_text_for_id(self.commit_ref, max_len=256, default=None))
        stage = _safe_label(self.ledger_stage, default="") if self.ledger_stage is not None else ""
        object.__setattr__(self, "ledger_stage", stage if stage in _ALLOWED_LEDGER_STAGE else (stage or None))
        object.__setattr__(self, "outbox_ref", _safe_text_for_id(self.outbox_ref, max_len=256, default=None))
        ob = _safe_label(self.outbox_status, default="") if self.outbox_status is not None else ""
        object.__setattr__(self, "outbox_status", ob if ob in _ALLOWED_OUTBOX_STATUS else (ob or None))
        object.__setattr__(self, "outbox_dedupe_key", _safe_text_for_id(self.outbox_dedupe_key, max_len=256, default=None))
        da = _coerce_int(self.delivery_attempts)
        object.__setattr__(self, "delivery_attempts", max(0, da) if da is not None else None)
        object.__setattr__(self, "chain_id", _safe_text_for_id(self.chain_id, max_len=256, default=None))
        object.__setattr__(self, "chain_head", _normalize_digest_token(self.chain_head, kind="any", default=None))
        produced = _normalize_str_tuple(self.produced_by, max_len=64, max_items=16)
        object.__setattr__(self, "produced_by", produced)
        prov = _normalize_digest_token(self.provenance_path_digest, kind="any", default=None)
        if prov is None and produced:
            prov = f"sha256:{_hash_hex(ctx='tcd:signals:produced_by', payload={'produced_by': list(produced)}, out_hex=64)}"
        object.__setattr__(self, "provenance_path_digest", prov)

    def to_artifact_refs_view(self, *, strict: bool = True) -> Any:
        payload = {
            "audit_ref": self.audit_ref,
            "receipt_ref": self.receipt_ref,
            "ledger_ref": self.ledger_ref,
            "attestation_ref": self.attestation_ref,
            "event_digest": self.event_digest,
            "body_digest": self.body_digest,
            "ledger_stage": self.ledger_stage,
            "outbox_status": self.outbox_status,
            "produced_by": list(self.produced_by),
            "provenance_path_digest": self.provenance_path_digest,
        }
        return _view_instance(ArtifactRefsView, payload)

    def to_public_dict(self) -> Dict[str, Any]:
        return _to_primitive(self.to_artifact_refs_view(strict=False))

    def to_internal_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


@dataclass(frozen=True)
class SubjectContext:
    subject_hash: str
    tenant: Optional[str] = None
    user: Optional[str] = None
    session: Optional[str] = None

    tenant_class: Optional[str] = None
    tenant_partition: Optional[str] = None
    subject_scope: Optional[str] = None
    identity_status: str = "ok"

    def __post_init__(self) -> None:
        tenant = _safe_text_for_id(self.tenant, max_len=128, default=None)
        user = _safe_text_for_id(self.user, max_len=128, default=None)
        session = _safe_text_for_id(self.session, max_len=128, default=None)
        if tenant and ("@" in tenant or " " in tenant):
            tenant = None
        if user and ("@" in user or " " in user):
            user = None
        if session and ("@" in session or " " in session):
            session = None
        subh = _safe_text_for_id(self.subject_hash, max_len=128, default=None)
        if subh is None:
            subh = _subject_hash(tenant or "tenant0", user or "user0", session or "sess0")
        object.__setattr__(self, "subject_hash", subh)
        object.__setattr__(self, "tenant", tenant)
        object.__setattr__(self, "user", user)
        object.__setattr__(self, "session", session)
        object.__setattr__(self, "tenant_class", _safe_label(self.tenant_class, default="") or None if self.tenant_class is not None else None)
        object.__setattr__(self, "tenant_partition", _safe_label(self.tenant_partition, default="") or None if self.tenant_partition is not None else None)
        object.__setattr__(self, "subject_scope", _safe_label(self.subject_scope, default="") or None if self.subject_scope is not None else None)
        object.__setattr__(self, "identity_status", _safe_label(self.identity_status, default="ok"))

    def key(self) -> str:
        return self.subject_hash

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "subject_hash": self.subject_hash,
            "tenant_class": self.tenant_class,
            "tenant_partition": self.tenant_partition,
            "subject_scope": self.subject_scope,
            "identity_status": self.identity_status,
        }

    def to_audit_dict(self) -> Dict[str, Any]:
        return self.to_public_dict()

    def to_internal_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


@dataclass(frozen=True)
class ModelContext:
    model_id: str = "model0"
    gpu_id: str = "gpu0"
    task: str = "chat"
    lang: str = "en"

    model_version: Optional[str] = None
    model_config_hash: Optional[str] = None
    region: Optional[str] = None
    runtime_env: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "model_id", _safe_text_for_id(self.model_id, max_len=128, default="model0") or "model0")
        object.__setattr__(self, "gpu_id", _safe_text_for_id(self.gpu_id, max_len=128, default="gpu0") or "gpu0")
        object.__setattr__(self, "task", _safe_label(self.task, default="chat"))
        object.__setattr__(self, "lang", _safe_label(self.lang, default="en"))
        object.__setattr__(self, "model_version", _safe_text_for_id(self.model_version, max_len=128, default=None))
        object.__setattr__(self, "model_config_hash", _normalize_digest_token(self.model_config_hash, kind="any", default=None))
        object.__setattr__(self, "region", _safe_label(self.region, default="") or None if self.region is not None else None)
        object.__setattr__(self, "runtime_env", _safe_label(self.runtime_env, default="") or None if self.runtime_env is not None else None)

    def to_public_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)

    def to_audit_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)

    def to_internal_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


@dataclass(frozen=True)
class SecurityContext:
    asserted_trust_zone: Optional[str] = None
    asserted_route_profile: Optional[str] = None
    asserted_threat_kind: Optional[str] = None
    asserted_pq_required: Optional[bool] = None

    effective_trust_zone: str = "internet"
    effective_route_profile: str = "inference"
    effective_threat_kind: Optional[str] = None
    effective_pq_required: bool = False
    pq_ok: Optional[bool] = None

    policy_ref: Optional[str] = None
    policyset_ref: Optional[str] = None
    policy_digest: Optional[str] = None

    build_id: Optional[str] = None
    image_digest: Optional[str] = None
    compliance_tags: Tuple[str, ...] = field(default_factory=tuple)

    override_requested: bool = False
    override_applied: bool = False
    override_reason_code: Optional[str] = None
    override_actor: Optional[str] = None

    supply_chain_risk: Optional[str] = None
    supply_chain_source: Optional[str] = None

    signal_source: Optional[str] = None
    signal_trust_mode: Optional[str] = None
    signal_signed: Optional[bool] = None
    signal_signer_kid: Optional[str] = None
    signal_cfg_fp: Optional[str] = None
    signal_policy_ref: Optional[str] = None
    signal_freshness_ms: Optional[int] = None
    signal_replay_checked: Optional[bool] = None

    derived_reason_codes: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        atz = _safe_oneof(self.asserted_trust_zone, allowed=_ALLOWED_TRUST_ZONES, default="internet")
        arp = _safe_oneof(self.asserted_route_profile, allowed=_ALLOWED_ROUTE_PROFILES, default="inference")
        atk = _safe_label(self.asserted_threat_kind, default="") or None if self.asserted_threat_kind is not None else None
        epq = _coerce_bool(self.asserted_pq_required)

        etz = _safe_oneof(self.effective_trust_zone or atz, allowed=_ALLOWED_TRUST_ZONES, default=atz)
        erp = _safe_oneof(self.effective_route_profile or arp, allowed=_ALLOWED_ROUTE_PROFILES, default=arp)
        etk = _safe_label(self.effective_threat_kind or atk, default="") or None if (self.effective_threat_kind or atk) is not None else None

        reasons = list(_normalize_reason_codes(self.derived_reason_codes, max_items=32))
        eff_pq_required = bool(epq) if epq is not None else bool(self.effective_pq_required)
        if not eff_pq_required and etz in {"admin", "partner"}:
            eff_pq_required = True
            reasons.append("DERIVED_PQ_REQUIRED")
        if not eff_pq_required and etk in {"apt", "supply_chain"}:
            eff_pq_required = True
            reasons.append("DERIVED_PQ_REQUIRED")

        object.__setattr__(self, "asserted_trust_zone", atz)
        object.__setattr__(self, "asserted_route_profile", arp)
        object.__setattr__(self, "asserted_threat_kind", atk)
        object.__setattr__(self, "asserted_pq_required", epq)
        object.__setattr__(self, "effective_trust_zone", etz)
        object.__setattr__(self, "effective_route_profile", erp)
        object.__setattr__(self, "effective_threat_kind", etk)
        object.__setattr__(self, "effective_pq_required", eff_pq_required)
        object.__setattr__(self, "pq_ok", _coerce_bool(self.pq_ok) if self.pq_ok is not None else None)
        object.__setattr__(self, "policy_ref", _safe_text_for_id(self.policy_ref, max_len=128, default=None))
        object.__setattr__(self, "policyset_ref", _safe_text_for_id(self.policyset_ref, max_len=128, default=None))
        object.__setattr__(self, "policy_digest", _normalize_digest_token(self.policy_digest, kind="any", default=None))
        object.__setattr__(self, "build_id", _safe_text_for_id(self.build_id, max_len=128, default=None))
        object.__setattr__(self, "image_digest", _safe_text(self.image_digest, max_len=256, redact_mode="token") or None)
        object.__setattr__(self, "compliance_tags", _normalize_namespaced_tags(self.compliance_tags, max_items=32))
        object.__setattr__(self, "override_requested", bool(self.override_requested))
        object.__setattr__(self, "override_applied", bool(self.override_applied))
        object.__setattr__(self, "override_reason_code", _safe_reason_code(self.override_reason_code, default=None))
        object.__setattr__(self, "override_actor", _safe_text_for_id(self.override_actor, max_len=128, default=None))
        object.__setattr__(self, "supply_chain_risk", _safe_label(self.supply_chain_risk, default="") or None if self.supply_chain_risk is not None else None)
        object.__setattr__(self, "supply_chain_source", _safe_text_for_id(self.supply_chain_source, max_len=128, default=None))
        object.__setattr__(self, "signal_source", _safe_name(self.signal_source, default="") or None if self.signal_source is not None else None)
        stm = _safe_oneof(self.signal_trust_mode, allowed=_ALLOWED_SIGNAL_TRUST, default="advisory") if self.signal_trust_mode is not None else None
        object.__setattr__(self, "signal_trust_mode", stm)
        object.__setattr__(self, "signal_signed", _coerce_bool(self.signal_signed) if self.signal_signed is not None else None)
        object.__setattr__(self, "signal_signer_kid", _safe_text_for_id(self.signal_signer_kid, max_len=128, default=None))
        object.__setattr__(self, "signal_cfg_fp", _normalize_digest_token(self.signal_cfg_fp, kind="cfg_fp", default=None))
        object.__setattr__(self, "signal_policy_ref", _safe_text_for_id(self.signal_policy_ref, max_len=128, default=None))
        sf = _coerce_int(self.signal_freshness_ms)
        object.__setattr__(self, "signal_freshness_ms", max(0, sf) if sf is not None else None)
        object.__setattr__(self, "signal_replay_checked", _coerce_bool(self.signal_replay_checked) if self.signal_replay_checked is not None else None)
        object.__setattr__(self, "derived_reason_codes", _normalize_reason_codes(reasons, max_items=32))

    @property
    def trust_zone(self) -> str:
        return self.effective_trust_zone

    @property
    def route_profile(self) -> str:
        return self.effective_route_profile

    @property
    def threat_kind(self) -> Optional[str]:
        return self.effective_threat_kind

    @property
    def pq_required(self) -> bool:
        return self.effective_pq_required

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "trust_zone": self.effective_trust_zone,
            "route_profile": self.effective_route_profile,
            "threat_kind": self.effective_threat_kind,
            "pq_required": self.effective_pq_required,
            "pq_ok": self.pq_ok,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "build_id": self.build_id,
            "image_digest": self.image_digest,
            "compliance_tags": list(self.compliance_tags),
            "override_requested": self.override_requested,
            "override_applied": self.override_applied,
            "override_reason_code": self.override_reason_code,
            "supply_chain_risk": self.supply_chain_risk,
            "signal_source": self.signal_source,
            "signal_trust_mode": self.signal_trust_mode,
            "signal_signed": self.signal_signed,
        }

    def to_audit_dict(self) -> Dict[str, Any]:
        return {
            **self.to_public_dict(),
            "asserted_trust_zone": self.asserted_trust_zone,
            "asserted_route_profile": self.asserted_route_profile,
            "asserted_threat_kind": self.asserted_threat_kind,
            "asserted_pq_required": self.asserted_pq_required,
            "policy_digest": self.policy_digest,
            "signal_signer_kid": self.signal_signer_kid,
            "signal_cfg_fp": self.signal_cfg_fp,
            "signal_policy_ref": self.signal_policy_ref,
            "signal_freshness_ms": self.signal_freshness_ms,
            "signal_replay_checked": self.signal_replay_checked,
            "derived_reason_codes": list(self.derived_reason_codes),
        }

    def to_internal_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


@dataclass(frozen=True)
class StreamContext:
    raw_stream_id: Optional[str] = None
    canonical_stream_id: Optional[str] = None
    stream_hash: Optional[str] = None
    raw_exposed: bool = False
    schema_ref: str = "stream.v1"

    av_label: Optional[str] = None
    av_policyset_ref: Optional[str] = None
    e_process_id: Optional[str] = None

    state_domain_id: Optional[str] = None
    adapter_registry_fp: Optional[str] = None
    selected_source: Optional[str] = None
    controller_mode: Optional[str] = None
    statistical_guarantee_scope: Optional[str] = None
    decision_mode: Optional[str] = None
    state_revision: Optional[int] = None
    identity_status: Optional[str] = None

    def __post_init__(self) -> None:
        raw_stream_id = _safe_text_for_id(self.raw_stream_id, max_len=256, default=None)
        canon_stream_id = _safe_text_for_id(self.canonical_stream_id, max_len=256, default=None) or raw_stream_id
        stream_hash = _safe_text_for_id(self.stream_hash, max_len=256, default=None)
        if stream_hash is None:
            stream_hash = f"str1:sha256:{_hash_hex(ctx='tcd:signals:stream', payload={'stream': canon_stream_id or 'default'}, out_hex=32)}"
        object.__setattr__(self, "raw_stream_id", raw_stream_id)
        object.__setattr__(self, "canonical_stream_id", canon_stream_id)
        object.__setattr__(self, "stream_hash", stream_hash)
        object.__setattr__(self, "raw_exposed", bool(self.raw_exposed))
        object.__setattr__(self, "schema_ref", _safe_text(self.schema_ref, max_len=64) or "stream.v1")
        object.__setattr__(self, "av_label", _safe_label(self.av_label, default="") or None if self.av_label is not None else None)
        object.__setattr__(self, "av_policyset_ref", _safe_text_for_id(self.av_policyset_ref, max_len=128, default=None))
        object.__setattr__(self, "e_process_id", _safe_text_for_id(self.e_process_id, max_len=256, default=None))
        object.__setattr__(self, "state_domain_id", _safe_text_for_id(self.state_domain_id, max_len=256, default=None))
        object.__setattr__(self, "adapter_registry_fp", _safe_text_for_id(self.adapter_registry_fp, max_len=256, default=None))
        object.__setattr__(self, "selected_source", _safe_label(self.selected_source, default="") or None if self.selected_source is not None else None)
        object.__setattr__(self, "controller_mode", _safe_oneof(self.controller_mode, allowed=_ALLOWED_CONTROLLER_MODES, default="normal"))
        object.__setattr__(self, "statistical_guarantee_scope", _safe_oneof(self.statistical_guarantee_scope, allowed=_ALLOWED_GUARANTEE_SCOPES, default="none"))
        object.__setattr__(self, "decision_mode", _safe_oneof(self.decision_mode, allowed=_ALLOWED_DECISION_MODES, default="dual_track") if self.decision_mode is not None else None)
        rev = _coerce_int(self.state_revision)
        object.__setattr__(self, "state_revision", max(0, rev) if rev is not None else None)
        object.__setattr__(self, "identity_status", _safe_label(self.identity_status, default="") or None if self.identity_status is not None else None)

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "stream_hash": self.stream_hash,
            "schema_ref": self.schema_ref,
            "av_label": self.av_label,
            "state_domain_id": self.state_domain_id,
            "adapter_registry_fp": self.adapter_registry_fp,
            "selected_source": self.selected_source,
            "controller_mode": self.controller_mode,
            "statistical_guarantee_scope": self.statistical_guarantee_scope,
            "decision_mode": self.decision_mode,
            "state_revision": self.state_revision,
            "identity_status": self.identity_status,
        }

    def to_audit_dict(self) -> Dict[str, Any]:
        return {
            **self.to_public_dict(),
            "canonical_stream_id": self.canonical_stream_id,
            "raw_stream_id": self.raw_stream_id if self.raw_exposed else None,
            "av_policyset_ref": self.av_policyset_ref,
            "e_process_id": self.e_process_id,
        }

    def to_internal_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


@dataclass(frozen=True)
class SignalEnvelope:
    contract: SignalContractVersion = field(default_factory=SignalContractVersion)
    producer_bundle: ProducerBundle = field(default_factory=ProducerBundle)
    producer_activation: ProducerActivation = field(default_factory=ProducerActivation)

    signal_kind: str = "risk_decision"
    phase: str = "evaluated"
    source_classification: str = "data_plane_observed"

    signal_id: Optional[str] = None
    ts_unix_ns: Optional[int] = None
    ts_monotonic_ns: Optional[int] = None

    source: str = "tcd"
    profile: str = "PROD"
    instance_id: Optional[str] = None
    node_id: Optional[str] = None

    config_fingerprint: Optional[str] = None
    bundle_version: Optional[int] = None

    evidence: EvidenceIdentity = field(default_factory=EvidenceIdentity)
    artifacts: ArtifactRefs = field(default_factory=ArtifactRefs)

    degraded_reason_codes: Tuple[str, ...] = field(default_factory=tuple)
    tags: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.contract, SignalContractVersion):
            object.__setattr__(self, "contract", SignalContractVersion(**(dict(self.contract) if isinstance(self.contract, Mapping) else {})))
        if not isinstance(self.producer_bundle, ProducerBundle):
            object.__setattr__(self, "producer_bundle", ProducerBundle(**(dict(self.producer_bundle) if isinstance(self.producer_bundle, Mapping) else {})))
        if not isinstance(self.producer_activation, ProducerActivation):
            object.__setattr__(self, "producer_activation", ProducerActivation(**(dict(self.producer_activation) if isinstance(self.producer_activation, Mapping) else {})))
        if not isinstance(self.evidence, EvidenceIdentity):
            object.__setattr__(self, "evidence", EvidenceIdentity(**(dict(self.evidence) if isinstance(self.evidence, Mapping) else {})))
        if not isinstance(self.artifacts, ArtifactRefs):
            object.__setattr__(self, "artifacts", ArtifactRefs(**(dict(self.artifacts) if isinstance(self.artifacts, Mapping) else {})))

        object.__setattr__(self, "signal_kind", _safe_oneof(self.signal_kind, allowed=_ALLOWED_SIGNAL_KINDS, default="risk_decision"))
        object.__setattr__(self, "phase", _safe_oneof(self.phase, allowed=_ALLOWED_PHASES, default="evaluated"))
        object.__setattr__(self, "source_classification", _safe_oneof(self.source_classification, allowed=_ALLOWED_SOURCE_CLASSIFICATION, default="data_plane_observed"))
        tun = _coerce_int(self.ts_unix_ns)
        tmn = _coerce_int(self.ts_monotonic_ns)
        object.__setattr__(self, "ts_unix_ns", max(0, tun) if tun is not None else now_unix_ns())
        object.__setattr__(self, "ts_monotonic_ns", max(0, tmn) if tmn is not None else now_monotonic_ns())
        object.__setattr__(self, "source", _safe_name(self.source, default="tcd"))
        prof = _safe_text(self.profile, max_len=32).upper() or "PROD"
        object.__setattr__(self, "profile", prof if prof in _ALLOWED_PROFILES else "PROD")
        object.__setattr__(self, "instance_id", _safe_text_for_id(self.instance_id, max_len=128, default=None))
        object.__setattr__(self, "node_id", _safe_text_for_id(self.node_id, max_len=128, default=None))
        cfg_fp = _normalize_digest_token(self.config_fingerprint, kind="cfg_fp", default=None) or self.producer_bundle.producer_cfg_fp or self.evidence.config_fingerprint
        object.__setattr__(self, "config_fingerprint", cfg_fp)
        bv = _coerce_int(self.bundle_version)
        effective_bv = max(0, bv) if bv is not None else (self.producer_bundle.producer_bundle_version or self.evidence.bundle_version)
        object.__setattr__(self, "bundle_version", effective_bv)
        object.__setattr__(self, "degraded_reason_codes", _normalize_reason_codes(self.degraded_reason_codes, max_items=32))
        object.__setattr__(self, "tags", _normalize_namespaced_tags(self.tags, max_items=64))

        sid = _safe_text_for_id(self.signal_id, max_len=256, default=None)
        if sid is None:
            sid = f"sig1:{_hash_hex(ctx='tcd:signals:id', payload=self._id_payload(), out_hex=32)}"
        object.__setattr__(self, "signal_id", sid)

    def _id_payload(self) -> Dict[str, Any]:
        return {
            "signal_kind": self.signal_kind,
            "phase": self.phase,
            "source_classification": self.source_classification,
            "event_id": self.evidence.event_id,
            "decision_id": self.evidence.decision_id,
            "route_plan_id": self.evidence.route_plan_id,
            "policy_ref": self.evidence.policy_ref,
            "source": self.source,
            "instance_id": self.instance_id or self.producer_bundle.producer_instance_id,
            "activation_id": self.producer_activation.producer_activation_id,
            "bundle_version": self.bundle_version or self.producer_bundle.producer_bundle_version,
            "config_fingerprint": self.config_fingerprint or self.producer_bundle.producer_cfg_fp,
            "ts_unix_ns": int(self.ts_unix_ns or 0),
        }

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "contract": self.contract.to_dict(),
            "producer_bundle": self.producer_bundle.to_public_dict(),
            "producer_activation": self.producer_activation.to_public_dict(),
            "signal_kind": self.signal_kind,
            "phase": self.phase,
            "source_classification": self.source_classification,
            "signal_id": self.signal_id,
            "ts_unix_ns": self.ts_unix_ns,
            "config_fingerprint": self.config_fingerprint,
            "bundle_version": self.bundle_version,
            "evidence": self.evidence.to_public_dict(),
            "artifacts": self.artifacts.to_public_dict(),
            "degraded_reason_codes": list(self.degraded_reason_codes),
            "tags": list(self.tags),
        }

    def to_internal_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


# =============================================================================
# Signal base
# =============================================================================


class GovernedSignal:
    envelope: SignalEnvelope

    def signal_kind(self) -> str:
        return getattr(self.envelope, "signal_kind", type(self).__name__)

    def signal_id(self) -> Optional[str]:
        return getattr(self.envelope, "signal_id", None)

    def normalization_warnings(self) -> Tuple[str, ...]:
        return tuple(getattr(self, "normalization_warnings", tuple()) or tuple())

    def compatibility_warnings(self) -> Tuple[str, ...]:
        return tuple(getattr(self, "compatibility_warnings", tuple()) or tuple())

    def integrity_errors(self) -> Tuple[str, ...]:
        return tuple(getattr(self, "integrity_errors", tuple()) or tuple())

    def to_public_dict(self) -> Dict[str, Any]:
        raise NotImplementedError

    def to_audit_dict(self) -> Dict[str, Any]:
        raise NotImplementedError

    def to_internal_dict(self) -> Dict[str, Any]:
        raise NotImplementedError


# =============================================================================
# Signal payloads
# =============================================================================


@dataclass(frozen=True)
class RiskDecisionSignal(GovernedSignal):
    envelope: SignalEnvelope
    subject: SubjectContext
    model: ModelContext
    security: SecurityContext
    stream: StreamContext

    verdict: bool = False
    allowed: Optional[bool] = None
    decision: Optional[str] = None
    required_action: Optional[str] = None
    enforcement_mode: Optional[str] = None
    cause: Optional[str] = None
    action: Optional[str] = None

    score: float = 0.0
    threshold: float = 0.0
    budget_remaining: float = 0.0
    e_value: float = 1.0
    alpha_alloc: float = 0.0
    alpha_spent: float = 0.0

    step: int = 0
    detector_trigger: bool = False
    av_trigger: bool = False

    risk_band: Optional[str] = None
    apt_score: Optional[float] = None
    insider_score: Optional[float] = None
    supply_chain_score: Optional[float] = None
    drift_score: Optional[float] = None

    selected_source: Optional[str] = None
    decision_mode: Optional[str] = None
    controller_mode: Optional[str] = None
    statistical_guarantee_scope: Optional[str] = None
    state_domain_id: Optional[str] = None
    adapter_registry_fp: Optional[str] = None
    state_revision: Optional[int] = None
    identity_status: Optional[str] = None

    primary_reason_code: Optional[str] = None
    reason_codes: Tuple[str, ...] = field(default_factory=tuple)
    degraded_reason_codes: Tuple[str, ...] = field(default_factory=tuple)
    tags: Tuple[str, ...] = field(default_factory=tuple)

    detector_components: Mapping[str, Any] = field(default_factory=dict)
    multivar_components: Mapping[str, Any] = field(default_factory=dict)
    e_process_state: Mapping[str, Any] = field(default_factory=dict)
    route_info: Mapping[str, Any] = field(default_factory=dict)

    normalization_warnings: Tuple[str, ...] = field(default_factory=tuple)
    compatibility_warnings: Tuple[str, ...] = field(default_factory=tuple)
    integrity_errors: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, SignalEnvelope):
            object.__setattr__(self, "envelope", make_signal_envelope(signal_kind="risk_decision"))
        if not isinstance(self.subject, SubjectContext):
            object.__setattr__(self, "subject", make_subject_context("tenant0", "user0", "sess0"))
        if not isinstance(self.model, ModelContext):
            object.__setattr__(self, "model", make_model_context("model0", "gpu0"))
        if not isinstance(self.security, SecurityContext):
            object.__setattr__(self, "security", make_security_context())
        if not isinstance(self.stream, StreamContext):
            object.__setattr__(self, "stream", make_stream_context())

        object.__setattr__(self, "verdict", bool(self.verdict))
        object.__setattr__(self, "allowed", _coerce_bool(self.allowed) if self.allowed is not None else None)
        object.__setattr__(self, "decision", _safe_oneof(self.decision, allowed=_ALLOWED_ACTIONS, default="allow") if self.decision is not None else None)
        object.__setattr__(self, "required_action", _safe_oneof(self.required_action, allowed=_ALLOWED_REQUIRED_ACTIONS, default="allow") if self.required_action is not None else None)
        object.__setattr__(self, "enforcement_mode", _safe_oneof(self.enforcement_mode, allowed=_ALLOWED_ENFORCEMENT, default="advisory") if self.enforcement_mode is not None else None)
        object.__setattr__(self, "cause", _safe_text_or_none(self.cause, max_len=128, redact_mode="token"))
        object.__setattr__(self, "action", _safe_oneof(self.action, allowed=_ALLOWED_ACTIONS, default="none") if self.action is not None else None)
        object.__setattr__(self, "score", float(_coerce_float(self.score) or 0.0))
        object.__setattr__(self, "threshold", float(_coerce_float(self.threshold) or 0.0))
        object.__setattr__(self, "budget_remaining", float(_coerce_float(self.budget_remaining) or 0.0))
        object.__setattr__(self, "e_value", float(_coerce_float(self.e_value) or 1.0))
        object.__setattr__(self, "alpha_alloc", float(_coerce_float(self.alpha_alloc) or 0.0))
        object.__setattr__(self, "alpha_spent", float(_coerce_float(self.alpha_spent) or 0.0))
        step = _coerce_int(self.step)
        object.__setattr__(self, "step", max(0, step) if step is not None else 0)
        object.__setattr__(self, "detector_trigger", bool(self.detector_trigger))
        object.__setattr__(self, "av_trigger", bool(self.av_trigger))
        rb = _safe_oneof(self.risk_band, allowed=_ALLOWED_RISK_LABELS, default="unknown") if self.risk_band is not None else None
        object.__setattr__(self, "risk_band", rb)
        object.__setattr__(self, "apt_score", _coerce_float(self.apt_score))
        object.__setattr__(self, "insider_score", _coerce_float(self.insider_score))
        object.__setattr__(self, "supply_chain_score", _coerce_float(self.supply_chain_score))
        object.__setattr__(self, "drift_score", _coerce_float(self.drift_score))
        object.__setattr__(self, "selected_source", _safe_label(self.selected_source, default="") or None if self.selected_source is not None else None)
        object.__setattr__(self, "decision_mode", _safe_oneof(self.decision_mode, allowed=_ALLOWED_DECISION_MODES, default="dual_track") if self.decision_mode is not None else None)
        object.__setattr__(self, "controller_mode", _safe_oneof(self.controller_mode or self.stream.controller_mode, allowed=_ALLOWED_CONTROLLER_MODES, default="normal"))
        object.__setattr__(
            self,
            "statistical_guarantee_scope",
            _safe_oneof(self.statistical_guarantee_scope or self.stream.statistical_guarantee_scope, allowed=_ALLOWED_GUARANTEE_SCOPES, default="none"),
        )
        object.__setattr__(self, "state_domain_id", _safe_text_for_id(self.state_domain_id or self.stream.state_domain_id, max_len=256, default=None))
        object.__setattr__(self, "adapter_registry_fp", _safe_text_for_id(self.adapter_registry_fp or self.stream.adapter_registry_fp, max_len=256, default=None))
        rev = _coerce_int(self.state_revision or self.stream.state_revision)
        object.__setattr__(self, "state_revision", max(0, rev) if rev is not None else None)
        object.__setattr__(self, "identity_status", _safe_label(self.identity_status or self.stream.identity_status, default="") or None if (self.identity_status or self.stream.identity_status) is not None else None)
        pr = _safe_reason_code(self.primary_reason_code, default=None)
        reasons = _normalize_reason_codes(self.reason_codes, max_items=32)
        if pr is None and reasons:
            pr = reasons[0]
        object.__setattr__(self, "primary_reason_code", pr)
        object.__setattr__(self, "reason_codes", reasons)
        object.__setattr__(self, "degraded_reason_codes", _normalize_reason_codes(self.degraded_reason_codes, max_items=32))
        object.__setattr__(self, "tags", _normalize_namespaced_tags(self.tags, max_items=64))
        object.__setattr__(self, "detector_components", _deep_freeze(_sanitize_mapping(self.detector_components)))
        object.__setattr__(self, "multivar_components", _deep_freeze(_sanitize_mapping(self.multivar_components)))
        object.__setattr__(self, "e_process_state", _deep_freeze(_sanitize_mapping(self.e_process_state, max_depth=12, max_items=512, max_str_total=256_000)))
        object.__setattr__(self, "route_info", _deep_freeze(_sanitize_mapping(self.route_info, max_depth=8, max_items=256, max_str_total=128_000)))
        object.__setattr__(self, "normalization_warnings", _normalize_reason_codes(self.normalization_warnings, max_items=32))
        object.__setattr__(self, "compatibility_warnings", _normalize_reason_codes(self.compatibility_warnings, max_items=32))
        object.__setattr__(self, "integrity_errors", _normalize_reason_codes(self.integrity_errors, max_items=32))

    def to_eprocess_state_view(self, *, strict: bool = True) -> Any:
        return _view_instance(EProcessStateView, dict(self.e_process_state) if isinstance(self.e_process_state, Mapping) else {})

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "envelope": self.envelope.to_public_dict(),
            "subject": self.subject.to_public_dict(),
            "model": self.model.to_public_dict(),
            "security": self.security.to_public_dict(),
            "stream": self.stream.to_public_dict(),
            "verdict": self.verdict,
            "allowed": self.allowed,
            "decision": self.decision,
            "required_action": self.required_action,
            "enforcement_mode": self.enforcement_mode,
            "cause": self.cause,
            "action": self.action,
            "score": self.score,
            "threshold": self.threshold,
            "budget_remaining": self.budget_remaining,
            "e_value": self.e_value,
            "alpha_alloc": self.alpha_alloc,
            "alpha_spent": self.alpha_spent,
            "step": self.step,
            "risk_band": self.risk_band,
            "selected_source": self.selected_source,
            "decision_mode": self.decision_mode,
            "controller_mode": self.controller_mode,
            "statistical_guarantee_scope": self.statistical_guarantee_scope,
            "state_domain_id": self.state_domain_id,
            "adapter_registry_fp": self.adapter_registry_fp,
            "state_revision": self.state_revision,
            "identity_status": self.identity_status,
            "primary_reason_code": self.primary_reason_code,
            "reason_codes": list(self.reason_codes),
            "degraded_reason_codes": list(self.degraded_reason_codes),
            "tags": list(self.tags),
        }

    def to_audit_dict(self) -> Dict[str, Any]:
        return {
            **self.to_public_dict(),
            "detector_trigger": self.detector_trigger,
            "av_trigger": self.av_trigger,
            "apt_score": self.apt_score,
            "insider_score": self.insider_score,
            "supply_chain_score": self.supply_chain_score,
            "drift_score": self.drift_score,
            "detector_components": _to_primitive(self.detector_components),
            "multivar_components": _to_primitive(self.multivar_components),
            "e_process_state": _to_primitive(self.e_process_state),
            "route_info": _to_primitive(self.route_info),
            "normalization_warnings": list(self.normalization_warnings),
            "compatibility_warnings": list(self.compatibility_warnings),
            "integrity_errors": list(self.integrity_errors),
        }

    def to_internal_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


@dataclass(frozen=True)
class RouteDecisionSignal(GovernedSignal):
    envelope: SignalEnvelope
    subject: SubjectContext
    model: ModelContext
    security: SecurityContext
    stream: StreamContext

    route_plan_id: Optional[str] = None
    decision_id: Optional[str] = None
    route_id_kind: str = "plan"

    policy_ref: Optional[str] = None
    policyset_ref: Optional[str] = None
    config_fingerprint: Optional[str] = None
    bundle_version: Optional[int] = None
    patch_id: Optional[str] = None
    change_ticket_id: Optional[str] = None

    temperature: float = 1.0
    top_p: float = 1.0
    decoder: str = "default"
    safety_tier: str = "normal"
    latency_hint: str = "normal"
    max_tokens: Optional[int] = None

    required_action: str = "allow"
    action_hint: Optional[str] = None
    enforcement_mode: str = "advisory"

    tool_calls_allowed: Optional[bool] = None
    retrieval_allowed: Optional[bool] = None
    streaming_allowed: Optional[bool] = None
    external_calls_allowed: Optional[bool] = None
    response_policy: Optional[str] = None
    receipt_required: Optional[bool] = None
    ledger_required: Optional[bool] = None
    attestation_required: Optional[bool] = None

    primary_reason_code: Optional[str] = None
    reason_codes: Tuple[str, ...] = field(default_factory=tuple)
    degraded_reason_codes: Tuple[str, ...] = field(default_factory=tuple)
    tags: Tuple[str, ...] = field(default_factory=tuple)
    threat_tags: Tuple[str, ...] = field(default_factory=tuple)
    override_flags: Tuple[str, ...] = field(default_factory=tuple)

    signal_digest: Optional[str] = None
    context_digest: Optional[str] = None
    pq_required: Optional[bool] = None
    pq_ok: Optional[bool] = None

    normalization_warnings: Tuple[str, ...] = field(default_factory=tuple)
    compatibility_warnings: Tuple[str, ...] = field(default_factory=tuple)
    integrity_errors: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, SignalEnvelope):
            object.__setattr__(self, "envelope", make_signal_envelope(signal_kind="route_decision"))
        if not isinstance(self.subject, SubjectContext):
            object.__setattr__(self, "subject", make_subject_context("tenant0", "user0", "sess0"))
        if not isinstance(self.model, ModelContext):
            object.__setattr__(self, "model", make_model_context("model0", "gpu0"))
        if not isinstance(self.security, SecurityContext):
            object.__setattr__(self, "security", make_security_context())
        if not isinstance(self.stream, StreamContext):
            object.__setattr__(self, "stream", make_stream_context())

        object.__setattr__(self, "route_plan_id", _safe_text_for_id(self.route_plan_id or self.envelope.evidence.route_plan_id, max_len=256, default=None))
        object.__setattr__(self, "decision_id", _safe_text_for_id(self.decision_id or self.envelope.evidence.decision_id, max_len=256, default=None))
        object.__setattr__(self, "route_id_kind", _safe_label(self.route_id_kind or self.envelope.evidence.route_id_kind, default="plan"))
        object.__setattr__(self, "policy_ref", _safe_text_for_id(self.policy_ref or self.envelope.evidence.policy_ref, max_len=128, default=None))
        object.__setattr__(self, "policyset_ref", _safe_text_for_id(self.policyset_ref or self.envelope.evidence.policyset_ref, max_len=128, default=None))
        object.__setattr__(self, "config_fingerprint", _normalize_digest_token(self.config_fingerprint or self.envelope.config_fingerprint, kind="cfg_fp", default=None))
        bv = _coerce_int(self.bundle_version or self.envelope.bundle_version)
        object.__setattr__(self, "bundle_version", max(0, bv) if bv is not None else None)
        object.__setattr__(self, "patch_id", _safe_text_for_id(self.patch_id or self.envelope.evidence.patch_id, max_len=128, default=None))
        object.__setattr__(self, "change_ticket_id", _safe_text_for_id(self.change_ticket_id or self.envelope.evidence.change_ticket_id, max_len=128, default=None))
        object.__setattr__(self, "temperature", float(_coerce_float(self.temperature) or 1.0))
        object.__setattr__(self, "top_p", float(_coerce_float(self.top_p) or 1.0))
        object.__setattr__(self, "decoder", _safe_name(self.decoder, default="default"))
        object.__setattr__(self, "safety_tier", _safe_oneof(self.safety_tier, allowed={"normal", "elevated", "strict"}, default="normal"))
        object.__setattr__(self, "latency_hint", _safe_label(self.latency_hint, default="normal"))
        mt = _coerce_int(self.max_tokens)
        object.__setattr__(self, "max_tokens", max(0, mt) if mt is not None else None)
        object.__setattr__(self, "required_action", _safe_oneof(self.required_action, allowed=_ALLOWED_REQUIRED_ACTIONS, default="allow"))
        object.__setattr__(self, "action_hint", _safe_oneof(self.action_hint, allowed=_ALLOWED_ACTIONS, default="none") if self.action_hint is not None else None)
        object.__setattr__(self, "enforcement_mode", _safe_oneof(self.enforcement_mode, allowed=_ALLOWED_ENFORCEMENT, default="advisory"))
        object.__setattr__(self, "tool_calls_allowed", _coerce_bool(self.tool_calls_allowed) if self.tool_calls_allowed is not None else None)
        object.__setattr__(self, "retrieval_allowed", _coerce_bool(self.retrieval_allowed) if self.retrieval_allowed is not None else None)
        object.__setattr__(self, "streaming_allowed", _coerce_bool(self.streaming_allowed) if self.streaming_allowed is not None else None)
        object.__setattr__(self, "external_calls_allowed", _coerce_bool(self.external_calls_allowed) if self.external_calls_allowed is not None else None)
        object.__setattr__(self, "response_policy", _safe_label(self.response_policy, default="") or None if self.response_policy is not None else None)
        object.__setattr__(self, "receipt_required", _coerce_bool(self.receipt_required) if self.receipt_required is not None else None)
        object.__setattr__(self, "ledger_required", _coerce_bool(self.ledger_required) if self.ledger_required is not None else None)
        object.__setattr__(self, "attestation_required", _coerce_bool(self.attestation_required) if self.attestation_required is not None else None)
        pr = _safe_reason_code(self.primary_reason_code, default=None)
        reasons = _normalize_reason_codes(self.reason_codes, max_items=32)
        if pr is None and reasons:
            pr = reasons[0]
        object.__setattr__(self, "primary_reason_code", pr)
        object.__setattr__(self, "reason_codes", reasons)
        object.__setattr__(self, "degraded_reason_codes", _normalize_reason_codes(self.degraded_reason_codes, max_items=32))
        object.__setattr__(self, "tags", _normalize_namespaced_tags(self.tags, max_items=64))
        object.__setattr__(self, "threat_tags", _normalize_namespaced_tags(self.threat_tags, max_items=16))
        object.__setattr__(self, "override_flags", _normalize_namespaced_tags(self.override_flags, max_items=16))
        object.__setattr__(self, "signal_digest", _normalize_digest_token(self.signal_digest, kind="any", default=None))
        object.__setattr__(self, "context_digest", _normalize_digest_token(self.context_digest, kind="any", default=None))
        object.__setattr__(self, "pq_required", _coerce_bool(self.pq_required) if self.pq_required is not None else None)
        object.__setattr__(self, "pq_ok", _coerce_bool(self.pq_ok) if self.pq_ok is not None else None)
        object.__setattr__(self, "normalization_warnings", _normalize_reason_codes(self.normalization_warnings, max_items=32))
        object.__setattr__(self, "compatibility_warnings", _normalize_reason_codes(self.compatibility_warnings, max_items=32))
        object.__setattr__(self, "integrity_errors", _normalize_reason_codes(self.integrity_errors, max_items=32))

    def to_route_contract_view(self, *, strict: bool = True) -> Any:
        payload = {
            "route_plan_id": self.route_plan_id,
            "decision_id": self.decision_id,
            "route_id_kind": self.route_id_kind,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "config_fingerprint": self.config_fingerprint,
            "bundle_version": self.bundle_version,
            "patch_id": self.patch_id,
            "change_ticket_id": self.change_ticket_id,
            "required_action": self.required_action,
            "enforcement_mode": self.enforcement_mode,
            "safety_tier": self.safety_tier,
            "primary_reason_code": self.primary_reason_code,
            "reason_codes": list(self.reason_codes),
            "degraded_reason_codes": list(self.degraded_reason_codes),
            "trust_zone": self.security.trust_zone,
            "route_profile": self.security.route_profile,
            "risk_label": getattr(self, "risk_label", None),
            "score": None,
            "signal_digest": self.signal_digest,
            "context_digest": self.context_digest,
            "receipt_required": self.receipt_required,
            "ledger_required": self.ledger_required,
            "attestation_required": self.attestation_required,
            "tool_calls_allowed": self.tool_calls_allowed,
            "retrieval_allowed": self.retrieval_allowed,
            "streaming_allowed": self.streaming_allowed,
            "external_calls_allowed": self.external_calls_allowed,
            "response_policy": self.response_policy,
            "temperature": self.temperature,
            "top_p": self.top_p,
            "decoder": self.decoder,
            "latency_hint": self.latency_hint,
            "max_tokens": self.max_tokens,
            "pq_required": self.pq_required,
            "pq_ok": self.pq_ok,
            "tags": list(self.tags),
            "threat_tags": list(self.threat_tags),
            "override_flags": list(self.override_flags),
        }
        return _view_instance(RouteContractView, payload)

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "envelope": self.envelope.to_public_dict(),
            "subject": self.subject.to_public_dict(),
            "model": self.model.to_public_dict(),
            "security": self.security.to_public_dict(),
            "stream": self.stream.to_public_dict(),
            "route_contract": _to_primitive(self.to_route_contract_view(strict=False)),
        }

    def to_audit_dict(self) -> Dict[str, Any]:
        return {
            **self.to_public_dict(),
            "normalization_warnings": list(self.normalization_warnings),
            "compatibility_warnings": list(self.compatibility_warnings),
            "integrity_errors": list(self.integrity_errors),
        }

    def to_internal_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


@dataclass(frozen=True)
class SecurityDecisionSignal(GovernedSignal):
    envelope: SignalEnvelope
    subject: SubjectContext
    model: ModelContext
    security: SecurityContext
    stream: StreamContext

    allowed: bool = True
    action: str = "allow"
    action_taken: Optional[str] = None
    required_action: str = "allow"
    enforcement_mode: str = "advisory"

    primary_reason_code: Optional[str] = None
    reason_codes: Tuple[str, ...] = field(default_factory=tuple)
    degraded_reason_codes: Tuple[str, ...] = field(default_factory=tuple)
    reason: Optional[str] = None

    policy_ref: Optional[str] = None
    policyset_ref: Optional[str] = None
    policy_digest: Optional[str] = None

    route_plan_id: Optional[str] = None
    decision_id: Optional[str] = None

    risk_score: Optional[float] = None
    risk_label: Optional[str] = None
    e_triggered: bool = False
    controller_mode: Optional[str] = None
    statistical_guarantee_scope: Optional[str] = None

    rate_decisions: Mapping[str, Any] = field(default_factory=dict)
    route_contract: Mapping[str, Any] = field(default_factory=dict)
    security_view: Mapping[str, Any] = field(default_factory=dict)
    evidence_identity_view: Mapping[str, Any] = field(default_factory=dict)
    artifacts_view: Mapping[str, Any] = field(default_factory=dict)
    receipt: Mapping[str, Any] = field(default_factory=dict)

    normalization_warnings: Tuple[str, ...] = field(default_factory=tuple)
    compatibility_warnings: Tuple[str, ...] = field(default_factory=tuple)
    integrity_errors: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, SignalEnvelope):
            object.__setattr__(self, "envelope", make_signal_envelope(signal_kind="security_decision"))
        if not isinstance(self.subject, SubjectContext):
            object.__setattr__(self, "subject", make_subject_context("tenant0", "user0", "sess0"))
        if not isinstance(self.model, ModelContext):
            object.__setattr__(self, "model", make_model_context("model0", "gpu0"))
        if not isinstance(self.security, SecurityContext):
            object.__setattr__(self, "security", make_security_context())
        if not isinstance(self.stream, StreamContext):
            object.__setattr__(self, "stream", make_stream_context())

        object.__setattr__(self, "allowed", bool(self.allowed))
        object.__setattr__(self, "action", _safe_oneof(self.action, allowed=_ALLOWED_ACTIONS, default="allow"))
        object.__setattr__(self, "action_taken", _safe_oneof(self.action_taken, allowed=_ALLOWED_ACTIONS, default="allow") if self.action_taken is not None else None)
        object.__setattr__(self, "required_action", _safe_oneof(self.required_action, allowed=_ALLOWED_REQUIRED_ACTIONS, default="allow"))
        object.__setattr__(self, "enforcement_mode", _safe_oneof(self.enforcement_mode, allowed=_ALLOWED_ENFORCEMENT, default="advisory"))
        pr = _safe_reason_code(self.primary_reason_code, default=None)
        reasons = _normalize_reason_codes(self.reason_codes, max_items=32)
        if pr is None and reasons:
            pr = reasons[0]
        object.__setattr__(self, "primary_reason_code", pr)
        object.__setattr__(self, "reason_codes", reasons)
        object.__setattr__(self, "degraded_reason_codes", _normalize_reason_codes(self.degraded_reason_codes, max_items=32))
        object.__setattr__(self, "reason", _safe_text_or_none(self.reason, max_len=256, redact_mode="strict"))
        object.__setattr__(self, "policy_ref", _safe_text_for_id(self.policy_ref or self.envelope.evidence.policy_ref, max_len=128, default=None))
        object.__setattr__(self, "policyset_ref", _safe_text_for_id(self.policyset_ref or self.envelope.evidence.policyset_ref, max_len=128, default=None))
        object.__setattr__(self, "policy_digest", _normalize_digest_token(self.policy_digest or self.envelope.evidence.policy_digest, kind="any", default=None))
        object.__setattr__(self, "route_plan_id", _safe_text_for_id(self.route_plan_id or self.envelope.evidence.route_plan_id, max_len=256, default=None))
        object.__setattr__(self, "decision_id", _safe_text_for_id(self.decision_id or self.envelope.evidence.decision_id, max_len=256, default=None))
        object.__setattr__(self, "risk_score", _coerce_float(self.risk_score))
        object.__setattr__(self, "risk_label", _safe_oneof(self.risk_label, allowed=_ALLOWED_RISK_LABELS, default="unknown") if self.risk_label is not None else None)
        object.__setattr__(self, "e_triggered", bool(self.e_triggered))
        object.__setattr__(self, "controller_mode", _safe_oneof(self.controller_mode or self.stream.controller_mode, allowed=_ALLOWED_CONTROLLER_MODES, default="normal"))
        object.__setattr__(
            self,
            "statistical_guarantee_scope",
            _safe_oneof(self.statistical_guarantee_scope or self.stream.statistical_guarantee_scope, allowed=_ALLOWED_GUARANTEE_SCOPES, default="none"),
        )
        object.__setattr__(self, "rate_decisions", _deep_freeze(_sanitize_mapping(self.rate_decisions)))
        object.__setattr__(self, "route_contract", _deep_freeze(_sanitize_mapping(self.route_contract, max_depth=10, max_items=512)))
        object.__setattr__(self, "security_view", _deep_freeze(_sanitize_mapping(self.security_view, max_depth=10, max_items=512)))
        object.__setattr__(self, "evidence_identity_view", _deep_freeze(_sanitize_mapping(self.evidence_identity_view, max_depth=10, max_items=512)))
        object.__setattr__(self, "artifacts_view", _deep_freeze(_sanitize_mapping(self.artifacts_view, max_depth=10, max_items=512)))
        object.__setattr__(self, "receipt", _deep_freeze(_sanitize_mapping(self.receipt, max_depth=10, max_items=512, drop_forbidden_keys=False)))
        object.__setattr__(self, "normalization_warnings", _normalize_reason_codes(self.normalization_warnings, max_items=32))
        object.__setattr__(self, "compatibility_warnings", _normalize_reason_codes(self.compatibility_warnings, max_items=32))
        object.__setattr__(self, "integrity_errors", _normalize_reason_codes(self.integrity_errors, max_items=32))

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.envelope.evidence.event_id,
            "allowed": self.allowed,
            "action": self.action,
            "action_taken": self.action_taken,
            "required_action": self.required_action,
            "enforcement_mode": self.enforcement_mode,
            "primary_reason_code": self.primary_reason_code,
            "reason_codes": list(self.reason_codes),
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "route_plan_id": self.route_plan_id,
            "decision_id": self.decision_id,
            "risk_score": self.risk_score,
            "risk_label": self.risk_label,
            "controller_mode": self.controller_mode,
            "statistical_guarantee_scope": self.statistical_guarantee_scope,
            "evidence_identity": self.envelope.evidence.to_public_dict(),
            "artifacts": self.envelope.artifacts.to_public_dict(),
        }

    def to_audit_dict(self) -> Dict[str, Any]:
        return {
            "type": "tcd.security_router.decision",
            "schema": self.envelope.contract.schema_version,
            "version": self.envelope.contract.signal_version,
            "instance_id": self.envelope.instance_id or self.envelope.producer_bundle.producer_instance_id,
            "activation_id": self.envelope.producer_activation.producer_activation_id,
            "config_fingerprint": self.envelope.config_fingerprint,
            "bundle_version": self.envelope.bundle_version,
            "event_id": self.envelope.evidence.event_id,
            "decision_ts_unix_ns": self.envelope.ts_unix_ns,
            "allowed": self.allowed,
            "action": self.action,
            "action_taken": self.action_taken,
            "required_action": self.required_action,
            "enforcement_mode": self.enforcement_mode,
            "primary_reason_code": self.primary_reason_code,
            "reason_codes": list(self.reason_codes),
            "degraded_reason_codes": list(self.degraded_reason_codes),
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "policy_digest": self.policy_digest,
            "route_plan_id": self.route_plan_id,
            "decision_id": self.decision_id,
            "risk_score": self.risk_score,
            "risk_label": self.risk_label,
            "controller_mode": self.controller_mode,
            "guarantee_scope": self.statistical_guarantee_scope,
            "route": _to_primitive(self.route_contract),
            "security": _to_primitive(self.security_view),
            "evidence_identity": self.envelope.evidence.to_internal_dict(),
            "artifacts": self.envelope.artifacts.to_internal_dict(),
            "receipt": _to_primitive(self.receipt),
            "normalization_warnings": list(self.normalization_warnings),
            "compatibility_warnings": list(self.compatibility_warnings),
            "integrity_errors": list(self.integrity_errors),
        }

    def to_internal_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


@dataclass(frozen=True)
class ReceiptSignal(GovernedSignal):
    envelope: SignalEnvelope
    subject: Optional[SubjectContext] = None
    model: Optional[ModelContext] = None
    security: Optional[SecurityContext] = None
    stream: Optional[StreamContext] = None

    head: Optional[str] = None
    body: Optional[str] = None
    sig: Optional[str] = None
    verify_key: Optional[str] = None

    receipt_ref: Optional[str] = None
    audit_ref: Optional[str] = None

    policy_ref: Optional[str] = None
    policyset_ref: Optional[str] = None
    policy_digest: Optional[str] = None
    cfg_fp: Optional[str] = None
    state_domain_id: Optional[str] = None
    adapter_registry_fp: Optional[str] = None

    event_id: Optional[str] = None
    decision_id: Optional[str] = None
    route_plan_id: Optional[str] = None

    verify_key_id: Optional[str] = None
    sig_key_id: Optional[str] = None
    verify_key_fp: Optional[str] = None
    receipt_integrity: Optional[str] = None

    body_kind: str = "opaque"
    body_digest: Optional[str] = None

    head_verified: Optional[bool] = None
    body_canonical_verified: Optional[bool] = None
    integrity_hash_verified: Optional[bool] = None
    signature_verified: Optional[bool] = None
    verify_key_allowed: Optional[bool] = None
    policy_binding_verified: Optional[bool] = None
    cfg_binding_verified: Optional[bool] = None

    pq_signature_required: Optional[bool] = None
    pq_signature_ok: Optional[bool] = None

    meta: Mapping[str, Any] = field(default_factory=dict)
    op_kind: str = "issue"

    integrity_ok: bool = True
    integrity_errors: Tuple[str, ...] = field(default_factory=tuple)
    normalization_warnings: Tuple[str, ...] = field(default_factory=tuple)
    compatibility_warnings: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, SignalEnvelope):
            object.__setattr__(self, "envelope", make_signal_envelope(signal_kind="receipt"))
        if self.subject is not None and not isinstance(self.subject, SubjectContext):
            object.__setattr__(self, "subject", make_subject_context("tenant0", "user0", "sess0"))
        if self.model is not None and not isinstance(self.model, ModelContext):
            object.__setattr__(self, "model", make_model_context("model0", "gpu0"))
        if self.security is not None and not isinstance(self.security, SecurityContext):
            object.__setattr__(self, "security", make_security_context())
        if self.stream is not None and not isinstance(self.stream, StreamContext):
            object.__setattr__(self, "stream", make_stream_context())

        object.__setattr__(self, "head", _normalize_digest_token(self.head or self.envelope.artifacts.chain_head, kind="any", default=None))
        body = _safe_text_or_none(self.body, max_len=_MAX_JSON_STR_TOTAL, redact_mode="strict")
        object.__setattr__(self, "body", body)
        object.__setattr__(self, "sig", _safe_text_or_none(self.sig, max_len=16_384, redact_mode="token"))
        object.__setattr__(self, "verify_key", _safe_text_or_none(self.verify_key, max_len=8_192, redact_mode="token"))
        object.__setattr__(self, "receipt_ref", _safe_text_for_id(self.receipt_ref or self.envelope.artifacts.receipt_ref, max_len=256, default=None))
        object.__setattr__(self, "audit_ref", _safe_text_for_id(self.audit_ref or self.envelope.artifacts.audit_ref, max_len=256, default=None))
        object.__setattr__(self, "policy_ref", _safe_text_for_id(self.policy_ref or self.envelope.evidence.policy_ref, max_len=128, default=None))
        object.__setattr__(self, "policyset_ref", _safe_text_for_id(self.policyset_ref or self.envelope.evidence.policyset_ref, max_len=128, default=None))
        object.__setattr__(self, "policy_digest", _normalize_digest_token(self.policy_digest or self.envelope.evidence.policy_digest, kind="any", default=None))
        object.__setattr__(self, "cfg_fp", _normalize_digest_token(self.cfg_fp or self.envelope.evidence.config_fingerprint or self.envelope.config_fingerprint, kind="cfg_fp", default=None))
        object.__setattr__(self, "state_domain_id", _safe_text_for_id(self.state_domain_id or self.envelope.evidence.state_domain_id, max_len=256, default=None))
        object.__setattr__(self, "adapter_registry_fp", _safe_text_for_id(self.adapter_registry_fp or self.envelope.evidence.adapter_registry_fp, max_len=256, default=None))
        object.__setattr__(self, "event_id", _safe_text_for_id(self.event_id or self.envelope.evidence.event_id, max_len=256, default=None))
        object.__setattr__(self, "decision_id", _safe_text_for_id(self.decision_id or self.envelope.evidence.decision_id, max_len=256, default=None))
        object.__setattr__(self, "route_plan_id", _safe_text_for_id(self.route_plan_id or self.envelope.evidence.route_plan_id, max_len=256, default=None))
        object.__setattr__(self, "verify_key_id", _safe_text_for_id(self.verify_key_id, max_len=128, default=None))
        object.__setattr__(self, "sig_key_id", _safe_text_for_id(self.sig_key_id, max_len=128, default=None))
        object.__setattr__(self, "verify_key_fp", _normalize_digest_token(self.verify_key_fp, kind="any", default=None))
        object.__setattr__(self, "receipt_integrity", _normalize_digest_token(self.receipt_integrity, kind="integrity", default=None))
        object.__setattr__(self, "body_kind", _safe_oneof(self.body_kind, allowed=_ALLOWED_RECEIPT_BODY_KINDS, default="opaque"))
        bd = _normalize_digest_token(self.body_digest, kind="any", default=None)
        if bd is None and body is not None:
            bd = f"sha256:{hashlib.sha256(body.encode('utf-8', errors='replace')).hexdigest()}"
        object.__setattr__(self, "body_digest", bd)
        object.__setattr__(self, "head_verified", _coerce_bool(self.head_verified) if self.head_verified is not None else None)
        object.__setattr__(self, "body_canonical_verified", _coerce_bool(self.body_canonical_verified) if self.body_canonical_verified is not None else None)
        object.__setattr__(self, "integrity_hash_verified", _coerce_bool(self.integrity_hash_verified) if self.integrity_hash_verified is not None else None)
        object.__setattr__(self, "signature_verified", _coerce_bool(self.signature_verified) if self.signature_verified is not None else None)
        object.__setattr__(self, "verify_key_allowed", _coerce_bool(self.verify_key_allowed) if self.verify_key_allowed is not None else None)
        object.__setattr__(self, "policy_binding_verified", _coerce_bool(self.policy_binding_verified) if self.policy_binding_verified is not None else None)
        object.__setattr__(self, "cfg_binding_verified", _coerce_bool(self.cfg_binding_verified) if self.cfg_binding_verified is not None else None)
        object.__setattr__(self, "pq_signature_required", _coerce_bool(self.pq_signature_required) if self.pq_signature_required is not None else None)
        object.__setattr__(self, "pq_signature_ok", _coerce_bool(self.pq_signature_ok) if self.pq_signature_ok is not None else None)
        object.__setattr__(self, "meta", _deep_freeze(_sanitize_mapping(self.meta, max_depth=8, max_items=256, max_str_total=128_000, drop_forbidden_keys=True)))
        object.__setattr__(self, "op_kind", _safe_oneof(self.op_kind, allowed=_ALLOWED_RECEIPT_OPS, default="issue"))
        errs = list(_normalize_reason_codes(self.integrity_errors, max_items=64))
        ok = bool(self.integrity_ok)
        if self.head is None:
            errs.append("INTEGRITY_ERROR")
            ok = False
        if self.receipt_ref and self.envelope.artifacts.receipt_ref and self.receipt_ref != self.envelope.artifacts.receipt_ref:
            errs.append("INTEGRITY_ERROR")
            ok = False
        object.__setattr__(self, "integrity_errors", _normalize_reason_codes(errs, max_items=64))
        if self.integrity_errors:
            ok = False
        object.__setattr__(self, "integrity_ok", bool(ok))
        object.__setattr__(self, "normalization_warnings", _normalize_reason_codes(self.normalization_warnings, max_items=32))
        object.__setattr__(self, "compatibility_warnings", _normalize_reason_codes(self.compatibility_warnings, max_items=32))

    def assert_integrity(self) -> None:
        if not self.integrity_ok:
            raise ValueError("receipt integrity failed")

    def to_public_view(self, *, strict: bool = True) -> Any:
        if strict:
            self.assert_integrity()
        payload = {
            "schema": self.envelope.contract.schema_version,
            "head": self.head,
            "receipt_ref": self.receipt_ref,
            "audit_ref": self.audit_ref,
            "event_id": self.event_id,
            "decision_id": self.decision_id,
            "route_plan_id": self.route_plan_id,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "cfg_fp": self.cfg_fp,
            "verify_key_id": self.verify_key_id or self.sig_key_id,
            "verify_key_fp": self.verify_key_fp,
            "receipt_integrity": self.receipt_integrity,
            "pq_signature_required": self.pq_signature_required,
            "pq_signature_ok": self.pq_signature_ok,
            "integrity_ok": self.integrity_ok,
            "integrity_errors": list(self.integrity_errors),
        }
        return _view_instance(ReceiptPublicView, payload)

    def to_audit_view(self, *, strict: bool = True) -> Any:
        if strict:
            self.assert_integrity()
        payload = {
            "schema": self.envelope.contract.schema_version,
            "head": self.head,
            "body_digest": self.body_digest,
            "receipt_ref": self.receipt_ref,
            "audit_ref": self.audit_ref,
            "event_id": self.event_id,
            "decision_id": self.decision_id,
            "route_plan_id": self.route_plan_id,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "policy_digest": self.policy_digest,
            "cfg_fp": self.cfg_fp,
            "state_domain_id": self.state_domain_id,
            "adapter_registry_fp": self.adapter_registry_fp,
            "verify_key_id": self.verify_key_id or self.sig_key_id,
            "verify_key_fp": self.verify_key_fp,
            "receipt_integrity": self.receipt_integrity,
            "integrity_ok": self.integrity_ok,
            "integrity_errors": list(self.integrity_errors),
            "meta": dict(self.meta) if isinstance(self.meta, Mapping) else {},
        }
        return _view_instance(ReceiptAuditView, payload)

    def to_verification_view(self, *, strict: bool = True, include_verify_key: bool = True) -> Any:
        if strict:
            self.assert_integrity()
        payload = {
            "schema": self.envelope.contract.schema_version,
            "head": self.head,
            "body": self.body,
            "sig": self.sig,
            "verify_key": self.verify_key if include_verify_key else None,
            "verify_key_id": self.verify_key_id or self.sig_key_id,
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
        return _view_instance(ReceiptVerificationView, payload)

    def to_public_dict(self) -> Dict[str, Any]:
        return _to_primitive(self.to_public_view(strict=False))

    def to_audit_dict(self) -> Dict[str, Any]:
        return _to_primitive(self.to_audit_view(strict=False))

    def to_internal_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


@dataclass(frozen=True)
class ArtifactLifecycleSignal(GovernedSignal):
    envelope: SignalEnvelope
    subject: Optional[SubjectContext] = None
    evidence: EvidenceIdentity = field(default_factory=EvidenceIdentity)
    artifacts: ArtifactRefs = field(default_factory=ArtifactRefs)

    artifact_kind: str = "receipt"
    lifecycle_kind: str = "prepared"
    ok: bool = True
    ref: Optional[str] = None
    dedupe_key: Optional[str] = None
    payload_digest: Optional[str] = None
    delivery_attempts: Optional[int] = None
    error_code: Optional[str] = None
    error_reason: Optional[str] = None

    normalization_warnings: Tuple[str, ...] = field(default_factory=tuple)
    compatibility_warnings: Tuple[str, ...] = field(default_factory=tuple)
    integrity_errors: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, SignalEnvelope):
            object.__setattr__(self, "envelope", make_signal_envelope(signal_kind="receipt"))
        if self.subject is not None and not isinstance(self.subject, SubjectContext):
            object.__setattr__(self, "subject", make_subject_context("tenant0", "user0", "sess0"))
        if not isinstance(self.evidence, EvidenceIdentity):
            object.__setattr__(self, "evidence", EvidenceIdentity(**(dict(self.evidence) if isinstance(self.evidence, Mapping) else {})))
        if not isinstance(self.artifacts, ArtifactRefs):
            object.__setattr__(self, "artifacts", ArtifactRefs(**(dict(self.artifacts) if isinstance(self.artifacts, Mapping) else {})))
        object.__setattr__(self, "artifact_kind", _safe_label(self.artifact_kind, default="receipt"))
        object.__setattr__(self, "lifecycle_kind", _safe_label(self.lifecycle_kind, default="prepared"))
        object.__setattr__(self, "ok", bool(self.ok))
        object.__setattr__(self, "ref", _safe_text_for_id(self.ref, max_len=256, default=None))
        object.__setattr__(self, "dedupe_key", _safe_text_for_id(self.dedupe_key, max_len=256, default=None))
        object.__setattr__(self, "payload_digest", _normalize_digest_token(self.payload_digest, kind="any", default=None))
        da = _coerce_int(self.delivery_attempts)
        object.__setattr__(self, "delivery_attempts", max(0, da) if da is not None else None)
        object.__setattr__(self, "error_code", _safe_reason_code(self.error_code, default=None))
        object.__setattr__(self, "error_reason", _safe_text_or_none(self.error_reason, max_len=256, redact_mode="strict"))
        object.__setattr__(self, "normalization_warnings", _normalize_reason_codes(self.normalization_warnings, max_items=32))
        object.__setattr__(self, "compatibility_warnings", _normalize_reason_codes(self.compatibility_warnings, max_items=32))
        object.__setattr__(self, "integrity_errors", _normalize_reason_codes(self.integrity_errors, max_items=32))

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "envelope": self.envelope.to_public_dict(),
            "artifact_kind": self.artifact_kind,
            "lifecycle_kind": self.lifecycle_kind,
            "ok": self.ok,
            "ref": self.ref,
            "delivery_attempts": self.delivery_attempts,
            "error_code": self.error_code,
        }

    def to_audit_dict(self) -> Dict[str, Any]:
        return {
            **self.to_public_dict(),
            "subject": self.subject.to_audit_dict() if self.subject else None,
            "evidence": self.evidence.to_internal_dict(),
            "artifacts": self.artifacts.to_internal_dict(),
            "dedupe_key": self.dedupe_key,
            "payload_digest": self.payload_digest,
            "error_reason": self.error_reason,
            "normalization_warnings": list(self.normalization_warnings),
            "compatibility_warnings": list(self.compatibility_warnings),
            "integrity_errors": list(self.integrity_errors),
        }

    def to_internal_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


@dataclass(frozen=True)
class ReceiptPreparedSignal(ArtifactLifecycleSignal):
    artifact_kind: str = "receipt"
    lifecycle_kind: str = "prepared"


@dataclass(frozen=True)
class ReceiptCommittedSignal(ArtifactLifecycleSignal):
    artifact_kind: str = "receipt"
    lifecycle_kind: str = "committed"


@dataclass(frozen=True)
class LedgerPreparedSignal(ArtifactLifecycleSignal):
    artifact_kind: str = "ledger"
    lifecycle_kind: str = "prepared"


@dataclass(frozen=True)
class LedgerCommittedSignal(ArtifactLifecycleSignal):
    artifact_kind: str = "ledger"
    lifecycle_kind: str = "committed"


@dataclass(frozen=True)
class OutboxQueuedSignal(ArtifactLifecycleSignal):
    artifact_kind: str = "outbox"
    lifecycle_kind: str = "queued"


@dataclass(frozen=True)
class OutboxFlushedSignal(ArtifactLifecycleSignal):
    artifact_kind: str = "outbox"
    lifecycle_kind: str = "flushed"


@dataclass(frozen=True)
class PQHealthSignal(GovernedSignal):
    envelope: SignalEnvelope
    sig_chain_id: str
    sig_scheme: str

    healthy: bool
    reason: Optional[str] = None
    details: Mapping[str, Any] = field(default_factory=dict)

    health_state: str = "ok"
    grace_until_ts: Optional[float] = None
    cluster_id: Optional[str] = None
    region: Optional[str] = None

    normalization_warnings: Tuple[str, ...] = field(default_factory=tuple)
    compatibility_warnings: Tuple[str, ...] = field(default_factory=tuple)
    integrity_errors: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, SignalEnvelope):
            object.__setattr__(self, "envelope", make_signal_envelope(signal_kind="pq_health"))
        object.__setattr__(self, "sig_chain_id", _safe_text_for_id(self.sig_chain_id, max_len=128, default="unknown") or "unknown")
        object.__setattr__(self, "sig_scheme", _safe_label(self.sig_scheme, default="unknown"))
        object.__setattr__(self, "healthy", bool(self.healthy))
        object.__setattr__(self, "reason", _safe_text_or_none(self.reason, max_len=256, redact_mode="strict"))
        object.__setattr__(self, "details", _deep_freeze(_sanitize_mapping(self.details, max_depth=6, max_items=128, max_str_total=64_000)))
        object.__setattr__(self, "health_state", _safe_label(self.health_state, default="ok"))
        gt = _coerce_float(self.grace_until_ts)
        object.__setattr__(self, "grace_until_ts", max(0.0, gt) if gt is not None else None)
        object.__setattr__(self, "cluster_id", _safe_text_for_id(self.cluster_id, max_len=128, default=None))
        object.__setattr__(self, "region", _safe_label(self.region, default="") or None if self.region is not None else None)
        object.__setattr__(self, "normalization_warnings", _normalize_reason_codes(self.normalization_warnings, max_items=32))
        object.__setattr__(self, "compatibility_warnings", _normalize_reason_codes(self.compatibility_warnings, max_items=32))
        object.__setattr__(self, "integrity_errors", _normalize_reason_codes(self.integrity_errors, max_items=32))

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "envelope": self.envelope.to_public_dict(),
            "sig_chain_id": self.sig_chain_id,
            "sig_scheme": self.sig_scheme,
            "healthy": self.healthy,
            "health_state": self.health_state,
            "grace_until_ts": self.grace_until_ts,
            "cluster_id": self.cluster_id,
            "region": self.region,
        }

    def to_audit_dict(self) -> Dict[str, Any]:
        return {
            **self.to_public_dict(),
            "reason": self.reason,
            "details": _to_primitive(self.details),
            "normalization_warnings": list(self.normalization_warnings),
            "compatibility_warnings": list(self.compatibility_warnings),
            "integrity_errors": list(self.integrity_errors),
        }

    def to_internal_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


@dataclass(frozen=True)
class BundleLifecycleSignal(GovernedSignal):
    envelope: SignalEnvelope
    component: str = "unknown"
    lifecycle_event: str = "bundle_activated"

    activation_id: Optional[str] = None
    cfg_fp: Optional[str] = None
    bundle_version: Optional[int] = None
    policy_ref: Optional[str] = None
    policyset_ref: Optional[str] = None
    patch_id: Optional[str] = None
    change_ticket_id: Optional[str] = None
    activated_by_hash: Optional[str] = None
    approved_by_hashes: Tuple[str, ...] = field(default_factory=tuple)
    approval_count: int = 0
    previous_cfg_fp: Optional[str] = None
    using_last_known_good: Optional[bool] = None
    warnings: Tuple[str, ...] = field(default_factory=tuple)
    errors: Tuple[str, ...] = field(default_factory=tuple)

    normalization_warnings: Tuple[str, ...] = field(default_factory=tuple)
    compatibility_warnings: Tuple[str, ...] = field(default_factory=tuple)
    integrity_errors: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, SignalEnvelope):
            object.__setattr__(self, "envelope", make_signal_envelope(signal_kind="bundle_lifecycle"))
        object.__setattr__(self, "component", _safe_name(self.component, default="unknown"))
        object.__setattr__(self, "lifecycle_event", _safe_oneof(self.lifecycle_event, allowed=_ALLOWED_BUNDLE_EVENTS, default="bundle_activated"))
        object.__setattr__(self, "activation_id", _safe_text_for_id(self.activation_id or self.envelope.producer_activation.producer_activation_id, max_len=256, default=None))
        object.__setattr__(self, "cfg_fp", _normalize_digest_token(self.cfg_fp or self.envelope.config_fingerprint, kind="cfg_fp", default=None))
        bv = _coerce_int(self.bundle_version or self.envelope.bundle_version)
        object.__setattr__(self, "bundle_version", max(0, bv) if bv is not None else None)
        object.__setattr__(self, "policy_ref", _safe_text_for_id(self.policy_ref or self.envelope.evidence.policy_ref, max_len=128, default=None))
        object.__setattr__(self, "policyset_ref", _safe_text_for_id(self.policyset_ref or self.envelope.evidence.policyset_ref, max_len=128, default=None))
        object.__setattr__(self, "patch_id", _safe_text_for_id(self.patch_id or self.envelope.producer_activation.patch_id, max_len=128, default=None))
        object.__setattr__(self, "change_ticket_id", _safe_text_for_id(self.change_ticket_id or self.envelope.producer_activation.change_ticket_id, max_len=128, default=None))
        object.__setattr__(self, "activated_by_hash", _safe_text_for_id(self.activated_by_hash or self.envelope.producer_activation.activated_by_hash, max_len=128, default=None))
        ab = _normalize_str_tuple(self.approved_by_hashes or self.envelope.producer_activation.approved_by_hashes, max_len=128, max_items=64)
        object.__setattr__(self, "approved_by_hashes", ab)
        ac = _coerce_int(self.approval_count)
        object.__setattr__(self, "approval_count", max(0, ac) if ac is not None else max(0, len(ab)))
        object.__setattr__(self, "previous_cfg_fp", _normalize_digest_token(self.previous_cfg_fp, kind="cfg_fp", default=None))
        object.__setattr__(self, "using_last_known_good", _coerce_bool(self.using_last_known_good) if self.using_last_known_good is not None else None)
        object.__setattr__(self, "warnings", _normalize_reason_codes(self.warnings, max_items=64))
        object.__setattr__(self, "errors", _normalize_reason_codes(self.errors, max_items=64))
        object.__setattr__(self, "normalization_warnings", _normalize_reason_codes(self.normalization_warnings, max_items=32))
        object.__setattr__(self, "compatibility_warnings", _normalize_reason_codes(self.compatibility_warnings, max_items=32))
        object.__setattr__(self, "integrity_errors", _normalize_reason_codes(self.integrity_errors, max_items=32))

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "envelope": self.envelope.to_public_dict(),
            "component": self.component,
            "lifecycle_event": self.lifecycle_event,
            "activation_id": self.activation_id,
            "cfg_fp": self.cfg_fp,
            "bundle_version": self.bundle_version,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "patch_id": self.patch_id,
            "change_ticket_id": self.change_ticket_id,
            "approval_count": self.approval_count,
            "using_last_known_good": self.using_last_known_good,
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }

    def to_audit_dict(self) -> Dict[str, Any]:
        return {
            **self.to_public_dict(),
            "activated_by_hash": self.activated_by_hash,
            "approved_by_hashes": list(self.approved_by_hashes),
            "previous_cfg_fp": self.previous_cfg_fp,
            "normalization_warnings": list(self.normalization_warnings),
            "compatibility_warnings": list(self.compatibility_warnings),
            "integrity_errors": list(self.integrity_errors),
        }

    def to_internal_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


# =============================================================================
# Integrity validation
# =============================================================================


def _integrity_report_for(signal: GovernedSignal) -> SignalIntegrityReport:
    errors: List[SignalIntegrityIssue] = []
    warnings: List[SignalIntegrityIssue] = []

    env = getattr(signal, "envelope", None)
    if not isinstance(env, SignalEnvelope):
        errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="envelope", message="missing envelope"))
        return SignalIntegrityReport(ok=False, errors=tuple(errors), warnings=tuple(warnings))

    # Envelope kind/class alignment
    expected_kind = {
        RiskDecisionSignal: "risk_decision",
        SecurityDecisionSignal: "security_decision",
        RouteDecisionSignal: "route_decision",
        ReceiptSignal: "receipt",
        ReceiptPreparedSignal: "receipt_prepared",
        ReceiptCommittedSignal: "receipt_committed",
        LedgerPreparedSignal: "ledger_prepared",
        LedgerCommittedSignal: "ledger_committed",
        OutboxQueuedSignal: "outbox_queued",
        OutboxFlushedSignal: "outbox_flushed",
        PQHealthSignal: "pq_health",
        BundleLifecycleSignal: "bundle_lifecycle",
    }.get(type(signal))
    if expected_kind and env.signal_kind != expected_kind:
        errors.append(
            SignalIntegrityIssue(
                code="INTEGRITY_ERROR",
                field="envelope.signal_kind",
                message=f"expected {expected_kind}, got {env.signal_kind}",
            )
        )

    # Common identity/artifact consistency
    if isinstance(signal, RouteDecisionSignal):
        if signal.route_plan_id and env.evidence.route_plan_id and signal.route_plan_id != env.evidence.route_plan_id:
            errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="route_plan_id", message="route_plan_id drift"))
        if signal.decision_id and env.evidence.decision_id and signal.decision_id != env.evidence.decision_id:
            errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="decision_id", message="decision_id drift"))
        if signal.policy_ref and env.evidence.policy_ref and signal.policy_ref != env.evidence.policy_ref:
            errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="policy_ref", message="policy_ref drift"))
        if signal.policyset_ref and env.evidence.policyset_ref and signal.policyset_ref != env.evidence.policyset_ref:
            errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="policyset_ref", message="policyset_ref drift"))
        if signal.config_fingerprint and env.config_fingerprint and signal.config_fingerprint != env.config_fingerprint:
            errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="config_fingerprint", message="config_fingerprint drift"))
        if signal.bundle_version is not None and env.bundle_version is not None and signal.bundle_version != env.bundle_version:
            errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="bundle_version", message="bundle_version drift"))
        if signal.required_action in {"degrade", "block"}:
            if not signal.signal_digest:
                errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="signal_digest", message="missing signal_digest"))
            if not signal.context_digest:
                errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="context_digest", message="missing context_digest"))

    if isinstance(signal, SecurityDecisionSignal):
        if signal.route_plan_id and env.evidence.route_plan_id and signal.route_plan_id != env.evidence.route_plan_id:
            errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="route_plan_id", message="route_plan_id drift"))
        if signal.decision_id and env.evidence.decision_id and signal.decision_id != env.evidence.decision_id:
            errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="decision_id", message="decision_id drift"))
        if signal.policy_ref and env.evidence.policy_ref and signal.policy_ref != env.evidence.policy_ref:
            errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="policy_ref", message="policy_ref drift"))
        if signal.policyset_ref and env.evidence.policyset_ref and signal.policyset_ref != env.evidence.policyset_ref:
            errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="policyset_ref", message="policyset_ref drift"))
        if signal.required_action in {"degrade", "block"}:
            rc = signal.route_contract
            if isinstance(rc, Mapping):
                sg = rc.get("signal_digest")
                cx = rc.get("context_digest")
                if not sg:
                    errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="route_contract.signal_digest", message="missing signal_digest"))
                if not cx:
                    errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="route_contract.context_digest", message="missing context_digest"))
            else:
                warnings.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", severity="warning", field="route_contract", message="missing structured route_contract"))

    if isinstance(signal, RiskDecisionSignal):
        if signal.controller_mode and env.evidence.controller_mode and signal.controller_mode != env.evidence.controller_mode:
            warnings.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", severity="warning", field="controller_mode", message="controller_mode drift"))
        if signal.statistical_guarantee_scope and env.evidence.statistical_guarantee_scope and signal.statistical_guarantee_scope != env.evidence.statistical_guarantee_scope:
            warnings.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", severity="warning", field="statistical_guarantee_scope", message="guarantee drift"))
        if signal.state_domain_id and env.evidence.state_domain_id and signal.state_domain_id != env.evidence.state_domain_id:
            warnings.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", severity="warning", field="state_domain_id", message="state domain drift"))

    if isinstance(signal, ReceiptSignal):
        if signal.receipt_ref and env.artifacts.receipt_ref and signal.receipt_ref != env.artifacts.receipt_ref:
            errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="receipt_ref", message="receipt_ref drift"))
        if signal.audit_ref and env.artifacts.audit_ref and signal.audit_ref != env.artifacts.audit_ref:
            errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="audit_ref", message="audit_ref drift"))
        if signal.event_id and env.evidence.event_id and signal.event_id != env.evidence.event_id:
            errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="event_id", message="event_id drift"))
        if signal.decision_id and env.evidence.decision_id and signal.decision_id != env.evidence.decision_id:
            errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="decision_id", message="decision_id drift"))
        if signal.route_plan_id and env.evidence.route_plan_id and signal.route_plan_id != env.evidence.route_plan_id:
            errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="route_plan_id", message="route_plan_id drift"))
        if not signal.head:
            errors.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", field="head", message="missing receipt head"))
        if signal.body_kind == "canonical_json" and signal.body and signal.body_digest is None:
            warnings.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", severity="warning", field="body_digest", message="missing body_digest"))
        if signal.integrity_ok and signal.integrity_errors:
            warnings.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", severity="warning", field="integrity_ok", message="integrity_ok true with errors"))

    if isinstance(signal, ArtifactLifecycleSignal):
        if signal.ref and signal.artifact_kind == "receipt" and env.artifacts.receipt_ref and signal.ref != env.artifacts.receipt_ref:
            warnings.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", severity="warning", field="ref", message="lifecycle ref drift"))
        if signal.payload_digest and env.artifacts.payload_digest and signal.payload_digest != env.artifacts.payload_digest:
            warnings.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", severity="warning", field="payload_digest", message="payload digest drift"))

    if isinstance(signal, BundleLifecycleSignal):
        if signal.activation_id and env.producer_activation.producer_activation_id and signal.activation_id != env.producer_activation.producer_activation_id:
            warnings.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", severity="warning", field="activation_id", message="activation drift"))
        if signal.cfg_fp and env.config_fingerprint and signal.cfg_fp != env.config_fingerprint:
            warnings.append(SignalIntegrityIssue(code="INTEGRITY_ERROR", severity="warning", field="cfg_fp", message="cfg_fp drift"))

    return SignalIntegrityReport(ok=(len(errors) == 0), errors=tuple(errors), warnings=tuple(warnings))


# =============================================================================
# Diagnostics / bus config
# =============================================================================


@dataclass(frozen=True)
class SignalBusConfig:
    enabled: bool = True
    profile: Profile = "PROD"
    on_sink_error: str = "log_and_continue"

    max_emit_depth: int = 4
    max_global_sinks: int = 64
    max_sinks_per_type: int = 64
    max_batch_items: int = 256

    suppress_duplicate_signal_ids: bool = True
    duplicate_ttl_s: float = 300.0
    duplicate_cache_max_entries: int = 10_000
    duplicate_cache_max_bytes: int = 1_000_000

    validate_integrity: bool = True
    reject_on_integrity_error: bool = False

    max_signal_payload_bytes: int = _MAX_SIGNAL_INTERNAL_BYTES
    max_envelope_bytes: int = _MAX_ENVELOPE_INTERNAL_BYTES

    service_name: str = "tcd.signals"
    activation_id: Optional[str] = None
    cfg_fp: Optional[str] = None
    bundle_version: Optional[int] = None

    consistency_level: str = "local_sync"
    delivery_semantics: str = "sync_in_process"
    fail_fast_on_required_sink_failure: bool = True

    def __post_init__(self) -> None:
        prof = _safe_text(self.profile, max_len=32).upper() or "PROD"
        object.__setattr__(self, "profile", prof if prof in _ALLOWED_PROFILES else "PROD")
        policy = _safe_oneof(self.on_sink_error, allowed=_ALLOWED_ON_SINK_ERROR, default="log_and_continue")
        object.__setattr__(self, "on_sink_error", policy)
        object.__setattr__(self, "enabled", bool(self.enabled))
        object.__setattr__(self, "max_emit_depth", _clamp_int(self.max_emit_depth, default=4, lo=1, hi=64))
        object.__setattr__(self, "max_global_sinks", _clamp_int(self.max_global_sinks, default=64, lo=1, hi=1024))
        object.__setattr__(self, "max_sinks_per_type", _clamp_int(self.max_sinks_per_type, default=64, lo=1, hi=1024))
        object.__setattr__(self, "max_batch_items", _clamp_int(self.max_batch_items, default=256, lo=1, hi=10_000))
        object.__setattr__(self, "suppress_duplicate_signal_ids", bool(self.suppress_duplicate_signal_ids))
        object.__setattr__(self, "duplicate_ttl_s", _clamp_float(self.duplicate_ttl_s, default=300.0, lo=1.0, hi=86_400.0))
        object.__setattr__(self, "duplicate_cache_max_entries", _clamp_int(self.duplicate_cache_max_entries, default=10_000, lo=128, hi=1_000_000))
        object.__setattr__(self, "duplicate_cache_max_bytes", _clamp_int(self.duplicate_cache_max_bytes, default=1_000_000, lo=1024, hi=100_000_000))
        object.__setattr__(self, "validate_integrity", bool(self.validate_integrity))
        object.__setattr__(self, "reject_on_integrity_error", bool(self.reject_on_integrity_error))
        object.__setattr__(self, "max_signal_payload_bytes", _clamp_int(self.max_signal_payload_bytes, default=_MAX_SIGNAL_INTERNAL_BYTES, lo=4096, hi=50_000_000))
        object.__setattr__(self, "max_envelope_bytes", _clamp_int(self.max_envelope_bytes, default=_MAX_ENVELOPE_INTERNAL_BYTES, lo=1024, hi=5_000_000))
        object.__setattr__(self, "service_name", _safe_name(self.service_name, default="tcd.signals"))
        object.__setattr__(self, "activation_id", _safe_text_for_id(self.activation_id, max_len=256, default=None))
        object.__setattr__(self, "cfg_fp", _normalize_digest_token(self.cfg_fp, kind="cfg_fp", default=None))
        bv = _coerce_int(self.bundle_version)
        object.__setattr__(self, "bundle_version", max(0, bv) if bv is not None else None)
        object.__setattr__(self, "consistency_level", _safe_oneof(self.consistency_level, allowed=_ALLOWED_CONSISTENCY_LEVELS, default="local_sync"))
        object.__setattr__(self, "delivery_semantics", _safe_oneof(self.delivery_semantics, allowed=_ALLOWED_DELIVERY_SEMANTICS, default="sync_in_process"))
        object.__setattr__(self, "fail_fast_on_required_sink_failure", bool(self.fail_fast_on_required_sink_failure))


@dataclass(frozen=True)
class SignalEmitResult:
    ok: bool
    signal_kind: str
    signal_id: Optional[str]
    phase: Optional[str]
    dispatched: int
    failures: int
    dropped: bool = False
    reason: Optional[str] = None
    required_sink_failed: bool = False
    integrity_ok: bool = True
    integrity_errors: Tuple[str, ...] = field(default_factory=tuple)
    normalization_warnings: Tuple[str, ...] = field(default_factory=tuple)
    compatibility_warnings: Tuple[str, ...] = field(default_factory=tuple)
    queued_to_outbox: bool = False
    delivery_status: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


@dataclass(frozen=True)
class SinkDiagnostics:
    registration_id: str
    sink_name: str
    priority: int
    global_sink: bool
    signal_types: Tuple[str, ...]
    include_subclasses: bool
    criticality: str
    max_handle_ms: Optional[int]
    timeout_behavior: str
    enabled: bool

    handled: int
    failures: int
    timeouts: int
    breaker_open: bool
    last_signal_kind: Optional[str]
    last_signal_id: Optional[str]
    last_emit_unix_ns: Optional[int]
    last_error: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


@dataclass(frozen=True)
class SignalBusPublicConfigView:
    enabled: bool
    profile: str
    on_sink_error: str
    activation_id: Optional[str]
    cfg_fp: Optional[str]
    bundle_version: Optional[int]
    service_name: str
    consistency_level: str
    delivery_semantics: str
    suppress_duplicate_signal_ids: bool
    duplicate_ttl_s: float
    validate_integrity: bool
    reject_on_integrity_error: bool
    required_sinks_satisfied: bool
    registered_global_sinks: int
    registered_typed_sinks: int

    def to_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


@dataclass(frozen=True)
class SignalBusDiagnosticsView:
    enabled: bool
    profile: str
    on_sink_error: str
    activation_id: Optional[str]
    cfg_fp: Optional[str]
    bundle_version: Optional[int]
    service_name: str
    consistency_level: str
    delivery_semantics: str

    registered_type_count: int
    global_sink_count: int
    typed_sink_count: int
    suppress_duplicate_signal_ids: bool
    duplicate_cache_size: int
    duplicate_cache_bytes: int

    emitted_total: int
    emitted_failures: int
    dropped_total: int
    duplicate_registration_rejected_total: int
    integrity_reject_total: int
    breaker_open_total: int

    sinks: Tuple[SinkDiagnostics, ...]

    def to_dict(self) -> Dict[str, Any]:
        return _to_primitive(self)


# =============================================================================
# Sink protocols / built-in sinks
# =============================================================================


class SignalSink(Protocol):
    def handle(self, signal: GovernedSignal) -> None:
        ...


class SignalProvider(Protocol):
    def emit(self, signal: GovernedSignal) -> SignalEmitResult:
        ...
    def emit_many(
        self,
        signals: Iterable[GovernedSignal],
        *,
        batch_id: Optional[str] = None,
        stop_on_first_required_failure: bool = False,
    ) -> Tuple[SignalEmitResult, ...]:
        ...
    def public_config_view(self) -> SignalBusPublicConfigView:
        ...
    def diagnostics_view(self) -> SignalBusDiagnosticsView:
        ...
    def compact(self) -> Dict[str, Any]:
        ...


class LoggingSink:
    def __init__(self, logger_obj: Optional[logging.Logger] = None, *, prefix: str = "tcd.signal", surface: str = "audit") -> None:
        self._logger = logger_obj or logger.getChild("signals")
        self._prefix = _safe_name(prefix, default="tcd.signal")
        self._surface = _safe_label(surface, default="audit")

    def handle(self, signal: GovernedSignal) -> None:  # pragma: no cover
        try:
            name = type(signal).__name__
            if self._surface == "public":
                payload = signal.to_public_dict()
            elif self._surface == "internal":
                payload = signal.to_internal_dict()
            else:
                payload = signal.to_audit_dict()
            self._logger.info(
                "%s.%s %s",
                self._prefix,
                name,
                json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False),
            )
        except Exception:
            self._logger.exception("Failed to log signal of type %s", type(signal).__name__)


class InMemorySink:
    """
    Bounded, profile-aware in-memory sink for tests / runtime diagnostics.

    Supports:
      - per-tenant capacity
      - per-signal-kind capacity
      - total bytes cap
      - TTL
    """

    def __init__(
        self,
        *,
        ttl_s: float = 900.0,
        per_tenant_capacity: int = 256,
        per_signal_kind_capacity: int = 512,
        max_total_items: int = 4096,
        max_total_bytes: int = 4_000_000,
    ) -> None:
        self._ttl_s = max(1.0, float(ttl_s))
        self._per_tenant_capacity = max(1, int(per_tenant_capacity))
        self._per_signal_kind_capacity = max(1, int(per_signal_kind_capacity))
        self._max_total_items = max(1, int(max_total_items))
        self._max_total_bytes = max(1024, int(max_total_bytes))
        self._lock = threading.RLock()
        self._records: Deque[Tuple[int, Optional[str], str, int, GovernedSignal]] = deque()
        self._tenant_counts: Dict[Optional[str], int] = {}
        self._kind_counts: Dict[str, int] = {}
        self._total_bytes = 0

    def _subject_hash(self, signal: GovernedSignal) -> Optional[str]:
        subj = getattr(signal, "subject", None)
        return getattr(subj, "subject_hash", None) if subj is not None else None

    def _size_of(self, signal: GovernedSignal) -> int:
        try:
            return len(_canonical_json_bytes(signal.to_internal_dict()))
        except Exception:
            return 1024

    def _prune(self, now_ns: Optional[int] = None) -> None:
        if now_ns is None:
            now_ns = now_unix_ns()
        cutoff = now_ns - int(self._ttl_s * 1_000_000_000)
        while self._records:
            ts_ns, tenant_hash, kind, size, _sig = self._records[0]
            if ts_ns >= cutoff and len(self._records) <= self._max_total_items and self._total_bytes <= self._max_total_bytes:
                break
            self._records.popleft()
            self._tenant_counts[tenant_hash] = max(0, self._tenant_counts.get(tenant_hash, 0) - 1)
            self._kind_counts[kind] = max(0, self._kind_counts.get(kind, 0) - 1)
            self._total_bytes = max(0, self._total_bytes - size)

    def handle(self, signal: GovernedSignal) -> None:
        with self._lock:
            now_ns = now_unix_ns()
            tenant_hash = self._subject_hash(signal)
            kind = signal.signal_kind()
            self._prune(now_ns)

            while self._tenant_counts.get(tenant_hash, 0) >= self._per_tenant_capacity and self._records:
                self._drop_oldest_matching(tenant_hash=tenant_hash, kind=None)
            while self._kind_counts.get(kind, 0) >= self._per_signal_kind_capacity and self._records:
                self._drop_oldest_matching(tenant_hash=None, kind=kind)

            size = self._size_of(signal)
            self._records.append((now_ns, tenant_hash, kind, size, signal))
            self._tenant_counts[tenant_hash] = self._tenant_counts.get(tenant_hash, 0) + 1
            self._kind_counts[kind] = self._kind_counts.get(kind, 0) + 1
            self._total_bytes += size
            self._prune(now_ns)

    def _drop_oldest_matching(self, *, tenant_hash: Optional[str], kind: Optional[str]) -> None:
        for idx, rec in enumerate(self._records):
            _ts, th, kd, size, _sig = rec
            if tenant_hash is not None and th != tenant_hash:
                continue
            if kind is not None and kd != kind:
                continue
            del self._records[idx]
            self._tenant_counts[th] = max(0, self._tenant_counts.get(th, 0) - 1)
            self._kind_counts[kd] = max(0, self._kind_counts.get(kd, 0) - 1)
            self._total_bytes = max(0, self._total_bytes - size)
            return

    def snapshot(self, *, tenant_hash: Optional[str] = None, signal_kind: Optional[str] = None, limit: int = 256) -> Tuple[GovernedSignal, ...]:
        with self._lock:
            self._prune()
            out: List[GovernedSignal] = []
            for _ts, th, kd, _sz, sig in reversed(self._records):
                if tenant_hash is not None and th != tenant_hash:
                    continue
                if signal_kind is not None and kd != signal_kind:
                    continue
                out.append(sig)
                if len(out) >= max(1, int(limit)):
                    break
            return tuple(out)

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            self._tenant_counts.clear()
            self._kind_counts.clear()
            self._total_bytes = 0


class OutboxBackendProtocol(Protocol):
    def enqueue(
        self,
        *,
        kind: str,
        dedupe_key: str,
        payload: Dict[str, Any],
        payload_digest: str,
        available_at_unix_ns: Optional[int] = None,
    ) -> Mapping[str, Any]:
        ...


class OutboxSignalSink:
    """
    Synchronous local durable sink.

    This sink is the correct place to bridge the synchronous bus to external
    evidence delivery. The bus only enqueues locally; remote flush happens
    elsewhere.
    """

    def __init__(self, backend: OutboxBackendProtocol, *, surface: str = "audit", kind: str = "signal_outbox") -> None:
        self._backend = backend
        self._surface = _safe_label(surface, default="audit")
        self._kind = _safe_label(kind, default="signal_outbox")
        self.last_enqueue_result: Optional[Mapping[str, Any]] = None

    def handle(self, signal: GovernedSignal) -> None:
        if self._surface == "public":
            payload = signal.to_public_dict()
        elif self._surface == "internal":
            payload = signal.to_internal_dict()
        else:
            payload = signal.to_audit_dict()
        payload_bytes = _canonical_json_bytes(payload)
        payload_digest = f"sha256:{hashlib.sha256(payload_bytes).hexdigest()}"
        dedupe_key = signal.signal_id() or f"sig:anonymous:{_hash_bytes(ctx='tcd:signals:outbox', payload=payload_bytes, out_hex=32)}"
        self.last_enqueue_result = self._backend.enqueue(
            kind=self._kind,
            dedupe_key=dedupe_key,
            payload=payload,
            payload_digest=payload_digest,
            available_at_unix_ns=None,
        )


# =============================================================================
# Translator
# =============================================================================


class SignalEvidenceTranslator:
    """
    Single translator from signal -> attestation / audit / ledger payloads.
    """

    @staticmethod
    def to_attestation_payload(signal: GovernedSignal, *, surface: str = "audit") -> Dict[str, Any]:
        body = signal.to_audit_dict() if surface == "audit" else (signal.to_public_dict() if surface == "public" else signal.to_internal_dict())
        return {
            "schema": _SCHEMA,
            "kind": signal.signal_kind(),
            "surface": surface,
            "signal_id": signal.signal_id(),
            "payload": body,
            "witness_segments": SignalEvidenceTranslator.witness_segments(signal),
        }

    @staticmethod
    def to_audit_event(signal: GovernedSignal) -> Dict[str, Any]:
        return {
            "type": f"tcd.signals.{signal.signal_kind()}",
            "schema": _SCHEMA,
            "signal_id": signal.signal_id(),
            "event": signal.to_audit_dict(),
        }

    @staticmethod
    def to_ledger_event(signal: GovernedSignal) -> Dict[str, Any]:
        env = signal.envelope
        return {
            "event_id": env.evidence.event_id,
            "decision_id": env.evidence.decision_id,
            "route_plan_id": env.evidence.route_plan_id,
            "signal_id": env.signal_id,
            "phase": env.phase,
            "kind": env.signal_kind,
            "payload_digest": f"sha256:{hashlib.sha256(_canonical_json_bytes(signal.to_audit_dict())).hexdigest()}",
            "artifacts": env.artifacts.to_internal_dict(),
        }

    @staticmethod
    def witness_segments(signal: GovernedSignal) -> Dict[str, str]:
        env = signal.envelope
        policy_digest = env.evidence.policy_digest
        signal_digest = None
        context_digest = None
        if isinstance(signal, RouteDecisionSignal):
            signal_digest = signal.signal_digest
            context_digest = signal.context_digest
        elif isinstance(signal, SecurityDecisionSignal):
            rc = signal.route_contract
            if isinstance(rc, Mapping):
                signal_digest = _normalize_digest_token(rc.get("signal_digest"), kind="any", default=None)
                context_digest = _normalize_digest_token(rc.get("context_digest"), kind="any", default=None)
        return {
            "signal_digest": signal_digest or f"sha256:{hashlib.sha256(_canonical_json_bytes(signal.to_audit_dict())).hexdigest()}",
            "context_digest": context_digest or f"sha256:{hashlib.sha256(_canonical_json_bytes(env.evidence.to_internal_dict())).hexdigest()}",
            "policy_digest": policy_digest or "",
            "cfg_fp": env.config_fingerprint or "",
            "bundle_version": str(env.bundle_version or ""),
            "state_domain_id": env.evidence.state_domain_id or "",
            "adapter_registry_fp": env.evidence.adapter_registry_fp or "",
            "ledger_head": env.artifacts.chain_head or "",
        }


# =============================================================================
# Signal bus
# =============================================================================


@dataclass
class _SinkBreakerState:
    consecutive_failures: int = 0
    open_until_ts: float = 0.0

    def is_open(self, now: float) -> bool:
        return now < self.open_until_ts

    def mark_success(self) -> None:
        self.consecutive_failures = 0
        self.open_until_ts = 0.0

    def mark_failure(self, *, threshold: int, open_seconds: float, now: float) -> bool:
        self.consecutive_failures += 1
        if self.consecutive_failures >= max(1, threshold):
            self.open_until_ts = now + max(1.0, open_seconds)
            return True
        return False


@dataclass
class _RegisteredSink:
    registration_id: str
    registration_seq: int
    sink: SignalSink
    sink_name: str
    signal_cls: Optional[Type[GovernedSignal]]
    priority: int
    include_subclasses: bool
    global_sink: bool
    criticality: str
    max_handle_ms: Optional[int]
    timeout_behavior: str
    enabled: bool = True

    handled: int = 0
    failures: int = 0
    timeouts: int = 0
    breaker: _SinkBreakerState = field(default_factory=_SinkBreakerState)
    last_signal_kind: Optional[str] = None
    last_signal_id: Optional[str] = None
    last_emit_unix_ns: Optional[int] = None
    last_error: Optional[str] = None

    def diagnostics(self) -> SinkDiagnostics:
        return SinkDiagnostics(
            registration_id=self.registration_id,
            sink_name=self.sink_name,
            priority=self.priority,
            global_sink=self.global_sink,
            signal_types=(self.signal_cls.__name__,) if self.signal_cls is not None else ("*",),
            include_subclasses=self.include_subclasses,
            criticality=self.criticality,
            max_handle_ms=self.max_handle_ms,
            timeout_behavior=self.timeout_behavior,
            enabled=self.enabled,
            handled=self.handled,
            failures=self.failures,
            timeouts=self.timeouts,
            breaker_open=self.breaker.is_open(now_ts()),
            last_signal_kind=self.last_signal_kind,
            last_signal_id=self.last_signal_id,
            last_emit_unix_ns=self.last_emit_unix_ns,
            last_error=self.last_error,
        )


class SignalBus:
    def __init__(self, config: Optional[SignalBusConfig] = None) -> None:
        self.config = config or SignalBusConfig()
        self._lock = threading.RLock()
        self._typed: Dict[Type[GovernedSignal], List[_RegisteredSink]] = {}
        self._global: List[_RegisteredSink] = []
        self._reg_index: Set[Tuple[int, str, bool]] = set()
        self._reg_seq = 0
        self._local = threading.local()

        self._duplicate_cache: "OrderedDict[Tuple[str, str, str, str], Tuple[float, int]]" = OrderedDict()
        self._duplicate_cache_bytes = 0

        self._emitted_total = 0
        self._emitted_failures = 0
        self._dropped_total = 0
        self._duplicate_registration_rejected_total = 0
        self._integrity_reject_total = 0
        self._breaker_open_total = 0

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_sink(
        self,
        signal_type: Type[GovernedSignal],
        sink: SignalSink,
        *,
        priority: int = 100,
        sink_name: Optional[str] = None,
        include_subclasses: bool = True,
        criticality: str = "optional",
        max_handle_ms: Optional[int] = None,
        timeout_behavior: str = "disable",
    ) -> str:
        if not isinstance(signal_type, type):
            raise TypeError("signal_type must be a class")
        crit = _safe_oneof(criticality, allowed=_ALLOWED_CRITICALITY, default="optional")
        to = _safe_oneof(timeout_behavior, allowed=_ALLOWED_TIMEOUT_BEHAVIOR, default="disable")
        with self._lock:
            if len(self._typed.get(signal_type, [])) >= self.config.max_sinks_per_type:
                raise ValueError("max_sinks_per_type exceeded")
            dedupe_key = (id(sink), signal_type.__name__, False)
            if dedupe_key in self._reg_index:
                self._duplicate_registration_rejected_total += 1
                raise ValueError("duplicate sink registration rejected")
            self._reg_seq += 1
            reg = _RegisteredSink(
                registration_id=f"reg:{self._reg_seq}",
                registration_seq=self._reg_seq,
                sink=sink,
                sink_name=_safe_name(sink_name or type(sink).__name__, default="SignalSink"),
                signal_cls=signal_type,
                priority=int(priority),
                include_subclasses=bool(include_subclasses),
                global_sink=False,
                criticality=crit,
                max_handle_ms=_clamp_int(max_handle_ms, default=1000, lo=1, hi=3_600_000) if max_handle_ms is not None else None,
                timeout_behavior=to,
            )
            self._typed.setdefault(signal_type, []).append(reg)
            self._typed[signal_type].sort(key=lambda r: (r.priority, r.registration_seq))
            self._reg_index.add(dedupe_key)
            return reg.registration_id

    def register_global_sink(
        self,
        sink: SignalSink,
        *,
        priority: int = 100,
        sink_name: Optional[str] = None,
        criticality: str = "optional",
        max_handle_ms: Optional[int] = None,
        timeout_behavior: str = "disable",
    ) -> str:
        crit = _safe_oneof(criticality, allowed=_ALLOWED_CRITICALITY, default="optional")
        to = _safe_oneof(timeout_behavior, allowed=_ALLOWED_TIMEOUT_BEHAVIOR, default="disable")
        with self._lock:
            if len(self._global) >= self.config.max_global_sinks:
                raise ValueError("max_global_sinks exceeded")
            dedupe_key = (id(sink), "*", True)
            if dedupe_key in self._reg_index:
                self._duplicate_registration_rejected_total += 1
                raise ValueError("duplicate global sink registration rejected")
            self._reg_seq += 1
            reg = _RegisteredSink(
                registration_id=f"reg:{self._reg_seq}",
                registration_seq=self._reg_seq,
                sink=sink,
                sink_name=_safe_name(sink_name or type(sink).__name__, default="SignalSink"),
                signal_cls=None,
                priority=int(priority),
                include_subclasses=True,
                global_sink=True,
                criticality=crit,
                max_handle_ms=_clamp_int(max_handle_ms, default=1000, lo=1, hi=3_600_000) if max_handle_ms is not None else None,
                timeout_behavior=to,
            )
            self._global.append(reg)
            self._global.sort(key=lambda r: (r.priority, r.registration_seq))
            self._reg_index.add(dedupe_key)
            return reg.registration_id

    def unregister_sink(self, signal_type: Type[GovernedSignal], sink: SignalSink) -> None:
        with self._lock:
            regs = self._typed.get(signal_type, [])
            new_regs = [r for r in regs if r.sink is not sink]
            self._typed[signal_type] = new_regs
            self._rebuild_reg_index()

    def unregister_global_sink(self, sink: SignalSink) -> None:
        with self._lock:
            self._global = [r for r in self._global if r.sink is not sink]
            self._rebuild_reg_index()

    def _rebuild_reg_index(self) -> None:
        idx: Set[Tuple[int, str, bool]] = set()
        for cls, regs in self._typed.items():
            for r in regs:
                idx.add((id(r.sink), cls.__name__, False))
        for r in self._global:
            idx.add((id(r.sink), "*", True))
        self._reg_index = idx

    # ------------------------------------------------------------------
    # Duplicate suppression
    # ------------------------------------------------------------------

    def _duplicate_scope(self, signal: GovernedSignal) -> Optional[Tuple[str, str, str, str]]:
        env = signal.envelope
        sid = env.signal_id
        if not sid:
            return None
        src = env.source or ""
        act = env.producer_activation.producer_activation_id or ""
        bv = str(env.bundle_version or env.producer_bundle.producer_bundle_version or "")
        return (sid, src, act, bv)

    def _compact_duplicate_cache(self, *, now: Optional[float] = None) -> Dict[str, Any]:
        if now is None:
            now = now_ts()
        removed = 0
        removed_bytes = 0
        with self._lock:
            while self._duplicate_cache:
                _k, (exp, sz) = next(iter(self._duplicate_cache.items()))
                if exp > now and len(self._duplicate_cache) <= self.config.duplicate_cache_max_entries and self._duplicate_cache_bytes <= self.config.duplicate_cache_max_bytes:
                    break
                key, (_exp, size) = self._duplicate_cache.popitem(last=False)
                removed += 1
                removed_bytes += size
                self._duplicate_cache_bytes = max(0, self._duplicate_cache_bytes - size)
        return {"removed_entries": removed, "removed_bytes": removed_bytes}

    def _mark_duplicate_scope(self, scope: Optional[Tuple[str, str, str, str]]) -> bool:
        if not self.config.suppress_duplicate_signal_ids or scope is None:
            return False
        now = now_ts()
        ttl = self.config.duplicate_ttl_s
        self._compact_duplicate_cache(now=now)
        key_bytes = len("|".join(scope).encode("utf-8", errors="ignore"))
        with self._lock:
            if scope in self._duplicate_cache:
                exp, size = self._duplicate_cache[scope]
                if exp > now:
                    self._duplicate_cache.move_to_end(scope, last=True)
                    return True
                self._duplicate_cache_bytes = max(0, self._duplicate_cache_bytes - size)
                del self._duplicate_cache[scope]
            self._duplicate_cache[scope] = (now + ttl, key_bytes)
            self._duplicate_cache_bytes += key_bytes
            while len(self._duplicate_cache) > self.config.duplicate_cache_max_entries or self._duplicate_cache_bytes > self.config.duplicate_cache_max_bytes:
                _k, (_exp, sz) = self._duplicate_cache.popitem(last=False)
                self._duplicate_cache_bytes = max(0, self._duplicate_cache_bytes - sz)
        return False

    # ------------------------------------------------------------------
    # Matching / dispatch
    # ------------------------------------------------------------------

    def _thread_depth(self) -> int:
        return int(getattr(self._local, "emit_depth", 0))

    def _push_depth(self) -> None:
        self._local.emit_depth = self._thread_depth() + 1

    def _pop_depth(self) -> None:
        self._local.emit_depth = max(0, self._thread_depth() - 1)

    def _matching_regs(self, signal: GovernedSignal) -> List[_RegisteredSink]:
        out: Dict[str, _RegisteredSink] = {}
        with self._lock:
            for cls, regs in self._typed.items():
                for reg in regs:
                    if not reg.enabled:
                        continue
                    if reg.include_subclasses:
                        if isinstance(signal, cls):
                            out[reg.registration_id] = reg
                    else:
                        if type(signal) is cls:
                            out[reg.registration_id] = reg
            for reg in self._global:
                if reg.enabled:
                    out[reg.registration_id] = reg
        regs = list(out.values())
        regs.sort(key=lambda r: (r.priority, r.registration_seq))
        return regs

    def _signal_sizes_ok(self, signal: GovernedSignal) -> Tuple[bool, Optional[str]]:
        try:
            env_bytes = len(_canonical_json_bytes(signal.envelope.to_internal_dict()))
        except Exception:
            return False, "envelope_serialize_failed"
        if env_bytes > self.config.max_envelope_bytes:
            return False, "envelope_too_large"
        try:
            sig_bytes = len(_canonical_json_bytes(signal.to_internal_dict()))
        except Exception:
            return False, "signal_serialize_failed"
        if sig_bytes > self.config.max_signal_payload_bytes:
            return False, "signal_too_large"
        return True, None

    def _required_sinks_satisfied(self) -> bool:
        with self._lock:
            for regs in list(self._typed.values()) + [self._global]:
                for reg in regs:
                    if reg.criticality == "required" and reg.enabled:
                        return True
        return True  # satisfied vacuously if none registered

    def _dispatch_one(self, reg: _RegisteredSink, signal: GovernedSignal) -> Tuple[bool, Optional[str], bool]:
        now = now_ts()
        if reg.breaker.is_open(now):
            with self._lock:
                self._breaker_open_total += 1
            return False, "breaker_open", False

        start_ns = now_monotonic_ns()
        try:
            reg.sink.handle(signal)
            elapsed_ms = (now_monotonic_ns() - start_ns) / 1_000_000.0
            reg.handled += 1
            reg.last_signal_kind = signal.signal_kind()
            reg.last_signal_id = signal.signal_id()
            reg.last_emit_unix_ns = signal.envelope.ts_unix_ns
            reg.last_error = None
            timeout_hit = bool(reg.max_handle_ms is not None and elapsed_ms > float(reg.max_handle_ms))
            if timeout_hit:
                reg.timeouts += 1
                if reg.timeout_behavior == "disable":
                    reg.enabled = False
                elif reg.timeout_behavior == "raise":
                    reg.failures += 1
                    reg.last_error = "timeout"
                    reg.breaker.mark_failure(threshold=3, open_seconds=15.0, now=now)
                    return False, "timeout", True
                elif reg.timeout_behavior == "degrade":
                    reg.breaker.mark_failure(threshold=3, open_seconds=15.0, now=now)
                    return True, "timeout_degraded", True
            reg.breaker.mark_success()
            return True, None if not timeout_hit else "timeout_degraded", timeout_hit
        except Exception as exc:
            reg.failures += 1
            reg.last_signal_kind = signal.signal_kind()
            reg.last_signal_id = signal.signal_id()
            reg.last_emit_unix_ns = signal.envelope.ts_unix_ns
            reg.last_error = _safe_text_for_log(exc, max_len=256) or type(exc).__name__
            opened = reg.breaker.mark_failure(threshold=3, open_seconds=15.0, now=now)
            if self.config.on_sink_error == "disable_sink":
                reg.enabled = False
            elif self.config.on_sink_error == "raise":
                raise
            if opened:
                with self._lock:
                    self._breaker_open_total += 1
            return False, "exception", False

    # ------------------------------------------------------------------
    # Emit
    # ------------------------------------------------------------------

    def emit(self, signal: GovernedSignal) -> SignalEmitResult:
        if not self.config.enabled:
            with self._lock:
                self._dropped_total += 1
            return SignalEmitResult(
                ok=False,
                signal_kind=signal.signal_kind(),
                signal_id=signal.signal_id(),
                phase=signal.envelope.phase,
                dispatched=0,
                failures=0,
                dropped=True,
                reason="bus_disabled",
                integrity_ok=True,
            )

        depth = self._thread_depth()
        if depth >= self.config.max_emit_depth:
            with self._lock:
                self._dropped_total += 1
            return SignalEmitResult(
                ok=False,
                signal_kind=signal.signal_kind(),
                signal_id=signal.signal_id(),
                phase=signal.envelope.phase,
                dispatched=0,
                failures=0,
                dropped=True,
                reason="emit_depth_exceeded",
                integrity_ok=True,
            )

        ok_size, size_reason = self._signal_sizes_ok(signal)
        if not ok_size:
            with self._lock:
                self._dropped_total += 1
            return SignalEmitResult(
                ok=False,
                signal_kind=signal.signal_kind(),
                signal_id=signal.signal_id(),
                phase=signal.envelope.phase,
                dispatched=0,
                failures=0,
                dropped=True,
                reason=size_reason,
                integrity_ok=True,
            )

        if self._mark_duplicate_scope(self._duplicate_scope(signal)):
            with self._lock:
                self._dropped_total += 1
            return SignalEmitResult(
                ok=False,
                signal_kind=signal.signal_kind(),
                signal_id=signal.signal_id(),
                phase=signal.envelope.phase,
                dispatched=0,
                failures=0,
                dropped=True,
                reason="duplicate_suppressed",
                integrity_ok=True,
            )

        integrity = _integrity_report_for(signal) if self.config.validate_integrity else SignalIntegrityReport(ok=True)
        if self.config.validate_integrity and (not integrity.ok) and self.config.reject_on_integrity_error:
            with self._lock:
                self._dropped_total += 1
                self._integrity_reject_total += 1
            return SignalEmitResult(
                ok=False,
                signal_kind=signal.signal_kind(),
                signal_id=signal.signal_id(),
                phase=signal.envelope.phase,
                dispatched=0,
                failures=0,
                dropped=True,
                reason="integrity_rejected",
                integrity_ok=False,
                integrity_errors=tuple(x.code for x in integrity.errors),
                normalization_warnings=signal.normalization_warnings(),
                compatibility_warnings=signal.compatibility_warnings(),
            )

        regs = self._matching_regs(signal)
        dispatched = 0
        failures = 0
        required_sink_failed = False
        delivery_status: Dict[str, Any] = {}

        self._push_depth()
        try:
            for reg in regs:
                ok, why, timeout_hit = self._dispatch_one(reg, signal)
                delivery_status[reg.sink_name] = {"ok": ok, "reason": why, "timeout": timeout_hit}
                if ok:
                    dispatched += 1
                    if why == "timeout_degraded":
                        failures += 1
                        if reg.criticality == "required":
                            required_sink_failed = True
                else:
                    failures += 1
                    if reg.criticality == "required":
                        required_sink_failed = True
                        if self.config.fail_fast_on_required_sink_failure:
                            break
        finally:
            self._pop_depth()

        with self._lock:
            self._emitted_total += 1
            if failures or required_sink_failed or (self.config.validate_integrity and not integrity.ok):
                self._emitted_failures += 1

        ok = (failures == 0) and (not required_sink_failed) and (integrity.ok or not self.config.reject_on_integrity_error)
        reason = None
        if required_sink_failed:
            reason = "required_sink_failure"
        elif failures > 0:
            reason = "sink_failure"
        elif self.config.validate_integrity and not integrity.ok:
            reason = "integrity_warning"

        queued = any(v.get("reason") == "queued" for v in delivery_status.values())
        return SignalEmitResult(
            ok=ok,
            signal_kind=signal.signal_kind(),
            signal_id=signal.signal_id(),
            phase=signal.envelope.phase,
            dispatched=dispatched,
            failures=failures,
            dropped=False,
            reason=reason,
            required_sink_failed=required_sink_failed,
            integrity_ok=integrity.ok,
            integrity_errors=tuple(x.code for x in integrity.errors),
            normalization_warnings=signal.normalization_warnings(),
            compatibility_warnings=signal.compatibility_warnings(),
            queued_to_outbox=queued,
            delivery_status=MappingProxyType(dict(delivery_status)),
        )

    def emit_many(
        self,
        signals: Iterable[GovernedSignal],
        *,
        batch_id: Optional[str] = None,
        stop_on_first_required_failure: bool = False,
    ) -> Tuple[SignalEmitResult, ...]:
        out: List[SignalEmitResult] = []
        count = 0
        for sig in signals:
            if count >= self.config.max_batch_items:
                break
            res = self.emit(sig)
            out.append(res)
            count += 1
            if stop_on_first_required_failure and res.required_sink_failed:
                break
        return tuple(out)

    # ------------------------------------------------------------------
    # Views / compaction
    # ------------------------------------------------------------------

    def public_config_view(self) -> SignalBusPublicConfigView:
        with self._lock:
            typed_count = sum(len(v) for v in self._typed.values())
            global_count = len(self._global)
        return SignalBusPublicConfigView(
            enabled=self.config.enabled,
            profile=self.config.profile,
            on_sink_error=self.config.on_sink_error,
            activation_id=self.config.activation_id,
            cfg_fp=self.config.cfg_fp,
            bundle_version=self.config.bundle_version,
            service_name=self.config.service_name,
            consistency_level=self.config.consistency_level,
            delivery_semantics=self.config.delivery_semantics,
            suppress_duplicate_signal_ids=self.config.suppress_duplicate_signal_ids,
            duplicate_ttl_s=self.config.duplicate_ttl_s,
            validate_integrity=self.config.validate_integrity,
            reject_on_integrity_error=self.config.reject_on_integrity_error,
            required_sinks_satisfied=self._required_sinks_satisfied(),
            registered_global_sinks=global_count,
            registered_typed_sinks=typed_count,
        )

    def diagnostics_view(self) -> SignalBusDiagnosticsView:
        sink_diags: List[SinkDiagnostics] = []
        with self._lock:
            for regs in self._typed.values():
                for reg in regs:
                    sink_diags.append(reg.diagnostics())
            for reg in self._global:
                sink_diags.append(reg.diagnostics())
            emitted_total = self._emitted_total
            emitted_failures = self._emitted_failures
            dropped_total = self._dropped_total
            dup_rej = self._duplicate_registration_rejected_total
            int_rej = self._integrity_reject_total
            brk = self._breaker_open_total
            dup_size = len(self._duplicate_cache)
            dup_bytes = self._duplicate_cache_bytes
            typed_count = sum(len(v) for v in self._typed.values())
            global_count = len(self._global)
            type_count = len(self._typed)
        sink_diags.sort(key=lambda x: (x.global_sink, x.priority, x.sink_name, x.registration_id))
        return SignalBusDiagnosticsView(
            enabled=self.config.enabled,
            profile=self.config.profile,
            on_sink_error=self.config.on_sink_error,
            activation_id=self.config.activation_id,
            cfg_fp=self.config.cfg_fp,
            bundle_version=self.config.bundle_version,
            service_name=self.config.service_name,
            consistency_level=self.config.consistency_level,
            delivery_semantics=self.config.delivery_semantics,
            registered_type_count=type_count,
            global_sink_count=global_count,
            typed_sink_count=typed_count,
            suppress_duplicate_signal_ids=self.config.suppress_duplicate_signal_ids,
            duplicate_cache_size=dup_size,
            duplicate_cache_bytes=dup_bytes,
            emitted_total=emitted_total,
            emitted_failures=emitted_failures,
            dropped_total=dropped_total,
            duplicate_registration_rejected_total=dup_rej,
            integrity_reject_total=int_rej,
            breaker_open_total=brk,
            sinks=tuple(sink_diags),
        )

    def compact(self) -> Dict[str, Any]:
        res = self._compact_duplicate_cache()
        res["ts_unix_ns"] = now_unix_ns()
        return res


# =============================================================================
# Default provider
# =============================================================================


class DefaultSignalProvider:
    def __init__(
        self,
        *,
        bus: Optional[SignalBus] = None,
        config: Optional[SignalBusConfig] = None,
        register_logging_sink: bool = False,
        logger_obj: Optional[logging.Logger] = None,
    ) -> None:
        self._bus = bus or SignalBus(config=config)
        if register_logging_sink:
            self._bus.register_global_sink(LoggingSink(logger_obj=logger_obj), sink_name="LoggingSink")

    @property
    def bus(self) -> SignalBus:
        return self._bus

    def emit(self, signal: GovernedSignal) -> SignalEmitResult:
        return self._bus.emit(signal)

    def emit_many(
        self,
        signals: Iterable[GovernedSignal],
        *,
        batch_id: Optional[str] = None,
        stop_on_first_required_failure: bool = False,
    ) -> Tuple[SignalEmitResult, ...]:
        return self._bus.emit_many(signals, batch_id=batch_id, stop_on_first_required_failure=stop_on_first_required_failure)

    def public_config_view(self) -> SignalBusPublicConfigView:
        return self._bus.public_config_view()

    def diagnostics_view(self) -> SignalBusDiagnosticsView:
        return self._bus.diagnostics_view()

    def compact(self) -> Dict[str, Any]:
        return self._bus.compact()

    # backward-compatible typed helpers
    def emit_risk_decision(self, signal: RiskDecisionSignal) -> SignalEmitResult:
        return self.emit(signal)

    def emit_security_decision(self, signal: SecurityDecisionSignal) -> SignalEmitResult:
        return self.emit(signal)

    def emit_route_decision(self, signal: RouteDecisionSignal) -> SignalEmitResult:
        return self.emit(signal)

    def emit_receipt(self, signal: ReceiptSignal) -> SignalEmitResult:
        return self.emit(signal)

    def emit_receipt_prepared(self, signal: ReceiptPreparedSignal) -> SignalEmitResult:
        return self.emit(signal)

    def emit_receipt_committed(self, signal: ReceiptCommittedSignal) -> SignalEmitResult:
        return self.emit(signal)

    def emit_ledger_prepared(self, signal: LedgerPreparedSignal) -> SignalEmitResult:
        return self.emit(signal)

    def emit_ledger_committed(self, signal: LedgerCommittedSignal) -> SignalEmitResult:
        return self.emit(signal)

    def emit_outbox_queued(self, signal: OutboxQueuedSignal) -> SignalEmitResult:
        return self.emit(signal)

    def emit_outbox_flushed(self, signal: OutboxFlushedSignal) -> SignalEmitResult:
        return self.emit(signal)

    def emit_pq_health(self, signal: PQHealthSignal) -> SignalEmitResult:
        return self.emit(signal)

    def emit_bundle_lifecycle(self, signal: BundleLifecycleSignal) -> SignalEmitResult:
        return self.emit(signal)


# backward compatibility alias
DefaultLLMSignals = DefaultSignalProvider


# =============================================================================
# Builders
# =============================================================================


def make_contract_version(
    *,
    schema_version: str = _SCHEMA,
    signal_version: str = _SIGNAL_VERSION,
    compatibility_epoch: str = _COMPATIBILITY_EPOCH,
    canonicalization_version: str = _CANONICALIZATION_VERSION,
    field_deprecation_policy: str = _DEFAULT_DEPRECATION_POLICY,
    producer_capabilities: Sequence[str] = (),
    consumer_capabilities: Sequence[str] = (),
) -> SignalContractVersion:
    return SignalContractVersion(
        schema_version=schema_version,
        signal_version=signal_version,
        compatibility_epoch=compatibility_epoch,
        canonicalization_version=canonicalization_version,
        field_deprecation_policy=field_deprecation_policy,
        producer_capabilities=tuple(producer_capabilities),
        consumer_capabilities=tuple(consumer_capabilities),
    )


def make_producer_bundle(
    *,
    producer_name: str = "tcd.signals",
    producer_instance_id: Optional[str] = None,
    producer_cfg_fp: Optional[str] = None,
    producer_bundle_version: Optional[int] = None,
    producer_mode: str = "normal",
    using_last_known_good: Optional[bool] = None,
    build_id: Optional[str] = None,
    image_digest: Optional[str] = None,
) -> ProducerBundle:
    return ProducerBundle(
        producer_name=producer_name,
        producer_instance_id=producer_instance_id,
        producer_cfg_fp=producer_cfg_fp,
        producer_bundle_version=producer_bundle_version,
        producer_mode=producer_mode,
        using_last_known_good=using_last_known_good,
        build_id=build_id,
        image_digest=image_digest,
    )


def make_producer_activation(
    *,
    producer_activation_id: Optional[str] = None,
    patch_id: Optional[str] = None,
    change_ticket_id: Optional[str] = None,
    activated_by_hash: Optional[str] = None,
    approved_by_hashes: Sequence[str] = (),
    approval_count: int = 0,
) -> ProducerActivation:
    return ProducerActivation(
        producer_activation_id=producer_activation_id,
        patch_id=patch_id,
        change_ticket_id=change_ticket_id,
        activated_by_hash=activated_by_hash,
        approved_by_hashes=tuple(approved_by_hashes),
        approval_count=approval_count,
    )


def make_evidence_identity(
    *,
    event_id: Optional[str] = None,
    event_id_kind: str = "event",
    decision_id: Optional[str] = None,
    decision_id_kind: str = "decision",
    route_plan_id: Optional[str] = None,
    route_id: Optional[str] = None,
    route_id_kind: str = "plan",
    config_fingerprint: Optional[str] = None,
    bundle_version: Optional[int] = None,
    policy_ref: Optional[str] = None,
    policyset_ref: Optional[str] = None,
    policy_digest: Optional[str] = None,
    state_domain_id: Optional[str] = None,
    activation_id: Optional[str] = None,
    patch_id: Optional[str] = None,
    change_ticket_id: Optional[str] = None,
    controller_mode: Optional[str] = None,
    statistical_guarantee_scope: Optional[str] = None,
    adapter_registry_fp: Optional[str] = None,
    selected_source: Optional[str] = None,
    state_revision: Optional[int] = None,
    identity_status: Optional[str] = None,
    audit_ref: Optional[str] = None,
    receipt_ref: Optional[str] = None,
) -> EvidenceIdentity:
    return EvidenceIdentity(
        event_id=event_id,
        event_id_kind=event_id_kind,
        decision_id=decision_id,
        decision_id_kind=decision_id_kind,
        route_plan_id=route_plan_id,
        route_id=route_id,
        route_id_kind=route_id_kind,
        config_fingerprint=config_fingerprint,
        bundle_version=bundle_version,
        policy_ref=policy_ref,
        policyset_ref=policyset_ref,
        policy_digest=policy_digest,
        state_domain_id=state_domain_id,
        activation_id=activation_id,
        patch_id=patch_id,
        change_ticket_id=change_ticket_id,
        controller_mode=controller_mode,
        statistical_guarantee_scope=statistical_guarantee_scope,
        adapter_registry_fp=adapter_registry_fp,
        selected_source=selected_source,
        state_revision=state_revision,
        identity_status=identity_status,
        audit_ref=audit_ref,
        receipt_ref=receipt_ref,
    )


def make_artifact_refs(
    *,
    audit_ref: Optional[str] = None,
    receipt_ref: Optional[str] = None,
    ledger_ref: Optional[str] = None,
    attestation_ref: Optional[str] = None,
    event_digest: Optional[str] = None,
    body_digest: Optional[str] = None,
    payload_digest: Optional[str] = None,
    prepare_ref: Optional[str] = None,
    commit_ref: Optional[str] = None,
    ledger_stage: Optional[str] = None,
    outbox_ref: Optional[str] = None,
    outbox_status: Optional[str] = None,
    outbox_dedupe_key: Optional[str] = None,
    delivery_attempts: Optional[int] = None,
    chain_id: Optional[str] = None,
    chain_head: Optional[str] = None,
    produced_by: Sequence[str] = (),
    provenance_path_digest: Optional[str] = None,
) -> ArtifactRefs:
    return ArtifactRefs(
        audit_ref=audit_ref,
        receipt_ref=receipt_ref,
        ledger_ref=ledger_ref,
        attestation_ref=attestation_ref,
        event_digest=event_digest,
        body_digest=body_digest,
        payload_digest=payload_digest,
        prepare_ref=prepare_ref,
        commit_ref=commit_ref,
        ledger_stage=ledger_stage,
        outbox_ref=outbox_ref,
        outbox_status=outbox_status,
        outbox_dedupe_key=outbox_dedupe_key,
        delivery_attempts=delivery_attempts,
        chain_id=chain_id,
        chain_head=chain_head,
        produced_by=tuple(produced_by),
        provenance_path_digest=provenance_path_digest,
    )


def make_signal_envelope(
    *,
    signal_kind: str,
    phase: str = "evaluated",
    source_classification: str = "data_plane_observed",
    signal_id: Optional[str] = None,
    ts_unix_ns: Optional[int] = None,
    ts_monotonic_ns: Optional[int] = None,
    source: str = "tcd",
    profile: str = "PROD",
    instance_id: Optional[str] = None,
    node_id: Optional[str] = None,
    config_fingerprint: Optional[str] = None,
    bundle_version: Optional[int] = None,
    contract: Optional[SignalContractVersion] = None,
    producer_bundle: Optional[ProducerBundle] = None,
    producer_activation: Optional[ProducerActivation] = None,
    evidence: Optional[EvidenceIdentity] = None,
    artifacts: Optional[ArtifactRefs] = None,
    degraded_reason_codes: Sequence[str] = (),
    tags: Sequence[str] = (),
) -> SignalEnvelope:
    return SignalEnvelope(
        contract=contract or SignalContractVersion(),
        producer_bundle=producer_bundle or ProducerBundle(),
        producer_activation=producer_activation or ProducerActivation(),
        signal_kind=signal_kind,
        phase=phase,
        source_classification=source_classification,
        signal_id=signal_id,
        ts_unix_ns=ts_unix_ns,
        ts_monotonic_ns=ts_monotonic_ns,
        source=source,
        profile=profile,
        instance_id=instance_id,
        node_id=node_id,
        config_fingerprint=config_fingerprint,
        bundle_version=bundle_version,
        evidence=evidence or EvidenceIdentity(),
        artifacts=artifacts or ArtifactRefs(),
        degraded_reason_codes=tuple(degraded_reason_codes),
        tags=tuple(tags),
    )


def make_subject_context(
    tenant: str,
    user: str,
    session: str,
    *,
    subject_hash: Optional[str] = None,
    tenant_class: Optional[str] = None,
    tenant_partition: Optional[str] = None,
    subject_scope: Optional[str] = None,
    identity_status: str = "ok",
) -> SubjectContext:
    sh = subject_hash or _subject_hash(tenant or "tenant0", user or "user0", session or "sess0")
    return SubjectContext(
        subject_hash=sh,
        tenant=tenant,
        user=user,
        session=session,
        tenant_class=tenant_class,
        tenant_partition=tenant_partition,
        subject_scope=subject_scope,
        identity_status=identity_status,
    )


def make_model_context(
    model_id: str,
    gpu_id: str,
    task: str = "chat",
    lang: str = "en",
    model_version: Optional[str] = None,
    model_config_hash: Optional[str] = None,
    region: Optional[str] = None,
    runtime_env: Optional[str] = None,
) -> ModelContext:
    return ModelContext(
        model_id=model_id,
        gpu_id=gpu_id,
        task=task,
        lang=lang,
        model_version=model_version,
        model_config_hash=model_config_hash,
        region=region,
        runtime_env=runtime_env,
    )


def make_security_context(
    *,
    asserted_trust_zone: Optional[str] = None,
    asserted_route_profile: Optional[str] = None,
    asserted_threat_kind: Optional[str] = None,
    asserted_pq_required: Optional[bool] = None,
    effective_trust_zone: str = "internet",
    effective_route_profile: str = "inference",
    effective_threat_kind: Optional[str] = None,
    effective_pq_required: bool = False,
    pq_ok: Optional[bool] = None,
    policy_ref: Optional[str] = None,
    policyset_ref: Optional[str] = None,
    policy_digest: Optional[str] = None,
    build_id: Optional[str] = None,
    image_digest: Optional[str] = None,
    compliance_tags: Sequence[str] = (),
    override_requested: bool = False,
    override_applied: bool = False,
    override_reason_code: Optional[str] = None,
    override_actor: Optional[str] = None,
    supply_chain_risk: Optional[str] = None,
    supply_chain_source: Optional[str] = None,
    signal_source: Optional[str] = None,
    signal_trust_mode: Optional[str] = None,
    signal_signed: Optional[bool] = None,
    signal_signer_kid: Optional[str] = None,
    signal_cfg_fp: Optional[str] = None,
    signal_policy_ref: Optional[str] = None,
    signal_freshness_ms: Optional[int] = None,
    signal_replay_checked: Optional[bool] = None,
    derived_reason_codes: Sequence[str] = (),
) -> SecurityContext:
    return SecurityContext(
        asserted_trust_zone=asserted_trust_zone,
        asserted_route_profile=asserted_route_profile,
        asserted_threat_kind=asserted_threat_kind,
        asserted_pq_required=asserted_pq_required,
        effective_trust_zone=effective_trust_zone,
        effective_route_profile=effective_route_profile,
        effective_threat_kind=effective_threat_kind,
        effective_pq_required=effective_pq_required,
        pq_ok=pq_ok,
        policy_ref=policy_ref,
        policyset_ref=policyset_ref,
        policy_digest=policy_digest,
        build_id=build_id,
        image_digest=image_digest,
        compliance_tags=tuple(compliance_tags),
        override_requested=override_requested,
        override_applied=override_applied,
        override_reason_code=override_reason_code,
        override_actor=override_actor,
        supply_chain_risk=supply_chain_risk,
        supply_chain_source=supply_chain_source,
        signal_source=signal_source,
        signal_trust_mode=signal_trust_mode,
        signal_signed=signal_signed,
        signal_signer_kid=signal_signer_kid,
        signal_cfg_fp=signal_cfg_fp,
        signal_policy_ref=signal_policy_ref,
        signal_freshness_ms=signal_freshness_ms,
        signal_replay_checked=signal_replay_checked,
        derived_reason_codes=tuple(derived_reason_codes),
    )


def make_stream_context(
    *,
    raw_stream_id: Optional[str] = None,
    canonical_stream_id: Optional[str] = None,
    stream_hash: Optional[str] = None,
    raw_exposed: bool = False,
    schema_ref: str = "stream.v1",
    av_label: Optional[str] = None,
    av_policyset_ref: Optional[str] = None,
    e_process_id: Optional[str] = None,
    state_domain_id: Optional[str] = None,
    adapter_registry_fp: Optional[str] = None,
    selected_source: Optional[str] = None,
    controller_mode: Optional[str] = None,
    statistical_guarantee_scope: Optional[str] = None,
    decision_mode: Optional[str] = None,
    state_revision: Optional[int] = None,
    identity_status: Optional[str] = None,
) -> StreamContext:
    return StreamContext(
        raw_stream_id=raw_stream_id,
        canonical_stream_id=canonical_stream_id,
        stream_hash=stream_hash,
        raw_exposed=raw_exposed,
        schema_ref=schema_ref,
        av_label=av_label,
        av_policyset_ref=av_policyset_ref,
        e_process_id=e_process_id,
        state_domain_id=state_domain_id,
        adapter_registry_fp=adapter_registry_fp,
        selected_source=selected_source,
        controller_mode=controller_mode,
        statistical_guarantee_scope=statistical_guarantee_scope,
        decision_mode=decision_mode,
        state_revision=state_revision,
        identity_status=identity_status,
    )