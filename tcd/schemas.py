下面这版直接把 schemas.py 对齐到了新版 routing.py 的 Route 契约、risk_av.py 的 eprocess.v3 输出、api_v1.py 当前 DiagnoseOut 归一化路径，以及 attest.py 的 receipt 返回键。 ￼  ￼  ￼  ￼

from __future__ import annotations

import json
import math
import re
import unicodedata
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator


__all__ = [
    "ReceiptView",
    "EProcessControllerView",
    "EProcessStreamView",
    "EProcessProcessView",
    "EProcessStatsView",
    "EProcessValidityView",
    "EProcessStateView",
    "RouteView",
    "DiagnoseIn",
    "DiagnoseOut",
]

# =============================================================================
# Low-level hardening helpers
# =============================================================================

_ASCII_CTRL_RE = re.compile(r"[\x00-\x1F\x7F]")
_SAFE_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9_.:\-]{0,63}$")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:\-]{0,127}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-@#/+=]{0,255}$")
_SAFE_REASON_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,127}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_ALGO_DIGEST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,31}:[A-Za-z0-9._:+/\-=]{8,1024}$")
_BASE64ISH_RE = re.compile(r"^[A-Za-z0-9+/=_:\-.,]{1,8192}$")
_TAGLIKE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,255}$")
_PATHLIKE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-/#]{0,255}$")

_ALLOWED_INPUT_KINDS = frozenset(
    {"prompt", "completion", "log", "meta", "request", "response", "other"}
)
_ALLOWED_SAFETY_TIERS = frozenset({"normal", "elevated", "strict"})
_ALLOWED_ROUTER_MODES = frozenset(
    {"normal", "last_known_good", "fail_closed", "disabled", "degraded"}
)
_ALLOWED_ACTIONS = frozenset(
    {"allow", "degrade", "block", "log_only", "none", "advisory", "degraded_allow", "degraded_block"}
)
_ALLOWED_REQUIRED_ACTIONS = frozenset({"allow", "degrade", "block"})
_ALLOWED_ENFORCEMENT = frozenset({"advisory", "must_enforce", "fail_closed"})
_ALLOWED_SIGNAL_TRUST = frozenset({"trusted", "advisory", "untrusted"})
_ALLOWED_STATE_SCOPE = frozenset({"local_best_effort", "node_persistent", "cluster_eventual", "cluster_strong"})
_ALLOWED_TRUST_ZONES = frozenset(
    {"internet", "internal", "partner", "admin", "ops", "unknown", "__config_error__"}
)
_ALLOWED_ROUTE_PROFILES = frozenset(
    {"inference", "batch", "admin", "control", "metrics", "health", "unknown"}
)
_ALLOWED_RISK_LABELS = frozenset({"low", "normal", "elevated", "high", "critical", "unknown"})
_ALLOWED_REASON_CODES = frozenset(
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
    }
)

_FORBIDDEN_META_KEY_TOKENS = {
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

_DEFAULT_CONTEXT_KEYS = (
    "tenant",
    "user",
    "session",
    "model_id",
    "gpu_id",
    "task",
    "lang",
    "env",
    "trust_zone",
    "route",
    "data_class",
    "workload",
    "jurisdiction",
    "regulation",
    "client_app",
    "access_channel",
)

_MAX_INPUT_BYTES = 262_144
_MAX_BODY_BYTES = 262_144
_MAX_SIG_BYTES = 16_384
_MAX_VERIFY_KEY_LEN = 8_192
_MAX_LIST_ITEMS = 128
_MAX_JSON_NODES = 2_048
_MAX_JSON_ITEMS = 256
_MAX_JSON_DEPTH = 8
_MAX_JSON_STR_TOTAL = 64_000
_MAX_JSON_STR_LEN = 2_048


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
    s = v[:max_len]
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


def _safe_label(v: Any, *, default: str) -> str:
    s = _strip_unsafe_text(v, max_len=64).lower()
    if not s or not _SAFE_LABEL_RE.fullmatch(s):
        return default
    return s


def _safe_name(v: Any, *, default: str) -> str:
    s = _strip_unsafe_text(v, max_len=128)
    if not s or not _SAFE_NAME_RE.fullmatch(s):
        return default
    return s


def _safe_id(v: Any, *, default: Optional[str], max_len: int = 256) -> Optional[str]:
    s = _strip_unsafe_text(v, max_len=max_len)
    if not s or not _SAFE_ID_RE.fullmatch(s):
        return default
    return s


def _safe_blob_string(v: Any, *, max_len: int) -> Optional[str]:
    if not isinstance(v, str):
        return None
    s = _strip_unsafe_text(v, max_len=max_len)
    return s if s else None


def _safe_reason_code(v: Any, *, default: Optional[str] = None) -> Optional[str]:
    if not isinstance(v, str):
        return default
    s = _strip_unsafe_text(v, max_len=128).strip()
    if not s or not _SAFE_REASON_RE.fullmatch(s):
        return default
    return s


def _looks_like_digestish(s: str) -> bool:
    if not s:
        return False
    if _HEX_RE.fullmatch(s) and 16 <= len(s) <= 1024:
        return True
    if _ALGO_DIGEST_RE.fullmatch(s):
        return True
    if s.startswith("0x") and _HEX_RE.fullmatch(s[2:]) and 16 <= len(s[2:]) <= 1024:
        return True
    return False


def _coerce_float(v: Any) -> Optional[float]:
    if type(v) is bool:
        return None
    if isinstance(v, (int, float)):
        try:
            x = float(v)
        except Exception:
            return None
        return x if math.isfinite(x) else None
    if type(v) is str:
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
    if type(v) is str:
        s = v.strip()
        if not s or len(s) > 128:
            return None
        if s.startswith(("+", "-")):
            sign = s[0]
            digits = s[1:]
        else:
            sign = ""
            digits = s
        if not digits.isdigit():
            return None
        try:
            return int(sign + digits, 10)
        except Exception:
            return None
    return None


def _coerce_bool(v: Any) -> Optional[bool]:
    if type(v) is bool:
        return v
    if type(v) is int:
        if v == 0:
            return False
        if v == 1:
            return True
        return None
    if type(v) is str:
        s = v.strip().lower()
        if s in {"1", "true", "yes", "y", "on"}:
            return True
        if s in {"0", "false", "no", "n", "off"}:
            return False
    return None


def _finite_float(v: Any, *, default: Optional[float] = None) -> Optional[float]:
    x = _coerce_float(v)
    return x if x is not None else default


def _finite_int(v: Any, *, default: Optional[int] = None) -> Optional[int]:
    x = _coerce_int(v)
    return x if x is not None else default


def _clamp_float(v: Any, *, default: float, lo: float, hi: float) -> float:
    x = _coerce_float(v)
    if x is None:
        return float(default)
    if x < lo:
        return float(lo)
    if x > hi:
        return float(hi)
    return float(x)


def _clamp_int(v: Any, *, default: int, lo: int, hi: int) -> int:
    x = _coerce_int(v)
    if x is None:
        return int(default)
    if x < lo:
        return int(lo)
    if x > hi:
        return int(hi)
    return int(x)


def _bounded_json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _normalize_str_list(
    values: Any,
    *,
    max_items: int = _MAX_LIST_ITEMS,
    max_len: int = 128,
    label_mode: bool = False,
    allow_reason_codes: bool = False,
) -> List[str]:
    if values is None:
        return []
    if isinstance(values, str):
        seq: Sequence[Any] = [values]
    elif isinstance(values, (list, tuple, set, frozenset)):
        seq = list(values)
    else:
        return []

    out: List[str] = []
    seen = set()
    for item in seq:
        if len(out) >= max_items:
            break
        if allow_reason_codes:
            s = _safe_reason_code(item, default=None)
        elif label_mode:
            s = _safe_label(item, default="")
        else:
            s = _strip_unsafe_text(item, max_len=max_len)
        if not s:
            continue
        if allow_reason_codes and s not in _ALLOWED_REASON_CODES:
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s[:max_len])
    return out


class _JsonBudget:
    __slots__ = ("max_nodes", "max_items", "max_depth", "max_str_total", "nodes", "str_used")

    def __init__(self, *, max_nodes: int, max_items: int, max_depth: int, max_str_total: int):
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


def _key_tokenize(k: str) -> Tuple[str, ...]:
    s = _strip_unsafe_text(k, max_len=128)
    if not s:
        return tuple()
    out: List[str] = []
    cur: List[str] = []
    prev_is_alnum = False
    for ch in s:
        if ch.isalnum():
            if prev_is_alnum:
                cur.append(ch.lower())
            else:
                if cur:
                    out.append("".join(cur))
                cur = [ch.lower()]
                prev_is_alnum = True
        else:
            if cur:
                out.append("".join(cur))
                cur = []
            prev_is_alnum = False
    if cur:
        out.append("".join(cur))
    fused = "".join(out)
    if fused and fused not in out:
        out.append(fused)
    return tuple(x for x in out if x)


def _json_sanitize(
    obj: Any,
    *,
    budget: _JsonBudget,
    depth: int,
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
        s = _strip_unsafe_text(obj, max_len=_MAX_JSON_STR_LEN)
        if len(s) > _MAX_JSON_STR_LEN:
            s = s[:_MAX_JSON_STR_LEN]
        if not budget.take_str(len(s)):
            return "[truncated]"
        return s
    if t in (bytes, bytearray):
        return f"[bytes:{len(obj)}]"

    if depth >= budget.max_depth:
        return "[truncated-depth]"

    if t is dict:
        out: Dict[str, Any] = {}
        n = 0
        for k, v in obj.items():
            if n >= budget.max_items:
                out["_tcd_truncated"] = True
                break
            if type(k) is not str:
                continue
            kk = _safe_id(k, default=None, max_len=128)
            if kk is None:
                continue
            toks = _key_tokenize(kk)
            if any(tok in _FORBIDDEN_META_KEY_TOKENS for tok in toks):
                continue
            out[kk] = _json_sanitize(v, budget=budget, depth=depth + 1)
            n += 1
        return out

    if t in (list, tuple):
        out_list = []
        for i, item in enumerate(obj):
            if i >= budget.max_items:
                out_list.append("[truncated]")
                break
            out_list.append(_json_sanitize(item, budget=budget, depth=depth + 1))
        return out_list

    return f"[type:{t.__name__}]"


def _safe_json_mapping(v: Any) -> Dict[str, Any]:
    if not isinstance(v, Mapping):
        return {}
    budget = _JsonBudget(
        max_nodes=_MAX_JSON_NODES,
        max_items=_MAX_JSON_ITEMS,
        max_depth=_MAX_JSON_DEPTH,
        max_str_total=_MAX_JSON_STR_TOTAL,
    )
    out = _json_sanitize(dict(v), budget=budget, depth=0)
    return out if isinstance(out, dict) else {}


def _safe_json_any(v: Any) -> Any:
    budget = _JsonBudget(
        max_nodes=_MAX_JSON_NODES,
        max_items=_MAX_JSON_ITEMS,
        max_depth=_MAX_JSON_DEPTH,
        max_str_total=_MAX_JSON_STR_TOTAL,
    )
    return _json_sanitize(v, budget=budget, depth=0)


def _coerce_canonical_json_string(v: Any, *, max_bytes: int) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, str):
        s = _strip_unsafe_text(v, max_len=max_bytes)
        if not s:
            return None
        if len(s.encode("utf-8", errors="ignore")) > max_bytes:
            s = s.encode("utf-8", errors="ignore")[:max_bytes].decode("utf-8", errors="ignore")
        return s
    if isinstance(v, (dict, list, tuple)):
        safe = _safe_json_any(v)
        try:
            s = _bounded_json_dumps(safe)
        except Exception:
            return None
        if len(s.encode("utf-8", errors="ignore")) > max_bytes:
            return None
        return s
    return None


# =============================================================================
# Base model
# =============================================================================


class _SchemaModel(BaseModel):
    model_config = ConfigDict(
        extra="ignore",
        from_attributes=True,
        populate_by_name=True,
        validate_assignment=True,
        str_strip_whitespace=True,
    )


# =============================================================================
# Receipt view
# =============================================================================


class ReceiptView(_SchemaModel):
    """
    Receipt / attestation view aligned to:
      - attestor.issue() output (`receipt`, `receipt_body`, `receipt_sig`, `verify_key`)
      - receipt-first control-plane payloads
      - ledger/admin receipt metadata
    """

    schema: Optional[str] = None
    schema_version: Optional[int] = None
    receipt_kind: Optional[str] = None
    event_type: Optional[str] = None

    head: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("head", "receipt", "receipt_head"),
    )
    body: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("body", "receipt_body", "receiptBody"),
    )
    sig: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("sig", "receipt_sig", "receiptSig"),
    )
    verify_key: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("verify_key", "verifyKey"),
    )

    receipt_secondary: Optional[str] = None
    receipt_sig_secondary: Optional[str] = None
    receipt_integrity: Optional[str] = None

    sig_scheme: Optional[str] = None
    sig_alg: Optional[str] = None
    sig_chain_id: Optional[str] = None
    sig_key_id: Optional[str] = None
    verify_key_fp: Optional[str] = None
    verify_key_id: Optional[str] = None

    pq_required: Optional[bool] = None
    pq_ok: Optional[bool] = None

    store_backend: Optional[str] = None
    store_id: Optional[int] = None

    ts: Optional[float] = None
    ts_ns: Optional[int] = None
    ts_unix_ns: Optional[int] = None

    build_id: Optional[str] = None
    image_digest: Optional[str] = None
    attestation_id: Optional[str] = None
    env_fingerprint: Optional[str] = None

    policy_ref: Optional[str] = None
    policyset_ref: Optional[str] = None
    policy_digest: Optional[str] = None
    cfg_fp: Optional[str] = None
    config_hash: Optional[str] = None

    stream_hash: Optional[str] = None
    state_domain_id: Optional[str] = None
    adapter_registry_fp: Optional[str] = None

    event_id: Optional[str] = None
    decision_id: Optional[str] = None
    route_plan_id: Optional[str] = None
    route_id: Optional[str] = None
    audit_ref: Optional[str] = None
    receipt_ref: Optional[str] = None

    chain_namespace: Optional[str] = None
    chain_id: Optional[str] = None
    chain_seq: Optional[int] = None
    prev_head_hex: Optional[str] = None

    action: Optional[str] = None
    reason: Optional[str] = None
    selected_source: Optional[str] = None
    statistical_guarantee_scope: Optional[str] = None
    trigger: Optional[bool] = None

    meta: Dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "schema",
        "receipt_kind",
        "event_type",
        "sig_scheme",
        "sig_alg",
        "sig_chain_id",
        "sig_key_id",
        "verify_key_fp",
        "verify_key_id",
        "policy_ref",
        "policyset_ref",
        "state_domain_id",
        "adapter_registry_fp",
        "event_id",
        "decision_id",
        "route_plan_id",
        "route_id",
        "audit_ref",
        "receipt_ref",
        "chain_namespace",
        "chain_id",
        "selected_source",
        "statistical_guarantee_scope",
        mode="before",
    )
    @classmethod
    def _v_idish(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = _safe_id(v, default=None, max_len=256)
        if s is not None:
            return s
        return _safe_blob_string(v, max_len=512)

    @field_validator("head", "receipt_secondary", "policy_digest", "cfg_fp", "config_hash", "prev_head_hex", mode="before")
    @classmethod
    def _v_digestish(cls, v: Any) -> Optional[str]:
        s = _safe_blob_string(v, max_len=1024)
        if s is None:
            return None
        if _looks_like_digestish(s):
            return s
        return _safe_id(s, default=None, max_len=256) or s[:256]

    @field_validator("body", mode="before")
    @classmethod
    def _v_body(cls, v: Any) -> Optional[str]:
        return _coerce_canonical_json_string(v, max_bytes=_MAX_BODY_BYTES)

    @field_validator("sig", "receipt_sig_secondary", mode="before")
    @classmethod
    def _v_sig(cls, v: Any) -> Optional[str]:
        s = _safe_blob_string(v, max_len=_MAX_SIG_BYTES)
        if s is None:
            return None
        return s if _BASE64ISH_RE.fullmatch(s) or len(s) <= _MAX_SIG_BYTES else s[:_MAX_SIG_BYTES]

    @field_validator("verify_key", mode="before")
    @classmethod
    def _v_verify_key(cls, v: Any) -> Optional[str]:
        return _safe_blob_string(v, max_len=_MAX_VERIFY_KEY_LEN)

    @field_validator("build_id", "image_digest", "attestation_id", "env_fingerprint", mode="before")
    @classmethod
    def _v_artifactish(cls, v: Any) -> Optional[str]:
        return _safe_blob_string(v, max_len=512)

    @field_validator("action", mode="before")
    @classmethod
    def _v_action(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = _safe_label(v, default="")
        return s or _safe_reason_code(v, default=None)

    @field_validator("reason", mode="before")
    @classmethod
    def _v_reason(cls, v: Any) -> Optional[str]:
        return _safe_blob_string(v, max_len=512)

    @field_validator("pq_required", "pq_ok", "trigger", mode="before")
    @classmethod
    def _v_boolish(cls, v: Any) -> Optional[bool]:
        if v is None:
            return None
        return _coerce_bool(v)

    @field_validator("schema_version", "store_id", "chain_seq", mode="before")
    @classmethod
    def _v_intish(cls, v: Any) -> Optional[int]:
        return _finite_int(v, default=None)

    @field_validator("ts_ns", "ts_unix_ns", mode="before")
    @classmethod
    def _v_ns(cls, v: Any) -> Optional[int]:
        x = _finite_int(v, default=None)
        if x is None:
            return None
        return max(0, x)

    @field_validator("ts", mode="before")
    @classmethod
    def _v_ts(cls, v: Any) -> Optional[float]:
        x = _finite_float(v, default=None)
        if x is None:
            return None
        return max(0.0, x)

    @field_validator("meta", mode="before")
    @classmethod
    def _v_meta(cls, v: Any) -> Dict[str, Any]:
        return _safe_json_mapping(v)

    @model_validator(mode="after")
    def _sync_fields(self) -> "ReceiptView":
        if self.ts is None and self.ts_unix_ns is not None:
            self.ts = float(self.ts_unix_ns) / 1_000_000_000.0
        if self.ts_unix_ns is None and self.ts is not None:
            self.ts_unix_ns = int(self.ts * 1_000_000_000.0)
        return self


# =============================================================================
# E-process view
# =============================================================================


class EProcessControllerView(_SchemaModel):
    name: Optional[str] = None
    version: Optional[str] = None
    instance_id: Optional[str] = None
    profile: Optional[str] = None
    label: Optional[str] = None
    policy_ref: Optional[str] = None
    policyset_ref: Optional[str] = None
    cfg_fp: Optional[str] = None
    config_fingerprint: Optional[str] = None
    bundle_version: Optional[int] = None
    state_domain_id: Optional[str] = None
    adapter_registry_fp: Optional[str] = None
    ts_monotonic_ns: Optional[int] = None
    ts_unix_ns: Optional[int] = None
    enabled: Optional[bool] = None
    controller_mode: Optional[str] = None
    state_scope: Optional[str] = None

    @field_validator(
        "name",
        "version",
        "instance_id",
        "profile",
        "label",
        "policy_ref",
        "policyset_ref",
        "cfg_fp",
        "config_fingerprint",
        "state_domain_id",
        "adapter_registry_fp",
        "controller_mode",
        mode="before",
    )
    @classmethod
    def _v_text(cls, v: Any) -> Optional[str]:
        return _safe_blob_string(v, max_len=256)

    @field_validator("bundle_version", "ts_monotonic_ns", "ts_unix_ns", mode="before")
    @classmethod
    def _v_ints(cls, v: Any) -> Optional[int]:
        x = _finite_int(v, default=None)
        if x is None:
            return None
        return max(0, x)

    @field_validator("enabled", mode="before")
    @classmethod
    def _v_bool(cls, v: Any) -> Optional[bool]:
        if v is None:
            return None
        return _coerce_bool(v)

    @field_validator("state_scope", mode="before")
    @classmethod
    def _v_scope(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = _safe_label(v, default="")
        return s if s in _ALLOWED_STATE_SCOPE else (s or None)


class EProcessStreamView(_SchemaModel):
    id: Optional[str] = None
    hash: Optional[str] = None
    identity_status: Optional[str] = None
    schema_ref: Optional[str] = None
    trust_zone: Optional[str] = None
    route_profile: Optional[str] = None
    subject_hash: Optional[str] = None
    threat_tags: List[str] = Field(default_factory=list)

    @field_validator("id", "hash", "identity_status", "schema_ref", "subject_hash", mode="before")
    @classmethod
    def _v_text(cls, v: Any) -> Optional[str]:
        return _safe_blob_string(v, max_len=256)

    @field_validator("trust_zone", mode="before")
    @classmethod
    def _v_zone(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = _safe_label(v, default="")
        return s if s in _ALLOWED_TRUST_ZONES else (s or None)

    @field_validator("route_profile", mode="before")
    @classmethod
    def _v_profile(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = _safe_label(v, default="")
        return s if s in _ALLOWED_ROUTE_PROFILES else (s or None)

    @field_validator("threat_tags", mode="before")
    @classmethod
    def _v_tags(cls, v: Any) -> List[str]:
        return _normalize_str_list(v, max_items=32, max_len=64, label_mode=True)


class EProcessProcessView(_SchemaModel):
    strict_e_value: Optional[float] = None
    controller_e_value: Optional[float] = None
    selected_source: Optional[str] = None
    selected_log_e: Optional[float] = None
    selected_e_value: Optional[float] = None

    alpha_base: Optional[float] = None
    alpha_wealth: Optional[float] = None
    alpha_wealth_init: Optional[float] = None
    alpha_wealth_cap: Optional[float] = None
    alpha_spend_per_decision: Optional[float] = None
    alpha_reward_per_safe_decision: Optional[float] = None

    threshold_log_e: Optional[float] = None
    threshold_clear_log_e: Optional[float] = None
    threshold_e_value: Optional[float] = None

    trigger: Optional[bool] = None
    decisions: Optional[int] = None
    triggers: Optional[int] = None
    last_trigger_step: Optional[int] = None

    strict_log_e: Optional[float] = None
    controller_log_e: Optional[float] = None
    log_e: Optional[float] = None
    e_value: Optional[float] = None

    frozen: Optional[bool] = None
    active: Optional[bool] = None
    exhausted_step: Optional[int] = None
    guarantee_scope: Optional[str] = None
    selected_reason: Optional[str] = None

    @field_validator(
        "strict_e_value",
        "controller_e_value",
        "selected_log_e",
        "selected_e_value",
        "alpha_base",
        "alpha_wealth",
        "alpha_wealth_init",
        "alpha_wealth_cap",
        "alpha_spend_per_decision",
        "alpha_reward_per_safe_decision",
        "threshold_log_e",
        "threshold_clear_log_e",
        "threshold_e_value",
        "strict_log_e",
        "controller_log_e",
        "log_e",
        "e_value",
        mode="before",
    )
    @classmethod
    def _v_floatish(cls, v: Any) -> Optional[float]:
        return _finite_float(v, default=None)

    @field_validator("decisions", "triggers", "last_trigger_step", "exhausted_step", mode="before")
    @classmethod
    def _v_intish(cls, v: Any) -> Optional[int]:
        x = _finite_int(v, default=None)
        if x is None:
            return None
        return max(0, x)

    @field_validator("trigger", "frozen", "active", mode="before")
    @classmethod
    def _v_boolish(cls, v: Any) -> Optional[bool]:
        if v is None:
            return None
        return _coerce_bool(v)

    @field_validator("selected_source", "guarantee_scope", "selected_reason", mode="before")
    @classmethod
    def _v_text(cls, v: Any) -> Optional[str]:
        return _safe_blob_string(v, max_len=128)


class EProcessStatsView(_SchemaModel):
    direct_p_steps: Optional[int] = None
    calibrated_p_steps: Optional[int] = None
    heuristic_p_steps: Optional[int] = None
    neutral_steps: Optional[int] = None

    min_p_value: Optional[float] = None
    min_p_value_step: Optional[int] = None
    max_score: Optional[float] = None
    max_score_step: Optional[int] = None

    ewma_score: Optional[float] = None
    ewma_neglogp: Optional[float] = None
    fisher_stat: Optional[float] = None
    fisher_df: Optional[int] = None

    small_p_count_05: Optional[int] = None
    small_p_count_01: Optional[int] = None
    small_p_count_001: Optional[int] = None

    last_p_value: Optional[float] = None
    last_p_source: Optional[str] = None
    last_score: Optional[float] = None
    last_update_mono_ns: Optional[int] = None
    last_update_unix_ns: Optional[int] = None

    history: Optional[Dict[str, Any]] = None

    @field_validator(
        "min_p_value",
        "max_score",
        "ewma_score",
        "ewma_neglogp",
        "fisher_stat",
        "last_p_value",
        "last_score",
        mode="before",
    )
    @classmethod
    def _v_floatish(cls, v: Any) -> Optional[float]:
        return _finite_float(v, default=None)

    @field_validator(
        "direct_p_steps",
        "calibrated_p_steps",
        "heuristic_p_steps",
        "neutral_steps",
        "min_p_value_step",
        "max_score_step",
        "fisher_df",
        "small_p_count_05",
        "small_p_count_01",
        "small_p_count_001",
        "last_update_mono_ns",
        "last_update_unix_ns",
        mode="before",
    )
    @classmethod
    def _v_intish(cls, v: Any) -> Optional[int]:
        x = _finite_int(v, default=None)
        if x is None:
            return None
        return max(0, x)

    @field_validator("last_p_source", mode="before")
    @classmethod
    def _v_text(cls, v: Any) -> Optional[str]:
        return _safe_blob_string(v, max_len=128)

    @field_validator("history", mode="before")
    @classmethod
    def _v_history(cls, v: Any) -> Optional[Dict[str, Any]]:
        if v is None:
            return None
        return _safe_json_mapping(v)


class EProcessValidityView(_SchemaModel):
    strict_process_valid_if_direct_p_values_are_valid: Optional[bool] = None
    controller_process_is_statistical_controller_not_pure_e_process: Optional[bool] = None
    decision_source: Optional[str] = None
    selected_source: Optional[str] = None
    p_source_this_step: Optional[str] = None
    has_direct_p_history: Optional[bool] = None
    has_heuristic_history: Optional[bool] = None
    has_calibrated_history: Optional[bool] = None
    statistical_guarantee_scope: Optional[str] = None

    @field_validator(
        "strict_process_valid_if_direct_p_values_are_valid",
        "controller_process_is_statistical_controller_not_pure_e_process",
        "has_direct_p_history",
        "has_heuristic_history",
        "has_calibrated_history",
        mode="before",
    )
    @classmethod
    def _v_boolish(cls, v: Any) -> Optional[bool]:
        if v is None:
            return None
        return _coerce_bool(v)

    @field_validator("decision_source", "selected_source", "p_source_this_step", "statistical_guarantee_scope", mode="before")
    @classmethod
    def _v_text(cls, v: Any) -> Optional[str]:
        return _safe_blob_string(v, max_len=128)


class EProcessStateView(_SchemaModel):
    schema: Optional[str] = None
    controller: EProcessControllerView = Field(default_factory=EProcessControllerView)
    stream: EProcessStreamView = Field(default_factory=EProcessStreamView)
    state_revision: Optional[int] = None
    process: EProcessProcessView = Field(default_factory=EProcessProcessView)
    stats: EProcessStatsView = Field(default_factory=EProcessStatsView)
    validity: EProcessValidityView = Field(default_factory=EProcessValidityView)

    @field_validator("schema", mode="before")
    @classmethod
    def _v_schema(cls, v: Any) -> Optional[str]:
        return _safe_blob_string(v, max_len=64)

    @field_validator("state_revision", mode="before")
    @classmethod
    def _v_state_revision(cls, v: Any) -> Optional[int]:
        x = _finite_int(v, default=None)
        if x is None:
            return None
        return max(0, x)


# =============================================================================
# Route view
# =============================================================================


class RouteView(_SchemaModel):
    """
    Public view of routing decisions.

    This model is forward-compatible with:
      - legacy compact routing objects
      - upgraded route contracts carrying plan/event IDs, enforcement mode,
        signal provenance, and receipt/ledger requirements.
    """

    schema: Optional[str] = None
    router: Optional[str] = None
    version: Optional[str] = None

    instance_id: Optional[str] = None
    activation_id: Optional[str] = None
    config_fingerprint: Optional[str] = None
    bundle_version: Optional[int] = None
    bundle_updated_at_unix_ns: Optional[int] = None

    policy_ref: Optional[str] = None
    policyset_ref: Optional[str] = None
    patch_id: Optional[str] = None
    change_ticket_id: Optional[str] = None
    activated_by: Optional[str] = None

    router_mode: Optional[str] = None
    route_id_kind: Optional[str] = None
    route_plan_id: Optional[str] = None
    route_id: Optional[str] = None
    decision_id: Optional[str] = None
    decision_seq: Optional[int] = None
    decision_ts_unix_ns: Optional[int] = None
    decision_ts_mono_ns: Optional[int] = None

    safety_tier: Optional[str] = None
    required_action: Optional[str] = None
    action_hint: Optional[str] = None
    enforcement_mode: Optional[str] = None

    temperature: float = 1.0
    top_p: float = 1.0
    decoder: str = "default"
    max_tokens: Optional[int] = None
    latency_hint: str = "normal"

    tool_calls_allowed: Optional[bool] = None
    retrieval_allowed: Optional[bool] = None
    streaming_allowed: Optional[bool] = None
    external_calls_allowed: Optional[bool] = None
    response_policy: Optional[str] = None
    receipt_required: Optional[bool] = None
    ledger_required: Optional[bool] = None
    attestation_required: Optional[bool] = None

    trust_zone: str = "internet"
    route_profile: str = "inference"
    risk_label: str = "normal"
    score: float = 0.0
    decision_fail: bool = False
    e_triggered: bool = False
    pq_unhealthy: bool = False
    av_label: Optional[str] = None
    av_trigger: Optional[bool] = None
    threat_tags: List[str] = Field(default_factory=list)
    controller_mode: Optional[str] = None
    guarantee_scope: Optional[str] = None

    signal_source: Optional[str] = None
    signal_trust_mode: Optional[str] = None
    signal_signed: Optional[bool] = None
    signal_signer_kid: Optional[str] = None
    signal_cfg_fp: Optional[str] = None
    signal_policy_ref: Optional[str] = None
    signal_freshness_ms: Optional[int] = None
    signal_replay_checked: Optional[bool] = None
    signal_digest: Optional[str] = None
    context_digest: Optional[str] = None

    primary_reason_code: Optional[str] = None
    reason_codes: List[str] = Field(default_factory=list)
    degraded_reason_codes: List[str] = Field(default_factory=list)
    reason: str = ""
    tags: List[str] = Field(default_factory=list)

    # backward-compatible extras kept explicit
    pq_required: Optional[bool] = None
    pq_ok: Optional[bool] = None
    override_flags: List[str] = Field(default_factory=list)

    @field_validator(
        "schema",
        "router",
        "version",
        "instance_id",
        "activation_id",
        "config_fingerprint",
        "policy_ref",
        "policyset_ref",
        "patch_id",
        "change_ticket_id",
        "activated_by",
        "route_id_kind",
        "route_plan_id",
        "route_id",
        "decision_id",
        "decoder",
        "response_policy",
        "controller_mode",
        "guarantee_scope",
        "signal_source",
        "signal_signer_kid",
        "signal_cfg_fp",
        "signal_policy_ref",
        "signal_digest",
        "context_digest",
        mode="before",
    )
    @classmethod
    def _v_text(cls, v: Any) -> Optional[str]:
        return _safe_blob_string(v, max_len=256)

    @field_validator("router_mode", mode="before")
    @classmethod
    def _v_router_mode(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = _safe_label(v, default="")
        return s if s in _ALLOWED_ROUTER_MODES else (s or None)

    @field_validator("safety_tier", mode="before")
    @classmethod
    def _v_tier(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = _safe_label(v, default="")
        return s if s in _ALLOWED_SAFETY_TIERS else (s or None)

    @field_validator("required_action", "action_hint", mode="before")
    @classmethod
    def _v_action(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = _safe_label(v, default="")
        return s if s in _ALLOWED_REQUIRED_ACTIONS or s in _ALLOWED_ACTIONS else (s or None)

    @field_validator("enforcement_mode", mode="before")
    @classmethod
    def _v_enforcement(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = _safe_label(v, default="")
        return s if s in _ALLOWED_ENFORCEMENT else (s or None)

    @field_validator("latency_hint", mode="before")
    @classmethod
    def _v_latency(cls, v: Any) -> str:
        s = _safe_label(v, default="normal")
        return s if s in _ALLOWED_LATENCY_HINTS else "normal"

    @field_validator("temperature", mode="before")
    @classmethod
    def _v_temperature(cls, v: Any) -> float:
        return _clamp_float(v, default=1.0, lo=0.0, hi=10.0)

    @field_validator("top_p", mode="before")
    @classmethod
    def _v_top_p(cls, v: Any) -> float:
        return _clamp_float(v, default=1.0, lo=0.0, hi=1.0)

    @field_validator("max_tokens", "bundle_version", "decision_seq", "decision_ts_unix_ns", "decision_ts_mono_ns", "bundle_updated_at_unix_ns", "signal_freshness_ms", mode="before")
    @classmethod
    def _v_ints(cls, v: Any) -> Optional[int]:
        x = _finite_int(v, default=None)
        if x is None:
            return None
        return max(0, x)

    @field_validator("score", mode="before")
    @classmethod
    def _v_score(cls, v: Any) -> float:
        return _clamp_float(v, default=0.0, lo=0.0, hi=1.0)

    @field_validator("decision_fail", "e_triggered", "pq_unhealthy", "av_trigger", "tool_calls_allowed", "retrieval_allowed", "streaming_allowed", "external_calls_allowed", "receipt_required", "ledger_required", "attestation_required", "pq_required", "pq_ok", "signal_signed", "signal_replay_checked", mode="before")
    @classmethod
    def _v_boolish(cls, v: Any) -> Optional[bool]:
        if v is None:
            return None
        return _coerce_bool(v)

    @field_validator("trust_zone", mode="before")
    @classmethod
    def _v_zone(cls, v: Any) -> str:
        s = _safe_label(v, default="internet")
        return s if s in _ALLOWED_TRUST_ZONES else "unknown"

    @field_validator("route_profile", mode="before")
    @classmethod
    def _v_profile(cls, v: Any) -> str:
        s = _safe_label(v, default="inference")
        return s if s in _ALLOWED_ROUTE_PROFILES else "unknown"

    @field_validator("risk_label", mode="before")
    @classmethod
    def _v_risk_label(cls, v: Any) -> str:
        s = _safe_label(v, default="normal")
        return s if s in _ALLOWED_RISK_LABELS else "unknown"

    @field_validator("av_label", mode="before")
    @classmethod
    def _v_av_label(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        return _safe_label(v, default="") or None

    @field_validator("signal_trust_mode", mode="before")
    @classmethod
    def _v_signal_trust(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = _safe_label(v, default="")
        return s if s in _ALLOWED_SIGNAL_TRUST else (s or None)

    @field_validator("primary_reason_code", mode="before")
    @classmethod
    def _v_primary_reason(cls, v: Any) -> Optional[str]:
        s = _safe_reason_code(v, default=None)
        if s is None:
            return None
        return s if s in _ALLOWED_REASON_CODES else s

    @field_validator("reason_codes", "degraded_reason_codes", mode="before")
    @classmethod
    def _v_reason_codes(cls, v: Any) -> List[str]:
        return _normalize_str_list(v, max_items=64, max_len=64, allow_reason_codes=True)

    @field_validator("threat_tags", "tags", "override_flags", mode="before")
    @classmethod
    def _v_tag_lists(cls, v: Any) -> List[str]:
        return _normalize_str_list(v, max_items=64, max_len=128, label_mode=False)

    @field_validator("reason", mode="before")
    @classmethod
    def _v_reason_text(cls, v: Any) -> str:
        return _safe_blob_string(v, max_len=1_024) or ""

    @model_validator(mode="after")
    def _sync(self) -> "RouteView":
        if self.route_id is None and self.route_plan_id is not None:
            self.route_id = self.route_plan_id
        if self.primary_reason_code is None and self.reason_codes:
            self.primary_reason_code = self.reason_codes[0]
        if not self.reason and self.reason_codes:
            self.reason = ";".join(self.reason_codes + self.degraded_reason_codes)
        return self


# =============================================================================
# Diagnose input / output
# =============================================================================


class DiagnoseIn(_SchemaModel):
    """
    Input schema for /v1/diagnose and adjacent control-plane entrypoints.

    This keeps the public contract compact, but makes all free-form surfaces
    bounded and sanitized so it can safely sit at the API boundary.
    """

    input: str = Field(..., description="Text or payload to check")
    input_kind: str = Field("prompt", description="Coarse input kind")
    subject: Optional[str] = None
    subject_hash: Optional[str] = None
    tenant_id: Optional[str] = None
    request_id: Optional[str] = None
    trace_id: Optional[str] = None

    trust_zone: Optional[str] = None
    route_profile: Optional[str] = None

    tags: List[str] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)

    threat_hint: Optional[str] = None
    threat_confidence: Optional[float] = None
    pq_required: Optional[bool] = None

    build_id: Optional[str] = None
    image_digest: Optional[str] = None
    compliance_tags: List[str] = Field(default_factory=list)

    @field_validator("input", mode="before")
    @classmethod
    def _v_input(cls, v: Any) -> str:
        s = _coerce_canonical_json_string(v, max_bytes=_MAX_INPUT_BYTES)
        if s is None or not s:
            return ""
        return s

    @field_validator("input_kind", mode="before")
    @classmethod
    def _v_input_kind(cls, v: Any) -> str:
        s = _safe_label(v, default="prompt")
        return s if s in _ALLOWED_INPUT_KINDS else "other"

    @field_validator("subject", "subject_hash", "tenant_id", "request_id", "trace_id", "build_id", "image_digest", mode="before")
    @classmethod
    def _v_ids(cls, v: Any) -> Optional[str]:
        s = _safe_id(v, default=None, max_len=256)
        if s is not None:
            return s
        return _safe_blob_string(v, max_len=256)

    @field_validator("trust_zone", mode="before")
    @classmethod
    def _v_zone(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = _safe_label(v, default="")
        return s if s in _ALLOWED_TRUST_ZONES else (s or None)

    @field_validator("route_profile", mode="before")
    @classmethod
    def _v_profile(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = _safe_label(v, default="")
        return s if s in _ALLOWED_ROUTE_PROFILES else (s or None)

    @field_validator("tags", "compliance_tags", mode="before")
    @classmethod
    def _v_tags(cls, v: Any) -> List[str]:
        return _normalize_str_list(v, max_items=64, max_len=64, label_mode=True)

    @field_validator("threat_hint", mode="before")
    @classmethod
    def _v_threat_hint(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        return _safe_label(v, default="") or None

    @field_validator("threat_confidence", mode="before")
    @classmethod
    def _v_threat_conf(cls, v: Any) -> Optional[float]:
        if v is None:
            return None
        return _clamp_float(v, default=0.0, lo=0.0, hi=1.0)

    @field_validator("pq_required", mode="before")
    @classmethod
    def _v_pq_req(cls, v: Any) -> Optional[bool]:
        if v is None:
            return None
        return _coerce_bool(v)

    @field_validator("context", mode="before")
    @classmethod
    def _v_context(cls, v: Any) -> Dict[str, Any]:
        return _safe_json_mapping(v)

    @model_validator(mode="after")
    def _validate_required(self) -> "DiagnoseIn":
        if not self.input:
            raise ValueError("input must be a non-empty bounded string")
        return self


class DiagnoseOut(_SchemaModel):
    """
    Output schema for diagnostic / safety evaluation.

    This model stays backward-compatible with the current `api_v1` normalize path,
    while also accepting richer receipt/route/eprocess objects from the upgraded
    routing and always-valid controller layers.
    """

    verdict: bool = False
    decision: str = "allow"
    cause: str = ""
    action: str = "none"

    score: float = 0.0
    threshold: float = 0.0

    budget_remaining: float = 0.0
    step: int = 0
    e_value: float = 1.0
    alpha_alloc: float = 0.0
    alpha_spent: float = 0.0

    components: Dict[str, Any] = Field(default_factory=dict)

    e_state: Optional[EProcessStateView] = None
    route: Optional[RouteView] = None

    trust_zone: Optional[str] = None
    route_profile: Optional[str] = None
    threat_kind: Optional[str] = None
    threat_confidence: Optional[float] = None
    pq_required: bool = False
    pq_ok: Optional[bool] = None
    policy_ref: Optional[str] = None
    policyset_ref: Optional[str] = None

    config_fingerprint: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("config_fingerprint", "cfg_fp"),
    )
    policy_digest: Optional[str] = None
    state_domain_id: Optional[str] = None
    bundle_version: Optional[int] = None
    decision_id: Optional[str] = None
    route_plan_id: Optional[str] = None
    event_id: Optional[str] = None
    audit_ref: Optional[str] = None
    receipt_ref: Optional[str] = None
    controller_mode: Optional[str] = None
    statistical_guarantee_scope: Optional[str] = None

    security: Dict[str, Any] = Field(default_factory=dict)

    receipt: Optional[ReceiptView] = None
    receipt_body: Optional[str] = None
    receipt_sig: Optional[str] = None
    verify_key: Optional[str] = None

    @field_validator("decision", "action", mode="before")
    @classmethod
    def _v_decisionish(cls, v: Any) -> str:
        s = _safe_label(v, default="")
        if s in _ALLOWED_ACTIONS:
            return s
        return _safe_blob_string(v, max_len=64) or "none"

    @field_validator("cause", mode="before")
    @classmethod
    def _v_cause(cls, v: Any) -> str:
        return _safe_blob_string(v, max_len=512) or ""

    @field_validator("score", "threshold", "budget_remaining", "e_value", "alpha_alloc", "alpha_spent", mode="before")
    @classmethod
    def _v_floats(cls, v: Any, info) -> float:
        default = 0.0
        if info.field_name == "e_value":
            default = 1.0
        x = _finite_float(v, default=default)
        return float(x if x is not None else default)

    @field_validator("threat_confidence", mode="before")
    @classmethod
    def _v_threat_conf(cls, v: Any) -> Optional[float]:
        if v is None:
            return None
        return _clamp_float(v, default=0.0, lo=0.0, hi=1.0)

    @field_validator("step", "bundle_version", mode="before")
    @classmethod
    def _v_step(cls, v: Any) -> Optional[int]:
        x = _finite_int(v, default=None)
        if x is None:
            return None
        return max(0, x)

    @field_validator("verdict", "pq_required", "pq_ok", mode="before")
    @classmethod
    def _v_boolish(cls, v: Any):
        if v is None:
            return None
        return _coerce_bool(v)

    @field_validator(
        "policy_ref",
        "policyset_ref",
        "config_fingerprint",
        "policy_digest",
        "state_domain_id",
        "decision_id",
        "route_plan_id",
        "event_id",
        "audit_ref",
        "receipt_ref",
        "controller_mode",
        "statistical_guarantee_scope",
        mode="before",
    )
    @classmethod
    def _v_ids(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        return _safe_blob_string(v, max_len=256)

    @field_validator("trust_zone", mode="before")
    @classmethod
    def _v_zone(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = _safe_label(v, default="")
        return s if s in _ALLOWED_TRUST_ZONES else (s or None)

    @field_validator("route_profile", mode="before")
    @classmethod
    def _v_profile(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = _safe_label(v, default="")
        return s if s in _ALLOWED_ROUTE_PROFILES else (s or None)

    @field_validator("threat_kind", mode="before")
    @classmethod
    def _v_threat(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        return _safe_label(v, default="") or None

    @field_validator("components", "security", mode="before")
    @classmethod
    def _v_maps(cls, v: Any) -> Dict[str, Any]:
        return _safe_json_mapping(v)

    @field_validator("receipt_body", mode="before")
    @classmethod
    def _v_receipt_body(cls, v: Any) -> Optional[str]:
        return _coerce_canonical_json_string(v, max_bytes=_MAX_BODY_BYTES)

    @field_validator("receipt_sig", mode="before")
    @classmethod
    def _v_receipt_sig(cls, v: Any) -> Optional[str]:
        return _safe_blob_string(v, max_len=_MAX_SIG_BYTES)

    @field_validator("verify_key", mode="before")
    @classmethod
    def _v_verify_key(cls, v: Any) -> Optional[str]:
        return _safe_blob_string(v, max_len=_MAX_VERIFY_KEY_LEN)

    @field_validator("receipt", mode="before")
    @classmethod
    def _v_receipt_obj(cls, v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, str):
            return {"head": v}
        return v

    @model_validator(mode="after")
    def _harmonize(self) -> "DiagnoseOut":
        # Build receipt from legacy raw fields if needed
        if self.receipt is None and any([self.receipt_body, self.receipt_sig, self.verify_key]):
            self.receipt = ReceiptView(
                head=None,
                body=self.receipt_body,
                sig=self.receipt_sig,
                verify_key=self.verify_key,
                policy_ref=self.policy_ref,
                policyset_ref=self.policyset_ref,
                cfg_fp=self.config_fingerprint,
                decision_id=self.decision_id,
                route_plan_id=self.route_plan_id,
                event_id=self.event_id,
                audit_ref=self.audit_ref,
                receipt_ref=self.receipt_ref,
                state_domain_id=self.state_domain_id,
            )

        # Backfill legacy raw fields from structured receipt
        if self.receipt is not None:
            if self.receipt_body is None:
                self.receipt_body = self.receipt.body
            if self.receipt_sig is None:
                self.receipt_sig = self.receipt.sig
            if self.verify_key is None:
                self.verify_key = self.receipt.verify_key
            if self.policy_ref is None:
                self.policy_ref = self.receipt.policy_ref
            if self.policyset_ref is None:
                self.policyset_ref = self.receipt.policyset_ref
            if self.config_fingerprint is None:
                self.config_fingerprint = self.receipt.cfg_fp
            if self.state_domain_id is None:
                self.state_domain_id = self.receipt.state_domain_id
            if self.decision_id is None:
                self.decision_id = self.receipt.decision_id
            if self.route_plan_id is None:
                self.route_plan_id = self.receipt.route_plan_id
            if self.event_id is None:
                self.event_id = self.receipt.event_id
            if self.audit_ref is None:
                self.audit_ref = self.receipt.audit_ref
            if self.receipt_ref is None:
                self.receipt_ref = self.receipt.receipt_ref

        # Backfill route-derived top-level fields
        if self.route is not None:
            if self.trust_zone is None:
                self.trust_zone = self.route.trust_zone
            if self.route_profile is None:
                self.route_profile = self.route.route_profile
            if self.policy_ref is None:
                self.policy_ref = self.route.policy_ref
            if self.policyset_ref is None:
                self.policyset_ref = self.route.policyset_ref
            if self.config_fingerprint is None:
                self.config_fingerprint = self.route.config_fingerprint
            if self.bundle_version is None:
                self.bundle_version = self.route.bundle_version
            if self.decision_id is None:
                self.decision_id = self.route.decision_id
            if self.route_plan_id is None:
                self.route_plan_id = self.route.route_plan_id
            if self.controller_mode is None:
                self.controller_mode = self.route.controller_mode
            if self.statistical_guarantee_scope is None:
                self.statistical_guarantee_scope = self.route.guarantee_scope
            if self.pq_required is False and self.route.receipt_required is not None:
                # do not over-promise; only set if explicit route-level pq flag exists
                if self.route.pq_required is not None:
                    self.pq_required = bool(self.route.pq_required)
            if self.pq_ok is None and self.route.pq_ok is not None:
                self.pq_ok = self.route.pq_ok

        # Backfill from e_state controller block
        if self.e_state is not None:
            ctrl = self.e_state.controller
            if self.policyset_ref is None:
                self.policyset_ref = ctrl.policyset_ref
            if self.config_fingerprint is None:
                self.config_fingerprint = ctrl.cfg_fp or ctrl.config_fingerprint
            if self.bundle_version is None:
                self.bundle_version = ctrl.bundle_version
            if self.state_domain_id is None:
                self.state_domain_id = ctrl.state_domain_id
            if self.controller_mode is None:
                self.controller_mode = ctrl.controller_mode

        # Backfill from security dict
        if self.security:
            if self.policy_ref is None:
                pr = _safe_blob_string(self.security.get("policy_ref"), max_len=256)
                if pr:
                    self.policy_ref = pr
            if self.policyset_ref is None:
                ps = _safe_blob_string(self.security.get("policyset_ref"), max_len=256)
                if ps:
                    self.policyset_ref = ps
            if self.config_fingerprint is None:
                fp = _safe_blob_string(self.security.get("cfg_fp"), max_len=256)
                if fp:
                    self.config_fingerprint = fp
            if self.state_domain_id is None:
                sd = _safe_blob_string(self.security.get("state_domain_id"), max_len=256)
                if sd:
                    self.state_domain_id = sd
            if self.statistical_guarantee_scope is None:
                gs = _safe_blob_string(self.security.get("statistical_guarantee_scope"), max_len=128)
                if gs:
                    self.statistical_guarantee_scope = gs

        return self