# FILE: tcd/otel_exporter.py
from __future__ import annotations

"""
TCD OpenTelemetry-style Exporter (L7+ hardened)

This revision upgrades the previous "L7 hardened" exporter by closing
remaining logic holes and improving auditability, performance, usability
and extensibility without introducing new attack surface.

Key upgrades:
  - Fingerprint now covers policy VALUES and resource VALUES (bounded digests),
    plus derived behavior knobs via bundle fingerprint.
  - LOCKDOWN no longer forbids resource attributes by default; resource and
    user attributes are sanitized in separate channels and only then merged.
  - Async worker no longer captures stale bundle/sink; sink hot-reload is effective.
  - Deep sanitization now redacts/drops sensitive NESTED keys, not only top-level keys.
  - Canonical key handling prevents case/space/variant spoofing and dimension pollution.
  - Deterministic sampling/hashing key material supports hex/base64; strict profiles
    can require strong keys without mandating external hash_fn.
  - flush()/shutdown(mode=...) with bounded semantics; drop counters are thread-safe.
  - Avoid str()/repr() on unknown objects in all untrusted paths.
"""

import base64
import hashlib
import hmac
import json
import math
import os
import queue
import random
import re
import sys
import threading
import time
import unicodedata
import uuid
from dataclasses import dataclass, field, fields as dataclass_fields
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple

JsonDict = Dict[str, Any]
SinkFn = Callable[[JsonDict], None]
HashFn = Callable[[str, str], str]

# -----------------------------
# Sanitization helpers
# -----------------------------

_ASCII_CTRL_RE = re.compile(r"[\x00-\x1F\x7F]")

# Secret-token detectors (conservative)
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

# High-entropy heuristic for STRICT redaction (NOT for allowlists)
_ENTROPY_B64URL_RE = re.compile(r"\b[A-Za-z0-9_-]{60,}\b")

_HEX_RE = re.compile(r"^[0-9a-fA-F]{8,256}$")

# Strict key grammar (OTel-friendly)
_SAFE_KEY_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.:-]{0,127}$")

# Reserved internal key prefix to prevent spoofing
_INTERNAL_KEY_PREFIXES = ("_tcd_", "__tcd_", "tcd_meta", "resource")

_FORBIDDEN_KEY_TOKENS = {
    # auth/secrets
    "authorization",
    "auth",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api-key",
    "api_key",
    "access_key",
    "access-key",
    "id_token",
    "bearer",
    "basic",
    "private",
    "privatekey",
    "ssh",
    "jwt",
    # payload/content
    "prompt",
    "completion",
    "body",
    "payload",
    "headers",
    "header",
    "messages",
    "message",
    "content",
    "multipart",
    "form",
}

# Keys where high-entropy strings are usually OK (digests/ids) to avoid over-redaction
_ENTROPY_EXEMPT_TOKENS = {
    "hash",
    "digest",
    "checksum",
    "fingerprint",
    "sha",
    "blake",
    "trace",
    "trace_id",
    "span",
    "span_id",
    "parent_span_id",
    "artifact_hash",
    "model_hash",
    "binary_hash",
    "tokenizer_hash",
    "service.instance.id",
}


def _has_unsafe_unicode(s: str) -> bool:
    for ch in s:
        if ch in ("\u2028", "\u2029"):
            return True
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            return True
    return False


def _strip_unsafe_text(s: str, *, max_len: int) -> str:
    if not s:
        return ""
    if len(s) > max_len:
        s = s[:max_len]

    if s.isascii():
        if _ASCII_CTRL_RE.search(s):
            s = _ASCII_CTRL_RE.sub("", s)
        return s

    if not _ASCII_CTRL_RE.search(s) and not _has_unsafe_unicode(s):
        if any(0x80 <= ord(ch) <= 0x9F for ch in s):
            pass
        else:
            return s

    out = []
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
    return "".join(out)


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


def _finite_float(x: Any) -> Optional[float]:
    if isinstance(x, bool):
        return None
    try:
        v = float(x)
    except Exception:
        return None
    if not math.isfinite(v):
        return None
    return v


def _clamp_float(v: float, lo: float, hi: float) -> float:
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def _clamp_int(v: int, lo: int, hi: int) -> int:
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def _safe_str_only(v: Any, *, max_len: int, default: str = "") -> str:
    if not isinstance(v, str):
        return default
    s = _strip_unsafe_text(v, max_len=max_len).strip()
    return s if s else default


def _tokenize_key(k: str) -> Tuple[str, ...]:
    """
    Tokenize key with camelCase + alpha/digit boundaries to prevent bypass:
      - authorizationToken -> authorization + token
      - idToken -> id + token
      - xAmzSecurityToken -> x + amz + security + token
    """
    s = _strip_unsafe_text(k, max_len=128)
    # camelCase boundary
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", s)
    # alpha-digit boundary
    s = re.sub(r"(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])", " ", s)
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", " ", s).strip()
    if not s:
        return tuple()
    parts = tuple(p for p in s.split(" ") if p)
    fused = "".join(parts)
    if fused and fused not in parts:
        return parts + (fused,)
    return parts


def _key_is_sensitive(key: str, *, redact_set: frozenset[str]) -> bool:
    kl = _strip_unsafe_text(key, max_len=128).lower().strip()
    if not kl:
        return True
    if kl in redact_set:
        return True
    toks = _tokenize_key(kl)
    return any((t in redact_set) or (t in _FORBIDDEN_KEY_TOKENS) for t in toks)


def _entropy_exempt_for_key(key_lower: Optional[str]) -> bool:
    if not key_lower:
        return False
    kl = key_lower.lower()
    if kl in _ENTROPY_EXEMPT_TOKENS:
        return True
    toks = _tokenize_key(kl)
    return any(t in _ENTROPY_EXEMPT_TOKENS for t in toks)


def _is_internal_key(key_lower: str) -> bool:
    return any(key_lower.startswith(p) for p in _INTERNAL_KEY_PREFIXES)


def _canonical_key(
    key: Any,
    *,
    max_len: int = 128,
    force_lower: bool = True,
    require_safe_re: bool = True,
) -> Optional[str]:
    """
    Canonicalize key to prevent spoofing:
      - strip unsafe chars
      - trim
      - lower (optional)
      - enforce safe key grammar (optional)
    """
    if not isinstance(key, str):
        return None
    k = _strip_unsafe_text(key, max_len=max_len).strip()
    if not k:
        return None
    if force_lower:
        k = k.lower()
    if len(k) > max_len:
        k = k[:max_len]
    if require_safe_re and not _SAFE_KEY_RE.fullmatch(k):
        return None
    if _is_internal_key(k):
        return None
    return k


# -----------------------------
# Key material parsing
# -----------------------------


def _parse_key_material(s: Optional[str]) -> Optional[bytes]:
    """
    Parse key material from:
      - hex (even length) or "hex:<...>"
      - base64 / urlsafe base64: "b64:<...>"
      - raw UTF-8: "raw:<...>" (not recommended for strict profiles)
    """
    if not isinstance(s, str):
        return None
    ss = _strip_unsafe_text(s, max_len=4096).strip()
    if not ss:
        return None

    if ss.lower().startswith("hex:"):
        hx = ss[4:].strip()
        if _HEX_RE.fullmatch(hx) and len(hx) % 2 == 0:
            try:
                return bytes.fromhex(hx)
            except Exception:
                return None
        return None

    if ss.lower().startswith("b64:"):
        b = ss[4:].strip()
        try:
            # accept urlsafe and standard base64
            pad = "=" * ((4 - (len(b) % 4)) % 4)
            return base64.urlsafe_b64decode((b + pad).encode("utf-8", errors="ignore"))
        except Exception:
            return None

    if ss.lower().startswith("raw:"):
        raw = ss[4:]
        return raw.encode("utf-8", errors="ignore")

    # Try plain hex
    if _HEX_RE.fullmatch(ss) and len(ss) % 2 == 0:
        try:
            return bytes.fromhex(ss)
        except Exception:
            return None

    # Try base64 as fallback
    try:
        pad = "=" * ((4 - (len(ss) % 4)) % 4)
        return base64.urlsafe_b64decode((ss + pad).encode("utf-8", errors="ignore"))
    except Exception:
        return None


def _kdf(master: bytes, label: str) -> bytes:
    return hmac.new(master, label.encode("utf-8", errors="ignore"), hashlib.sha256).digest()


# -----------------------------
# JSON-safe bounded conversion for attribute VALUES
# -----------------------------


class _AttrBudget:
    __slots__ = ("max_nodes", "max_items", "max_scan", "max_str", "max_str_len", "nodes", "str_used")

    def __init__(self, *, max_nodes: int, max_items: int, max_scan: int, max_str: int, max_str_len: int):
        self.max_nodes = max_nodes
        self.max_items = max_items
        self.max_scan = max_scan
        self.max_str = max_str
        self.max_str_len = max_str_len
        self.nodes = 0
        self.str_used = 0

    def take_node(self) -> bool:
        self.nodes += 1
        return self.nodes <= self.max_nodes

    def take_str(self, n: int) -> bool:
        self.str_used += n
        return self.str_used <= self.max_str


def _jsonable_attr(
    obj: Any,
    *,
    budget: _AttrBudget,
    depth: int,
    max_depth: int,
    redaction_mode: str,  # "none" | "token" | "token_or_entropy"
    redact_set: frozenset[str],
    deep_key_redaction: bool,
    key_ctx_lower: Optional[str],
    redact_behavior: str,  # "placeholder" | "drop"
) -> Any:
    """
    Convert attribute values into JSON-safe, bounded structures.
    - Only supports built-in containers (dict/list/tuple).
    - Never calls __str__/__repr__ on unknown objects.
    - Optionally redacts sensitive NESTED keys.
    """
    if not budget.take_node():
        return "[truncated]"

    if obj is None:
        return None
    if isinstance(obj, bool):
        return bool(obj)
    if isinstance(obj, int) and not isinstance(obj, bool):
        if obj.bit_length() > 256:
            return "[int:oversize]"
        return int(obj)
    if isinstance(obj, float):
        if not math.isfinite(obj):
            return None
        return float(obj)
    if isinstance(obj, str):
        s = _strip_unsafe_text(obj, max_len=budget.max_str_len).strip()
        if redaction_mode != "none":
            if _looks_like_secret_token(s):
                s = "[redacted]"
            elif redaction_mode == "token_or_entropy" and _looks_like_high_entropy(s):
                # Avoid over-redaction for digest-like keys
                if not _entropy_exempt_for_key(key_ctx_lower):
                    s = "[redacted]"
        if len(s) > budget.max_str_len:
            s = s[: budget.max_str_len] + "...[truncated]"
        if not budget.take_str(len(s)):
            return "[truncated]"
        return s
    if isinstance(obj, bytes):
        return f"[bytes:{len(obj)}]"

    if depth >= max_depth:
        return "[truncated-depth]"

    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        scanned = 0
        written = 0
        truncated = False
        for k, v in obj.items():
            scanned += 1
            if scanned > budget.max_scan or written >= budget.max_items:
                truncated = True
                break

            ks = _canonical_key(k, max_len=128, force_lower=True, require_safe_re=False)
            if ks is None:
                continue

            # Deep sensitive key redaction
            if deep_key_redaction and _key_is_sensitive(ks, redact_set=redact_set):
                if redact_behavior == "drop":
                    continue
                out[ks] = "[redacted]"
                written += 1
                continue

            out[ks] = _jsonable_attr(
                v,
                budget=budget,
                depth=depth + 1,
                max_depth=max_depth,
                redaction_mode=redaction_mode,
                redact_set=redact_set,
                deep_key_redaction=deep_key_redaction,
                key_ctx_lower=ks,
                redact_behavior=redact_behavior,
            )
            written += 1

        if truncated:
            out["_tcd_truncated"] = True
        return out

    if isinstance(obj, (list, tuple)):
        out_list = []
        scanned = 0
        for v in obj:
            scanned += 1
            if scanned > budget.max_scan or len(out_list) >= budget.max_items:
                out_list.append("[truncated]")
                break
            out_list.append(
                _jsonable_attr(
                    v,
                    budget=budget,
                    depth=depth + 1,
                    max_depth=max_depth,
                    redaction_mode=redaction_mode,
                    redact_set=redact_set,
                    deep_key_redaction=deep_key_redaction,
                    key_ctx_lower=key_ctx_lower,
                    redact_behavior=redact_behavior,
                )
            )
        return out_list

    return f"[type:{type(obj).__name__}]"


def _stable_str_for_hashing(value: Any, *, max_len: int) -> str:
    """
    Produce a stable string for hashing WITHOUT calling __str__ on unknown objects.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)[:max_len]
    if isinstance(value, float):
        v = float(value)
        if not math.isfinite(v):
            return "null"
        return f"{v:.12g}"[:max_len]
    if isinstance(value, str):
        return _strip_unsafe_text(value, max_len=max_len)[:max_len]
    if isinstance(value, bytes):
        prefix = value[:64].hex()
        return f"bytes:{len(value)}:{prefix}"[:max_len]
    if isinstance(value, (dict, list, tuple)):
        budget = _AttrBudget(max_nodes=512, max_items=64, max_scan=256, max_str=4096, max_str_len=128)
        safe = _jsonable_attr(
            value,
            budget=budget,
            depth=0,
            max_depth=3,
            redaction_mode="none",
            redact_set=frozenset(),
            deep_key_redaction=False,
            key_ctx_lower=None,
            redact_behavior="placeholder",
        )
        try:
            s = json.dumps(safe, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except Exception:
            s = "[unserializable]"
        return s[:max_len]
    return f"type:{type(value).__name__}"[:max_len]


# -----------------------------
# Config
# -----------------------------


def _canonical_profile(p: Any) -> str:
    if not isinstance(p, str):
        return "PROD"
    s = _strip_unsafe_text(p, max_len=32).strip().upper()
    if s in {"DEV", "PROD", "FINREG", "LOCKDOWN"}:
        return s
    return "PROD"


def _coerce_rate(x: Any, default: float) -> float:
    v = _finite_float(x)
    if v is None:
        return default
    return _clamp_float(float(v), 0.0, 1.0)


def _normalize_policy_value(v: Any) -> Optional[str]:
    if not isinstance(v, str):
        return None
    s = _strip_unsafe_text(v, max_len=16).strip().lower()
    if s in {"allow", "hash", "forbid"}:
        return s
    return None


@dataclass
class OtelExporterConfig:
    """
    L7+ exporter config (safe normalization + bounded fingerprint).

    Notes:
      - Strict profiles (FINREG/LOCKDOWN) can require strong key material.
      - Fingerprint is policy-focused and bounded; you can exclude volatile
        resource keys like service.instance.id by default.
    """

    schema_version: int = 3

    enabled: bool = False

    service_name: str = "tcd-safety-sidecar"
    service_version: str = "0.3.0"

    # Resource attributes (authoritative)
    resource_attributes: Dict[str, Any] = field(
        default_factory=lambda: {
            "service.namespace": "tcd",
            "service.instance.id": "auto",  # do NOT randomize during normalize; exporter will fill stable instance id
            "deployment.env": "prod",
            "deployment.region": "unknown",
            "deployment.trust_zone": "default",
            "tcd.version": "0.0.0",
            "crypto.profile": "unspecified",
            "audit.schema.version": "1.0",
        }
    )
    # Resource always authoritative; optionally merge into attributes for backward compat
    include_resource_field: bool = True
    merge_resource_into_attributes: bool = True

    compliance_profile: str = "PROD"
    compliance_profile_version: str = "1.0"

    # Sampling ratios
    sample_metrics: float = 1.0
    sample_traces: float = 1.0
    sample_events: float = 1.0

    deterministic_sampling: bool = False
    deterministic_seed: Optional[str] = None  # sampling key material (hex:/b64:/raw:)

    # Hashing:
    # Prefer hash_fn; otherwise use hash_key_material for internal HMAC hashing.
    hash_fn: Optional[HashFn] = None
    hash_key_material: Optional[str] = None  # hex:/b64:/raw:
    crypto_label_base: str = "otel"
    require_hash_key_for_strict_profiles: bool = True

    # Key redaction list (case-insensitive tokens + exact match)
    redact_keys: Tuple[str, ...] = (
        "authorization",
        "cookie",
        "set-cookie",
        "password",
        "token",
        "secret",
        "api_key",
        "api-key",
        "access_key",
        "access-key",
        "id_token",
        "prompt",
        "completion",
        "body",
        "payload",
        "headers",
    )

    # Exact per-key policy
    attribute_policy: Dict[str, str] = field(
        default_factory=lambda: {
            "request_id": "allow",
            "session_id": "hash",
            "tenant": "hash",
            "tenant_id": "hash",
            "user": "hash",
            "user_id": "hash",
            "client_ip": "hash",
            "ip": "hash",
            "operator_id": "hash",
            "policy_id": "hash",
        }
    )
    # Prefix policy (safer than regex; avoids ReDoS)
    attribute_policy_prefix: Dict[str, str] = field(default_factory=dict)

    # Default policy for unknown keys; if None, derived from profile:
    # DEV/PROD => allow, FINREG => hash, LOCKDOWN => forbid
    default_attribute_policy: Optional[str] = None

    # Deep sensitive-key governance for nested maps/lists
    deep_sanitize_sensitive_keys: Optional[bool] = None  # None => derived from profile

    # If "drop", forbidden/redacted attributes are removed instead of placeholder strings.
    forbid_behavior: Optional[str] = None  # None => derived from profile
    redact_behavior: Optional[str] = None  # None => derived from profile

    # Attribute budgets
    max_attr_len: int = 256
    max_attr_depth: int = 5
    max_attr_items: int = 256
    max_attr_nodes: int = 2048
    max_attr_scan: int = 4096
    max_attr_total_str: int = 64_000

    # Output byte budget (after sanitization)
    output_max_bytes: int = 16_384

    # Top-level string disclosure controls
    include_status_description: bool = True
    include_status_description_strict: bool = False

    # Async sink
    async_enabled: bool = False
    async_queue_maxsize: int = 10_000
    async_drop_on_full: bool = True

    # Default sink
    sink: Optional[SinkFn] = None
    stdout_flush: bool = False

    # Fingerprint controls
    fingerprint_exclude_resource_keys: Tuple[str, ...] = ("service.instance.id",)

    # Strict key strength
    min_key_bytes_strict: int = 16

    # Time sources
    time_fn: Callable[[], float] = time.time
    monotonic_fn: Callable[[], float] = time.perf_counter

    def normalized_copy(self) -> "OtelExporterConfig":
        c = OtelExporterConfig()

        c.schema_version = int(self.schema_version) if isinstance(self.schema_version, int) else 3
        c.enabled = bool(self.enabled)

        c.service_name = _safe_str_only(self.service_name, max_len=128, default="tcd-safety-sidecar")
        c.service_version = _safe_str_only(self.service_version, max_len=64, default="0.0.0")

        c.compliance_profile = _canonical_profile(self.compliance_profile)
        c.compliance_profile_version = _safe_str_only(self.compliance_profile_version, max_len=32, default="1.0")

        c.sample_metrics = _coerce_rate(self.sample_metrics, 1.0)
        c.sample_traces = _coerce_rate(self.sample_traces, 1.0)
        c.sample_events = _coerce_rate(self.sample_events, 1.0)

        c.deterministic_sampling = bool(self.deterministic_sampling)
        c.deterministic_seed = _safe_str_only(self.deterministic_seed, max_len=256, default="") if isinstance(self.deterministic_seed, str) else None
        if c.deterministic_seed == "":
            c.deterministic_seed = None

        c.hash_fn = self.hash_fn
        c.hash_key_material = _safe_str_only(self.hash_key_material, max_len=4096, default="") if isinstance(self.hash_key_material, str) else None
        if c.hash_key_material == "":
            c.hash_key_material = None

        c.crypto_label_base = _safe_str_only(self.crypto_label_base, max_len=32, default="otel")
        c.require_hash_key_for_strict_profiles = bool(self.require_hash_key_for_strict_profiles)

        c.include_resource_field = bool(self.include_resource_field)
        c.merge_resource_into_attributes = bool(self.merge_resource_into_attributes)

        # Budgets with profile clamps
        if c.compliance_profile in {"FINREG", "LOCKDOWN"}:
            c.sample_traces = max(c.sample_traces, 0.5)
            c.sample_metrics = max(c.sample_metrics, 0.1)
            c.sample_events = max(c.sample_events, 0.1)

        if c.compliance_profile == "LOCKDOWN":
            c.max_attr_len = min(int(self.max_attr_len or 64), 64)
            c.max_attr_depth = min(int(self.max_attr_depth or 4), 4)
            c.max_attr_items = min(int(self.max_attr_items or 64), 64)
        else:
            c.max_attr_len = _clamp_int(int(self.max_attr_len or 256), 16, 32_768)
            c.max_attr_depth = _clamp_int(int(self.max_attr_depth or 5), 1, 16)
            c.max_attr_items = _clamp_int(int(self.max_attr_items or 256), 16, 4096)

        c.max_attr_nodes = _clamp_int(int(self.max_attr_nodes or 2048), 256, 1_000_000)
        c.max_attr_scan = _clamp_int(int(self.max_attr_scan or 4096), c.max_attr_items, 1_000_000)
        c.max_attr_total_str = _clamp_int(int(self.max_attr_total_str or 64_000), 256, 10_000_000)

        c.output_max_bytes = _clamp_int(int(self.output_max_bytes or 16_384), 1024, 1_000_000)

        # Redaction lists normalized to lower tokens
        rk: Sequence[str] = self.redact_keys or tuple()
        c.redact_keys = tuple(sorted({x.lower() for x in rk if isinstance(x, str)}))

        # attribute_policy (exact)
        ap: Dict[str, str] = {}
        if isinstance(self.attribute_policy, Mapping):
            scanned = 0
            for k, v in self.attribute_policy.items():
                scanned += 1
                if scanned > 4096:
                    break
                kk = _canonical_key(k, max_len=128, force_lower=True, require_safe_re=False)
                if not kk:
                    continue
                pv = _normalize_policy_value(v)
                if not pv:
                    continue
                ap[kk] = pv
        c.attribute_policy = ap

        # attribute_policy_prefix
        pp: Dict[str, str] = {}
        if isinstance(self.attribute_policy_prefix, Mapping):
            scanned = 0
            for k, v in self.attribute_policy_prefix.items():
                scanned += 1
                if scanned > 4096:
                    break
                if not isinstance(k, str):
                    continue
                prefix = _strip_unsafe_text(k, max_len=128).strip().lower()
                if not prefix:
                    continue
                # Keep prefixes modest and OTel-like (avoid weird chars)
                if len(prefix) > 64:
                    continue
                pv = _normalize_policy_value(v)
                if not pv:
                    continue
                pp[prefix] = pv
        c.attribute_policy_prefix = pp

        dp = _normalize_policy_value(self.default_attribute_policy) if isinstance(self.default_attribute_policy, str) else None
        c.default_attribute_policy = dp

        # Deep key redaction defaults by profile
        if isinstance(self.deep_sanitize_sensitive_keys, bool):
            c.deep_sanitize_sensitive_keys = self.deep_sanitize_sensitive_keys
        else:
            c.deep_sanitize_sensitive_keys = None

        # Forbid/redact behavior
        def _norm_beh(x: Any) -> Optional[str]:
            if not isinstance(x, str):
                return None
            s = _strip_unsafe_text(x, max_len=16).strip().lower()
            return s if s in {"drop", "placeholder"} else None

        c.forbid_behavior = _norm_beh(self.forbid_behavior) if self.forbid_behavior is not None else None
        c.redact_behavior = _norm_beh(self.redact_behavior) if self.redact_behavior is not None else None

        c.include_status_description = bool(self.include_status_description)
        c.include_status_description_strict = bool(self.include_status_description_strict)

        c.async_enabled = bool(self.async_enabled)
        c.async_queue_maxsize = _clamp_int(int(self.async_queue_maxsize or 10_000), 1, 1_000_000)
        c.async_drop_on_full = bool(self.async_drop_on_full)

        c.sink = self.sink
        c.stdout_flush = bool(self.stdout_flush)

        # Fingerprint excludes
        ferk: Sequence[str] = self.fingerprint_exclude_resource_keys or tuple()
        c.fingerprint_exclude_resource_keys = tuple(sorted({x.lower() for x in ferk if isinstance(x, str)}))

        c.min_key_bytes_strict = _clamp_int(int(self.min_key_bytes_strict or 16), 8, 64)

        c.time_fn = self.time_fn if callable(self.time_fn) else time.time
        c.monotonic_fn = self.monotonic_fn if callable(self.monotonic_fn) else time.perf_counter

        # resource attrs: sanitize keys/values now (bounded, canonical)
        ra: Dict[str, Any] = {}
        if isinstance(self.resource_attributes, Mapping):
            scanned = 0
            budget = _AttrBudget(max_nodes=512, max_items=128, max_scan=512, max_str=8192, max_str_len=128)
            for k, v in self.resource_attributes.items():
                scanned += 1
                if scanned > 1024:
                    break
                kk = _canonical_key(k, max_len=128, force_lower=True, require_safe_re=True)
                if not kk:
                    continue
                ra[kk] = _jsonable_attr(
                    v,
                    budget=budget,
                    depth=0,
                    max_depth=3,
                    redaction_mode="token_or_entropy",
                    redact_set=frozenset(set(c.redact_keys).union(_FORBIDDEN_KEY_TOKENS)),
                    deep_key_redaction=True,
                    key_ctx_lower=kk,
                    redact_behavior="placeholder",
                )
        # do NOT auto-generate random instance id during normalization
        if "service.instance.id" not in ra:
            ra["service.instance.id"] = "auto"
        c.resource_attributes = ra

        return c

    def to_dict(self) -> Dict[str, Any]:
        c = self.normalized_copy()
        return {
            "schema_version": c.schema_version,
            "enabled": c.enabled,
            "service_name": c.service_name,
            "service_version": c.service_version,
            "resource_attributes": dict(c.resource_attributes),
            "include_resource_field": c.include_resource_field,
            "merge_resource_into_attributes": c.merge_resource_into_attributes,
            "compliance_profile": c.compliance_profile,
            "compliance_profile_version": c.compliance_profile_version,
            "sample_metrics": c.sample_metrics,
            "sample_traces": c.sample_traces,
            "sample_events": c.sample_events,
            "deterministic_sampling": c.deterministic_sampling,
            "deterministic_seed": c.deterministic_seed,
            "hash_key_material": c.hash_key_material,
            "crypto_label_base": c.crypto_label_base,
            "require_hash_key_for_strict_profiles": c.require_hash_key_for_strict_profiles,
            "redact_keys": list(c.redact_keys),
            "attribute_policy": dict(sorted(c.attribute_policy.items())),
            "attribute_policy_prefix": dict(sorted(c.attribute_policy_prefix.items())),
            "default_attribute_policy": c.default_attribute_policy,
            "deep_sanitize_sensitive_keys": c.deep_sanitize_sensitive_keys,
            "forbid_behavior": c.forbid_behavior,
            "redact_behavior": c.redact_behavior,
            "max_attr_len": c.max_attr_len,
            "max_attr_depth": c.max_attr_depth,
            "max_attr_items": c.max_attr_items,
            "max_attr_nodes": c.max_attr_nodes,
            "max_attr_scan": c.max_attr_scan,
            "max_attr_total_str": c.max_attr_total_str,
            "output_max_bytes": c.output_max_bytes,
            "include_status_description": c.include_status_description,
            "include_status_description_strict": c.include_status_description_strict,
            "async_enabled": c.async_enabled,
            "async_queue_maxsize": c.async_queue_maxsize,
            "async_drop_on_full": c.async_drop_on_full,
            "stdout_flush": c.stdout_flush,
            "fingerprint_exclude_resource_keys": list(c.fingerprint_exclude_resource_keys),
            "min_key_bytes_strict": c.min_key_bytes_strict,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "OtelExporterConfig":
        base = cls()
        if not isinstance(data, Mapping):
            return base.normalized_copy()
        allowed = {f.name for f in dataclass_fields(cls)}
        for k, v in data.items():
            if isinstance(k, str) and k in allowed:
                try:
                    setattr(base, k, v)
                except Exception:
                    continue
        return base.normalized_copy()

    def fingerprint(self) -> str:
        """
        Bounded policy fingerprint.
        Covers policy VALUES and resource VALUES (excluding volatile keys by default).
        """
        c = self.normalized_copy()

        # policy map digest (exact + prefix)
        hp = hashlib.sha256()
        for k, v in sorted(c.attribute_policy.items()):
            hp.update(k.encode("utf-8", errors="ignore"))
            hp.update(b"\0")
            hp.update(v.encode("utf-8", errors="ignore"))
            hp.update(b"\n")
        hp.update(b"__prefix__\n")
        for k, v in sorted(c.attribute_policy_prefix.items()):
            hp.update(k.encode("utf-8", errors="ignore"))
            hp.update(b"\0")
            hp.update(v.encode("utf-8", errors="ignore"))
            hp.update(b"\n")
        policy_digest = hp.hexdigest()

        # redact keys digest
        hr = hashlib.sha256()
        for k in c.redact_keys:
            hr.update(k.encode("utf-8", errors="ignore"))
            hr.update(b"\n")
        redact_digest = hr.hexdigest()

        # resource digest (bounded, excludes volatile keys)
        exclude = set(c.fingerprint_exclude_resource_keys)
        hx = hashlib.sha256()
        # values already JSON-safe from normalized_copy; dump deterministically
        for k, v in sorted(c.resource_attributes.items()):
            if k.lower() in exclude:
                continue
            hx.update(k.encode("utf-8", errors="ignore"))
            hx.update(b"\0")
            try:
                vs = json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
            except Exception:
                vs = '"[unserializable]"'
            hx.update(vs.encode("utf-8", errors="ignore"))
            hx.update(b"\n")
        resource_digest = hx.hexdigest()

        payload = {
            "schema_version": c.schema_version,
            "enabled": c.enabled,
            "service_name": c.service_name,
            "service_version": c.service_version,
            "compliance_profile": c.compliance_profile,
            "compliance_profile_version": c.compliance_profile_version,
            "sampling": {"metrics": c.sample_metrics, "traces": c.sample_traces, "events": c.sample_events},
            "deterministic_sampling": c.deterministic_sampling,
            "crypto_label_base": c.crypto_label_base,
            "require_hash_key_for_strict_profiles": c.require_hash_key_for_strict_profiles,
            "default_attribute_policy": c.default_attribute_policy,
            "deep_sanitize_sensitive_keys": c.deep_sanitize_sensitive_keys,
            "forbid_behavior": c.forbid_behavior,
            "redact_behavior": c.redact_behavior,
            "budgets": {
                "max_attr_len": c.max_attr_len,
                "max_attr_depth": c.max_attr_depth,
                "max_attr_items": c.max_attr_items,
                "max_attr_nodes": c.max_attr_nodes,
                "max_attr_scan": c.max_attr_scan,
                "max_attr_total_str": c.max_attr_total_str,
                "output_max_bytes": c.output_max_bytes,
            },
            "resource": {"include": c.include_resource_field, "merge": c.merge_resource_into_attributes},
            "policy_digest": policy_digest,
            "redact_digest": redact_digest,
            "resource_digest": resource_digest,
        }
        b = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        return hashlib.sha256(b).hexdigest()


@dataclass
class SpanContext:
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    sampled: bool = True


class _Span:
    __slots__ = ("_exporter", "name", "ctx", "attributes", "start_ns", "end_ns")

    def __init__(
        self,
        exporter: "TCDOtelExporter",
        name: str,
        ctx: SpanContext,
        attributes: Optional[Mapping[str, Any]] = None,
        start_ns: Optional[int] = None,
    ) -> None:
        self._exporter = exporter
        self.name = name
        self.ctx = ctx
        # do not copy unbounded here; sanitizer will scan-limit later
        self.attributes = attributes if isinstance(attributes, Mapping) else {}
        self.start_ns = start_ns or time.time_ns()
        self.end_ns: Optional[int] = None

    def __enter__(self) -> "_Span":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        status = "OK" if exc is None else "ERROR"
        status_description = self._exporter._format_status_description(exc) if exc is not None else None
        self._exporter.end_span(self, status=status, status_description=status_description)


@dataclass(frozen=True)
class _PolicyBundle:
    cfg: OtelExporterConfig
    cfg_fp: str
    bundle_fp: str
    strict: bool
    lockdown: bool
    redact_set: frozenset[str]
    policy_exact: Mapping[str, str]
    policy_prefixes: Tuple[Tuple[str, str], ...]  # (prefix, policy), sorted by len desc
    default_policy: str
    redaction_mode: str
    deep_key_redaction: bool
    forbid_behavior: str
    redact_behavior: str
    sample_key: bytes
    hash_key: bytes


class TCDOtelExporter:
    """
    Lightweight OpenTelemetry-style exporter for TCD (L7+ hardened).
    """

    def __init__(
        self,
        enabled: Optional[bool] = None,
        service_name: Optional[str] = None,
        version: Optional[str] = None,
        *,
        config: Optional[OtelExporterConfig] = None,
    ) -> None:
        # stable per-exporter master key (used when config does not provide key material)
        self._ephemeral_master = os.urandom(32)
        # stable instance id for this exporter instance
        self._instance_id = uuid.uuid4().hex[:16]

        # thread-safe dropped counter
        self._drop_lock = threading.Lock()
        self._dropped_total = 0

        # sink lock
        self._sink_lock = threading.Lock()

        # async sink infra
        self._async_q: Optional["queue.Queue[JsonDict]"] = None
        self._async_stop = threading.Event()
        self._async_thread: Optional[threading.Thread] = None

        # RNG for non-deterministic sampling
        self._rand = random.Random()

        # Normalize config without mutating external objects.
        if config is None:
            cfg = OtelExporterConfig(
                enabled=bool(enabled) if enabled is not None else False,
                service_name=service_name or "tcd-safety-sidecar",
                service_version=version or "0.3.0",
            ).normalized_copy()
        else:
            base = config.normalized_copy()
            if enabled is not None:
                base.enabled = bool(enabled)
            if isinstance(service_name, str) and service_name.strip():
                base.service_name = _safe_str_only(service_name, max_len=128, default=base.service_name)
            if isinstance(version, str) and version.strip():
                base.service_version = _safe_str_only(version, max_len=64, default=base.service_version)
            cfg = base.normalized_copy()

        if cfg.sink is None:
            cfg.sink = self._default_stdout_sink

        self._bundle_lock = threading.Lock()
        self._bundle: _PolicyBundle = self._build_bundle(cfg)

        if self._bundle.cfg.enabled and self._bundle.cfg.async_enabled:
            self._start_async_worker()

    # ------------------------
    # Bundle / config
    # ------------------------

    def _build_bundle(self, cfg: OtelExporterConfig) -> _PolicyBundle:
        cfg2 = cfg.normalized_copy()

        strict = cfg2.compliance_profile in {"FINREG", "LOCKDOWN"}
        lockdown = cfg2.compliance_profile == "LOCKDOWN"

        # Resolve defaults
        if cfg2.default_attribute_policy in {"allow", "hash", "forbid"}:
            default_policy = cfg2.default_attribute_policy
        else:
            default_policy = "forbid" if lockdown else ("hash" if cfg2.compliance_profile == "FINREG" else "allow")

        # Redaction mode for VALUES
        if cfg2.compliance_profile == "DEV":
            redaction_mode = "token"
        elif strict:
            redaction_mode = "token_or_entropy"
        else:
            redaction_mode = "token"

        # Deep key redaction defaults
        if isinstance(cfg2.deep_sanitize_sensitive_keys, bool):
            deep_key_redaction = cfg2.deep_sanitize_sensitive_keys
        else:
            deep_key_redaction = True if strict else False

        # forbid/redact behavior defaults
        forbid_behavior = cfg2.forbid_behavior if cfg2.forbid_behavior in {"drop", "placeholder"} else ("drop" if lockdown else "placeholder")
        redact_behavior = cfg2.redact_behavior if cfg2.redact_behavior in {"drop", "placeholder"} else ("drop" if lockdown else "placeholder")

        # Precompute redact set
        redact_set = frozenset(set(cfg2.redact_keys).union(_FORBIDDEN_KEY_TOKENS))

        # Precompute policy
        policy_exact = dict(cfg2.attribute_policy or {})
        # prefix rules: sort by prefix length desc to match most specific
        pfx_items = []
        for pfx, pol in (cfg2.attribute_policy_prefix or {}).items():
            if pol in {"allow", "hash", "forbid"} and isinstance(pfx, str) and pfx:
                pfx_items.append((pfx.lower(), pol))
        pfx_items.sort(key=lambda kv: len(kv[0]), reverse=True)
        policy_prefixes = tuple(pfx_items)

        # Key material (sampling)
        sample_master = _parse_key_material(cfg2.deterministic_seed) if cfg2.deterministic_seed else None
        if sample_master is None:
            sample_master = _kdf(self._ephemeral_master, "tcd/otel/sample/master/v1")
        sample_key = _kdf(sample_master, "tcd/otel/sample/key/v1")

        # Key material (hashing)
        hash_master = _parse_key_material(cfg2.hash_key_material) if cfg2.hash_key_material else None
        if hash_master is None:
            hash_master = _kdf(self._ephemeral_master, "tcd/otel/hash/master/v1")
        hash_key = _kdf(hash_master, "tcd/otel/hash/key/v1")

        # Strict profile: if hashing is used but neither hash_fn nor strong key provided => fail
        hashing_used = ("hash" in policy_exact.values()) or any(pol == "hash" for _, pol in policy_prefixes) or (default_policy == "hash")
        if strict and cfg2.require_hash_key_for_strict_profiles and hashing_used and cfg2.hash_fn is None:
            km = _parse_key_material(cfg2.hash_key_material) if cfg2.hash_key_material else None
            if km is None or len(km) < cfg2.min_key_bytes_strict:
                raise ValueError(
                    "FINREG/LOCKDOWN requires hash_fn or sufficiently strong hash_key_material when hashing is used."
                )

        # Strict profile: deterministic seed strength if deterministic_sampling is enabled
        if strict and cfg2.deterministic_sampling:
            km = _parse_key_material(cfg2.deterministic_seed) if cfg2.deterministic_seed else None
            if km is None or len(km) < cfg2.min_key_bytes_strict:
                raise ValueError(
                    "FINREG/LOCKDOWN deterministic_sampling requires sufficiently strong deterministic_seed."
                )

        cfg_fp = cfg2.fingerprint()

        # Bundle fingerprint must include derived behavior too (audit replay)
        bundle_payload = {
            "cfg_fp": cfg_fp,
            "strict": strict,
            "lockdown": lockdown,
            "default_policy_resolved": default_policy,
            "redaction_mode_resolved": redaction_mode,
            "deep_key_redaction": deep_key_redaction,
            "forbid_behavior": forbid_behavior,
            "redact_behavior": redact_behavior,
            # include whether resource is merged & included (changes observable output)
            "include_resource_field": cfg2.include_resource_field,
            "merge_resource_into_attributes": cfg2.merge_resource_into_attributes,
        }
        bundle_fp = hashlib.sha256(
            json.dumps(bundle_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        ).hexdigest()

        return _PolicyBundle(
            cfg=cfg2,
            cfg_fp=cfg_fp,
            bundle_fp=bundle_fp,
            strict=strict,
            lockdown=lockdown,
            redact_set=redact_set,
            policy_exact=policy_exact,
            policy_prefixes=policy_prefixes,
            default_policy=default_policy,
            redaction_mode=redaction_mode,
            deep_key_redaction=deep_key_redaction,
            forbid_behavior=forbid_behavior,
            redact_behavior=redact_behavior,
            sample_key=sample_key,
            hash_key=hash_key,
        )

    @property
    def config(self) -> OtelExporterConfig:
        with self._bundle_lock:
            return self._bundle.cfg.normalized_copy()

    def set_config(self, config: OtelExporterConfig) -> None:
        new_bundle = self._build_bundle(config.normalized_copy())
        with self._bundle_lock:
            self._bundle = new_bundle
        # toggle async worker
        if new_bundle.cfg.enabled and new_bundle.cfg.async_enabled and self._async_thread is None:
            self._start_async_worker()
        if (not new_bundle.cfg.enabled or not new_bundle.cfg.async_enabled) and self._async_thread is not None:
            self.shutdown(mode="drain", timeout=2.0)

    # ------------------------
    # Default sink
    # ------------------------

    def _default_stdout_sink(self, rec: JsonDict) -> None:
        bundle = self._bundle  # no lock read
        cfg = bundle.cfg
        s = json.dumps(rec, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)
        sys.stdout.write(s + "\n")
        if cfg.stdout_flush:
            try:
                sys.stdout.flush()
            except Exception:
                pass

    # ------------------------
    # Sampling
    # ------------------------

    def _should_sample(self, bundle: _PolicyBundle, rate: float, stable_key: Optional[str]) -> bool:
        r = _coerce_rate(rate, 1.0)
        if r <= 0.0:
            return False
        if r >= 1.0:
            return True

        cfg = bundle.cfg
        if cfg.deterministic_sampling and stable_key:
            msg = stable_key.encode("utf-8", errors="ignore")
            dig = hmac.new(bundle.sample_key, msg, digestmod=hashlib.sha256).digest()
            u = int.from_bytes(dig[:8], "big")
            x = u / float(2**64)
            return x < r

        return self._rand.random() < r

    # ------------------------
    # Hashing
    # ------------------------

    def _hash_value(self, bundle: _PolicyBundle, value: Any, label: str) -> str:
        cfg = bundle.cfg
        lab = _safe_str_only(label, max_len=64, default="attr").lower()
        domain = f"{cfg.crypto_label_base}/{lab}"

        inp = _stable_str_for_hashing(value, max_len=2048)

        if cfg.hash_fn is not None:
            # Never call str()/repr() on unknown outputs. Accept str only.
            try:
                out = cfg.hash_fn(inp, domain)
            except Exception:
                return hashlib.sha256(b"bad_hash_fn_call").hexdigest()
            if isinstance(out, str):
                s = _strip_unsafe_text(out, max_len=512).strip()
                if _HEX_RE.fullmatch(s):
                    return s.lower()
                return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()
            # non-str output: treat as constant to avoid side effects
            return hashlib.sha256(b"bad_hash_fn_return").hexdigest()

        # Internal HMAC fallback (cryptographically sane)
        dig = hmac.new(bundle.hash_key, (domain + "\0" + inp).encode("utf-8", errors="ignore"), hashlib.sha256).hexdigest()
        return dig

    # ------------------------
    # Public API: metrics
    # ------------------------

    def push_metrics(self, value: float, name: str = "diagnose_count", attrs: Optional[Mapping[str, Any]] = None) -> None:
        self.record_metric(name=name, value=value, labels=attrs)

    def record_metric(self, name: str, value: float, labels: Optional[Mapping[str, Any]] = None) -> None:
        bundle = self._bundle
        cfg = bundle.cfg
        if not cfg.enabled:
            return

        stable_key = None
        if isinstance(labels, Mapping):
            rid = labels.get("request_id")
            if isinstance(rid, str):
                stable_key = rid

        if not self._should_sample(bundle, cfg.sample_metrics, stable_key):
            return

        now = cfg.time_fn()
        mono = cfg.monotonic_fn()
        v = _finite_float(value)
        if v is None:
            v = 0.0

        metric_name = name if isinstance(name, str) else "metric"
        metric_name = _safe_str_only(metric_name, max_len=128, default="metric")

        rec: JsonDict = {
            "schema": "tcd.otel",
            "schema_version": cfg.schema_version,
            # bundle_fp is the audit-grade behavior fingerprint
            "config_fingerprint": bundle.bundle_fp,
            "config_fingerprint_cfg": bundle.cfg_fp,
            "kind": "metric",
            "type": "metric",  # backward compat
            "name": metric_name,
            "metric": metric_name,  # backward compat
            "value": float(v),
            "ts_unix_nano": int(now * 1e9),
            "ts_mono": float(mono),
            "service": cfg.service_name,
            "service_version": cfg.service_version,
            "compliance_profile": cfg.compliance_profile,
            "attributes": labels if isinstance(labels, Mapping) else {},
        }
        self._emit(bundle, rec)

    # ------------------------
    # Public API: events
    # ------------------------

    def push_event(self, name: str, attrs: Optional[Mapping[str, Any]] = None) -> None:
        bundle = self._bundle
        cfg = bundle.cfg
        if not cfg.enabled:
            return

        stable_key = None
        if isinstance(attrs, Mapping):
            rid = attrs.get("request_id")
            if isinstance(rid, str):
                stable_key = rid
            else:
                tid = attrs.get("trace_id")
                if isinstance(tid, str):
                    stable_key = tid

        if not self._should_sample(bundle, cfg.sample_events, stable_key):
            return

        now = cfg.time_fn()
        mono = cfg.monotonic_fn()

        event_name = name if isinstance(name, str) else "event"
        event_name = _safe_str_only(event_name, max_len=128, default="event")

        rec: JsonDict = {
            "schema": "tcd.otel",
            "schema_version": cfg.schema_version,
            "config_fingerprint": bundle.bundle_fp,
            "config_fingerprint_cfg": bundle.cfg_fp,
            "kind": "event",
            "type": "event",  # backward compat
            "name": event_name,
            "event": event_name,  # backward compat
            "ts_unix_nano": int(now * 1e9),
            "ts_mono": float(mono),
            "service": cfg.service_name,
            "service_version": cfg.service_version,
            "compliance_profile": cfg.compliance_profile,
            "attributes": attrs if isinstance(attrs, Mapping) else {},
        }
        self._emit(bundle, rec)

    # Convenience helpers (kept; sanitizer governs what is emitted)
    def record_decision_event(
        self,
        *,
        request_id: Optional[str],
        session_id: Optional[str],
        tenant: Optional[str],
        policy_id: Optional[str],
        rule_path: Optional[str],
        action: str,
        wealth_before: Optional[float] = None,
        wealth_after: Optional[float] = None,
        risk_level: Optional[str] = None,
        receipt_id: Optional[str] = None,
        extra_attrs: Optional[Mapping[str, Any]] = None,
    ) -> None:
        attrs: Dict[str, Any] = {
            "request_id": request_id,
            "session_id": session_id,
            "tenant": tenant,
            "policy_id": policy_id,
            "rule_path": rule_path,
            "action": action,
            "risk_level": risk_level,
            "wealth_before": wealth_before,
            "wealth_after": wealth_after,
            "receipt_id": receipt_id,
        }
        if extra_attrs:
            for k, v in extra_attrs.items():
                attrs[k] = v
        self.push_event("tcd.decision", attrs=attrs)

    def record_policy_change_event(
        self,
        *,
        operator_id: Optional[str],
        policy_id: Optional[str],
        old_version: Optional[str],
        new_version: Optional[str],
        four_eyes: Optional[bool] = None,
        extra_attrs: Optional[Mapping[str, Any]] = None,
    ) -> None:
        attrs: Dict[str, Any] = {
            "operator_id": operator_id,
            "policy_id": policy_id,
            "old_version": old_version,
            "new_version": new_version,
            "four_eyes": four_eyes,
        }
        if extra_attrs:
            for k, v in extra_attrs.items():
                attrs[k] = v
        self.push_event("tcd.policy.change", attrs=attrs)

    def record_deployment_artifact_event(
        self,
        *,
        artifact_type: str,
        artifact_hash: str,
        sig_status: str,
        source: Optional[str] = None,
        extra_attrs: Optional[Mapping[str, Any]] = None,
    ) -> None:
        attrs: Dict[str, Any] = {
            "artifact_type": artifact_type,
            "artifact_hash": artifact_hash,
            "sig_status": sig_status,
            "source": source,
        }
        if extra_attrs:
            for k, v in extra_attrs.items():
                attrs[k] = v
        self.push_event("tcd.deployment.artifact", attrs=attrs)

    def record_crypto_profile_event(
        self,
        *,
        profile_id: str,
        kem: Optional[str],
        signature_scheme: Optional[str],
        rollover: Optional[bool] = None,
        extra_attrs: Optional[Mapping[str, Any]] = None,
    ) -> None:
        attrs: Dict[str, Any] = {
            "profile_id": profile_id,
            "kem": kem,
            "signature_scheme": signature_scheme,
            "rollover": rollover,
        }
        if extra_attrs:
            for k, v in extra_attrs.items():
                attrs[k] = v
        self.push_event("tcd.crypto.profile", attrs=attrs)

    def record_attestation_event(
        self,
        *,
        attestation_id: str,
        status: str,
        extra_attrs: Optional[Mapping[str, Any]] = None,
    ) -> None:
        attrs: Dict[str, Any] = {"attestation_id": attestation_id, "status": status}
        if extra_attrs:
            for k, v in extra_attrs.items():
                attrs[k] = v
        self.push_event("tcd.attestation", attrs=attrs)

    def record_apt_verdict_event(
        self,
        *,
        request_id: Optional[str],
        tenant: Optional[str],
        score: float,
        signal_type: str,
        decision: str,
        extra_attrs: Optional[Mapping[str, Any]] = None,
    ) -> None:
        attrs: Dict[str, Any] = {
            "request_id": request_id,
            "tenant": tenant,
            "score": float(_finite_float(score) or 0.0),
            "signal_type": signal_type,
            "decision": decision,
        }
        if extra_attrs:
            for k, v in extra_attrs.items():
                attrs[k] = v
        self.push_event("tcd.apt.verdict", attrs=attrs)

    # ------------------------
    # Tracing
    # ------------------------

    def start_span(
        self,
        name: str,
        attributes: Optional[Mapping[str, Any]] = None,
        parent: Optional[SpanContext] = None,
        sampled: Optional[bool] = None,
    ) -> _Span:
        bundle = self._bundle
        cfg = bundle.cfg

        # Parent-based sampling; if no parent and exporter disabled => unsampled unless forced
        if sampled is None:
            if parent is not None:
                sampled = bool(parent.sampled)
            else:
                sampled = False if not cfg.enabled else self._should_sample(bundle, cfg.sample_traces, stable_key=None)

        # Validate parent ids lightly (avoid output pollution)
        if parent is not None and isinstance(parent.trace_id, str) and isinstance(parent.span_id, str):
            trace_id = _safe_str_only(parent.trace_id, max_len=64, default=uuid.uuid4().hex)
            parent_span_id = _safe_str_only(parent.span_id, max_len=32, default=None) or None
        else:
            trace_id = uuid.uuid4().hex
            parent_span_id = None

        span_id = uuid.uuid4().hex[:16]
        span_name = name if isinstance(name, str) else "span"
        span_name = _safe_str_only(span_name, max_len=128, default="span")

        ctx = SpanContext(trace_id=trace_id, span_id=span_id, parent_span_id=parent_span_id, sampled=bool(sampled))
        return _Span(self, name=span_name, ctx=ctx, attributes=attributes)

    def _format_status_description(self, exc: Any) -> str:
        bundle = self._bundle
        cfg = bundle.cfg

        exc_name = type(exc).__name__ if exc is not None else "Exception"
        exc_name = _safe_str_only(exc_name, max_len=64, default="Exception")

        if bundle.strict and not cfg.include_status_description_strict:
            return exc_name

        # Non-strict: include message but sanitize/redact
        msg = _safe_str_only(str(exc) if isinstance(exc, Exception) else "", max_len=512, default="")
        if _looks_like_secret_token(msg) or (bundle.strict and _looks_like_high_entropy(msg)):
            msg = "[redacted]"
        if len(msg) > 256:
            msg = msg[:256] + "...[truncated]"
        return f"{exc_name}: {msg}" if msg else exc_name

    def end_span(self, span: _Span, *, status: str = "OK", status_description: Optional[str] = None) -> None:
        bundle = self._bundle
        cfg = bundle.cfg
        if not cfg.enabled:
            return
        if not span.ctx.sampled:
            return

        if span.end_ns is None:
            span.end_ns = time.time_ns()

        st = status if isinstance(status, str) else "OK"
        st = _safe_str_only(st, max_len=16, default="OK")

        rec: JsonDict = {
            "schema": "tcd.otel",
            "schema_version": cfg.schema_version,
            "config_fingerprint": bundle.bundle_fp,
            "config_fingerprint_cfg": bundle.cfg_fp,
            "kind": "span",
            "type": "span",  # backward compat
            "name": _safe_str_only(span.name, max_len=128, default="span"),
            "ts_unix_nano": int(cfg.time_fn() * 1e9),
            "service": cfg.service_name,
            "service_version": cfg.service_version,
            "compliance_profile": cfg.compliance_profile,
            "trace_id": _safe_str_only(span.ctx.trace_id, max_len=64, default=""),
            "span_id": _safe_str_only(span.ctx.span_id, max_len=32, default=""),
            "parent_span_id": _safe_str_only(span.ctx.parent_span_id, max_len=32, default="") or None,
            "start_unix_nano": int(span.start_ns),
            "end_unix_nano": int(span.end_ns),
            "status": st,
            "attributes": span.attributes if isinstance(span.attributes, Mapping) else {},
        }
        if cfg.include_status_description and isinstance(status_description, str) and status_description:
            rec["status_description"] = status_description
        self._emit(bundle, rec)

    # ------------------------
    # flush / shutdown
    # ------------------------

    def flush(self, timeout: float = 2.0) -> bool:
        """
        Best-effort flush for async mode. Returns True if queue appears drained.
        """
        q = self._async_q
        if q is None:
            return True
        deadline = time.monotonic() + max(0.0, float(timeout))
        while time.monotonic() < deadline:
            try:
                if q.unfinished_tasks == 0:
                    return True
            except Exception:
                # fallback: qsize heuristic
                try:
                    if q.qsize() == 0:
                        return True
                except Exception:
                    return False
            time.sleep(0.01)
        return False

    def shutdown(self, mode: str = "drain", timeout: float = 2.0) -> None:
        """
        Shutdown async worker.

        mode:
          - "drain": best-effort flush then stop
          - "drop": drop queued records then stop
        """
        if self._async_thread is None or self._async_q is None:
            return

        q = self._async_q
        if mode == "drop":
            # drop everything quickly
            while True:
                try:
                    _ = q.get_nowait()
                    try:
                        q.task_done()
                    except Exception:
                        pass
                    with self._drop_lock:
                        self._dropped_total += 1
                except Exception:
                    break
        else:
            self.flush(timeout=timeout)

        self._async_stop.set()
        try:
            self._async_thread.join(timeout=max(0.1, float(timeout)))
        except Exception:
            pass

        # do NOT null out queue until thread is joined (race-safe enough now)
        self._async_thread = None
        self._async_q = None

    # ------------------------
    # Async worker
    # ------------------------

    def _start_async_worker(self) -> None:
        bundle = self._bundle
        cfg = bundle.cfg

        self._async_q = queue.Queue(maxsize=cfg.async_queue_maxsize)
        self._async_stop.clear()

        def _worker() -> None:
            assert self._async_q is not None
            q = self._async_q
            while not self._async_stop.is_set():
                try:
                    rec = q.get(timeout=0.2)
                except Exception:
                    continue

                # deliver using CURRENT sink (fix stale-bundle issue)
                self._deliver(rec)

                try:
                    q.task_done()
                except Exception:
                    pass

            # drain best-effort
            while True:
                try:
                    rec = q.get_nowait()
                except Exception:
                    break
                self._deliver(rec)
                try:
                    q.task_done()
                except Exception:
                    pass

        self._async_thread = threading.Thread(target=_worker, name="tcd-otel-exporter", daemon=True)
        self._async_thread.start()

    # ------------------------
    # Emit / sanitize / deliver
    # ------------------------

    def _emit(self, bundle: _PolicyBundle, rec: JsonDict) -> None:
        cfg = bundle.cfg

        # If disabled, no-op
        if not cfg.enabled:
            return

        # Prepare resource (authoritative, separate channel)
        resource = dict(cfg.resource_attributes or {})
        # Fill stable instance id
        if resource.get("service.instance.id") in (None, "", "auto"):
            resource["service.instance.id"] = self._instance_id

        # Sanitize record (top-level + resource + user attributes), then enforce byte budget
        rec2, meta = self._sanitize_record(bundle, rec, resource)
        rec3 = self._enforce_output_budget(bundle, rec2, meta)

        # Deliver
        if cfg.async_enabled and self._async_q is not None:
            try:
                self._async_q.put_nowait(rec3)
            except Exception:
                if cfg.async_drop_on_full:
                    with self._drop_lock:
                        self._dropped_total += 1
                else:
                    try:
                        self._async_q.put(rec3, timeout=0.05)
                    except Exception:
                        with self._drop_lock:
                            self._dropped_total += 1
            return

        self._deliver(rec3)

    def _deliver(self, rec: JsonDict) -> None:
        bundle = self._bundle
        cfg = bundle.cfg
        sink = cfg.sink
        if sink is None:
            return
        with self._sink_lock:
            try:
                sink(rec)
            except Exception:
                pass

    def _resolve_policy(self, bundle: _PolicyBundle, key_lower: str) -> str:
        p = bundle.policy_exact.get(key_lower)
        if p in {"allow", "hash", "forbid"}:
            return p
        for prefix, pol in bundle.policy_prefixes:
            if key_lower.startswith(prefix):
                return pol
        return bundle.default_policy

    def _sanitize_user_attributes(self, bundle: _PolicyBundle, attrs: Mapping[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        cfg = bundle.cfg
        meta: Dict[str, Any] = {"truncated": False, "dropped_keys": 0}

        budget = _AttrBudget(
            max_nodes=cfg.max_attr_nodes,
            max_items=cfg.max_attr_items,
            max_scan=cfg.max_attr_scan,
            max_str=cfg.max_attr_total_str,
            max_str_len=cfg.max_attr_len,
        )

        cleaned: Dict[str, Any] = {}
        scanned = 0
        written = 0

        for k, v in attrs.items():
            scanned += 1
            if scanned > cfg.max_attr_scan or written >= cfg.max_attr_items:
                meta["truncated"] = True
                break

            kk = _canonical_key(k, max_len=128, force_lower=True, require_safe_re=True)
            if not kk:
                meta["dropped_keys"] += 1
                continue

            # Hard sensitive key redaction
            if _key_is_sensitive(kk, redact_set=bundle.redact_set):
                if bundle.redact_behavior == "drop":
                    meta["dropped_keys"] += 1
                    continue
                cleaned[kk] = "[redacted]"
                written += 1
                continue

            pol = self._resolve_policy(bundle, kk)

            if pol == "forbid":
                if bundle.forbid_behavior == "drop":
                    meta["dropped_keys"] += 1
                    continue
                cleaned[kk] = "[forbidden]"
                written += 1
                continue

            if pol == "hash":
                cleaned[kk] = self._hash_value(bundle, v, label=kk)
                written += 1
                continue

            # allow
            cleaned[kk] = _jsonable_attr(
                v,
                budget=budget,
                depth=0,
                max_depth=cfg.max_attr_depth,
                redaction_mode=bundle.redaction_mode,
                redact_set=bundle.redact_set,
                deep_key_redaction=bundle.deep_key_redaction,
                key_ctx_lower=kk,
                redact_behavior=bundle.redact_behavior,
            )
            written += 1

        return cleaned, meta

    def _sanitize_resource_attributes(self, bundle: _PolicyBundle, resource: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Resource channel: always sanitized, but NOT subject to default forbid in LOCKDOWN.
        Still redacts obvious secret tokens defensively.
        """
        cfg = bundle.cfg
        budget = _AttrBudget(max_nodes=512, max_items=128, max_scan=512, max_str=8192, max_str_len=128)

        out: Dict[str, Any] = {}
        scanned = 0
        for k, v in resource.items():
            scanned += 1
            if scanned > 1024 or len(out) >= 256:
                break
            kk = _canonical_key(k, max_len=128, force_lower=True, require_safe_re=True)
            if not kk:
                continue
            # Even for resource, drop internal key names
            if _is_internal_key(kk):
                continue
            # Redact if key itself sensitive (shouldn't happen)
            if _key_is_sensitive(kk, redact_set=bundle.redact_set):
                out[kk] = "[redacted]"
                continue
            out[kk] = _jsonable_attr(
                v,
                budget=budget,
                depth=0,
                max_depth=3,
                redaction_mode="token_or_entropy" if bundle.strict else "token",
                redact_set=bundle.redact_set,
                deep_key_redaction=True,
                key_ctx_lower=kk,
                redact_behavior="placeholder",
            )
        return out

    def _sanitize_record(self, bundle: _PolicyBundle, rec: JsonDict, resource: Mapping[str, Any]) -> Tuple[JsonDict, Dict[str, Any]]:
        cfg = bundle.cfg

        out: Dict[str, Any] = dict(rec)

        # Sanitize top-level strings (no fallback to original)
        for k in ("kind", "type", "service", "service_version", "compliance_profile", "metric", "event", "name", "status"):
            if k in out:
                out[k] = _safe_str_only(out[k], max_len=128, default="unknown") if isinstance(out[k], str) else out[k]

        # status_description is risky
        if "status_description" in out and isinstance(out["status_description"], str):
            sd = _strip_unsafe_text(out["status_description"], max_len=512).strip()
            if _looks_like_secret_token(sd) or (bundle.strict and _looks_like_high_entropy(sd) and not _entropy_exempt_for_key("status_description")):
                sd = "[redacted]"
            if bundle.strict and not cfg.include_status_description_strict:
                sd = sd.split(":")[0].strip()[:64] if sd else ""
            out["status_description"] = sd[:256] if sd else sd

        # Sanitize trace ids lightly
        for kid in ("trace_id", "span_id", "parent_span_id"):
            if kid in out and isinstance(out[kid], str):
                s = _safe_str_only(out[kid], max_len=64, default="")
                if not s:
                    out.pop(kid, None)
                else:
                    out[kid] = s

        # User attributes
        attrs = out.get("attributes")
        if not isinstance(attrs, Mapping):
            attrs = {}

        user_clean, user_meta = self._sanitize_user_attributes(bundle, attrs)
        res_clean = self._sanitize_resource_attributes(bundle, resource)

        # Merge resource into attributes if configured (resource wins)
        merged = dict(user_clean)
        if cfg.merge_resource_into_attributes:
            for k, v in res_clean.items():
                merged[k] = v

        out["attributes"] = merged

        # Optionally include separate resource field (authoritative)
        if cfg.include_resource_field:
            out["resource"] = res_clean

        # Internal meta separated to avoid spoofing
        with self._drop_lock:
            dropped_total = int(self._dropped_total)

        out["tcd_meta"] = {
            "truncated": bool(user_meta.get("truncated")),
            "dropped_keys": int(user_meta.get("dropped_keys") or 0),
            "async_dropped_total": dropped_total if bundle.strict else None,
            "strict": bundle.strict,
            "lockdown": bundle.lockdown,
        }

        return out, out["tcd_meta"]

    def _enforce_output_budget(self, bundle: _PolicyBundle, rec: JsonDict, meta: Dict[str, Any]) -> JsonDict:
        cfg = bundle.cfg
        max_bytes = cfg.output_max_bytes

        def try_dump(o: JsonDict) -> Optional[bytes]:
            try:
                s = json.dumps(o, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)
                return s.encode("utf-8", errors="strict")
            except Exception:
                return None

        b = try_dump(rec)
        if b is not None and len(b) <= max_bytes:
            return rec

        # shrink deterministically
        shrunk = dict(rec)
        tcd_meta = dict(shrunk.get("tcd_meta") or {})
        tcd_meta["shrunk"] = True
        shrunk["tcd_meta"] = tcd_meta

        # Drop status_description first
        if "status_description" in shrunk:
            shrunk.pop("status_description", None)
            b = try_dump(shrunk)
            if b is not None and len(b) <= max_bytes:
                return shrunk

        # Shrink attributes while preserving critical keys
        critical = [
            "request_id",
            "trace_id",
            "span_id",
            "parent_span_id",
            "tenant",
            "tenant_id",
            "user",
            "user_id",
            "policy_id",
            "receipt_id",
        ]

        attrs = shrunk.get("attributes")
        if isinstance(attrs, dict):
            keep: Dict[str, Any] = {}
            # keep critical in fixed order if present
            for k in critical:
                if k in attrs:
                    keep[k] = attrs[k]
            # add remaining keys in sorted order to deterministic cap
            for k in sorted(attrs.keys()):
                if k in keep:
                    continue
                if len(keep) >= 32:
                    break
                keep[k] = attrs[k]
            keep["_tcd_shrunk_attrs"] = True
            shrunk["attributes"] = keep
            b = try_dump(shrunk)
            if b is not None and len(b) <= max_bytes:
                return shrunk

        # Minimal last resort
        minimal: JsonDict = {
            "schema": rec.get("schema", "tcd.otel"),
            "schema_version": rec.get("schema_version", cfg.schema_version),
            "config_fingerprint": rec.get("config_fingerprint", bundle.bundle_fp),
            "config_fingerprint_cfg": rec.get("config_fingerprint_cfg", bundle.cfg_fp),
            "kind": rec.get("kind", rec.get("type", "record")),
            "type": rec.get("type", rec.get("kind", "record")),
            "name": rec.get("name", rec.get("metric", rec.get("event", "record"))),
            "ts_unix_nano": rec.get("ts_unix_nano", int(cfg.time_fn() * 1e9)),
            "service": rec.get("service", cfg.service_name),
            "service_version": rec.get("service_version", cfg.service_version),
            "compliance_profile": rec.get("compliance_profile", cfg.compliance_profile),
            "tcd_meta": {"shrunk": True},
        }
        return minimal


__all__ = ["TCDOtelExporter", "OtelExporterConfig", "SpanContext"]