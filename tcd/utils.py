from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple, Literal

try:  # optional, stronger hashing when available
    from .crypto import Blake3Hash  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    Blake3Hash = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Versions / surfaces / profiles
# ---------------------------------------------------------------------------

Profile = Literal["DEV", "PROD", "FINREG", "LOCKDOWN"]
SanitizeSurface = Literal["receipt_public", "receipt_audit", "signal", "storage", "internal"]
HashAlgorithm = Literal["sha256", "blake2s", "blake3"]
ForbiddenKeyAction = Literal["reject", "drop", "redact"]
NonFiniteMode = Literal["reject", "null", "default", "tag"]
OversizeIntMode = Literal["reject", "tag", "clamp"]
UnknownTypeMode = Literal["tag", "drop", "reject"]

_SANITIZE_ENGINE_VERSION = "tcd.utils.v3"
_COMPATIBILITY_EPOCH = "2026Q2"
_CANONICALIZATION_VERSION = "canonjson_v2"

# ---------------------------------------------------------------------------
# Limits / constants
# ---------------------------------------------------------------------------

_SANITIZE_MAX_DEPTH = 8
_SANITIZE_MAX_LIST_LEN = 512
_SANITIZE_MAX_STR_LEN = 2048
_SANITIZE_MAX_NODES = 4096
_SANITIZE_MAX_TOTAL_STR_BYTES = 128_000
_SANITIZE_MAX_TOTAL_BYTES = 256_000
_SANITIZE_MAX_KEY_BYTES = 128
_MAX_INT_BITS = 256

# PII detectors (metadata-level only; intentionally conservative)
_PII_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.UNICODE)
_PII_PHONE_RE = re.compile(r"\+?\d[\d\-\s]{6,}\d", re.UNICODE)
# We keep numeric-ID detection deliberately weak to avoid over-redacting business ids.
_PII_IDLIKE_RE = re.compile(r"\b\d{9,}\b", re.UNICODE)

# Secret/token detectors (metadata-level only)
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

_ASCII_CTRL_RE = re.compile(r"[\x00-\x1F\x7F]")
_SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,127}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DIGEST_HEX_RE = re.compile(r"^[0-9a-f]{16,256}$")
_DIGEST_HEX_0X_RE = re.compile(r"^0x[0-9a-f]{16,256}$")
_DIGEST_ALG_HEX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,31}:[0-9a-f]{16,256}$")
_CFG_FP_RE = re.compile(
    r"^(?:[A-Za-z0-9][A-Za-z0-9_.-]{1,15}:[A-Za-z0-9][A-Za-z0-9_.-]{1,15}:[0-9a-f]{16,256}|[A-Za-z0-9][A-Za-z0-9_.-]{1,15}:[0-9a-f]{16,256})$"
)
_RECEIPT_INTEGRITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{1,31}:[A-Za-z0-9][A-Za-z0-9_.:\-]{1,63}$")

# Exact forbidden keys kept for backward compatibility
_FORBIDDEN_META_KEYS = {
    "prompt",
    "completion",
    "input_text",
    "output_text",
    "messages",
    "content",
    "raw",
    "body",
}

# Token-level forbidden keys used for stricter recursive scans
_FORBIDDEN_META_KEY_TOKENS = frozenset(
    {
        "prompt",
        "completion",
        "input",
        "output",
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
        "secret",
        "password",
        "passwd",
        "pwd",
        "api",
        "apikey",
        "api_key",
        "private",
        "privatekey",
        "token",
    }
)

# Keys/tokens where long high-entropy values are expected and should not be
# blindly redacted on external/public surfaces.
_ENTROPY_EXEMPT_TOKENS = frozenset(
    {
        "hash",
        "digest",
        "checksum",
        "fingerprint",
        "sha",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha3",
        "blake",
        "blake2",
        "blake2s",
        "blake2b",
        "blake3",
        "cfg_fp",
        "config_hash",
        "policy_digest",
        "body_digest",
        "event_digest",
        "payload_digest",
        "trace_id",
        "span_id",
        "receipt_head",
        "receipt_ref",
        "audit_ref",
        "ledger_ref",
        "attestation_ref",
        "verify_key_id",
        "key_id",
        "kid",
        "route_plan_id",
        "decision_id",
        "event_id",
    }
)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SanitizeError(RuntimeError):
    pass


class BudgetExceededError(SanitizeError):
    pass


class ForbiddenKeyError(SanitizeError):
    pass


class SerializationPolicyError(SanitizeError):
    pass


# ---------------------------------------------------------------------------
# Low-level text / token helpers
# ---------------------------------------------------------------------------


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

    out: list[str] = []
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


def _looks_like_pii(s: str) -> bool:
    if not s:
        return False
    if len(s) > _SANITIZE_MAX_STR_LEN:
        return True
    if _PII_EMAIL_RE.search(s):
        return True
    if _PII_PHONE_RE.search(s):
        return True
    if _PII_IDLIKE_RE.search(s):
        return True
    return False


def _safe_text(v: Any, *, max_len: int = 256, redact_mode: str = "none") -> str:
    s = _strip_unsafe_text(_scalar_text(v), max_len=max_len)
    if not s:
        return ""
    mode = (redact_mode or "none").lower()
    if mode in {"token", "log", "strict"} and _looks_like_secret_token(s):
        return "[redacted]"
    if mode == "strict" and _looks_like_high_entropy(s):
        return "[redacted]"
    return s[:max_len]


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


def _token_seq_in(tokens: Sequence[str], seq: Sequence[str]) -> bool:
    if not seq or not tokens or len(seq) > len(tokens):
        return False
    n = len(seq)
    for i in range(0, len(tokens) - n + 1):
        if tuple(tokens[i : i + n]) == tuple(seq):
            return True
    return False


def _entropy_exempt_for_key(key: Optional[str]) -> bool:
    if not key:
        return False
    toks = _key_tokens(key)
    return any(t in _ENTROPY_EXEMPT_TOKENS for t in toks)


def _safe_key_name(v: Any, *, max_len: int = _SANITIZE_MAX_KEY_BYTES) -> Optional[str]:
    if not isinstance(v, str):
        return None
    s = _strip_unsafe_text(v, max_len=max_len).strip()
    if not s:
        return None
    if not _SAFE_KEY_RE.fullmatch(s):
        return None
    return s


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
        try:
            return bytes.fromhex(hx)
        except Exception:
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
        try:
            return bytes.fromhex(s)
        except Exception:
            return None
    try:
        pad = "=" * ((4 - (len(s) % 4)) % 4)
        return base64.urlsafe_b64decode((s + pad).encode("utf-8", errors="strict"))
    except Exception:
        return None


def _safe_profile(v: Any, *, default: Profile = "PROD") -> Profile:
    s = _safe_text(v, max_len=16).upper()
    return s if s in {"DEV", "PROD", "FINREG", "LOCKDOWN"} else default  # type: ignore[return-value]


def _safe_surface(v: Any, *, default: SanitizeSurface = "internal") -> SanitizeSurface:
    s = _safe_text(v, max_len=32).lower()
    if s in {"receipt_public", "receipt_audit", "signal", "storage", "internal"}:
        return s  # type: ignore[return-value]
    return default


def _safe_hash_alg(v: Any, *, default: HashAlgorithm = "sha256") -> HashAlgorithm:
    s = _safe_text(v, max_len=16).lower()
    if s in {"sha256", "blake2s", "blake3"}:
        return s  # type: ignore[return-value]
    return default


# ---------------------------------------------------------------------------
# Numeric helpers
# ---------------------------------------------------------------------------


def is_finite_number(value: Any) -> bool:
    if isinstance(value, bool):
        return True
    if isinstance(value, (int, float)):
        try:
            return math.isfinite(float(value))
        except Exception:
            return False
    return False


def safe_float(value: Any, default: float = 0.0) -> float:
    """
    Strict-enough public helper:
      - bool -> 1.0/0.0
      - int/float finite -> float(value)
      - strict numeric string -> float
      - otherwise default
    """
    try:
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        if isinstance(value, (int, float)):
            f = float(value)
            return f if math.isfinite(f) else float(default)
        if isinstance(value, str):
            s = value.strip()
            if s:
                f = float(s)
                return f if math.isfinite(f) else float(default)
    except Exception:
        return float(default)
    return float(default)


def safe_int(value: Any, default: int = 0) -> int:
    """
    Strict integer conversion:
      - bool -> 1/0
      - int -> int(value)
      - float only if integral and finite
      - strict base-10 integer string
      - otherwise default
    """
    try:
        if isinstance(value, bool):
            return 1 if value else 0
        if isinstance(value, int):
            return int(value)
        if isinstance(value, float):
            if math.isfinite(value) and float(value).is_integer():
                return int(value)
            return int(default)
        if isinstance(value, str):
            s = value.strip()
            if s and re.fullmatch(r"[+-]?\d+", s):
                return int(s, 10)
    except Exception:
        return int(default)
    return int(default)


def parse_int_strict(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("bool is not a strict integer")
    if isinstance(value, int):
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"[+-]?\d+", value.strip() or ""):
        return int(value.strip(), 10)
    raise ValueError("not a strict integer")


def parse_float_strict(value: Any) -> float:
    if isinstance(value, bool):
        raise ValueError("bool is not a strict float")
    if isinstance(value, (int, float)):
        f = float(value)
        if math.isfinite(f):
            return f
        raise ValueError("non-finite float")
    if isinstance(value, str):
        s = value.strip()
        if not s:
            raise ValueError("empty float")
        f = float(s)
        if math.isfinite(f):
            return f
        raise ValueError("non-finite float")
    raise ValueError("not a strict float")


def coerce_int_lossy(value: Any, default: int = 0) -> int:
    try:
        if isinstance(value, bool):
            return 1 if value else 0
        if isinstance(value, (int, float)):
            f = float(value)
            return int(f) if math.isfinite(f) else int(default)
        if isinstance(value, str):
            s = value.strip()
            if s:
                return int(float(s))
    except Exception:
        return int(default)
    return int(default)


@dataclass(frozen=True)
class NumericSanitizeReport:
    nodes_scanned: int = 0
    replaced_nonfinite: int = 0
    truncated_sequences: int = 0
    dropped_values: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "nodes_scanned": int(self.nodes_scanned),
            "replaced_nonfinite": int(self.replaced_nonfinite),
            "truncated_sequences": int(self.truncated_sequences),
            "dropped_values": int(self.dropped_values),
        }


def sanitize_floats(
    obj: Any,
    *,
    default: float = 0.0,
    max_len: Optional[int] = None,
    max_depth: int = _SANITIZE_MAX_DEPTH,
    return_info: Optional[bool] = None,
    _depth: int = 0,
) -> Any:
    """
    Compatibility:
      - sanitize_floats(obj) -> sanitized_obj
      - sanitize_floats(obj, max_len=N) -> (sanitized_obj, info_dict)
    """
    if return_info is None:
        return_info = max_len is not None

    stats = {
        "nodes_scanned": 0,
        "replaced_nonfinite": 0,
        "truncated_sequences": 0,
        "dropped_values": 0,
    }

    def _walk(value: Any, depth: int) -> Any:
        stats["nodes_scanned"] += 1

        if isinstance(value, float):
            if math.isnan(value) or math.isinf(value):
                stats["replaced_nonfinite"] += 1
                return float(default)
            return float(value)

        if depth > max_depth:
            if isinstance(value, (Mapping, list, tuple, set, frozenset)):
                stats["dropped_values"] += 1
                return "[max_depth]"
            return value

        if isinstance(value, (int, bool)):
            return value

        if isinstance(value, Mapping):
            out: Dict[Any, Any] = {}
            for k, v in value.items():
                out[k] = _walk(v, depth + 1)
            return out

        if isinstance(value, (list, tuple)):
            seq = list(value)
            if max_len is not None and len(seq) > int(max_len):
                seq = seq[: int(max_len)]
                stats["truncated_sequences"] += 1
            sanitized_seq = [_walk(x, depth + 1) for x in seq]
            return tuple(sanitized_seq) if isinstance(value, tuple) else sanitized_seq

        return value

    sanitized = _walk(obj, _depth)
    if return_info:
        return sanitized, NumericSanitizeReport(**stats).to_dict()
    return sanitized


# ---------------------------------------------------------------------------
# Rich policy objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CanonicalJsonPolicy:
    schema_version: int = 1
    canonicalization_version: str = _CANONICALIZATION_VERSION
    ensure_ascii: bool = False
    forbid_float: bool = False
    nonfinite_mode: NonFiniteMode = "null"  # reject | null | default | tag
    nonfinite_default: float = 0.0
    oversize_int_mode: OversizeIntMode = "tag"  # reject | tag | clamp
    max_int_bits: int = _MAX_INT_BITS
    sort_keys: bool = True
    compact: bool = True

    def normalized(self) -> "CanonicalJsonPolicy":
        nf = self.nonfinite_mode if self.nonfinite_mode in {"reject", "null", "default", "tag"} else "null"
        oi = self.oversize_int_mode if self.oversize_int_mode in {"reject", "tag", "clamp"} else "tag"
        return CanonicalJsonPolicy(
            schema_version=max(1, min(1_000_000, int(self.schema_version))),
            canonicalization_version=_safe_text(self.canonicalization_version, max_len=64) or _CANONICALIZATION_VERSION,
            ensure_ascii=bool(self.ensure_ascii),
            forbid_float=bool(self.forbid_float),
            nonfinite_mode=nf,
            nonfinite_default=float(self.nonfinite_default) if math.isfinite(float(self.nonfinite_default)) else 0.0,
            oversize_int_mode=oi,
            max_int_bits=max(32, min(8192, int(self.max_int_bits))),
            sort_keys=bool(self.sort_keys),
            compact=bool(self.compact),
        )


@dataclass(frozen=True)
class RedactionPolicy:
    schema_version: int = 1
    strip_pii: bool = True
    redact_secrets: bool = True
    redact_high_entropy: bool = True
    pseudonymize_pii: bool = False
    pseudonymize_secrets: bool = False
    pseudonymize_key: Optional[bytes] = None
    pseudonymize_key_id: Optional[str] = None
    pseudonymize_hex_chars: int = 16
    redact_value_placeholder: str = "[REDACTED]"

    def normalized(self) -> "RedactionPolicy":
        key = self.pseudonymize_key
        if isinstance(key, str):  # type: ignore[unreachable]
            key = _parse_key_material(key)
        kid = _safe_text(self.pseudonymize_key_id, max_len=32) or None
        return RedactionPolicy(
            schema_version=max(1, min(1_000_000, int(self.schema_version))),
            strip_pii=bool(self.strip_pii),
            redact_secrets=bool(self.redact_secrets),
            redact_high_entropy=bool(self.redact_high_entropy),
            pseudonymize_pii=bool(self.pseudonymize_pii),
            pseudonymize_secrets=bool(self.pseudonymize_secrets),
            pseudonymize_key=key if isinstance(key, (bytes, bytearray)) and 1 <= len(key) <= 4096 else None,
            pseudonymize_key_id=kid,
            pseudonymize_hex_chars=max(8, min(64, int(self.pseudonymize_hex_chars))),
            redact_value_placeholder=_safe_text(self.redact_value_placeholder, max_len=32) or "[REDACTED]",
        )


@dataclass(frozen=True)
class KeyPolicyEngine:
    schema_version: int = 1
    forbid_keys: Sequence[str] = tuple(_FORBIDDEN_META_KEYS)
    numeric_only_keys: Sequence[str] = tuple()
    strict_forbidden_key_scan: bool = True
    forbidden_key_action: ForbiddenKeyAction = "reject"

    def normalized(self) -> "KeyPolicyEngine":
        action = self.forbidden_key_action if self.forbidden_key_action in {"reject", "drop", "redact"} else "reject"
        forbid = tuple(str(x) for x in self.forbid_keys or tuple(_FORBIDDEN_META_KEYS))
        nums = tuple(str(x) for x in self.numeric_only_keys or ())
        return KeyPolicyEngine(
            schema_version=max(1, min(1_000_000, int(self.schema_version))),
            forbid_keys=forbid,
            numeric_only_keys=nums,
            strict_forbidden_key_scan=bool(self.strict_forbidden_key_scan),
            forbidden_key_action=action,
        )

    def matches_forbidden(self, key: str) -> bool:
        lower = key.lower()
        exact = {k.lower() for k in self.forbid_keys}
        if lower in exact:
            return True
        if not self.strict_forbidden_key_scan:
            return False
        tokens = _key_tokens(key)
        if not tokens:
            return False
        for raw in self.forbid_keys:
            seq = _key_tokens(str(raw))
            if not seq:
                continue
            if _token_seq_in(tokens, seq):
                return True
        return False

    def numeric_only(self, key: str) -> bool:
        lower = key.lower()
        exact = {k.lower() for k in self.numeric_only_keys}
        if lower in exact:
            return True
        tokens = _key_tokens(key)
        if not tokens:
            return False
        for raw in self.numeric_only_keys:
            seq = _key_tokens(str(raw))
            if seq and _token_seq_in(tokens, seq):
                return True
        return False


@dataclass(frozen=True)
class SanitizePolicyBundle:
    schema_version: int
    engine_version: str
    compatibility_epoch: str
    profile: Profile
    surface: SanitizeSurface
    policy_name: str
    policy_ref: Optional[str]
    policy_digest: str

    max_depth: int
    max_items: int
    max_str_len: int
    max_nodes: int
    max_total_str_bytes: int
    max_total_bytes: int

    return_json_only: bool
    reject_on_forbidden_keys: bool
    allow_unknown_types: bool
    unknown_type_mode: UnknownTypeMode

    redact_behavior: Literal["placeholder", "drop"]
    key_policy: KeyPolicyEngine
    canonical_json: CanonicalJsonPolicy
    redaction: RedactionPolicy


@dataclass(frozen=True)
class SanitizeReport:
    schema_version: int = 1
    engine_version: str = _SANITIZE_ENGINE_VERSION
    compatibility_epoch: str = _COMPATIBILITY_EPOCH
    profile: str = "PROD"
    surface: str = "internal"
    policy_name: str = "default"
    policy_ref: Optional[str] = None
    policy_digest: str = ""

    bytes_in_est: int = 0
    bytes_out: int = 0
    nodes_scanned: int = 0
    strings_seen: int = 0

    redacted_values: int = 0
    pseudonymized_values: int = 0
    dropped_keys: int = 0
    forbidden_key_hits: int = 0
    numeric_type_violations: int = 0
    truncated_nodes: int = 0
    truncated_items: int = 0
    truncated_strings: int = 0
    nonfinite_normalized: int = 0
    oversize_ints: int = 0
    unknown_types_tagged: int = 0
    lossy_transform_count: int = 0
    overflow: bool = False
    compat_mode_used: bool = False
    warnings: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "engine_version": self.engine_version,
            "compatibility_epoch": self.compatibility_epoch,
            "profile": self.profile,
            "surface": self.surface,
            "policy_name": self.policy_name,
            "policy_ref": self.policy_ref,
            "policy_digest": self.policy_digest,
            "bytes_in_est": self.bytes_in_est,
            "bytes_out": self.bytes_out,
            "nodes_scanned": self.nodes_scanned,
            "strings_seen": self.strings_seen,
            "redacted_values": self.redacted_values,
            "pseudonymized_values": self.pseudonymized_values,
            "dropped_keys": self.dropped_keys,
            "forbidden_key_hits": self.forbidden_key_hits,
            "numeric_type_violations": self.numeric_type_violations,
            "truncated_nodes": self.truncated_nodes,
            "truncated_items": self.truncated_items,
            "truncated_strings": self.truncated_strings,
            "nonfinite_normalized": self.nonfinite_normalized,
            "oversize_ints": self.oversize_ints,
            "unknown_types_tagged": self.unknown_types_tagged,
            "lossy_transform_count": self.lossy_transform_count,
            "overflow": self.overflow,
            "compat_mode_used": self.compat_mode_used,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class SanitizeConfig:
    """
    Compatibility + forward path.

    Old call sites can still pass:
      SanitizeConfig(sanitize_nan=..., prune_large=..., strip_pii=..., forbid_keys=...)
    New call sites can set profile/surface/redaction/strict behavior and compile via to_bundle().
    """

    profile: Profile = "PROD"
    surface: SanitizeSurface = "internal"
    policy_name: str = "default"
    policy_ref: Optional[str] = None

    max_depth: int = _SANITIZE_MAX_DEPTH
    max_list_len: int = _SANITIZE_MAX_LIST_LEN
    max_str_len: int = _SANITIZE_MAX_STR_LEN
    max_nodes: int = _SANITIZE_MAX_NODES
    max_total_str_bytes: int = _SANITIZE_MAX_TOTAL_STR_BYTES
    max_total_bytes: int = _SANITIZE_MAX_TOTAL_BYTES

    sanitize_nan: bool = True
    prune_large: bool = True
    strip_pii: bool = True
    redact_secrets: bool = True
    redact_high_entropy_in_external: bool = True

    forbid_keys: Sequence[str] = tuple(_FORBIDDEN_META_KEYS)
    numeric_only_keys: Sequence[str] = tuple()

    strict_forbidden_key_scan: bool = True
    reject_on_forbidden_keys: bool = True
    return_json_only: bool = True

    # forward knobs
    redact_behavior: Literal["placeholder", "drop"] = "placeholder"
    forbidden_key_action: Optional[ForbiddenKeyAction] = None
    nonfinite_mode: Optional[NonFiniteMode] = None
    oversize_int_mode: Optional[OversizeIntMode] = None
    unknown_type_mode: Optional[UnknownTypeMode] = None
    allow_unknown_types: Optional[bool] = None
    pseudonymize_pii: bool = False
    pseudonymize_secrets: bool = False
    pseudonymize_key: Optional[Any] = None
    pseudonymize_key_id: Optional[str] = None
    pseudonymize_hex_chars: int = 16
    ensure_ascii: bool = False
    forbid_float: bool = False
    canonicalization_version: str = _CANONICALIZATION_VERSION

    def normalized(self) -> "SanitizeConfig":
        profile = _safe_profile(self.profile)
        surface = _safe_surface(self.surface)
        policy_name = _safe_text(self.policy_name, max_len=64) or "default"
        policy_ref = _safe_text(self.policy_ref, max_len=128) or None if isinstance(self.policy_ref, str) else None
        pk = self.pseudonymize_key
        if isinstance(pk, str):
            pk = _parse_key_material(pk)
        return SanitizeConfig(
            profile=profile,
            surface=surface,
            policy_name=policy_name,
            policy_ref=policy_ref,
            max_depth=max(1, min(128, int(self.max_depth))),
            max_list_len=max(1, min(4096, int(self.max_list_len))),
            max_str_len=max(32, min(1_000_000, int(self.max_str_len))),
            max_nodes=max(64, min(1_000_000, int(self.max_nodes))),
            max_total_str_bytes=max(1024, min(16_000_000, int(self.max_total_str_bytes))),
            max_total_bytes=max(2048, min(64_000_000, int(self.max_total_bytes))),
            sanitize_nan=bool(self.sanitize_nan),
            prune_large=bool(self.prune_large),
            strip_pii=bool(self.strip_pii),
            redact_secrets=bool(self.redact_secrets),
            redact_high_entropy_in_external=bool(self.redact_high_entropy_in_external),
            forbid_keys=tuple(str(x) for x in self.forbid_keys or tuple(_FORBIDDEN_META_KEYS)),
            numeric_only_keys=tuple(str(x) for x in self.numeric_only_keys or ()),
            strict_forbidden_key_scan=bool(self.strict_forbidden_key_scan),
            reject_on_forbidden_keys=bool(self.reject_on_forbidden_keys),
            return_json_only=bool(self.return_json_only),
            redact_behavior="drop" if self.redact_behavior == "drop" else "placeholder",
            forbidden_key_action=self.forbidden_key_action if self.forbidden_key_action in {"reject", "drop", "redact"} else None,
            nonfinite_mode=self.nonfinite_mode if self.nonfinite_mode in {"reject", "null", "default", "tag"} else None,
            oversize_int_mode=self.oversize_int_mode if self.oversize_int_mode in {"reject", "tag", "clamp"} else None,
            unknown_type_mode=self.unknown_type_mode if self.unknown_type_mode in {"tag", "drop", "reject"} else None,
            allow_unknown_types=None if self.allow_unknown_types is None else bool(self.allow_unknown_types),
            pseudonymize_pii=bool(self.pseudonymize_pii),
            pseudonymize_secrets=bool(self.pseudonymize_secrets),
            pseudonymize_key=pk if isinstance(pk, (bytes, bytearray)) else None,
            pseudonymize_key_id=_safe_text(self.pseudonymize_key_id, max_len=32) or None if isinstance(self.pseudonymize_key_id, str) else None,
            pseudonymize_hex_chars=max(8, min(64, int(self.pseudonymize_hex_chars))),
            ensure_ascii=bool(self.ensure_ascii),
            forbid_float=bool(self.forbid_float),
            canonicalization_version=_safe_text(self.canonicalization_version, max_len=64) or _CANONICALIZATION_VERSION,
        )

    def to_bundle(self) -> "SanitizePolicyBundle":
        cfg = self.normalized()
        defaults = _surface_defaults(profile=cfg.profile, surface=cfg.surface)
        combined_forbid = tuple(
            dict.fromkeys(
                list(_FORBIDDEN_META_KEYS)
                + list(_FORBIDDEN_META_KEY_TOKENS)
                + list(cfg.forbid_keys or ())
                + list(defaults["forbid_keys"] or ())
            ).keys()
        )
        forbidden_action = cfg.forbidden_key_action or ("reject" if cfg.reject_on_forbidden_keys else defaults["forbidden_key_action"])
        key_policy = KeyPolicyEngine(
            forbid_keys=combined_forbid,
            numeric_only_keys=cfg.numeric_only_keys,
            strict_forbidden_key_scan=cfg.strict_forbidden_key_scan,
            forbidden_key_action=forbidden_action,
        ).normalized()

        redaction = RedactionPolicy(
            strip_pii=cfg.strip_pii,
            redact_secrets=cfg.redact_secrets,
            redact_high_entropy=(cfg.redact_high_entropy_in_external if cfg.surface != "internal" else False),
            pseudonymize_pii=cfg.pseudonymize_pii,
            pseudonymize_secrets=cfg.pseudonymize_secrets,
            pseudonymize_key=cfg.pseudonymize_key if isinstance(cfg.pseudonymize_key, (bytes, bytearray)) else None,
            pseudonymize_key_id=cfg.pseudonymize_key_id,
            pseudonymize_hex_chars=cfg.pseudonymize_hex_chars,
        ).normalized()

        canonical = CanonicalJsonPolicy(
            canonicalization_version=cfg.canonicalization_version,
            ensure_ascii=cfg.ensure_ascii,
            forbid_float=cfg.forbid_float or defaults["forbid_float"],
            nonfinite_mode=cfg.nonfinite_mode or defaults["nonfinite_mode"],
            oversize_int_mode=cfg.oversize_int_mode or defaults["oversize_int_mode"],
            max_int_bits=_MAX_INT_BITS,
        ).normalized()

        bundle_material = {
            "engine_version": _SANITIZE_ENGINE_VERSION,
            "compatibility_epoch": _COMPATIBILITY_EPOCH,
            "profile": cfg.profile,
            "surface": cfg.surface,
            "policy_name": cfg.policy_name,
            "policy_ref": cfg.policy_ref,
            "max_depth": cfg.max_depth,
            "max_items": cfg.max_list_len,
            "max_str_len": cfg.max_str_len,
            "max_nodes": cfg.max_nodes,
            "max_total_str_bytes": cfg.max_total_str_bytes,
            "max_total_bytes": cfg.max_total_bytes,
            "return_json_only": cfg.return_json_only,
            "reject_on_forbidden_keys": cfg.reject_on_forbidden_keys,
            "allow_unknown_types": defaults["allow_unknown_types"] if cfg.allow_unknown_types is None else bool(cfg.allow_unknown_types),
            "unknown_type_mode": cfg.unknown_type_mode or defaults["unknown_type_mode"],
            "redact_behavior": cfg.redact_behavior,
            "key_policy": {
                "forbid_keys": list(key_policy.forbid_keys),
                "numeric_only_keys": list(key_policy.numeric_only_keys),
                "strict_forbidden_key_scan": key_policy.strict_forbidden_key_scan,
                "forbidden_key_action": key_policy.forbidden_key_action,
            },
            "canonical": {
                "forbid_float": canonical.forbid_float,
                "nonfinite_mode": canonical.nonfinite_mode,
                "oversize_int_mode": canonical.oversize_int_mode,
                "ensure_ascii": canonical.ensure_ascii,
                "canonicalization_version": canonical.canonicalization_version,
            },
            "redaction": {
                "strip_pii": redaction.strip_pii,
                "redact_secrets": redaction.redact_secrets,
                "redact_high_entropy": redaction.redact_high_entropy,
                "pseudonymize_pii": redaction.pseudonymize_pii,
                "pseudonymize_secrets": redaction.pseudonymize_secrets,
                "pseudonymize_key_present": redaction.pseudonymize_key is not None,
                "pseudonymize_key_id": redaction.pseudonymize_key_id,
                "pseudonymize_hex_chars": redaction.pseudonymize_hex_chars,
            },
        }
        policy_digest = make_policy_fingerprint(bundle_material)
        return SanitizePolicyBundle(
            schema_version=1,
            engine_version=_SANITIZE_ENGINE_VERSION,
            compatibility_epoch=_COMPATIBILITY_EPOCH,
            profile=cfg.profile,
            surface=cfg.surface,
            policy_name=cfg.policy_name,
            policy_ref=cfg.policy_ref,
            policy_digest=policy_digest,
            max_depth=cfg.max_depth,
            max_items=cfg.max_list_len,
            max_str_len=cfg.max_str_len,
            max_nodes=cfg.max_nodes,
            max_total_str_bytes=cfg.max_total_str_bytes,
            max_total_bytes=cfg.max_total_bytes,
            return_json_only=cfg.return_json_only,
            reject_on_forbidden_keys=cfg.reject_on_forbidden_keys,
            allow_unknown_types=defaults["allow_unknown_types"] if cfg.allow_unknown_types is None else bool(cfg.allow_unknown_types),
            unknown_type_mode=cfg.unknown_type_mode or defaults["unknown_type_mode"],
            redact_behavior=cfg.redact_behavior,
            key_policy=key_policy,
            canonical_json=canonical,
            redaction=redaction,
        )


# ---------------------------------------------------------------------------
# Policy defaults / fingerprints / pseudonyms
# ---------------------------------------------------------------------------


def _stable_jsonable(obj: Any) -> Any:
    if obj is None or isinstance(obj, (bool, int)):
        return obj
    if isinstance(obj, float):
        if not math.isfinite(obj):
            return None
        s = f"{float(obj):.12f}".rstrip("0").rstrip(".")
        return s or "0"
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
    return _safe_text(obj, max_len=64, redact_mode="strict") or f"<{type(obj).__name__}>"


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        _stable_jsonable(obj),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8", errors="strict")


def _surface_defaults(*, profile: Profile, surface: SanitizeSurface) -> Dict[str, Any]:
    strict_profile = profile in {"FINREG", "LOCKDOWN"}

    defaults: Dict[str, Any] = {
        "allow_unknown_types": False,
        "unknown_type_mode": "tag",
        "forbidden_key_action": "reject",
        "nonfinite_mode": "null",
        "oversize_int_mode": "tag",
        "forbid_float": False,
        "forbid_keys": tuple(_FORBIDDEN_META_KEYS) + tuple(sorted(_FORBIDDEN_META_KEY_TOKENS - set(_FORBIDDEN_META_KEYS))),
    }

    if surface == "internal":
        defaults.update(
            {
                "allow_unknown_types": True,
                "unknown_type_mode": "tag",
                "forbidden_key_action": "drop",
                "nonfinite_mode": "default",
                "oversize_int_mode": "tag",
                "forbid_float": False,
            }
        )
    elif surface == "receipt_audit":
        defaults.update(
            {
                "allow_unknown_types": False,
                "unknown_type_mode": "tag",
                "forbidden_key_action": "drop" if not strict_profile else "reject",
                "nonfinite_mode": "null" if strict_profile else "tag",
                "oversize_int_mode": "tag",
                "forbid_float": False,
            }
        )
    elif surface == "receipt_public":
        defaults.update(
            {
                "allow_unknown_types": False,
                "unknown_type_mode": "drop" if strict_profile else "tag",
                "forbidden_key_action": "drop",
                "nonfinite_mode": "null",
                "oversize_int_mode": "tag",
                "forbid_float": strict_profile,
            }
        )
    elif surface == "signal":
        defaults.update(
            {
                "allow_unknown_types": False,
                "unknown_type_mode": "tag",
                "forbidden_key_action": "reject" if strict_profile else "drop",
                "nonfinite_mode": "null",
                "oversize_int_mode": "tag",
                "forbid_float": False,
            }
        )
    elif surface == "storage":
        defaults.update(
            {
                "allow_unknown_types": False,
                "unknown_type_mode": "tag",
                "forbidden_key_action": "reject" if strict_profile else "drop",
                "nonfinite_mode": "null",
                "oversize_int_mode": "tag",
                "forbid_float": False,
            }
        )
    return defaults


def make_policy_fingerprint(policy: Any) -> str:
    payload = {
        "engine_version": _SANITIZE_ENGINE_VERSION,
        "compatibility_epoch": _COMPATIBILITY_EPOCH,
        "policy": _stable_jsonable(policy),
    }
    raw = _canonical_json_bytes(payload)
    if Blake3Hash is not None:
        try:
            return f"spol1:blake3:{Blake3Hash().hex(raw, ctx='tcd:utils:policy')[:32]}"
        except Exception:
            pass
    return f"spol1:sha256:{hashlib.sha256(raw).hexdigest()[:32]}"


def deterministic_pseudonymize(
    value: Any,
    *,
    purpose: str,
    key: Optional[bytes] = None,
    key_id: Optional[str] = None,
    prefix: str = "p",
    hex_chars: int = 16,
) -> str:
    raw = _safe_text(value, max_len=4096, redact_mode="none").encode("utf-8", errors="ignore")
    label = _safe_text(purpose, max_len=64) or "generic"
    prefix_s = _safe_text(prefix, max_len=16) or "p"
    out_hex = max(8, min(64, int(hex_chars)))
    if key:
        dig = hmac.new(key, b"tcd:pseudo:v1\x00" + label.encode("utf-8") + b"\x00" + raw, hashlib.sha256).hexdigest()[:out_hex]
        kid = _safe_text(key_id, max_len=16) or "hmac"
        return f"{prefix_s}-{kid}-{dig}"
    dig = hashlib.sha256(b"tcd:pseudo:v1\x00" + label.encode("utf-8") + b"\x00" + raw).hexdigest()[:out_hex]
    return f"{prefix_s}-sha256-{dig}"


# ---------------------------------------------------------------------------
# Key enforcement
# ---------------------------------------------------------------------------


def _matches_forbidden_key(key: str, *, engine: KeyPolicyEngine) -> bool:
    return engine.matches_forbidden(key)


def enforce_metadata_keys(
    obj: Any,
    *,
    forbid_keys: Iterable[str] = (),
    numeric_only_keys: Iterable[str] = (),
    max_depth: int = 3,
    strict_forbidden_key_scan: bool = True,
    _depth: int = 0,
) -> None:
    """
    Recursive validation for ANY top-level JSON shape (dict/list/tuple/set).
    """
    if _depth > max_depth:
        return

    engine = KeyPolicyEngine(
        forbid_keys=tuple(forbid_keys),
        numeric_only_keys=tuple(numeric_only_keys),
        strict_forbidden_key_scan=bool(strict_forbidden_key_scan),
        forbidden_key_action="reject",
    ).normalized()

    if isinstance(obj, Mapping):
        for k, v in obj.items():
            key_str = str(k)
            if _matches_forbidden_key(key_str, engine=engine):
                raise ForbiddenKeyError(
                    f"Metadata contains forbidden key '{key_str}'; raw content MUST NOT be attached here."
                )
            if engine.numeric_only(key_str):
                if v is not None and not isinstance(v, (int, float, bool)):
                    raise ValueError(
                        f"Metadata key '{key_str}' must be numeric/bool/None; got {type(v).__name__}."
                    )
                if isinstance(v, (int, float)) and not math.isfinite(float(v)):
                    raise ValueError(
                        f"Metadata key '{key_str}' must be a finite number; got non-finite value."
                    )
            enforce_metadata_keys(
                v,
                forbid_keys=engine.forbid_keys,
                numeric_only_keys=engine.numeric_only_keys,
                max_depth=max_depth,
                strict_forbidden_key_scan=engine.strict_forbidden_key_scan,
                _depth=_depth + 1,
            )
        return

    if isinstance(obj, (list, tuple, set, frozenset)):
        for v in obj:
            enforce_metadata_keys(
                v,
                forbid_keys=forbid_keys,
                numeric_only_keys=numeric_only_keys,
                max_depth=max_depth,
                strict_forbidden_key_scan=strict_forbidden_key_scan,
                _depth=_depth + 1,
            )


# ---------------------------------------------------------------------------
# Reports / budgets / walker
# ---------------------------------------------------------------------------


class _Budget:
    __slots__ = (
        "max_nodes",
        "max_items",
        "max_depth",
        "max_str_total",
        "max_total_bytes",
        "nodes",
        "str_used",
        "bytes_used",
    )

    def __init__(
        self,
        *,
        max_nodes: int,
        max_items: int,
        max_depth: int,
        max_str_total: int,
        max_total_bytes: int,
    ) -> None:
        self.max_nodes = max_nodes
        self.max_items = max_items
        self.max_depth = max_depth
        self.max_str_total = max_str_total
        self.max_total_bytes = max_total_bytes
        self.nodes = 0
        self.str_used = 0
        self.bytes_used = 0

    def take_node(self) -> bool:
        self.nodes += 1
        return self.nodes <= self.max_nodes

    def take_str(self, n: int) -> bool:
        self.str_used += n
        self.bytes_used += n
        return self.str_used <= self.max_str_total and self.bytes_used <= self.max_total_bytes

    def take_bytes(self, n: int) -> bool:
        self.bytes_used += n
        return self.bytes_used <= self.max_total_bytes


def _report_add_warning(report: SanitizeReport, code: str) -> SanitizeReport:
    ws = list(report.warnings)
    if code not in ws:
        ws.append(code)
    return dataclasses_replace(report, warnings=tuple(ws))


def dataclasses_replace(obj: Any, **kwargs: Any) -> Any:
    import dataclasses as _dc
    return _dc.replace(obj, **kwargs)


def _estimate_struct_bytes(obj: Any, *, max_depth: int = 16, _depth: int = 0) -> int:
    if _depth > max_depth:
        return 16
    if obj is None:
        return 4
    if isinstance(obj, bool):
        return 4
    if isinstance(obj, int):
        return len(str(obj))
    if isinstance(obj, float):
        return 8 if math.isfinite(obj) else 4
    if isinstance(obj, str):
        return len(obj.encode("utf-8", errors="ignore"))
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return len(obj)
    if isinstance(obj, Mapping):
        total = 2
        for k, v in obj.items():
            if isinstance(k, str):
                total += len(k.encode("utf-8", errors="ignore"))
            total += _estimate_struct_bytes(v, max_depth=max_depth, _depth=_depth + 1)
        return total
    if isinstance(obj, (list, tuple, set, frozenset)):
        total = 2
        for v in obj:
            total += _estimate_struct_bytes(v, max_depth=max_depth, _depth=_depth + 1)
        return total
    return len(f"<{type(obj).__name__}>".encode("utf-8", errors="ignore"))


def _mask_email(m: re.Match) -> str:
    full = m.group(0)
    local, _, domain = full.partition("@")
    if len(local) <= 1:
        masked_local = "*"
    elif len(local) == 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[:2] + "***"
    return f"{masked_local}@{domain}"


def _mask_phone(m: re.Match) -> str:
    full = re.sub(r"\s+", "", m.group(0))
    if len(full) <= 4:
        return "***"
    return "***" + full[-4:]


def _redact_pii_in_str(s: str) -> str:
    if not s:
        return s
    s = _PII_EMAIL_RE.sub(_mask_email, s)
    s = _PII_PHONE_RE.sub(_mask_phone, s)
    s = _PII_IDLIKE_RE.sub("[ID_REDACTED]", s)
    return s


def redact_pii_metadata(
    obj: Any,
    *,
    _depth: int = 0,
    max_depth: int = _SANITIZE_MAX_DEPTH,
) -> Any:
    if _depth > max_depth:
        return obj
    if isinstance(obj, str):
        return _redact_pii_in_str(obj)
    if isinstance(obj, Mapping):
        out: Dict[Any, Any] = {}
        for k, v in obj.items():
            out[k] = redact_pii_metadata(v, _depth=_depth + 1, max_depth=max_depth)
        return out
    if isinstance(obj, (list, tuple)):
        seq = [redact_pii_metadata(x, _depth=_depth + 1, max_depth=max_depth) for x in obj]
        return tuple(seq) if isinstance(obj, tuple) else seq
    return obj


def redact_secret_metadata(
    obj: Any,
    *,
    _depth: int = 0,
    max_depth: int = _SANITIZE_MAX_DEPTH,
    redact_high_entropy: bool = False,
) -> Any:
    if _depth > max_depth:
        return obj
    if isinstance(obj, str):
        s = _strip_unsafe_text(obj, max_len=_SANITIZE_MAX_STR_LEN)
        if _looks_like_secret_token(s):
            return "[SECRET_REDACTED]"
        if redact_high_entropy and _looks_like_high_entropy(s):
            return "[SECRET_REDACTED]"
        return s
    if isinstance(obj, Mapping):
        out: Dict[Any, Any] = {}
        for k, v in obj.items():
            out[k] = redact_secret_metadata(
                v,
                _depth=_depth + 1,
                max_depth=max_depth,
                redact_high_entropy=redact_high_entropy,
            )
        return out
    if isinstance(obj, (list, tuple)):
        seq = [
            redact_secret_metadata(
                x,
                _depth=_depth + 1,
                max_depth=max_depth,
                redact_high_entropy=redact_high_entropy,
            )
            for x in obj
        ]
        return tuple(seq) if isinstance(obj, tuple) else seq
    return obj


def _overflow_envelope(*, bundle: SanitizePolicyBundle, report: SanitizeReport, max_bytes: int) -> Dict[str, Any]:
    return {
        "_schema": "tcd.meta.overflow.v1",
        "_engine_version": bundle.engine_version,
        "_compatibility_epoch": bundle.compatibility_epoch,
        "_canonicalization_version": bundle.canonical_json.canonicalization_version,
        "_surface": bundle.surface,
        "_profile": bundle.profile,
        "_policy_digest": bundle.policy_digest,
        "_overflow": True,
        "_max_bytes": int(max_bytes),
        "_bytes_in_est": int(report.bytes_in_est),
        "_bytes_out": int(report.bytes_out),
        "_warnings": list(report.warnings),
    }


def _apply_string_redaction(
    s: str,
    *,
    key_context: Optional[str],
    bundle: SanitizePolicyBundle,
    report: SanitizeReport,
) -> Tuple[str, SanitizeReport]:
    out = s
    is_secret = _looks_like_secret_token(s)
    is_pii = _looks_like_pii(s)
    is_entropy = _looks_like_high_entropy(s) and not _entropy_exempt_for_key(key_context)

    if bundle.redaction.redact_secrets and is_secret:
        if bundle.redaction.pseudonymize_secrets:
            out = deterministic_pseudonymize(
                s,
                purpose=f"secret:{key_context or 'value'}",
                key=bundle.redaction.pseudonymize_key,
                key_id=bundle.redaction.pseudonymize_key_id,
                prefix="secret",
                hex_chars=bundle.redaction.pseudonymize_hex_chars,
            )
            report = dataclasses_replace(
                report,
                pseudonymized_values=report.pseudonymized_values + 1,
                lossy_transform_count=report.lossy_transform_count + 1,
            )
        else:
            out = bundle.redaction.redact_value_placeholder
            report = dataclasses_replace(
                report,
                redacted_values=report.redacted_values + 1,
                lossy_transform_count=report.lossy_transform_count + 1,
            )
        return out, report

    if bundle.redaction.strip_pii and is_pii:
        if bundle.redaction.pseudonymize_pii:
            out = deterministic_pseudonymize(
                s,
                purpose=f"pii:{key_context or 'value'}",
                key=bundle.redaction.pseudonymize_key,
                key_id=bundle.redaction.pseudonymize_key_id,
                prefix="pii",
                hex_chars=bundle.redaction.pseudonymize_hex_chars,
            )
            report = dataclasses_replace(
                report,
                pseudonymized_values=report.pseudonymized_values + 1,
                lossy_transform_count=report.lossy_transform_count + 1,
            )
        else:
            red = _redact_pii_in_str(s)
            if red != s:
                out = red
                report = dataclasses_replace(
                    report,
                    redacted_values=report.redacted_values + 1,
                    lossy_transform_count=report.lossy_transform_count + 1,
                )
        return out, report

    if bundle.redaction.redact_high_entropy and is_entropy:
        out = bundle.redaction.redact_value_placeholder
        report = dataclasses_replace(
            report,
            redacted_values=report.redacted_values + 1,
            lossy_transform_count=report.lossy_transform_count + 1,
        )
        return out, report

    return out, report


def _sanitize_any(
    obj: Any,
    *,
    bundle: SanitizePolicyBundle,
    report: SanitizeReport,
    budget: _Budget,
    depth: int = 0,
    key_context: Optional[str] = None,
) -> Tuple[Any, SanitizeReport]:
    report = dataclasses_replace(report, nodes_scanned=report.nodes_scanned + 1)

    if not budget.take_node():
        report = dataclasses_replace(
            report,
            truncated_nodes=report.truncated_nodes + 1,
            lossy_transform_count=report.lossy_transform_count + 1,
        )
        return "[truncated]", report

    if depth > bundle.max_depth:
        report = dataclasses_replace(
            report,
            truncated_nodes=report.truncated_nodes + 1,
            lossy_transform_count=report.lossy_transform_count + 1,
        )
        return {"_truncated": True, "_depth": depth}, report

    if obj is None:
        return None, report

    t = type(obj)

    if t is bool:
        return bool(obj), report

    if t is int:
        if obj.bit_length() > bundle.canonical_json.max_int_bits:
            report = dataclasses_replace(
                report,
                oversize_ints=report.oversize_ints + 1,
                lossy_transform_count=report.lossy_transform_count + 1,
            )
            if bundle.canonical_json.oversize_int_mode == "reject":
                raise SerializationPolicyError("oversize integer rejected by policy")
            if bundle.canonical_json.oversize_int_mode == "clamp":
                maxv = (1 << bundle.canonical_json.max_int_bits) - 1
                return int(maxv if obj >= 0 else -maxv), report
            return "[int:oversize]", report
        return int(obj), report

    if t is float:
        if not math.isfinite(obj):
            report = dataclasses_replace(
                report,
                nonfinite_normalized=report.nonfinite_normalized + 1,
                lossy_transform_count=report.lossy_transform_count + 1,
            )
            mode = bundle.canonical_json.nonfinite_mode
            if mode == "reject":
                raise SerializationPolicyError("non-finite float rejected by policy")
            if mode == "null":
                return None, report
            if mode == "default":
                return float(bundle.canonical_json.nonfinite_default), report
            return "[float:nonfinite]", report
        if bundle.canonical_json.forbid_float:
            raise SerializationPolicyError("float rejected by canonical policy")
        return float(obj), report

    if t is str:
        s = _strip_unsafe_text(obj, max_len=bundle.max_str_len)
        report = dataclasses_replace(report, strings_seen=report.strings_seen + 1)
        s2, report = _apply_string_redaction(s, key_context=key_context, bundle=bundle, report=report)
        if len(s2) > bundle.max_str_len:
            s2 = s2[: bundle.max_str_len]
            report = dataclasses_replace(
                report,
                truncated_strings=report.truncated_strings + 1,
                lossy_transform_count=report.lossy_transform_count + 1,
            )
        if not budget.take_str(len(s2.encode("utf-8", errors="ignore"))):
            report = dataclasses_replace(
                report,
                truncated_strings=report.truncated_strings + 1,
                lossy_transform_count=report.lossy_transform_count + 1,
            )
            return "[truncated]", report
        return s2, report

    if t in (bytes, bytearray, memoryview):
        marker = f"[bytes:{len(obj)}]"
        if not budget.take_bytes(len(marker.encode("utf-8", errors="ignore"))):
            report = dataclasses_replace(
                report,
                truncated_strings=report.truncated_strings + 1,
                lossy_transform_count=report.lossy_transform_count + 1,
            )
            return "[truncated]", report
        return marker, report

    if isinstance(obj, Mapping):
        out: Dict[str, Any] = {}
        scanned = 0
        for raw_k, raw_v in obj.items():
            scanned += 1
            if scanned > bundle.max_items:
                out["_truncated"] = True
                report = dataclasses_replace(
                    report,
                    truncated_items=report.truncated_items + 1,
                    lossy_transform_count=report.lossy_transform_count + 1,
                )
                break

            kk = _safe_key_name(raw_k)
            if kk is None:
                report = dataclasses_replace(
                    report,
                    dropped_keys=report.dropped_keys + 1,
                    lossy_transform_count=report.lossy_transform_count + 1,
                )
                continue

            if bundle.key_policy.matches_forbidden(kk):
                report = dataclasses_replace(
                    report,
                    forbidden_key_hits=report.forbidden_key_hits + 1,
                    dropped_keys=report.dropped_keys + 1,
                    lossy_transform_count=report.lossy_transform_count + 1,
                )
                action = bundle.key_policy.forbidden_key_action
                if bundle.reject_on_forbidden_keys and action == "reject":
                    raise ForbiddenKeyError(f"forbidden key: {kk}")
                if action == "redact":
                    out[kk] = bundle.redaction.redact_value_placeholder
                    continue
                # drop
                continue

            if bundle.key_policy.numeric_only(kk):
                if raw_v is not None and not isinstance(raw_v, (int, float, bool)):
                    report = dataclasses_replace(
                        report,
                        numeric_type_violations=report.numeric_type_violations + 1,
                        lossy_transform_count=report.lossy_transform_count + 1,
                    )
                    raise SerializationPolicyError(f"numeric-only key '{kk}' violated policy")
                if isinstance(raw_v, (int, float)) and not math.isfinite(float(raw_v)):
                    report = dataclasses_replace(
                        report,
                        numeric_type_violations=report.numeric_type_violations + 1,
                        lossy_transform_count=report.lossy_transform_count + 1,
                    )
                    raise SerializationPolicyError(f"numeric-only key '{kk}' has non-finite value")

            sanitized_v, report = _sanitize_any(
                raw_v,
                bundle=bundle,
                report=report,
                budget=budget,
                depth=depth + 1,
                key_context=kk,
            )
            out[kk] = sanitized_v
        return out, report

    if isinstance(obj, (list, tuple)):
        out_list: list[Any] = []
        for idx, item in enumerate(obj):
            if idx >= bundle.max_items:
                out_list.append("[truncated]")
                report = dataclasses_replace(
                    report,
                    truncated_items=report.truncated_items + 1,
                    lossy_transform_count=report.lossy_transform_count + 1,
                )
                break
            sv, report = _sanitize_any(
                item,
                bundle=bundle,
                report=report,
                budget=budget,
                depth=depth + 1,
                key_context=key_context,
            )
            out_list.append(sv)
        return (tuple(out_list) if isinstance(obj, tuple) else out_list), report

    if isinstance(obj, (set, frozenset)):
        xs: list[Any] = []
        for idx, item in enumerate(list(obj)):
            if idx >= bundle.max_items:
                xs.append("[truncated]")
                report = dataclasses_replace(
                    report,
                    truncated_items=report.truncated_items + 1,
                    lossy_transform_count=report.lossy_transform_count + 1,
                )
                break
            sv, report = _sanitize_any(
                item,
                bundle=bundle,
                report=report,
                budget=budget,
                depth=depth + 1,
                key_context=key_context,
            )
            xs.append(sv)
        try:
            xs = sorted(
                xs,
                key=lambda x: json.dumps(
                    x,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ),
            )
        except Exception:
            pass
        return xs, report

    # Unknown objects
    report = dataclasses_replace(
        report,
        unknown_types_tagged=report.unknown_types_tagged + 1,
        lossy_transform_count=report.lossy_transform_count + 1,
    )
    if not bundle.allow_unknown_types and bundle.unknown_type_mode == "reject":
        raise SerializationPolicyError(f"unknown type rejected: {type(obj).__name__}")
    if bundle.unknown_type_mode == "drop":
        return None, report
    return f"[type:{type(obj).__name__}]", report


def sanitize_with_report(
    obj: Any,
    *,
    policy: SanitizePolicyBundle | SanitizeConfig | None = None,
) -> Tuple[Any, SanitizeReport]:
    bundle = policy if isinstance(policy, SanitizePolicyBundle) else (policy.to_bundle() if isinstance(policy, SanitizeConfig) else SanitizeConfig().to_bundle())
    report = SanitizeReport(
        profile=bundle.profile,
        surface=bundle.surface,
        policy_name=bundle.policy_name,
        policy_ref=bundle.policy_ref,
        policy_digest=bundle.policy_digest,
        bytes_in_est=_estimate_struct_bytes(obj),
        compat_mode_used=not isinstance(policy, SanitizePolicyBundle),
    )
    budget = _Budget(
        max_nodes=bundle.max_nodes,
        max_items=bundle.max_items,
        max_depth=bundle.max_depth,
        max_str_total=bundle.max_total_str_bytes,
        max_total_bytes=bundle.max_total_bytes,
    )
    sanitized, report = _sanitize_any(obj, bundle=bundle, report=report, budget=budget)
    try:
        out_bytes = len(
            json.dumps(
                _stable_jsonable(sanitized),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=bundle.canonical_json.ensure_ascii,
                allow_nan=False,
            ).encode("utf-8", errors="strict")
        )
    except Exception:
        out_bytes = 0

    if out_bytes > bundle.max_total_bytes:
        report = dataclasses_replace(
            report,
            bytes_out=out_bytes,
            overflow=True,
            lossy_transform_count=report.lossy_transform_count + 1,
        )
        return _overflow_envelope(bundle=bundle, report=report, max_bytes=bundle.max_total_bytes), report

    report = dataclasses_replace(report, bytes_out=out_bytes)
    return sanitized, report


# ---------------------------------------------------------------------------
# Public bundle-based APIs
# ---------------------------------------------------------------------------


def sanitize_for_receipt_public(
    obj: Any,
    *,
    policy: SanitizePolicyBundle | SanitizeConfig | None = None,
) -> Tuple[Any, SanitizeReport]:
    cfg = policy if isinstance(policy, SanitizePolicyBundle) else (
        policy if isinstance(policy, SanitizeConfig) else SanitizeConfig(profile="PROD", surface="receipt_public")
    )
    if isinstance(cfg, SanitizeConfig):
        cfg = cfg.normalized()
        cfg = dataclasses_replace(cfg, surface="receipt_public")
    return sanitize_with_report(obj, policy=cfg)


def sanitize_for_receipt_audit(
    obj: Any,
    *,
    policy: SanitizePolicyBundle | SanitizeConfig | None = None,
) -> Tuple[Any, SanitizeReport]:
    cfg = policy if isinstance(policy, SanitizePolicyBundle) else (
        policy if isinstance(policy, SanitizeConfig) else SanitizeConfig(profile="PROD", surface="receipt_audit")
    )
    if isinstance(cfg, SanitizeConfig):
        cfg = cfg.normalized()
        cfg = dataclasses_replace(cfg, surface="receipt_audit")
    return sanitize_with_report(obj, policy=cfg)


def sanitize_for_signal(
    obj: Any,
    *,
    policy: SanitizePolicyBundle | SanitizeConfig | None = None,
) -> Tuple[Any, SanitizeReport]:
    cfg = policy if isinstance(policy, SanitizePolicyBundle) else (
        policy if isinstance(policy, SanitizeConfig) else SanitizeConfig(profile="PROD", surface="signal")
    )
    if isinstance(cfg, SanitizeConfig):
        cfg = cfg.normalized()
        cfg = dataclasses_replace(cfg, surface="signal")
    return sanitize_with_report(obj, policy=cfg)


def sanitize_for_storage(
    obj: Any,
    *,
    policy: SanitizePolicyBundle | SanitizeConfig | None = None,
) -> Tuple[Any, SanitizeReport]:
    cfg = policy if isinstance(policy, SanitizePolicyBundle) else (
        policy if isinstance(policy, SanitizeConfig) else SanitizeConfig(profile="PROD", surface="storage")
    )
    if isinstance(cfg, SanitizeConfig):
        cfg = cfg.normalized()
        cfg = dataclasses_replace(cfg, surface="storage")
    return sanitize_with_report(obj, policy=cfg)


# ---------------------------------------------------------------------------
# Compatibility wrappers
# ---------------------------------------------------------------------------


def sanitize_metadata_for_receipt(
    obj: Any,
    *,
    config: SanitizeConfig | None = None,
) -> Any:
    cfg = (config or SanitizeConfig()).normalized()
    sanitized, _ = sanitize_with_report(obj, policy=cfg)
    return sanitized


# ---------------------------------------------------------------------------
# Structural pruning / JSON-safe stabilization compatibility
# ---------------------------------------------------------------------------


def prune_large_values(
    obj: Any,
    *,
    max_depth: int = _SANITIZE_MAX_DEPTH,
    max_list_len: int = _SANITIZE_MAX_LIST_LEN,
    max_str_len: int = _SANITIZE_MAX_STR_LEN,
    max_nodes: int = _SANITIZE_MAX_NODES,
    max_total_str_bytes: int = _SANITIZE_MAX_TOTAL_STR_BYTES,
    max_total_bytes: int = _SANITIZE_MAX_TOTAL_BYTES,
    _depth: int = 0,
) -> Any:
    cfg = SanitizeConfig(
        profile="DEV",
        surface="internal",
        max_depth=max_depth,
        max_list_len=max_list_len,
        max_str_len=max_str_len,
        max_nodes=max_nodes,
        max_total_str_bytes=max_total_str_bytes,
        max_total_bytes=max_total_bytes,
        sanitize_nan=False,
        prune_large=True,
        strip_pii=False,
        redact_secrets=False,
        reject_on_forbidden_keys=False,
        strict_forbidden_key_scan=False,
        return_json_only=True,
        forbidden_key_action="drop",
        allow_unknown_types=True,
        unknown_type_mode="tag",
        nonfinite_mode="default",
    )
    sanitized, _ = sanitize_with_report(obj, policy=cfg)
    return sanitized


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------


def json_depth_exceeds(raw: str | bytes, *, max_depth: int) -> bool:
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
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == '"':
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


def json_loads_strict(
    raw: str | bytes,
    *,
    max_bytes: int = _SANITIZE_MAX_TOTAL_BYTES,
    max_depth: int = _SANITIZE_MAX_DEPTH * 2,
    max_int_digits: int = 2048,
) -> Any:
    data = raw.encode("utf-8", errors="strict") if isinstance(raw, str) else bytes(raw)

    if len(data) > max_bytes:
        raise ValueError("json payload too large")

    if json_depth_exceeds(data, max_depth=max_depth):
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


def canonical_json_dumps(
    obj: Any,
    *,
    ensure_ascii: bool = False,
    sanitize_nan: bool = True,
    prune_large: bool = True,
    strip_pii: bool = False,
    redact_secrets: bool = False,
    forbid_keys: Iterable[str] | None = None,
    numeric_only_keys: Iterable[str] | None = None,
    profile: Profile | str = "PROD",
) -> str:
    cfg = SanitizeConfig(
        profile=_safe_profile(profile),
        surface="internal",
        sanitize_nan=sanitize_nan,
        prune_large=prune_large,
        strip_pii=strip_pii,
        redact_secrets=redact_secrets,
        forbid_keys=tuple(forbid_keys or tuple(_FORBIDDEN_META_KEYS)),
        numeric_only_keys=tuple(numeric_only_keys or ()),
        ensure_ascii=ensure_ascii,
        reject_on_forbidden_keys=bool(forbid_keys),
    )
    sanitized, _ = sanitize_with_report(obj, policy=cfg)
    return json.dumps(
        _stable_jsonable(sanitized),
        ensure_ascii=ensure_ascii,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def canonical_json_bytes(
    obj: Any,
    *,
    ensure_ascii: bool = False,
    sanitize_nan: bool = True,
    prune_large: bool = True,
    strip_pii: bool = False,
    redact_secrets: bool = False,
    forbid_keys: Iterable[str] | None = None,
    numeric_only_keys: Iterable[str] | None = None,
    profile: Profile | str = "PROD",
) -> bytes:
    return canonical_json_dumps(
        obj,
        ensure_ascii=ensure_ascii,
        sanitize_nan=sanitize_nan,
        prune_large=prune_large,
        strip_pii=strip_pii,
        redact_secrets=redact_secrets,
        forbid_keys=forbid_keys,
        numeric_only_keys=numeric_only_keys,
        profile=profile,
    ).encode("utf-8", errors="strict")


def canonical_json_bytes_strict(
    obj: Any,
    *,
    policy: SanitizePolicyBundle | SanitizeConfig | None = None,
) -> bytes:
    sanitized, _ = sanitize_with_report(obj, policy=policy)
    return json.dumps(
        _stable_jsonable(sanitized),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8", errors="strict")


def bounded_json_dumps(
    obj: Any,
    *,
    max_bytes: int,
    ensure_ascii: bool = False,
    sanitize_nan: bool = True,
    prune_large: bool = True,
    strip_pii: bool = False,
    redact_secrets: bool = False,
    profile: Profile | str = "PROD",
) -> str:
    cfg = SanitizeConfig(
        profile=_safe_profile(profile),
        surface="internal",
        sanitize_nan=sanitize_nan,
        prune_large=prune_large,
        strip_pii=strip_pii,
        redact_secrets=redact_secrets,
        ensure_ascii=ensure_ascii,
    )
    sanitized, report = sanitize_with_report(obj, policy=cfg)
    txt = json.dumps(
        _stable_jsonable(sanitized),
        ensure_ascii=ensure_ascii,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    if len(txt.encode("utf-8", errors="strict")) <= max_bytes:
        return txt
    overflow = _overflow_envelope(bundle=cfg.to_bundle(), report=report, max_bytes=max_bytes)
    return json.dumps(
        overflow,
        ensure_ascii=ensure_ascii,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


# ---------------------------------------------------------------------------
# Digest / fingerprint helpers
# ---------------------------------------------------------------------------


def normalize_digest_token(v: Any, *, kind: str = "any", default: Optional[str] = None) -> Optional[str]:
    s = _safe_text(v, max_len=1024, redact_mode="token")
    if not s or s == "[redacted]":
        return default
    kind_l = (kind or "any").lower()
    if kind_l == "cfg_fp":
        return s if _CFG_FP_RE.fullmatch(s) else default
    if kind_l == "integrity":
        return s if _RECEIPT_INTEGRITY_RE.fullmatch(s) else default
    if kind_l == "hex":
        if _DIGEST_HEX_RE.fullmatch(s):
            return s.lower()
        return default
    if kind_l == "0xhex":
        if _DIGEST_HEX_0X_RE.fullmatch(s):
            return s.lower()
        if _DIGEST_HEX_RE.fullmatch(s):
            return "0x" + s.lower()
        return default
    if kind_l == "alg:hex":
        return s if _DIGEST_ALG_HEX_RE.fullmatch(s) else default
    if kind_l == "receipt_head":
        if _DIGEST_HEX_RE.fullmatch(s) or _DIGEST_HEX_0X_RE.fullmatch(s):
            return s.lower()
        if _DIGEST_ALG_HEX_RE.fullmatch(s):
            return s
        return default
    if _DIGEST_HEX_RE.fullmatch(s):
        return s.lower()
    if _DIGEST_HEX_0X_RE.fullmatch(s):
        return s.lower()
    if _DIGEST_ALG_HEX_RE.fullmatch(s):
        algo, _, rest = s.partition(":")
        return f"{algo}:{rest.lower()}"
    return default


def blake2s_hex(
    data: Any,
    *,
    digest_size: int = 16,
    canonical: bool = True,
    key: bytes | None = None,
    person: bytes | None = None,
    domain: str | None = None,
    sanitize_config: SanitizeConfig | None = None,
) -> str:
    if digest_size < 1 or digest_size > 32:
        raise ValueError("digest_size must be in [1, 32] bytes for blake2s.")

    person_b = bytes(person[:8]) if person is not None else b""
    h = hashlib.blake2s(digest_size=digest_size, key=key or b"", person=person_b)

    if domain:
        h.update(b"domain:")
        h.update(domain.encode("utf-8", errors="ignore"))
        h.update(b"\x00")

    if canonical:
        cfg = sanitize_config or SanitizeConfig(
            sanitize_nan=True,
            prune_large=True,
            strip_pii=False,
            redact_secrets=False,
        )
        encoded = canonical_json_bytes(
            data,
            ensure_ascii=False,
            sanitize_nan=cfg.sanitize_nan,
            prune_large=cfg.prune_large,
            strip_pii=cfg.strip_pii,
            redact_secrets=cfg.redact_secrets,
            forbid_keys=cfg.forbid_keys,
            numeric_only_keys=cfg.numeric_only_keys,
            profile=cfg.profile,
        )
        h.update(encoded)
    else:
        if isinstance(data, (bytes, bytearray, memoryview)):
            h.update(bytes(data))
        elif isinstance(data, str):
            h.update(data.encode("utf-8", errors="ignore"))
        elif isinstance(data, (Mapping, list, tuple, set, frozenset)):
            h.update(
                canonical_json_bytes(
                    data,
                    ensure_ascii=False,
                    sanitize_nan=False,
                    prune_large=False,
                    strip_pii=False,
                    redact_secrets=False,
                )
            )
        else:
            h.update(f"<{type(data).__name__}>".encode("utf-8", errors="ignore"))

    return h.hexdigest()


def sha256_hex(
    data: Any,
    *,
    canonical: bool = True,
    domain: str | None = None,
    sanitize_config: SanitizeConfig | None = None,
) -> str:
    h = hashlib.sha256()

    if domain:
        h.update(b"domain:")
        h.update(domain.encode("utf-8", errors="ignore"))
        h.update(b"\x00")

    if canonical:
        cfg = sanitize_config or SanitizeConfig(
            sanitize_nan=True,
            prune_large=True,
            strip_pii=False,
            redact_secrets=False,
        )
        h.update(
            canonical_json_bytes(
                data,
                ensure_ascii=False,
                sanitize_nan=cfg.sanitize_nan,
                prune_large=cfg.prune_large,
                strip_pii=cfg.strip_pii,
                redact_secrets=cfg.redact_secrets,
                forbid_keys=cfg.forbid_keys,
                numeric_only_keys=cfg.numeric_only_keys,
                profile=cfg.profile,
            )
        )
    else:
        if isinstance(data, (bytes, bytearray, memoryview)):
            h.update(bytes(data))
        else:
            h.update(_safe_text(data, max_len=4096, redact_mode="strict").encode("utf-8", errors="ignore"))

    return h.hexdigest()


def blake3_hex(
    data: Any,
    *,
    canonical: bool = True,
    domain: str | None = None,
    sanitize_config: SanitizeConfig | None = None,
) -> str:
    if Blake3Hash is None:
        return sha256_hex(data, canonical=canonical, domain=domain, sanitize_config=sanitize_config)

    if canonical:
        cfg = sanitize_config or SanitizeConfig()
        raw = canonical_json_bytes(
            data,
            ensure_ascii=False,
            sanitize_nan=cfg.sanitize_nan,
            prune_large=cfg.prune_large,
            strip_pii=cfg.strip_pii,
            redact_secrets=cfg.redact_secrets,
            forbid_keys=cfg.forbid_keys,
            numeric_only_keys=cfg.numeric_only_keys,
            profile=cfg.profile,
        )
    else:
        if isinstance(data, (bytes, bytearray, memoryview)):
            raw = bytes(data)
        elif isinstance(data, str):
            raw = data.encode("utf-8", errors="ignore")
        else:
            raw = canonical_json_bytes(data, sanitize_nan=False, prune_large=False)
    ctx = domain or "tcd:utils:blake3"
    return Blake3Hash().hex(raw, ctx=ctx)


def commitment_hex(
    payload: Mapping[str, Any],
    *,
    schema: str = "tcd.meta.v3",
    domain: str = "tcd-commitment",
    sanitize_config: SanitizeConfig | None = None,
) -> str:
    meta = dict(payload)
    cfg = sanitize_config or SanitizeConfig()
    meta.setdefault("_schema", schema)
    meta.setdefault("_compatibility_epoch", _COMPATIBILITY_EPOCH)
    meta.setdefault("_canonicalization_version", cfg.canonicalization_version)
    meta.setdefault("_sanitize_policy_digest", cfg.to_bundle().policy_digest)
    return blake2s_hex(meta, canonical=True, domain=domain, sanitize_config=cfg)


def secure_compare_hex(a: str, b: str) -> bool:
    if not isinstance(a, str) or not isinstance(b, str):
        return False

    def _norm(s: str) -> Optional[bytes]:
        ss = s.strip()
        if ss.startswith(("0x", "0X")):
            ss = ss[2:]
        if not ss or not _HEX_RE.fullmatch(ss):
            return None
        if len(ss) % 2 == 1:
            ss = "0" + ss
        try:
            return bytes.fromhex(ss.lower())
        except Exception:
            return None

    ba = _norm(a)
    bb = _norm(b)
    if ba is None or bb is None:
        return False

    return hmac.compare_digest(ba, bb)


__all__ = [
    "Profile",
    "SanitizeSurface",
    "HashAlgorithm",
    "ForbiddenKeyAction",
    "NonFiniteMode",
    "OversizeIntMode",
    "UnknownTypeMode",
    "CanonicalJsonPolicy",
    "RedactionPolicy",
    "KeyPolicyEngine",
    "SanitizePolicyBundle",
    "SanitizeConfig",
    "SanitizeReport",
    "SanitizeError",
    "BudgetExceededError",
    "ForbiddenKeyError",
    "SerializationPolicyError",
    "is_finite_number",
    "safe_float",
    "safe_int",
    "parse_int_strict",
    "parse_float_strict",
    "coerce_int_lossy",
    "sanitize_floats",
    "prune_large_values",
    "json_depth_exceeds",
    "json_loads_strict",
    "bounded_json_dumps",
    "canonical_json_dumps",
    "canonical_json_bytes",
    "canonical_json_bytes_strict",
    "blake2s_hex",
    "sha256_hex",
    "blake3_hex",
    "redact_pii_metadata",
    "redact_secret_metadata",
    "sanitize_metadata_for_receipt",
    "sanitize_with_report",
    "sanitize_for_receipt_public",
    "sanitize_for_receipt_audit",
    "sanitize_for_signal",
    "sanitize_for_storage",
    "enforce_metadata_keys",
    "normalize_digest_token",
    "make_policy_fingerprint",
    "deterministic_pseudonymize",
    "commitment_hex",
    "secure_compare_hex",
    "NumericSanitizeReport",
]