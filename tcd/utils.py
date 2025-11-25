# FILE: tcd/utils.py
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Sequence

# ---------------------------------------------------------------------------
# Numeric / JSON sanitization helpers
# ---------------------------------------------------------------------------

_SANITIZE_MAX_DEPTH = 8
_SANITIZE_MAX_LIST_LEN = 512
_SANITIZE_MAX_STR_LEN = 2048

# PII / content-safety regexes (metadata-level only, not NLP-grade)
_PII_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.UNICODE
)
_PII_PHONE_RE = re.compile(r"\+?\d[\d\-\s]{6,}\d", re.UNICODE)
_PII_IDLIKE_RE = re.compile(r"\b\d{6,}\b", re.UNICODE)  # coarse ID / account pattern

# Keys that must not appear in metadata (align with trust_graph / storage)
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


def is_finite_number(value: Any) -> bool:
    """
    Return True if `value` is an int/float and is finite (not NaN / +/-inf).

    This is a small helper used by other sanitizers; it never raises.
    """
    if isinstance(value, bool):
        # bool is a subclass of int, but we treat it separately
        return True
    if isinstance(value, (int, float)):
        try:
            return math.isfinite(float(value))
        except Exception:
            return False
    return False


def safe_float(value: Any, default: float = 0.0) -> float:
    """
    Convert `value` to a finite float, falling back to `default` if needed.

    Rules:
      - ints / floats: return float(value) if finite; otherwise `default`.
      - bool: return 1.0 for True, 0.0 for False.
      - anything else: `default`.

    This function never raises.
    """
    try:
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        if isinstance(value, (int, float)):
            f = float(value)
            if math.isfinite(f):
                return f
            return float(default)
    except Exception:
        return float(default)
    return float(default)


def sanitize_floats(obj: Any, *, default: float = 0.0, _depth: int = 0) -> Any:
    """
    Recursively sanitize floats inside a nested structure.

    Behavior (backwards compatible with the original version, but stricter):
      - For plain float:
            * if finite: returned unchanged;
            * if NaN / +/-inf: replaced with `default` (0.0 by default).
      - For dict:
            * all values are sanitized recursively.
      - For list / tuple:
            * all elements are sanitized recursively; tuples become tuples.
      - For other types:
            * returned unchanged.

    Additional safety:
      - Recursion depth is limited to `_SANITIZE_MAX_DEPTH` to avoid
        pathological cycles; once the limit is reached, values are returned
        as-is.
    """
    if _depth > _SANITIZE_MAX_DEPTH:
        return obj

    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return float(default)
        return obj

    if isinstance(obj, (int, bool)):
        # ints / bools are already safe from NaN/inf issues
        return obj

    if isinstance(obj, Mapping):
        out: Dict[Any, Any] = {}
        for k, v in obj.items():
            out[k] = sanitize_floats(v, default=default, _depth=_depth + 1)
        return out

    if isinstance(obj, (list, tuple)):
        sanitized_seq = [
            sanitize_floats(x, default=default, _depth=_depth + 1) for x in obj
        ]
        return tuple(sanitized_seq) if isinstance(obj, tuple) else sanitized_seq

    # Any other types (str, None, custom objects) are left unchanged
    return obj


def prune_large_values(
    obj: Any,
    *,
    max_depth: int = _SANITIZE_MAX_DEPTH,
    max_list_len: int = _SANITIZE_MAX_LIST_LEN,
    max_str_len: int = _SANITIZE_MAX_STR_LEN,
    _depth: int = 0,
) -> Any:
    """
    Recursively prune overly large structures to keep logs / receipts compact.

    Designed for metadata only and purely structural:
      - Strings longer than `max_str_len` are truncated and suffixed with "…".
      - Lists / tuples longer than `max_list_len` are truncated.
      - Nested mappings / sequences deeper than `max_depth` are replaced
        with a small placeholder describing their type and depth.

    This function never raises and aims to be deterministic.
    It does NOT try to detect raw prompts or completions.
    """
    if _depth > max_depth:
        # Replace deep branches with a small structural marker
        return {"_truncated": True, "_depth": _depth}

    # Strings: truncate if too long, but keep type stable
    if isinstance(obj, str):
        if len(obj) > max_str_len:
            return obj[: max_str_len - 1] + "…"
        return obj

    # Numbers / bool / None: unchanged
    if isinstance(obj, (int, float, bool)) or obj is None:
        return obj

    # Mapping: prune values recursively
    if isinstance(obj, Mapping):
        out: Dict[Any, Any] = {}
        for k, v in obj.items():
            out[k] = prune_large_values(
                v,
                max_depth=max_depth,
                max_list_len=max_list_len,
                max_str_len=max_str_len,
                _depth=_depth + 1,
            )
        return out

    # Sequences: prune length and recurse
    if isinstance(obj, (list, tuple)):
        seq = list(obj)
        if len(seq) > max_list_len:
            seq = seq[:max_list_len]
        pruned = [
            prune_large_values(
                x,
                max_depth=max_depth,
                max_list_len=max_list_len,
                max_str_len=max_str_len,
                _depth=_depth + 1,
            )
            for x in seq
        ]
        return tuple(pruned) if isinstance(obj, tuple) else pruned

    # Other objects: leave as-is (typically small scalars or enums / simple types)
    return obj


# ---------------------------------------------------------------------------
# PII detection / redaction helpers (for metadata only)
# ---------------------------------------------------------------------------


def _looks_like_pii(s: str) -> bool:
    """
    Coarse PII / sensitive-text detection for metadata.

    This is only for metadata (receipt body / evidence.payload) and is not
    intended for general NLP classification.
    """
    if not s:
        return False
    # Very long strings should not appear in metadata; treat as suspicious
    if len(s) > _SANITIZE_MAX_STR_LEN:
        return True
    if _PII_EMAIL_RE.search(s):
        return True
    if _PII_PHONE_RE.search(s):
        return True
    # Simple ID / account pattern
    if _PII_IDLIKE_RE.search(s):
        return True
    return False


def _redact_pii_in_str(s: str) -> str:
    """
    Redact PII-like segments inside a string.

    - Email: keep 1–3 leading chars of local part, mask the rest.
    - Phone: keep only last 2–4 digits, mask prefix.
    - Other ID-like numeric runs: replace by a fixed token.
    """
    if not s:
        return s

    # Email redaction
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

    s = _PII_EMAIL_RE.sub(_mask_email, s)

    # Phone redaction: keep only last 2–4 digits
    def _mask_phone(m: re.Match) -> str:
        full = re.sub(r"\s+", "", m.group(0))
        if len(full) <= 4:
            return "***"
        tail = full[-4:]
        return "***" + tail

    s = _PII_PHONE_RE.sub(_mask_phone, s)

    # ID-like numeric patterns
    s = _PII_IDLIKE_RE.sub("[ID_REDACTED]", s)
    return s


def redact_pii_metadata(
    obj: Any, *, _depth: int = 0, max_depth: int = _SANITIZE_MAX_DEPTH
) -> Any:
    """
    Recursively redact PII-like content in metadata while preserving structure.

    - dict: values are processed recursively;
    - list/tuple: elements are processed recursively;
    - str: passed through `_redact_pii_in_str`;
    - other types: returned as-is.
    """
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
        seq = [
            redact_pii_metadata(x, _depth=_depth + 1, max_depth=max_depth) for x in obj
        ]
        return tuple(seq) if isinstance(obj, tuple) else seq

    return obj


# ---------------------------------------------------------------------------
# Metadata sanitization config and helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SanitizeConfig:
    """
    Metadata security configuration for receipts / evidence / commitments.

    This defines how to normalize and constrain metadata before it is
    serialized or hashed.
    """

    max_depth: int = _SANITIZE_MAX_DEPTH
    max_list_len: int = _SANITIZE_MAX_LIST_LEN
    max_str_len: int = _SANITIZE_MAX_STR_LEN

    # Numeric safety
    sanitize_nan: bool = True
    # Structural pruning
    prune_large: bool = True
    # PII redaction
    strip_pii: bool = True

    # Keys that must not appear anywhere (case-insensitive) up to max_depth
    forbid_keys: Sequence[str] = tuple(_FORBIDDEN_META_KEYS)
    # Keys that must have numeric/bool/None values only (case-insensitive)
    numeric_only_keys: Sequence[str] = tuple()


def enforce_metadata_keys(
    obj: Mapping[str, Any],
    *,
    forbid_keys: Iterable[str] = (),
    numeric_only_keys: Iterable[str] = (),
    max_depth: int = 3,
    _depth: int = 0,
) -> None:
    """
    Validate metadata keys without mutating the object.

    - forbid_keys:
        If any key (case-insensitive) appears within depth <= max_depth,
        raise ValueError.
    - numeric_only_keys:
        These keys (case-insensitive) must have values that are
        numeric/bool/None and finite if numeric.
    """
    if _depth > max_depth:
        return

    forbid_lower = {k.lower() for k in forbid_keys}
    numeric_only_lower = {k.lower() for k in numeric_only_keys}

    for k, v in obj.items():
        key_str = str(k)
        key_lower = key_str.lower()

        if key_lower in forbid_lower:
            raise ValueError(
                f"Metadata contains forbidden key '{key_str}'; "
                "raw content MUST NOT be attached here."
            )

        if key_lower in numeric_only_lower:
            # Only accept numbers / bool / None
            if v is not None and not isinstance(v, (int, float, bool)):
                raise ValueError(
                    f"Metadata key '{key_str}' must be numeric/bool/None; "
                    f"got {type(v).__name__}."
                )
            if isinstance(v, (int, float)) and not math.isfinite(float(v)):
                raise ValueError(
                    f"Metadata key '{key_str}' must be a finite number; "
                    "got non-finite value."
                )

        # Recurse into nested mappings
        if isinstance(v, Mapping):
            enforce_metadata_keys(
                v,
                forbid_keys=forbid_keys,
                numeric_only_keys=numeric_only_keys,
                max_depth=max_depth,
                _depth=_depth + 1,
            )
        elif isinstance(v, (list, tuple)):
            for x in v:
                if isinstance(x, Mapping):
                    enforce_metadata_keys(
                        x,
                        forbid_keys=forbid_keys,
                        numeric_only_keys=numeric_only_keys,
                        max_depth=max_depth,
                        _depth=_depth + 1,
                    )


def sanitize_metadata_for_receipt(
    obj: Any,
    *,
    config: SanitizeConfig | None = None,
) -> Any:
    """
    One-shot metadata sanitization for receipts / trust_graph / commitments.

    Pipeline:
      1) sanitize NaN/Inf;
      2) prune deep / large structures;
      3) optionally redact PII-like content;
      4) enforce forbidden/numeric-only key rules.

    Returns a JSON-serializable structure and never mutates the original
    object.
    """
    cfg = config or SanitizeConfig()

    data = obj
    if cfg.sanitize_nan:
        data = sanitize_floats(data)

    if cfg.prune_large:
        data = prune_large_values(
            data,
            max_depth=cfg.max_depth,
            max_list_len=cfg.max_list_len,
            max_str_len=cfg.max_str_len,
        )

    if cfg.strip_pii:
        data = redact_pii_metadata(data, max_depth=cfg.max_depth)

    # Key validation applies to mappings (typical receipt body / payload)
    if isinstance(data, Mapping):
        enforce_metadata_keys(
            data,
            forbid_keys=cfg.forbid_keys,
            numeric_only_keys=cfg.numeric_only_keys,
        )

    return data


# ---------------------------------------------------------------------------
# Canonical JSON + hashing helpers
# ---------------------------------------------------------------------------


def canonical_json_dumps(
    obj: Any,
    *,
    ensure_ascii: bool = False,
    sanitize_nan: bool = True,
    prune_large: bool = True,
    strip_pii: bool = False,
    forbid_keys: Iterable[str] | None = None,
    numeric_only_keys: Iterable[str] | None = None,
) -> str:
    """
    Serialize `obj` to a canonical JSON string suitable for logs / receipts.

    Security-related behavior:
      - By default, NaN/Inf are sanitized and structures are pruned.
      - Optional PII redaction via `strip_pii=True`.
      - Optional key-level validation via `forbid_keys` / `numeric_only_keys`.

    This function does not encrypt or sign; it only normalizes and constrains
    metadata before serialization.
    """
    if sanitize_nan or prune_large or strip_pii or forbid_keys or numeric_only_keys:
        cfg = SanitizeConfig(
            sanitize_nan=sanitize_nan,
            prune_large=prune_large,
            strip_pii=strip_pii,
            forbid_keys=tuple(forbid_keys or ()),
            numeric_only_keys=tuple(numeric_only_keys or ()),
        )
        data = sanitize_metadata_for_receipt(obj, config=cfg)
    else:
        data = obj

    return json.dumps(
        data,
        ensure_ascii=ensure_ascii,
        sort_keys=True,
        separators=(",", ":"),
    )


def blake2s_hex(
    data: Any,
    *,
    digest_size: int = 16,
    canonical: bool = True,
    key: bytes | None = None,
    person: bytes | None = None,
    domain: str | None = None,
) -> str:
    """
    Compute a Blake2s hex digest for `data`.

    Args:
      data:
        - canonical=True: serialize via `canonical_json_dumps` first;
        - canonical=False: treat `data` as raw bytes/str.
      digest_size:
        Number of bytes in digest (1–32).
      key:
        Optional key for MAC / keyed hashing (e.g., internal supply-chain
        checks).
      person:
        Optional personalization bytes for domain separation.
      domain:
        Optional domain string; if provided, it is mixed into the hash
        input as a prefixed tag.

    Returns:
      Hex-encoded digest.
    """
    if digest_size < 1 or digest_size > 32:
        raise ValueError("digest_size must be in [1, 32] bytes for blake2s.")

    h = hashlib.blake2s(digest_size=digest_size, key=key or b"", person=person or b"")

    if domain:
        h.update(b"domain:")
        h.update(domain.encode("utf-8", errors="ignore"))
        h.update(b"\x00")

    if canonical:
        encoded = canonical_json_dumps(
            data,
            ensure_ascii=False,
            sanitize_nan=True,
            prune_large=True,
            strip_pii=False,  # commitment redaction is a caller decision
        ).encode("utf-8", errors="ignore")
        h.update(encoded)
    else:
        if isinstance(data, (bytes, bytearray)):
            h.update(data)
        else:
            h.update(str(data).encode("utf-8", errors="ignore"))

    return h.hexdigest()


def commitment_hex(
    payload: Mapping[str, Any],
    *,
    schema: str = "tcd.meta.v1",
    domain: str = "tcd-commitment",
) -> str:
    """
    Generate a standard commitment hash for receipts / trust_graph / PQ proof.

    Behavior:
      - Adds a `_schema` tag if missing, so future schema versions can be
        distinguished.
      - Uses `canonical_json_dumps` and `blake2s_hex(domain=...)` for a
        stable, domain-separated digest.
    """
    meta = dict(payload)
    meta.setdefault("_schema", schema)
    return blake2s_hex(meta, canonical=True, domain=domain)


def secure_compare_hex(a: str, b: str) -> bool:
    """
    Constant-time comparison of two hex strings (for MAC / commitment checks).

    This avoids timing side channels that could leak information about the
    compared values.
    """
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    # Normalize case to keep comparisons consistent
    return hmac.compare_digest(a.lower(), b.lower())


__all__ = [
    "is_finite_number",
    "safe_float",
    "sanitize_floats",
    "prune_large_values",
    "canonical_json_dumps",
    "blake2s_hex",
    # extended helpers
    "SanitizeConfig",
    "redact_pii_metadata",
    "sanitize_metadata_for_receipt",
    "enforce_metadata_keys",
    "commitment_hex",
    "secure_compare_hex",
]