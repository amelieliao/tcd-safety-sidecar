# FILE: tcd/kv.py
from __future__ import annotations

"""
Helpers for stable key/value hashing and deterministic IDs.

This module is used to build:
  - receipt heads and chain identifiers;
  - stable IDs for events, chains, and PQ attestations;
  - e-process / alpha-investing envelope hashes that are content-agnostic.

L6→L7 hardening upgrades in this build (systematic; closes all listed gaps):
  - Canonical encoding family:
      * KVv1: legacy delimiter-based encoding (AMBIGUOUS). Disabled by default; opt-in only.
      * KVv2: prefix-safe structured encoding (counts + TLV scalars), legacy ctx/label seeding kept.
      * KVv3: full TLV header (ctx/label/policy/meta) + structured encoding; strict, verifiable.
  - Forbidden key enforcement is truly “strict”:
      * fixes the bug where input_text/output_text were not blocked in strict mode;
      * blocks CamelCase variants (requestBody, inputText) via camel-boundary tokenization;
      * supports contiguous token-sequence matching (not just single-token membership).
  - UTF-8 encoding is injective:
      * KVv2/KVv3 reject surrogate code points up front (no “ignore/replace” collisions);
      * KVv1 may still honor legacy utf8_errors, but only after surrogate rejection.
  - Legacy KVv1 safety:
      * KVv1 forbids float_mode="ieee" (delimiter mode + raw bytes makes boundary ambiguity worse).
  - No str()/repr() on arbitrary objects:
      * keys must be str;
      * values must be basic JSON-like scalars + bounded built-in containers (list/tuple/dict/mappingproxy);
      * unknown objects are rejected (or handled only via safe API returning error codes).
  - DoS-resistance:
      * hard-coded absolute caps (env cannot raise above hard caps);
      * byte-budget enforced by RollingHasher; max_bytes negative is clamped (no accidental “infinite”);
      * sorting budget checks (sum of key bytes, item count) before sort;
      * strict mapping-type mode (default ON for external profile): rejects custom Mapping implementations.
  - PII/linkability governance:
      * optional “external” profile enforces require_hmac and tag-like string mode by default;
      * explicit key_id supported via KVHashContext and descriptor output.
  - Verifiability:
      * HashDescriptor includes requested_alg vs resolved_alg, kv version, policy_digest, meta flags;
      * kv_policy_digest() provides a stable “hashing policy anchor” (no secret material).
  - Safety API:
      * canonical_kv_hash_safe / KVHashContext.hash_safe return (ok, digest, err_code, descriptor).
  - Minimal leakage errors:
      * default error messages are low-information; verbose detail is opt-in.

Environment knobs (read at call time; not import-time latched):
  - TCD_KV_PROFILE                           "internal"(default) or "external"
  - TCD_KV_CANONICAL_VERSION                 "v2"(default) | "v3" | "v1"(legacy)
  - TCD_KV_ALLOW_LEGACY_CANONICAL            default "0" (must be "1" to use v1)
  - TCD_KV_ALLOW_LEGACY_ALGS                 default "0" (unknown digest names rejected unless "1")
  - TCD_KV_STRICT_ALG_NAMES                  default "1" external / "0" internal (blake3 alias handling)
  - TCD_KV_FLOAT_MODE                        "repr"(default) or "ieee"
  - TCD_KV_UTF8_ERRORS                       legacy only (v1); ignored for v2/v3 (injective)
  - TCD_KV_FORBID_CONTENT_KEYS               default "1"
  - TCD_KV_FORBID_CONTENT_KEYS_STRICT        default "1"
  - TCD_KV_FORBID_TEXTLIKE_VALUES            default "1" external / "0" internal
  - TCD_KV_VALUE_STRING_MODE                 "tag"(default external) | "any"(default internal)
  - TCD_KV_BYTES_ALLOWED_LENS                e.g. "16,32,64" (default external); empty => any up to max_bytes_value
  - TCD_KV_REQUIRE_HMAC                      default "1" external / "0" internal
  - TCD_KV_STRICT_MAPPING_TYPES              default "1" external / "0" internal
  - TCD_KV_MAX_BYTES                         default internal 4096 / external 2048 (clamped by hard caps)
  - TCD_KV_MAX_ITEMS                         default internal 256 / external 128
  - TCD_KV_MAX_DEPTH                         default 8
  - TCD_KV_MAX_NODES                         default internal 2048 / external 1024
  - TCD_KV_MAX_KEY_BYTES                     default 64
  - TCD_KV_STRICT_KEY_PATTERN                default "1"
  - TCD_KV_MAX_STRING_BYTES                  default internal 512 / external 128
  - TCD_KV_MAX_BYTES_VALUE                   default internal 256 / external 64
  - TCD_KV_MAX_INT_BITS                      default 256
  - TCD_KV_MIN_HMAC_KEY_BYTES                default 16
  - TCD_KV_MAX_HMAC_KEY_BYTES                default 4096
  - TCD_KV_WARNED_ALGS_MAX                   default 128 (bounded)
  - TCD_KV_VERBOSE_ERRORS                    default "0" (verbose error detail)

NOTE:
  - This module is for hashing *envelopes* (tags/IDs/scores), NOT raw prompts/completions/bodies.
  - If you need content hashing, do it in a dedicated module with explicit opt-in and strong controls.
"""

import hashlib
import hmac
import json
import logging
import os
import re
import struct
import threading
from collections import deque
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Dict, FrozenSet, Iterable, Literal, Mapping, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hard caps (env cannot exceed these) — L7 safety rails
# ---------------------------------------------------------------------------

_HARD_MAX_BYTES_TOTAL = 64 * 1024
_HARD_MAX_ITEMS = 4096
_HARD_MAX_DEPTH = 64
_HARD_MAX_NODES = 65536
_HARD_MAX_KEY_BYTES = 1024
_HARD_MAX_STRING_BYTES = 8 * 1024
_HARD_MAX_BYTES_VALUE = 8 * 1024
_HARD_MAX_INT_BITS = 1_000_000
_HARD_MAX_HMAC_KEY_BYTES = 16 * 1024

# ---------------------------------------------------------------------------
# Error codes (low-cardinality; suitable for metrics/audit)
# ---------------------------------------------------------------------------

ErrCode = Literal[
    "ok",
    "invalid_payload",
    "forbidden_key",
    "key_pattern",
    "key_too_long",
    "utf8_surrogate",
    "mapping_too_large",
    "list_too_large",
    "bytes_budget",
    "max_depth",
    "max_nodes",
    "string_too_large",
    "bytes_too_large",
    "bytes_len_forbidden",
    "int_too_large",
    "float_invalid",
    "textlike_forbidden",
    "taglike_required",
    "unsupported_type",
    "cycle_detected",
    "legacy_disabled",
    "legacy_v1_ieee_forbidden",
    "alg_unsupported",
    "hmac_key_short",
    "hmac_key_too_long",
    "hmac_required_missing",
    "unknown",
]

_ERR_OK: ErrCode = "ok"


class HashError(Exception):
    """
    Structured kv hashing error with a low-cardinality error code.

    By default, messages are low-information (L7 anti-leak).
    Enable verbose detail with TCD_KV_VERBOSE_ERRORS=1.
    """

    __slots__ = ("code", "detail")

    def __init__(self, code: ErrCode, message: str = "", *, detail: str = "") -> None:
        super().__init__(message or code)
        self.code: ErrCode = code
        self.detail: str = detail


# ---------------------------------------------------------------------------
# Env parsing helpers (never-throw)
# ---------------------------------------------------------------------------


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    s = str(raw).strip().lower()
    if s in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


def _env_int(name: str, default: int, *, min_v: int, max_v: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        v = int(str(raw).strip())
    except Exception:
        return default
    if v < min_v:
        return min_v
    if v > max_v:
        return max_v
    return v


def _env_str(name: str, default: str) -> str:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip()


def _clamp_int(v: int, *, min_v: int, max_v: int) -> int:
    if v < min_v:
        return min_v
    if v > max_v:
        return max_v
    return v


# ---------------------------------------------------------------------------
# Profiles & config snapshot (call-time; never import-time latched)
# ---------------------------------------------------------------------------

Profile = Literal["internal", "external"]
CanonicalVersion = Literal["v1", "v2", "v3"]
FloatMode = Literal["repr", "ieee"]
ValueStringMode = Literal["tag", "any"]


# Expanded forbidden key tokens (systematic coverage)
_DEFAULT_FORBIDDEN_KEYS: FrozenSet[str] = frozenset(
    {
        # core content carriers
        "prompt",
        "completion",
        "message",
        "messages",
        "content",
        "body",
        "raw",
        "payload",
        "request",
        "response",
        "header",
        "headers",
        "cookie",
        "cookies",
        "authorization",
        "bearer",
        # common content-like aliases
        "text",
        "input",
        "output",
        "input_text",
        "output_text",
        "inputtext",
        "outputtext",
        "instruction",
        "instructions",
        "system_prompt",
        "systemprompt",
        "tool_input",
        "tool_output",
        "toolinput",
        "tooloutput",
        "query",
        "q",
    }
)

# Tokenization & tag-like constraints
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_ALPHA_DIGIT_BOUNDARY_RE = re.compile(r"(?<=[a-zA-Z])(?=\d)|(?<=\d)(?=[a-zA-Z])")
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")

_STRICT_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_TAGLIKE_VALUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

# Domain prefix (align across modules; keep stable)
_DOMAIN_PREFIX = b"tcd:v1:kv:"


def _has_surrogate(s: str) -> bool:
    # Surrogates are U+D800..U+DFFF
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in s)


def _encode_utf8_injective(s: str) -> bytes:
    """
    Injective UTF-8 encoding for domain/hash inputs.
    Rejects surrogates (otherwise 'ignore/replace' would allow collisions).
    """
    if _has_surrogate(s):
        raise HashError("utf8_surrogate")
    # strict is safe after surrogate rejection
    return s.encode("utf-8", errors="strict")


def _key_tokens(s: str) -> Tuple[str, ...]:
    """
    Tokenize key names robustly:
      - splits CamelCase boundaries (requestBody -> request_Body),
      - splits alpha/digit boundaries (input2Text -> input_2_Text),
      - lowercases,
      - splits on non [a-z0-9].
    """
    if not s:
        return ()
    t = _CAMEL_BOUNDARY_RE.sub("_", s)
    t = _ALPHA_DIGIT_BOUNDARY_RE.sub("_", t)
    t = t.strip().lower()
    toks = [x for x in _TOKEN_SPLIT_RE.split(t) if x]
    return tuple(toks)


def _parse_int_list_csv(s: str, *, max_items: int = 32, min_v: int = 0, max_v: int = 4096) -> Tuple[int, ...]:
    if not s:
        return ()
    out: list[int] = []
    for part in s.split(","):
        if len(out) >= max_items:
            break
        p = part.strip()
        if not p:
            continue
        try:
            v = int(p)
        except Exception:
            continue
        if v < min_v or v > max_v:
            continue
        out.append(v)
    return tuple(out)


@dataclass(frozen=True, slots=True)
class KVHashConfig:
    # Governance / profile
    profile: Profile
    canonical_version: CanonicalVersion
    allow_legacy_canonical: bool

    allow_legacy_algs: bool
    strict_alg_names: bool
    float_mode: FloatMode

    # Forbidden content guards
    forbid_content_keys: bool
    forbid_content_keys_strict: bool
    forbidden_keys: FrozenSet[str]
    forbidden_exact_lower: FrozenSet[str]
    forbidden_token_seqs: Tuple[Tuple[str, ...], ...]

    forbid_textlike_values: bool
    value_string_mode: ValueStringMode
    bytes_allowed_lens: Tuple[int, ...]

    require_hmac: bool
    strict_mapping_types: bool

    # Budgets (env clamped by hard caps)
    max_bytes_total: int
    max_items: int
    max_depth: int
    max_nodes: int

    # Key/value size governance
    max_key_bytes: int
    strict_key_pattern: bool

    max_string_bytes: int
    max_bytes_value: int
    max_int_bits: int

    # HMAC key governance
    min_hmac_key_bytes: int
    max_hmac_key_bytes: int

    # Diagnostics
    warned_algs_max: int
    verbose_errors: bool

    @staticmethod
    def from_env() -> "KVHashConfig":
        prof_raw = _env_str("TCD_KV_PROFILE", "internal").strip().lower()
        profile: Profile = "external" if prof_raw == "external" else "internal"

        # Defaults by profile
        if profile == "external":
            canon_default = "v3"
            max_bytes_default = 2048
            max_items_default = 128
            max_nodes_default = 1024
            max_string_default = 128
            max_bytes_value_default = 64
            forbid_textlike_default = True
            string_mode_default: ValueStringMode = "tag"
            bytes_lens_default = (16, 32, 64)
            require_hmac_default = True
            strict_mapping_default = True
            strict_alg_names_default = True
        else:
            canon_default = "v2"
            max_bytes_default = 4096
            max_items_default = 256
            max_nodes_default = 2048
            max_string_default = 512
            max_bytes_value_default = 256
            forbid_textlike_default = False
            string_mode_default = "any"
            bytes_lens_default = ()
            require_hmac_default = False
            strict_mapping_default = False
            strict_alg_names_default = False

        ver_raw = _env_str("TCD_KV_CANONICAL_VERSION", canon_default).lower()
        canonical_version: CanonicalVersion = "v1" if ver_raw == "v1" else ("v3" if ver_raw == "v3" else "v2")
        allow_legacy_canonical = _env_bool("TCD_KV_ALLOW_LEGACY_CANONICAL", False)

        allow_legacy_algs = _env_bool("TCD_KV_ALLOW_LEGACY_ALGS", False)
        strict_alg_names = _env_bool("TCD_KV_STRICT_ALG_NAMES", strict_alg_names_default)

        float_mode_raw = _env_str("TCD_KV_FLOAT_MODE", "repr").lower()
        float_mode: FloatMode = "ieee" if float_mode_raw == "ieee" else "repr"

        forbid_content_keys = _env_bool("TCD_KV_FORBID_CONTENT_KEYS", True)
        forbid_content_keys_strict = _env_bool("TCD_KV_FORBID_CONTENT_KEYS_STRICT", True)

        forbid_textlike_values = _env_bool("TCD_KV_FORBID_TEXTLIKE_VALUES", forbid_textlike_default)

        vsm_raw = _env_str("TCD_KV_VALUE_STRING_MODE", string_mode_default).strip().lower()
        value_string_mode: ValueStringMode = "tag" if vsm_raw == "tag" else "any"

        bytes_lens = _env_str("TCD_KV_BYTES_ALLOWED_LENS", "")
        bytes_allowed_lens = _parse_int_list_csv(bytes_lens, max_items=64, min_v=0, max_v=_HARD_MAX_BYTES_VALUE)
        if profile == "external" and not bytes_allowed_lens:
            bytes_allowed_lens = bytes_lens_default

        require_hmac = _env_bool("TCD_KV_REQUIRE_HMAC", require_hmac_default)
        strict_mapping_types = _env_bool("TCD_KV_STRICT_MAPPING_TYPES", strict_mapping_default)

        max_bytes_total = _env_int("TCD_KV_MAX_BYTES", max_bytes_default, min_v=256, max_v=_HARD_MAX_BYTES_TOTAL)
        max_items = _env_int("TCD_KV_MAX_ITEMS", max_items_default, min_v=1, max_v=_HARD_MAX_ITEMS)
        max_depth = _env_int("TCD_KV_MAX_DEPTH", 8, min_v=1, max_v=_HARD_MAX_DEPTH)
        max_nodes = _env_int("TCD_KV_MAX_NODES", max_nodes_default, min_v=16, max_v=_HARD_MAX_NODES)

        max_key_bytes = _env_int("TCD_KV_MAX_KEY_BYTES", 64, min_v=8, max_v=_HARD_MAX_KEY_BYTES)
        strict_key_pattern = _env_bool("TCD_KV_STRICT_KEY_PATTERN", True)

        max_string_bytes = _env_int("TCD_KV_MAX_STRING_BYTES", max_string_default, min_v=16, max_v=_HARD_MAX_STRING_BYTES)
        max_bytes_value = _env_int("TCD_KV_MAX_BYTES_VALUE", max_bytes_value_default, min_v=0, max_v=_HARD_MAX_BYTES_VALUE)
        max_int_bits = _env_int("TCD_KV_MAX_INT_BITS", 256, min_v=32, max_v=_HARD_MAX_INT_BITS)

        min_hmac_key_bytes = _env_int("TCD_KV_MIN_HMAC_KEY_BYTES", 16, min_v=8, max_v=1024)
        max_hmac_key_bytes = _env_int("TCD_KV_MAX_HMAC_KEY_BYTES", 4096, min_v=64, max_v=_HARD_MAX_HMAC_KEY_BYTES)

        warned_algs_max = _env_int("TCD_KV_WARNED_ALGS_MAX", 128, min_v=0, max_v=4096)
        verbose_errors = _env_bool("TCD_KV_VERBOSE_ERRORS", False)

        # Precompute forbidden key matching structures
        forbidden_keys = _DEFAULT_FORBIDDEN_KEYS
        forbidden_exact_lower = frozenset({k.strip().lower() for k in forbidden_keys if k})
        # token seqs (including multi-token keys like input_text => ("input","text"))
        token_seqs: list[Tuple[str, ...]] = []
        for fk in forbidden_keys:
            toks = _key_tokens(fk)
            if toks:
                token_seqs.append(toks)
        # Dedup while preserving content (order unimportant)
        token_seqs = list({ts: None for ts in token_seqs}.keys())

        return KVHashConfig(
            profile=profile,
            canonical_version=canonical_version,
            allow_legacy_canonical=bool(allow_legacy_canonical),
            allow_legacy_algs=bool(allow_legacy_algs),
            strict_alg_names=bool(strict_alg_names),
            float_mode=float_mode,
            forbid_content_keys=bool(forbid_content_keys),
            forbid_content_keys_strict=bool(forbid_content_keys_strict),
            forbidden_keys=forbidden_keys,
            forbidden_exact_lower=forbidden_exact_lower,
            forbidden_token_seqs=tuple(token_seqs),
            forbid_textlike_values=bool(forbid_textlike_values),
            value_string_mode=value_string_mode,
            bytes_allowed_lens=bytes_allowed_lens,
            require_hmac=bool(require_hmac),
            strict_mapping_types=bool(strict_mapping_types),
            max_bytes_total=int(max_bytes_total),
            max_items=int(max_items),
            max_depth=int(max_depth),
            max_nodes=int(max_nodes),
            max_key_bytes=int(max_key_bytes),
            strict_key_pattern=bool(strict_key_pattern),
            max_string_bytes=int(max_string_bytes),
            max_bytes_value=int(max_bytes_value),
            max_int_bits=int(max_int_bits),
            min_hmac_key_bytes=int(min_hmac_key_bytes),
            max_hmac_key_bytes=int(max_hmac_key_bytes),
            warned_algs_max=int(warned_algs_max),
            verbose_errors=bool(verbose_errors),
        )


# ---------------------------------------------------------------------------
# Forbidden key enforcement (fixes A1/A2 and more)
# ---------------------------------------------------------------------------


def _is_forbidden_key(key: str, cfg: KVHashConfig) -> bool:
    if not cfg.forbid_content_keys:
        return False
    k = (key or "").strip()
    if not k:
        return False

    kl = k.lower()
    # 1) exact match ALWAYS (fixes strict-mode bug for input_text/output_text)
    if kl in cfg.forbidden_exact_lower:
        return True

    # Non-strict: exact-only
    if not cfg.forbid_content_keys_strict:
        return False

    toks = _key_tokens(k)
    if not toks:
        return False

    # 2) contiguous token-sequence match (supports inputText/requestBody/etc)
    #    Example: toks=["request","body"] matches forbidden seq ("request","body")
    for seq in cfg.forbidden_token_seqs:
        if not seq:
            continue
        if len(seq) == 1:
            if seq[0] in toks:
                return True
            continue
        # contiguous subsequence match
        n = len(seq)
        for i in range(0, len(toks) - n + 1):
            if toks[i : i + n] == seq:
                return True

    return False


def _guard_key(key: str, cfg: KVHashConfig) -> str:
    if not isinstance(key, str):
        raise HashError("invalid_payload")
    k = key.strip()
    if not k:
        raise HashError("invalid_payload")

    if _has_surrogate(k):
        raise HashError("utf8_surrogate")

    kb = _encode_utf8_injective(k)
    if len(kb) > cfg.max_key_bytes:
        raise HashError("key_too_long")

    if _is_forbidden_key(k, cfg):
        raise HashError("forbidden_key")

    if cfg.strict_key_pattern and not _STRICT_KEY_RE.fullmatch(k):
        raise HashError("key_pattern")

    return k


# ---------------------------------------------------------------------------
# Light textlike heuristic (bounded scan; optional in external)
# ---------------------------------------------------------------------------


def _looks_textlike(s: str, *, max_scan: int = 2048) -> bool:
    if not s:
        return False
    ss = s
    if len(ss) > max_scan:
        ss = ss[:max_scan]
    if "\n" in ss or "\r" in ss:
        return True
    ws = 0
    punct = 0
    for ch in ss:
        if ch.isspace():
            ws += 1
        elif ch in {".", ",", ";", ":", "?", "!"}:
            punct += 1
    if len(ss) >= 128 and ws >= max(4, len(ss) // 20):
        return True
    if len(ss) >= 256 and ws >= 8 and punct >= 2:
        return True
    return False


def _guard_value_string(s: str, cfg: KVHashConfig) -> bytes:
    if not isinstance(s, str):
        raise HashError("invalid_payload")
    if _has_surrogate(s):
        raise HashError("utf8_surrogate")

    b = _encode_utf8_injective(s)
    if len(b) > cfg.max_string_bytes:
        raise HashError("string_too_large")

    if cfg.value_string_mode == "tag":
        if not _TAGLIKE_VALUE_RE.fullmatch(s):
            raise HashError("taglike_required")

    if cfg.forbid_textlike_values and _looks_textlike(s):
        raise HashError("textlike_forbidden")

    return b


def _guard_value_bytes(v: Union[bytes, bytearray, memoryview], cfg: KVHashConfig) -> bytes:
    if not isinstance(v, (bytes, bytearray, memoryview)):
        raise HashError("invalid_payload")
    b = bytes(v)
    if cfg.max_bytes_value >= 0 and len(b) > cfg.max_bytes_value:
        raise HashError("bytes_too_large")
    if cfg.bytes_allowed_lens:
        if len(b) not in set(cfg.bytes_allowed_lens):
            raise HashError("bytes_len_forbidden")
    return b


def _guard_int(iv: int, cfg: KVHashConfig) -> bytes:
    if isinstance(iv, bool):
        raise HashError("invalid_payload")
    i = int(iv)
    if i.bit_length() > cfg.max_int_bits:
        raise HashError("int_too_large")
    # decimal ASCII is deterministic, cross-language friendly
    return str(i).encode("ascii", errors="strict")


def _encode_float_bytes(value: float, *, mode: FloatMode, normalize_zero: bool) -> bytes:
    v = float(value)
    if not (v == v) or v in (float("inf"), float("-inf")):
        raise HashError("float_invalid")
    if normalize_zero and v == 0.0:
        # canonicalize -0.0 to +0.0 (L7 semantic normalization)
        v = 0.0
    if mode == "ieee":
        return struct.pack("!d", v)
    # repr mode: stable in Python; KVv3 encourages ieee for cross-language
    return repr(v).encode("utf-8", errors="strict")


# ---------------------------------------------------------------------------
# Digest algorithm controls (bounded warnings; explicit resolved alg)
# ---------------------------------------------------------------------------

_WARNED_ALGS_LOCK = threading.Lock()
_WARNED_ALGS_SET: Set[str] = set()
_WARNED_ALGS_ORDER: deque[str] = deque()


def _warn_unknown_alg(name: str, *, max_items: int) -> None:
    if max_items <= 0:
        return
    with _WARNED_ALGS_LOCK:
        if name in _WARNED_ALGS_SET:
            return
        # bounded growth
        while len(_WARNED_ALGS_ORDER) >= max_items:
            old = _WARNED_ALGS_ORDER.popleft()
            _WARNED_ALGS_SET.discard(old)
        _WARNED_ALGS_SET.add(name)
        _WARNED_ALGS_ORDER.append(name)


def _resolve_digest(alg: str, *, cfg: KVHashConfig) -> Tuple[Any, str]:
    """
    Returns (hashlib_constructor, resolved_alg_name).

    - "blake3" is an alias for sha256 for backwards compatibility.
    - strict_alg_names controls whether the alias is allowed silently vs warned.
    """
    name = (alg or "").strip().lower()

    if name in ("", "sha256", "sha-256"):
        return hashlib.sha256, "sha256"

    if name in ("blake2s", "b2s"):
        return getattr(hashlib, "blake2s", hashlib.sha256), "blake2s"

    if name == "blake3":
        # compatibility alias; never pretend it's actually blake3
        if cfg.strict_alg_names:
            # still allow for compatibility, but make it observable
            _warn_unknown_alg("blake3_alias", max_items=cfg.warned_algs_max)
            logger.warning("TCD kv hashing: alg='blake3' is a compatibility alias; resolved to sha256")
        return hashlib.sha256, "sha256"

    if cfg.allow_legacy_algs:
        _warn_unknown_alg(name or "unknown", max_items=cfg.warned_algs_max)
        logger.warning("TCD kv hashing: unsupported alg %r requested; falling back to sha256", alg)
        return hashlib.sha256, "sha256"

    raise HashError("alg_unsupported")


# ---------------------------------------------------------------------------
# HMAC key normalization (min+max; strict)
# ---------------------------------------------------------------------------


def _normalize_key(key: Optional[bytes], cfg: KVHashConfig) -> Optional[bytes]:
    if key is None:
        return None
    if not isinstance(key, (bytes, bytearray)):
        raise HashError("invalid_payload")
    kb = bytes(key)
    if len(kb) < cfg.min_hmac_key_bytes:
        raise HashError("hmac_key_short")
    if len(kb) > cfg.max_hmac_key_bytes:
        raise HashError("hmac_key_too_long")
    return kb


# ---------------------------------------------------------------------------
# RollingHasher with byte-budget enforcement (negative budgets clamped)
# ---------------------------------------------------------------------------


def _u32be(n: int) -> bytes:
    iv = int(n)
    if iv < 0 or iv > 0xFFFFFFFF:
        raise HashError("invalid_payload")
    return iv.to_bytes(4, "big", signed=False)


def _encode_u64_le(value: int) -> bytes:
    if isinstance(value, bool):
        raise HashError("invalid_payload")
    iv = int(value)
    if iv < 0:
        raise HashError("invalid_payload")
    if iv > 0xFFFFFFFFFFFFFFFF:
        raise HashError("int_too_large")
    return iv.to_bytes(8, "little", signed=False)


class RollingHasher:
    """
    Streaming hasher for building stable digests over simple structures.

    Notes:
      - For KVv2, legacy ctx/label seeding is preserved for compatibility.
      - For KVv3, prefer explicit TLV header encoding (ctx/label/policy).
    """

    __slots__ = ("_h", "_cfg", "_written", "_max_bytes", "requested_alg", "resolved_alg")

    def __init__(
        self,
        alg: str = "sha256",
        ctx: str = "",
        *,
        key: Optional[bytes] = None,
        label: str = "",
        cfg: Optional[KVHashConfig] = None,
        max_bytes: Optional[int] = None,
        seed_ctx_label_legacy: bool = True,
    ) -> None:
        self._cfg = cfg or KVHashConfig.from_env()

        digestmod, resolved = _resolve_digest(alg, cfg=self._cfg)
        self.requested_alg = (alg or "").strip() or "sha256"
        self.resolved_alg = resolved

        k = _normalize_key(key, self._cfg) if key is not None else None
        if k is not None:
            self._h = hmac.new(k, digestmod=digestmod)
        else:
            self._h = digestmod()

        mb = int(max_bytes) if max_bytes is not None else int(self._cfg.max_bytes_total)
        # A6 fix: negative budgets do not mean “infinite”
        self._max_bytes = max(0, mb)
        self._written = 0

        # KVv2 legacy seeding semantics (not TLV); keep only when requested
        if seed_ctx_label_legacy:
            if label:
                self.update_bytes(b"kv.label:")
                self.update_str(label, legacy_utf8=True)
                self.update_bytes(b"\x00")
            if ctx:
                self.update_str(ctx, legacy_utf8=True)

    def _consume(self, n: int) -> None:
        self._written += int(n)
        if self._max_bytes > 0 and self._written > self._max_bytes:
            raise HashError("bytes_budget")

    def update_bytes(self, data: bytes) -> None:
        if not data:
            return
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise HashError("invalid_payload")
        b = bytes(data)
        self._consume(len(b))
        self._h.update(b)

    def update_str(self, value: str, *, legacy_utf8: bool = False) -> None:
        if not value:
            return
        if not isinstance(value, str):
            raise HashError("invalid_payload")

        # Injective for v2/v3; v1 may request legacy behavior, but we still reject surrogates
        if _has_surrogate(value):
            raise HashError("utf8_surrogate")

        if legacy_utf8:
            # legacy behavior allowed only for KVv1/KVv2 legacy seeding; still safe since no surrogates
            b = value.encode("utf-8", errors="ignore")
        else:
            b = value.encode("utf-8", errors="strict")

        self._consume(len(b))
        self._h.update(b)

    def update_ints(self, xs: Iterable[int]) -> None:
        for v in xs or []:
            b = _encode_u64_le(v)
            self._consume(len(b))
            self._h.update(b)

    def update_json_legacy(self, obj: Any) -> None:
        """
        Legacy canonical JSON encoding (only for KVv1 fallback).

        Hardened:
          - allow_nan=False (reject NaN/Inf)
          - no custom default serializer
        """
        payload = json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        b = payload.encode("utf-8", errors="strict")
        self._consume(len(b))
        self._h.update(b)

    def hex(self) -> str:
        return self._h.hexdigest()


# ---------------------------------------------------------------------------
# Policy digest & descriptor (B2/F2)
# ---------------------------------------------------------------------------


def kv_policy_digest(cfg: Optional[KVHashConfig] = None) -> str:
    """
    Stable, content-free digest of the KV hashing policy configuration.
    Does NOT include secret key material.
    """
    c = cfg or KVHashConfig.from_env()
    payload = {
        "profile": c.profile,
        "canonical_version": c.canonical_version,
        "allow_legacy_canonical": bool(c.allow_legacy_canonical),
        "allow_legacy_algs": bool(c.allow_legacy_algs),
        "strict_alg_names": bool(c.strict_alg_names),
        "float_mode": c.float_mode,
        "forbid_content_keys": bool(c.forbid_content_keys),
        "forbid_content_keys_strict": bool(c.forbid_content_keys_strict),
        "forbidden_keys": sorted(c.forbidden_keys),
        "forbid_textlike_values": bool(c.forbid_textlike_values),
        "value_string_mode": c.value_string_mode,
        "bytes_allowed_lens": list(c.bytes_allowed_lens),
        "require_hmac": bool(c.require_hmac),
        "strict_mapping_types": bool(c.strict_mapping_types),
        "max_bytes_total": int(c.max_bytes_total),
        "max_items": int(c.max_items),
        "max_depth": int(c.max_depth),
        "max_nodes": int(c.max_nodes),
        "max_key_bytes": int(c.max_key_bytes),
        "strict_key_pattern": bool(c.strict_key_pattern),
        "max_string_bytes": int(c.max_string_bytes),
        "max_bytes_value": int(c.max_bytes_value),
        "max_int_bits": int(c.max_int_bits),
        "min_hmac_key_bytes": int(c.min_hmac_key_bytes),
        "max_hmac_key_bytes": int(c.max_hmac_key_bytes),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode(
        "utf-8", errors="strict"
    )
    return hashlib.sha256(b"tcd:kv|policy|v1|" + raw).hexdigest()


@dataclass(frozen=True, slots=True)
class HashDescriptor:
    kv_version: CanonicalVersion
    requested_alg: str
    resolved_alg: str
    keyed: bool
    key_id: str
    policy_digest: str

    profile: Profile
    float_mode: FloatMode
    value_string_mode: ValueStringMode
    bytes_allowed_lens: Tuple[int, ...]
    require_hmac: bool
    strict_mapping_types: bool

    max_bytes_total: int
    max_items: int
    max_depth: int
    max_nodes: int

    label: str
    ctx: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kv_version": self.kv_version,
            "requested_alg": self.requested_alg,
            "resolved_alg": self.resolved_alg,
            "keyed": "1" if self.keyed else "0",
            "key_id": self.key_id,
            "policy_digest": self.policy_digest,
            "profile": self.profile,
            "float_mode": self.float_mode,
            "value_string_mode": self.value_string_mode,
            "bytes_allowed_lens": list(self.bytes_allowed_lens),
            "require_hmac": "1" if self.require_hmac else "0",
            "strict_mapping_types": "1" if self.strict_mapping_types else "0",
            "max_bytes_total": int(self.max_bytes_total),
            "max_items": int(self.max_items),
            "max_depth": int(self.max_depth),
            "max_nodes": int(self.max_nodes),
            "label": self.label,
            "ctx": self.ctx,
        }


# ---------------------------------------------------------------------------
# Mapping snapshot (D3)
# ---------------------------------------------------------------------------


def _is_builtin_safe_mapping(m: Any) -> bool:
    return isinstance(m, (dict, MappingProxyType))


def _snapshot_mapping(mapping: Mapping[str, Any], cfg: KVHashConfig) -> Dict[str, Any]:
    """
    Convert a mapping to a plain dict defensively.

    - If strict_mapping_types: only accepts dict or mappingproxy (built-in safe).
    - Otherwise: attempts to iterate and copy with item budget.
    """
    if not isinstance(mapping, Mapping):
        raise HashError("invalid_payload")

    if cfg.strict_mapping_types:
        if not _is_builtin_safe_mapping(mapping):
            raise HashError("invalid_payload")
        # safe snapshot
        try:
            d = dict(mapping)
        except Exception:
            raise HashError("invalid_payload")
        return d

    # Non-strict: copy iteratively with cap (still rejects non-str keys)
    out: Dict[str, Any] = {}
    count = 0
    try:
        for k, v in mapping.items():
            count += 1
            if count > cfg.max_items:
                raise HashError("mapping_too_large")
            if not isinstance(k, str):
                raise HashError("invalid_payload")
            out[k] = v
    except HashError:
        raise
    except Exception:
        raise HashError("invalid_payload")
    return out


# ---------------------------------------------------------------------------
# KVv2 encoder (keeps legacy ctx/label seeding semantics for compatibility)
# ---------------------------------------------------------------------------


class _KVv2Encoder:
    """
    KVv2 encoding:
      - Map/list containers are prefix-safe via counts;
      - Scalars are TLV (type byte + len32 + payload).
    """

    __slots__ = ("_h", "_cfg", "_nodes", "_seen")

    def __init__(self, rh: RollingHasher, cfg: KVHashConfig) -> None:
        self._h = rh
        self._cfg = cfg
        self._nodes = 0
        self._seen: Set[int] = set()

    def _bump(self) -> None:
        self._nodes += 1
        if self._nodes > self._cfg.max_nodes:
            raise HashError("max_nodes")

    def _enc_tlv(self, t: bytes, payload: bytes) -> None:
        self._h.update_bytes(t)
        self._h.update_bytes(_u32be(len(payload)))
        if payload:
            self._h.update_bytes(payload)

    def _cycle_guard(self, obj: Any) -> None:
        oid = id(obj)
        if oid in self._seen:
            raise HashError("cycle_detected")
        self._seen.add(oid)

    def _cycle_release(self, obj: Any) -> None:
        self._seen.discard(id(obj))

    def feed_value(self, v: Any, *, depth: int) -> None:
        self._bump()
        if depth > self._cfg.max_depth:
            raise HashError("max_depth")

        if v is None:
            self._enc_tlv(b"N", b"")
            return

        if isinstance(v, bool):
            self._enc_tlv(b"B", b"\x01" if v else b"\x00")
            return

        if isinstance(v, int) and not isinstance(v, bool):
            self._enc_tlv(b"I", _guard_int(v, self._cfg))
            return

        if isinstance(v, float):
            self._enc_tlv(b"F", _encode_float_bytes(v, mode=self._cfg.float_mode, normalize_zero=False))
            return

        if isinstance(v, str):
            self._enc_tlv(b"S", _guard_value_string(v, self._cfg))
            return

        if isinstance(v, (bytes, bytearray, memoryview)):
            self._enc_tlv(b"Y", _guard_value_bytes(v, self._cfg))
            return

        if isinstance(v, (list, tuple)):
            if len(v) > self._cfg.max_items:
                raise HashError("list_too_large")
            self._cycle_guard(v)
            try:
                self._h.update_bytes(b"L")
                self._h.update_bytes(_u32be(len(v)))
                for item in v:
                    self.feed_value(item, depth=depth + 1)
            finally:
                self._cycle_release(v)
            return

        if isinstance(v, Mapping):
            m = _snapshot_mapping(v, self._cfg)
            if len(m) > self._cfg.max_items:
                raise HashError("mapping_too_large")
            self._cycle_guard(m)
            try:
                items: list[Tuple[bytes, str, Any]] = []
                sum_key_bytes = 0
                for kk, vv in m.items():
                    ks = _guard_key(kk, self._cfg)
                    kb = _encode_utf8_injective(ks)
                    sum_key_bytes += len(kb)
                    items.append((kb, ks, vv))

                # D4: sorting budget guard (prevents large key material DoS)
                if sum_key_bytes > self._cfg.max_bytes_total:
                    raise HashError("bytes_budget")

                items.sort(key=lambda t: t[0])

                self._h.update_bytes(b"M")
                self._h.update_bytes(_u32be(len(items)))
                for kb, _ks, vv in items:
                    self._enc_tlv(b"K", kb)
                    self.feed_value(vv, depth=depth + 1)
            finally:
                self._cycle_release(m)
            return

        raise HashError("unsupported_type")


def _canonical_kv_hash_v2(
    mapping: Mapping[str, Any],
    *,
    ctx: str,
    label: str,
    key: Optional[bytes],
    alg: str,
    cfg: KVHashConfig,
) -> Tuple[str, HashDescriptor]:
    m = _snapshot_mapping(mapping, cfg)
    if len(m) > cfg.max_items:
        raise HashError("mapping_too_large")

    # KVv2 preserves legacy ctx/label seeding in RollingHasher for compatibility
    rh = RollingHasher(
        alg=alg,
        ctx=ctx,
        key=key,
        label=label,
        cfg=cfg,
        max_bytes=cfg.max_bytes_total,
        seed_ctx_label_legacy=True,
    )

    rh.update_bytes(b"kv.ver:2\x00")

    enc = _KVv2Encoder(rh, cfg)

    # map container
    items: list[Tuple[bytes, str, Any]] = []
    sum_key_bytes = 0
    for k, v in m.items():
        ks = _guard_key(k, cfg)
        kb = _encode_utf8_injective(ks)
        sum_key_bytes += len(kb)
        items.append((kb, ks, v))

    if sum_key_bytes > cfg.max_bytes_total:
        raise HashError("bytes_budget")

    items.sort(key=lambda t: t[0])

    rh.update_bytes(b"M")
    rh.update_bytes(_u32be(len(items)))
    for kb, _ks, v in items:
        rh.update_bytes(b"K")
        rh.update_bytes(_u32be(len(kb)))
        rh.update_bytes(kb)
        enc.feed_value(v, depth=1)

    digest = rh.hex()
    desc = HashDescriptor(
        kv_version="v2",
        requested_alg=rh.requested_alg,
        resolved_alg=rh.resolved_alg,
        keyed=bool(key is not None),
        key_id="",
        policy_digest=kv_policy_digest(cfg),
        profile=cfg.profile,
        float_mode=cfg.float_mode,
        value_string_mode=cfg.value_string_mode,
        bytes_allowed_lens=cfg.bytes_allowed_lens,
        require_hmac=cfg.require_hmac,
        strict_mapping_types=cfg.strict_mapping_types,
        max_bytes_total=cfg.max_bytes_total,
        max_items=cfg.max_items,
        max_depth=cfg.max_depth,
        max_nodes=cfg.max_nodes,
        label=label[:64],
        ctx=ctx[:64],
    )
    return digest, desc


# ---------------------------------------------------------------------------
# KVv3 encoder (B1/B2/B3/I2): fully TLV header + meta + structured body
# ---------------------------------------------------------------------------


class _KVv3Encoder:
    """
    KVv3 encoding:
      - TLV header includes domain prefix, version, ctx, label, and policy/meta flags;
      - body encoding reuses KVv2-style prefix-safe containers + TLV scalars;
      - floats normalize -0.0 to +0.0 (B3).
    """

    __slots__ = ("_h", "_cfg", "_nodes", "_seen")

    def __init__(self, rh: RollingHasher, cfg: KVHashConfig) -> None:
        self._h = rh
        self._cfg = cfg
        self._nodes = 0
        self._seen: Set[int] = set()

    def _bump(self) -> None:
        self._nodes += 1
        if self._nodes > self._cfg.max_nodes:
            raise HashError("max_nodes")

    def _tlv(self, t: bytes, payload: bytes) -> None:
        self._h.update_bytes(t)
        self._h.update_bytes(_u32be(len(payload)))
        if payload:
            self._h.update_bytes(payload)

    def _cycle_guard(self, obj: Any) -> None:
        oid = id(obj)
        if oid in self._seen:
            raise HashError("cycle_detected")
        self._seen.add(oid)

    def _cycle_release(self, obj: Any) -> None:
        self._seen.discard(id(obj))

    def feed_value(self, v: Any, *, depth: int) -> None:
        self._bump()
        if depth > self._cfg.max_depth:
            raise HashError("max_depth")

        if v is None:
            self._tlv(b"N", b"")
            return

        if isinstance(v, bool):
            self._tlv(b"B", b"\x01" if v else b"\x00")
            return

        if isinstance(v, int) and not isinstance(v, bool):
            self._tlv(b"I", _guard_int(v, self._cfg))
            return

        if isinstance(v, float):
            self._tlv(b"F", _encode_float_bytes(v, mode=self._cfg.float_mode, normalize_zero=True))
            return

        if isinstance(v, str):
            self._tlv(b"S", _guard_value_string(v, self._cfg))
            return

        if isinstance(v, (bytes, bytearray, memoryview)):
            self._tlv(b"Y", _guard_value_bytes(v, self._cfg))
            return

        if isinstance(v, (list, tuple)):
            if len(v) > self._cfg.max_items:
                raise HashError("list_too_large")
            self._cycle_guard(v)
            try:
                self._h.update_bytes(b"L")
                self._h.update_bytes(_u32be(len(v)))
                for item in v:
                    self.feed_value(item, depth=depth + 1)
            finally:
                self._cycle_release(v)
            return

        if isinstance(v, Mapping):
            m = _snapshot_mapping(v, self._cfg)
            if len(m) > self._cfg.max_items:
                raise HashError("mapping_too_large")
            self._cycle_guard(m)
            try:
                items: list[Tuple[bytes, str, Any]] = []
                sum_key_bytes = 0
                for kk, vv in m.items():
                    ks = _guard_key(kk, self._cfg)
                    kb = _encode_utf8_injective(ks)
                    sum_key_bytes += len(kb)
                    items.append((kb, ks, vv))

                if sum_key_bytes > self._cfg.max_bytes_total:
                    raise HashError("bytes_budget")

                items.sort(key=lambda t: t[0])

                self._h.update_bytes(b"M")
                self._h.update_bytes(_u32be(len(items)))
                for kb, _ks, vv in items:
                    self._tlv(b"K", kb)
                    self.feed_value(vv, depth=depth + 1)
            finally:
                self._cycle_release(m)
            return

        raise HashError("unsupported_type")


def _guard_label_ctx_tag(s: str, *, field_name: str) -> str:
    # ctx/label are developer-chosen domain-sep strings; keep them low-leak and bounded
    if not isinstance(s, str):
        raise HashError("invalid_payload")
    ss = s.strip()
    if not ss:
        return ""
    if _has_surrogate(ss):
        raise HashError("utf8_surrogate")
    if len(ss) > 128:
        # L7: do not allow huge domain strings to become covert channels
        raise HashError("invalid_payload")
    # allow slightly broader than TAGLIKE_VALUE_RE (ctx often uses ":" and "/")
    # but still forbid whitespace/newlines
    if any(ch.isspace() for ch in ss):
        raise HashError("invalid_payload")
    return ss


def _canonical_kv_hash_v3(
    mapping: Mapping[str, Any],
    *,
    ctx: str,
    label: str,
    key: Optional[bytes],
    key_id: str,
    alg: str,
    cfg: KVHashConfig,
) -> Tuple[str, HashDescriptor]:
    m = _snapshot_mapping(mapping, cfg)
    if len(m) > cfg.max_items:
        raise HashError("mapping_too_large")

    # External profile: require HMAC if configured
    if cfg.require_hmac and key is None:
        raise HashError("hmac_required_missing")

    # KVv3 uses explicit TLV header; DO NOT seed ctx/label via RollingHasher legacy mode
    rh = RollingHasher(
        alg=alg,
        ctx="",
        key=key,
        label="",
        cfg=cfg,
        max_bytes=cfg.max_bytes_total,
        seed_ctx_label_legacy=False,
    )

    # Domain prefix & version marker
    rh.update_bytes(_DOMAIN_PREFIX)
    rh.update_bytes(b"kv.ver:3\x00")

    # TLV header fields (B1)
    ctx2 = _guard_label_ctx_tag(ctx, field_name="ctx")
    label2 = _guard_label_ctx_tag(label, field_name="label")

    # Include policy/meta flags inside the digest (verifiable)
    pol = kv_policy_digest(cfg)
    rh.update_bytes(b"H")  # header container marker
    rh.update_bytes(_u32be(0))  # reserved length=0 (marker-only; makes it harder to accidentally collide)

    def tlv(t: bytes, payload: bytes) -> None:
        rh.update_bytes(t)
        rh.update_bytes(_u32be(len(payload)))
        if payload:
            rh.update_bytes(payload)

    tlv(b"V", b"\x03")
    tlv(b"A", _encode_utf8_injective(rh.resolved_alg))
    tlv(b"F", _encode_utf8_injective(cfg.float_mode))
    tlv(b"S", _encode_utf8_injective(cfg.value_string_mode))
    tlv(b"R", b"\x01" if cfg.require_hmac else b"\x00")
    tlv(b"M", b"\x01" if cfg.strict_mapping_types else b"\x00")
    # bytes lens list (comma)
    if cfg.bytes_allowed_lens:
        lens_csv = ",".join(str(x) for x in cfg.bytes_allowed_lens)
        tlv(b"Y", _encode_utf8_injective(lens_csv))
    tlv(b"P", bytes.fromhex(pol[:32]))  # short policy anchor inside hash (128-bit)

    if label2:
        tlv(b"L", _encode_utf8_injective(label2))
    if ctx2:
        tlv(b"C", _encode_utf8_injective(ctx2))

    # Body: deterministic map
    enc = _KVv3Encoder(rh, cfg)

    items: list[Tuple[bytes, str, Any]] = []
    sum_key_bytes = 0
    for k, v in m.items():
        ks = _guard_key(k, cfg)
        kb = _encode_utf8_injective(ks)
        sum_key_bytes += len(kb)
        items.append((kb, ks, v))

    if sum_key_bytes > cfg.max_bytes_total:
        raise HashError("bytes_budget")

    items.sort(key=lambda t: t[0])

    rh.update_bytes(b"M")
    rh.update_bytes(_u32be(len(items)))
    for kb, _ks, v in items:
        tlv(b"K", kb)
        enc.feed_value(v, depth=1)

    digest = rh.hex()
    desc = HashDescriptor(
        kv_version="v3",
        requested_alg=rh.requested_alg,
        resolved_alg=rh.resolved_alg,
        keyed=bool(key is not None),
        key_id=(key_id or "")[:32],
        policy_digest=pol,
        profile=cfg.profile,
        float_mode=cfg.float_mode,
        value_string_mode=cfg.value_string_mode,
        bytes_allowed_lens=cfg.bytes_allowed_lens,
        require_hmac=cfg.require_hmac,
        strict_mapping_types=cfg.strict_mapping_types,
        max_bytes_total=cfg.max_bytes_total,
        max_items=cfg.max_items,
        max_depth=cfg.max_depth,
        max_nodes=cfg.max_nodes,
        label=label2[:64],
        ctx=ctx2[:64],
    )
    return digest, desc


# ---------------------------------------------------------------------------
# KVv1 legacy encoder (AMBIGUOUS; opt-in only; additional restrictions)
# ---------------------------------------------------------------------------


def _canonical_kv_hash_v1(
    mapping: Mapping[str, Any],
    *,
    ctx: str,
    label: str,
    key: Optional[bytes],
    alg: str,
    cfg: KVHashConfig,
) -> Tuple[str, HashDescriptor]:
    if not cfg.allow_legacy_canonical:
        raise HashError("legacy_disabled")

    # A4 fix: v1 forbids ieee floats (delimiter-based encoding + raw bytes = worse ambiguity)
    if cfg.float_mode == "ieee":
        raise HashError("legacy_v1_ieee_forbidden")

    m = _snapshot_mapping(mapping, cfg)
    if len(m) > cfg.max_items:
        raise HashError("mapping_too_large")

    # v1 preserves legacy seeding of ctx/label
    rh = RollingHasher(
        alg=alg,
        ctx=ctx,
        key=key,
        label=label,
        cfg=cfg,
        max_bytes=cfg.max_bytes_total,
        seed_ctx_label_legacy=True,
    )
    rh.update_bytes(b"kv.ver:1\x00")

    # Canonical ordering by key bytes
    keys: list[str] = []
    sum_key_bytes = 0
    for k in m.keys():
        ks = _guard_key(k, cfg)
        kb = _encode_utf8_injective(ks)
        sum_key_bytes += len(kb)
        keys.append(ks)
    if sum_key_bytes > cfg.max_bytes_total:
        raise HashError("bytes_budget")

    keys.sort(key=lambda s: _encode_utf8_injective(s))

    def feed_scalar_v1(v: Any) -> None:
        # typed tags with delimiter boundaries (legacy; still safer than raw)
        if v is None:
            rh.update_bytes(b"t:none;")
            return
        if isinstance(v, bool):
            rh.update_bytes(b"t:bool;")
            rh.update_bytes(b"1" if v else b"0")
            rh.update_bytes(b";")
            return
        if isinstance(v, int) and not isinstance(v, bool):
            rh.update_bytes(b"t:int;")
            rh.update_bytes(_guard_int(v, cfg))
            rh.update_bytes(b";")
            return
        if isinstance(v, float):
            rh.update_bytes(b"t:float;")
            rh.update_bytes(_encode_float_bytes(v, mode="repr", normalize_zero=False))
            rh.update_bytes(b";")
            return
        if isinstance(v, str):
            rh.update_bytes(b"t:str;")
            rh.update_bytes(_guard_value_string(v, cfg))
            rh.update_bytes(b";")
            return
        if isinstance(v, (list, tuple, dict)):
            # legacy JSON fallback, hardened
            rh.update_bytes(b"t:json;")
            rh.update_json_legacy(v)
            rh.update_bytes(b";")
            return
        raise HashError("unsupported_type")

    for ks in keys:
        rh.update_bytes(b"k:")
        rh.update_bytes(_encode_utf8_injective(ks))
        rh.update_bytes(b";v:")
        feed_scalar_v1(m[ks])
        rh.update_bytes(b";")

    digest = rh.hex()
    desc = HashDescriptor(
        kv_version="v1",
        requested_alg=rh.requested_alg,
        resolved_alg=rh.resolved_alg,
        keyed=bool(key is not None),
        key_id="",
        policy_digest=kv_policy_digest(cfg),
        profile=cfg.profile,
        float_mode=cfg.float_mode,
        value_string_mode=cfg.value_string_mode,
        bytes_allowed_lens=cfg.bytes_allowed_lens,
        require_hmac=cfg.require_hmac,
        strict_mapping_types=cfg.strict_mapping_types,
        max_bytes_total=cfg.max_bytes_total,
        max_items=cfg.max_items,
        max_depth=cfg.max_depth,
        max_nodes=cfg.max_nodes,
        label=label[:64],
        ctx=ctx[:64],
    )
    return digest, desc


# ---------------------------------------------------------------------------
# Public API: canonical_kv_hash (digest-only), plus safe+descriptor variants
# ---------------------------------------------------------------------------


def canonical_kv_hash(
    mapping: Mapping[str, Any],
    *,
    ctx: str = "",
    label: str = "kv",
    key: Optional[bytes] = None,
    alg: str = "blake3",
    cfg: Optional[KVHashConfig] = None,
) -> str:
    """
    Compute a canonical hash for a mapping of key/value pairs.

    Default version depends on profile:
      - internal: v2 (compat)
      - external: v3 (strict)

    For a never-throw API and descriptors, use canonical_kv_hash_safe().
    """
    c = cfg or KVHashConfig.from_env()
    k = _normalize_key(key, c) if key is not None else None

    ver = c.canonical_version
    if ver == "v1":
        digest, _ = _canonical_kv_hash_v1(mapping, ctx=ctx, label=label, key=k, alg=alg, cfg=c)
        return digest
    if ver == "v3":
        digest, _ = _canonical_kv_hash_v3(mapping, ctx=ctx, label=label, key=k, key_id="", alg=alg, cfg=c)
        return digest
    digest, _ = _canonical_kv_hash_v2(mapping, ctx=ctx, label=label, key=k, alg=alg, cfg=c)
    return digest


def canonical_kv_hash_with_descriptor(
    mapping: Mapping[str, Any],
    *,
    ctx: str = "",
    label: str = "kv",
    key: Optional[bytes] = None,
    key_id: str = "",
    alg: str = "blake3",
    cfg: Optional[KVHashConfig] = None,
) -> Tuple[str, HashDescriptor]:
    """
    Descriptor-returning variant (may raise HashError).
    """
    c = cfg or KVHashConfig.from_env()
    k = _normalize_key(key, c) if key is not None else None

    ver = c.canonical_version
    if ver == "v1":
        return _canonical_kv_hash_v1(mapping, ctx=ctx, label=label, key=k, alg=alg, cfg=c)
    if ver == "v3":
        return _canonical_kv_hash_v3(mapping, ctx=ctx, label=label, key=k, key_id=key_id, alg=alg, cfg=c)
    return _canonical_kv_hash_v2(mapping, ctx=ctx, label=label, key=k, alg=alg, cfg=c)


def canonical_kv_hash_safe(
    mapping: Mapping[str, Any],
    *,
    ctx: str = "",
    label: str = "kv",
    key: Optional[bytes] = None,
    key_id: str = "",
    alg: str = "blake3",
    cfg: Optional[KVHashConfig] = None,
) -> Tuple[bool, str, ErrCode, HashDescriptor]:
    """
    Never-throw API: returns (ok, digest, err_code, descriptor).

    On error, digest is "", ok=False, err_code is low-cardinality, and descriptor
    still reflects the policy snapshot for observability.
    """
    c = cfg or KVHashConfig.from_env()
    pol = kv_policy_digest(c)
    # best-effort descriptor placeholder (filled properly on success)
    placeholder = HashDescriptor(
        kv_version=c.canonical_version,
        requested_alg=(alg or "").strip() or "sha256",
        resolved_alg="",
        keyed=bool(key is not None),
        key_id=(key_id or "")[:32],
        policy_digest=pol,
        profile=c.profile,
        float_mode=c.float_mode,
        value_string_mode=c.value_string_mode,
        bytes_allowed_lens=c.bytes_allowed_lens,
        require_hmac=c.require_hmac,
        strict_mapping_types=c.strict_mapping_types,
        max_bytes_total=c.max_bytes_total,
        max_items=c.max_items,
        max_depth=c.max_depth,
        max_nodes=c.max_nodes,
        label=(label or "")[:64],
        ctx=(ctx or "")[:64],
    )

    try:
        digest, desc = canonical_kv_hash_with_descriptor(
            mapping, ctx=ctx, label=label, key=key, key_id=key_id, alg=alg, cfg=c
        )
        return True, digest, _ERR_OK, desc
    except HashError as e:
        # minimal leakage: do not re-emit details unless configured
        if c.verbose_errors and e.detail:
            logger.debug("kv hash error %s detail=%s", e.code, e.detail)
        return False, "", e.code, placeholder
    except Exception:
        return False, "", "unknown", placeholder


# ---------------------------------------------------------------------------
# KVHashContext (I1/E2/E3): immutable policy+keys, supports rotation & safe calls
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KeyMaterial:
    key_id: str
    key: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class KVHashContext:
    """
    Context object holding:
      - a frozen KVHashConfig snapshot,
      - one or more HMAC keys (for rotation),
      - a default alg.

    Use this to ensure one process doesn't accidentally hash with inconsistent policy snapshots.
    """

    cfg: KVHashConfig
    keys: Tuple[KeyMaterial, ...] = ()
    default_alg: str = "blake3"

    @staticmethod
    def from_env(*, keys: Optional[Iterable[KeyMaterial]] = None, default_alg: str = "blake3") -> "KVHashContext":
        cfg = KVHashConfig.from_env()
        ks = tuple(keys or ())
        # Normalize keys (validate lengths up front)
        normed: list[KeyMaterial] = []
        for km in ks:
            k = _normalize_key(km.key, cfg)
            if k is None:
                continue
            kid = (km.key_id or "")[:32]
            normed.append(KeyMaterial(key_id=kid, key=k))
        return KVHashContext(cfg=cfg, keys=tuple(normed), default_alg=default_alg)

    def active_key(self) -> Optional[KeyMaterial]:
        return self.keys[0] if self.keys else None

    def hash(self, mapping: Mapping[str, Any], *, ctx: str = "", label: str = "kv", alg: Optional[str] = None) -> str:
        km = self.active_key()
        if self.cfg.require_hmac and km is None:
            raise HashError("hmac_required_missing")
        return canonical_kv_hash(
            mapping,
            ctx=ctx,
            label=label,
            key=(km.key if km else None),
            alg=alg or self.default_alg,
            cfg=self.cfg,
        )

    def hash_with_descriptor(
        self, mapping: Mapping[str, Any], *, ctx: str = "", label: str = "kv", alg: Optional[str] = None
    ) -> Tuple[str, HashDescriptor]:
        km = self.active_key()
        if self.cfg.require_hmac and km is None:
            raise HashError("hmac_required_missing")
        return canonical_kv_hash_with_descriptor(
            mapping,
            ctx=ctx,
            label=label,
            key=(km.key if km else None),
            key_id=(km.key_id if km else ""),
            alg=alg or self.default_alg,
            cfg=self.cfg,
        )

    def hash_safe(
        self, mapping: Mapping[str, Any], *, ctx: str = "", label: str = "kv", alg: Optional[str] = None
    ) -> Tuple[bool, str, ErrCode, HashDescriptor]:
        km = self.active_key()
        return canonical_kv_hash_safe(
            mapping,
            ctx=ctx,
            label=label,
            key=(km.key if km else None),
            key_id=(km.key_id if km else ""),
            alg=alg or self.default_alg,
            cfg=self.cfg,
        )

    def hash_all_keys(
        self, mapping: Mapping[str, Any], *, ctx: str = "", label: str = "kv", alg: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Rotation helper: compute digests under all configured keys.

        Returns dict key_id -> digest. Keys without key_id use "".
        """
        out: Dict[str, str] = {}
        for km in self.keys:
            d = canonical_kv_hash(
                mapping, ctx=ctx, label=label, key=km.key, alg=alg or self.default_alg, cfg=self.cfg
            )
            out[km.key_id] = d
        if not self.keys:
            # unkeyed
            out[""] = canonical_kv_hash(mapping, ctx=ctx, label=label, key=None, alg=alg or self.default_alg, cfg=self.cfg)
        return out


# ---------------------------------------------------------------------------
# Standardized envelope helpers (F3/J1): strict schemas, no silent type coercion
# ---------------------------------------------------------------------------


def _require_float(x: Any, *, name: str) -> float:
    if isinstance(x, bool):
        raise HashError("invalid_payload")
    if isinstance(x, (int, float)) and not isinstance(x, bool):
        v = float(x)
        if not (v == v) or v in (float("inf"), float("-inf")):
            raise HashError("float_invalid")
        return v
    raise HashError("invalid_payload")


def _require_bool(x: Any, *, name: str) -> bool:
    if isinstance(x, bool):
        return x
    # do not coerce arbitrary values
    raise HashError("invalid_payload")


def _require_tag_str(x: Any, *, name: str, max_len: int = 64) -> str:
    if not isinstance(x, str):
        raise HashError("invalid_payload")
    s = x.strip()
    if not s:
        raise HashError("invalid_payload")
    if len(s) > max_len:
        raise HashError("invalid_payload")
    if _has_surrogate(s):
        raise HashError("utf8_surrogate")
    # schema fields should be tag-like
    if not _TAGLIKE_VALUE_RE.fullmatch(s):
        raise HashError("taglike_required")
    return s


def eprocess_envelope_hash(
    *,
    e_value: float,
    a_alloc: float,
    score: float,
    wealth_before: float,
    wealth_after: float,
    policy_ref: str,
    ctx: str = "",
    key: Optional[bytes] = None,
    alg: str = "blake3",
    cfg: Optional[KVHashConfig] = None,
) -> str:
    """
    Hash for e-process / alpha-investing envelope (schema e_process@1).
    """
    mapping = {
        "schema": "e_process@1",
        "e_value": _require_float(e_value, name="e_value"),
        "a_alloc": _require_float(a_alloc, name="a_alloc"),
        "score": _require_float(score, name="score"),
        "wealth_before": _require_float(wealth_before, name="wealth_before"),
        "wealth_after": _require_float(wealth_after, name="wealth_after"),
        "policy_ref": _require_tag_str(policy_ref, name="policy_ref", max_len=64),
    }
    return canonical_kv_hash(mapping, ctx=ctx, label="e_process", key=key, alg=alg, cfg=cfg)


def pq_attestation_hash(
    *,
    pq_scheme: str,
    pq_required: bool,
    pq_ok: bool,
    chain_id: str,
    ctx: str = "",
    key: Optional[bytes] = None,
    alg: str = "blake3",
    cfg: Optional[KVHashConfig] = None,
) -> str:
    """
    Hash for PQ attestation envelope (schema pq_attest@1).
    """
    mapping = {
        "schema": "pq_attest@1",
        "pq_scheme": _require_tag_str(pq_scheme, name="pq_scheme", max_len=32),
        "pq_required": _require_bool(pq_required, name="pq_required"),
        "pq_ok": _require_bool(pq_ok, name="pq_ok"),
        "chain_id": _require_tag_str(chain_id, name="chain_id", max_len=64),
    }
    return canonical_kv_hash(mapping, ctx=ctx, label="pq_attest", key=key, alg=alg, cfg=cfg)


def chain_id_hash(
    *,
    tenant: str,
    route_profile: str,
    policy_ref: str,
    ctx: str = "",
    key: Optional[bytes] = None,
    alg: str = "blake3",
    cfg: Optional[KVHashConfig] = None,
) -> str:
    """
    Stable chain identifier for receipts and routes (schema chain_id@1).
    """
    mapping = {
        "schema": "chain_id@1",
        "tenant": _require_tag_str(tenant, name="tenant", max_len=64),
        "route_profile": _require_tag_str(route_profile, name="route_profile", max_len=64),
        "policy_ref": _require_tag_str(policy_ref, name="policy_ref", max_len=64),
    }
    return canonical_kv_hash(mapping, ctx=ctx, label="chain_id", key=key, alg=alg, cfg=cfg)


# ---------------------------------------------------------------------------
# Optional: minimal self-test vectors helper (H1 convenience; no side effects)
# ---------------------------------------------------------------------------


def kv_selftest_vectors() -> Dict[str, str]:
    """
    Deterministic vectors using an explicit in-code config (independent of env),
    useful for unit tests / cross-language fixtures.

    NOTE: This function does not run automatically; it only returns data.
    """
    cfg = KVHashConfig(
        profile="internal",
        canonical_version="v3",
        allow_legacy_canonical=False,
        allow_legacy_algs=False,
        strict_alg_names=True,
        float_mode="ieee",
        forbid_content_keys=True,
        forbid_content_keys_strict=True,
        forbidden_keys=_DEFAULT_FORBIDDEN_KEYS,
        forbidden_exact_lower=frozenset({k.strip().lower() for k in _DEFAULT_FORBIDDEN_KEYS if k}),
        forbidden_token_seqs=tuple({ts: None for ts in (_key_tokens(k) for k in _DEFAULT_FORBIDDEN_KEYS) if ts}.keys()),
        forbid_textlike_values=True,
        value_string_mode="tag",
        bytes_allowed_lens=(16, 32, 64),
        require_hmac=False,
        strict_mapping_types=True,
        max_bytes_total=4096,
        max_items=256,
        max_depth=8,
        max_nodes=2048,
        max_key_bytes=64,
        strict_key_pattern=True,
        max_string_bytes=256,
        max_bytes_value=64,
        max_int_bits=256,
        min_hmac_key_bytes=16,
        max_hmac_key_bytes=4096,
        warned_algs_max=64,
        verbose_errors=False,
    )

    samples = {
        "scalars": {"a": 1, "b": True, "c": None, "d": 0.0, "e": "tag-OK"},
        "nested": {"x": {"y": [1, 2, 3], "z": b"\x00" * 16}},
        "order_invariant": {"k2": "v2", "k1": "v1"},
    }
    out: Dict[str, str] = {}
    for name, m in samples.items():
        ok, dig, _code, _desc = canonical_kv_hash_safe(m, ctx="test", label=f"kv_selftest:{name}", cfg=cfg, alg="sha256")
        out[name] = dig if ok else ""
    return out