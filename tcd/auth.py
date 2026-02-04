from __future__ import annotations

import asyncio
import base64
import collections
import hashlib
import hmac
import ipaddress
import json
import math
import os
import random
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from fastapi import HTTPException
from starlette.requests import Request

from .kv import canonical_kv_hash

# ---------------------------------------------------------------------------
# Optional dependencies
# ---------------------------------------------------------------------------

try:
    from prometheus_client import REGISTRY, CollectorRegistry, Counter, Gauge, Histogram  # type: ignore

    _HAS_PROM = True
except Exception:  # pragma: no cover
    _HAS_PROM = False

try:
    from jwcrypto import jwk, jwt  # type: ignore

    _HAS_JWCRYPTO = True
except Exception:  # pragma: no cover
    _HAS_JWCRYPTO = False

# stdlib http (blocking) for JWKS fetch
try:
    from urllib.request import build_opener, urlopen, Request as UrlRequest  # type: ignore
    from urllib.error import URLError, HTTPError  # type: ignore
    from urllib.request import HTTPRedirectHandler  # type: ignore

    _HAS_URL = True
except Exception:  # pragma: no cover
    _HAS_URL = False

# blake3 is optional; HMAC-SHA256 is available in stdlib as alternative
try:
    from blake3 import blake3  # type: ignore

    _HAS_BLAKE3 = True
except Exception:  # pragma: no cover
    _HAS_BLAKE3 = False

# ---------------------------------------------------------------------------
# Low-cardinality enums (reasons/fields must be bounded)
# ---------------------------------------------------------------------------

# Generic
R_OTHER = "other"
R_MISSING = "missing"
R_MALFORMED = "malformed"
R_DENIED = "denied"
R_FORBIDDEN = "forbidden"
R_BAD_MODE = "bad_mode"
R_HEADER_TOO_LARGE = "header_too_large"
R_BODY_TOO_LARGE = "body_too_large"
R_BODY_READ_ERROR = "body_read_error"
R_PATH_TOO_LARGE = "path_too_large"
R_QUERY_TOO_LARGE = "query_too_large"
R_HEADERS_TOO_LARGE = "headers_too_large"

# HMAC
R_BAD_SCHEME = "bad_scheme"
R_UNKNOWN_KEY = "unknown_key"
R_BAD_KID = "bad_kid"
R_SKEW = "skew"
R_REPLAY = "replay"
R_SIG_MISMATCH = "sig_mismatch"
R_KEY_INVALID = "key_invalid"
R_LIB_MISSING = "lib_missing"
R_BAD_ALG = "bad_alg"
R_NONCE_REQUIRED = "nonce_required"
R_QUERY_INVALID = "query_invalid"
R_HEADER_INVALID = "header_invalid"
R_PATH_INVALID = "path_invalid"

# JWT
R_TOKEN_TOO_LARGE = "token_too_large"
R_BAD_HEADER = "bad_header"
R_NO_KID = "no_kid"
R_NO_JWK = "no_jwk"
R_BAD_SIG = "bad_sig"
R_BAD_CLAIMS = "bad_claims"
R_BAD_ISS = "bad_iss"
R_BAD_AUD = "bad_aud"
R_EXPIRED = "expired"
R_NOT_YET = "not_yet"
R_NO_EXP = "no_exp"
R_IAT = "iat"
R_TOO_OLD = "too_old"
R_NO_PRINCIPAL = "no_principal"
R_JTI_REPLAY = "jti_replay"

# mTLS / XFCC
R_XFCC_UNTRUSTED = "xfcc_untrusted"
R_XFCC_PARSE = "xfcc_parse"
R_XFCC_HASH = "xfcc_hash"
R_XFCC_SPIFFE = "xfcc_spiffe"

# JWT claim fail fields (bounded)
CF_ALG = "alg"
CF_KID = "kid"
CF_TYP = "typ"
CF_CRIT = "crit"
CF_ISS = "iss"
CF_AUD = "aud"
CF_EXP = "exp"
CF_NBF = "nbf"
CF_IAT = "iat"
CF_JTI = "jti"
CF_SIG = "sig"
CF_PRINCIPAL = "principal"

# Bounded allowlists to prevent accidental high-cardinality metrics
_ALLOWED_REASONS = {
    R_OTHER,
    R_MISSING,
    R_MALFORMED,
    R_DENIED,
    R_FORBIDDEN,
    R_BAD_MODE,
    R_HEADER_TOO_LARGE,
    R_BODY_TOO_LARGE,
    R_BODY_READ_ERROR,
    R_PATH_TOO_LARGE,
    R_QUERY_TOO_LARGE,
    R_HEADERS_TOO_LARGE,
    R_BAD_SCHEME,
    R_UNKNOWN_KEY,
    R_BAD_KID,
    R_SKEW,
    R_REPLAY,
    R_SIG_MISMATCH,
    R_KEY_INVALID,
    R_LIB_MISSING,
    R_BAD_ALG,
    R_NONCE_REQUIRED,
    R_QUERY_INVALID,
    R_HEADER_INVALID,
    R_PATH_INVALID,
    R_TOKEN_TOO_LARGE,
    R_BAD_HEADER,
    R_NO_KID,
    R_NO_JWK,
    R_BAD_SIG,
    R_BAD_CLAIMS,
    R_BAD_ISS,
    R_BAD_AUD,
    R_EXPIRED,
    R_NOT_YET,
    R_NO_EXP,
    R_IAT,
    R_TOO_OLD,
    R_NO_PRINCIPAL,
    R_JTI_REPLAY,
    R_XFCC_UNTRUSTED,
    R_XFCC_PARSE,
    R_XFCC_HASH,
    R_XFCC_SPIFFE,
}

_ALLOWED_JWKS_FAIL_KINDS = {"ok", "lib_missing", "bad_status", "too_large", "bad_json", "redirect", "exception", "backoff"}
_ALLOWED_HEADERS_LABEL = {"authorization", "x-tcd-signature", "x-tcd-key-id", "x-forwarded-client-cert", "content-length", "other"}

_ALLOWED_JWT_CLAIM_FIELDS = {
    CF_ALG,
    CF_KID,
    CF_TYP,
    CF_CRIT,
    CF_ISS,
    CF_AUD,
    CF_EXP,
    CF_NBF,
    CF_IAT,
    CF_JTI,
    CF_SIG,
    CF_PRINCIPAL,
}

_CTRL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_SAFE_KID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SAFE_NONCE_RE = re.compile(r"^[A-Za-z0-9._:-]{8,256}$")  # bounded and conservative
_SAFE_SPIFFE_RE = re.compile(r"^spiffe://[A-Za-z0-9\-._~/%:@+]+$")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class AuthContext:
    mode: str
    principal: str
    scopes: List[str]
    key_id: Optional[str]
    raw: Dict[str, str]
    policy_digest: Optional[str] = None
    issued_at: float = 0.0
    authn_strength: str = ""  # e.g. "disabled"|"bearer"|"hmac"|"jwt"|"mtls"


@dataclass(slots=True)
class AuthResult:
    ok: bool
    ctx: Optional[AuthContext]
    reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Safety helpers
# ---------------------------------------------------------------------------

def _safe_text(x: Any, *, max_len: int = 128) -> str:
    try:
        s = str(x)
    except Exception:
        s = "<unprintable>"
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = _CTRL_CHARS_RE.sub("", s).strip()
    s = s.encode("utf-8", errors="replace").decode("utf-8", errors="strict")
    if max_len <= 0:
        return ""
    if len(s) <= max_len:
        return s
    return s[: max(0, max_len - 3)] + "..."


def _is_finite(x: float) -> bool:
    return math.isfinite(x)


def _b(s: str) -> bytes:
    return s.encode("utf-8", errors="strict")


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _json_loads_strict(s: str) -> Any:
    # Reject NaN/Infinity and other non-standard JSON constants.
    def _bad_const(_: str) -> Any:
        raise ValueError("non-finite json constant")

    return json.loads(s, parse_constant=_bad_const)


def _parse_bool_env(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _parse_int_env(name: str, default: int) -> int:
    v = os.environ.get(name)
    if v is None:
        return int(default)
    try:
        return int(str(v).strip())
    except Exception:
        return int(default)


def _parse_float_env(name: str, default: float) -> float:
    v = os.environ.get(name)
    if v is None:
        return float(default)
    try:
        x = float(str(v).strip())
        return x if _is_finite(x) else float(default)
    except Exception:
        return float(default)


def _hex_bytes_limited(s: str, *, max_hex_chars: int) -> Optional[bytes]:
    ss = (s or "").strip()
    if ss.startswith(("0x", "0X")):
        ss = ss[2:]
    if ss == "":
        return None
    if len(ss) > int(max_hex_chars):
        return None
    if len(ss) % 2 == 1:
        ss = "0" + ss
        if len(ss) > int(max_hex_chars):
            return None
    if not _HEX_RE.fullmatch(ss):
        return None
    try:
        return bytes.fromhex(ss)
    except Exception:
        return None


def _pct_encode_bytes(bts: bytes) -> str:
    # RFC3986 unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~"
    out: List[str] = []
    for c in bts:
        if (48 <= c <= 57) or (65 <= c <= 90) or (97 <= c <= 122) or c in (45, 46, 95, 126):
            out.append(chr(c))
        else:
            out.append(f"%{c:02X}")
    return "".join(out)


def _percent_decode_bytes(inp: bytes, *, plus_as_space: bool, max_out: int) -> Optional[bytes]:
    if plus_as_space:
        inp = inp.replace(b"+", b" ")
    out = bytearray()
    i = 0
    n = len(inp)
    while i < n:
        if len(out) > max_out:
            return None
        c = inp[i]
        if c == 37:  # %
            if i + 2 >= n:
                return None
            h1 = inp[i + 1]
            h2 = inp[i + 2]
            try:
                v = int(bytes([h1, h2]).decode("ascii"), 16)
            except Exception:
                return None
            out.append(v)
            i += 3
        else:
            out.append(c)
            i += 1
    if len(out) > max_out:
        return None
    return bytes(out)


def _canonicalize_query_bytes(
    query_bytes: bytes,
    *,
    mode: str,
    max_query_bytes: int,
    max_pairs: int,
    max_key_bytes: int,
    max_val_bytes: int,
) -> Optional[bytes]:
    if query_bytes is None:
        return b""
    qb = bytes(query_bytes)
    if len(qb) > int(max_query_bytes):
        return None
    if not qb:
        return b""

    plus_as_space = (mode == "form")
    pairs_raw = qb.split(b"&")
    if len(pairs_raw) > int(max_pairs):
        return None

    decoded_pairs: List[Tuple[bytes, bytes]] = []
    for item in pairs_raw:
        if item == b"":
            # keep blank as ("","")? For canonical stability, keep as empty key with empty value.
            k_raw = b""
            v_raw = b""
        else:
            if b"=" in item:
                k_raw, v_raw = item.split(b"=", 1)
            else:
                k_raw, v_raw = item, b""
        k = _percent_decode_bytes(k_raw, plus_as_space=plus_as_space, max_out=max_key_bytes)
        v = _percent_decode_bytes(v_raw, plus_as_space=plus_as_space, max_out=max_val_bytes)
        if k is None or v is None:
            return None
        decoded_pairs.append((k, v))

    decoded_pairs.sort(key=lambda kv: (kv[0], kv[1]))

    # encode with normalized percent-encoding
    out_parts: List[str] = []
    for k, v in decoded_pairs:
        out_parts.append(f"{_pct_encode_bytes(k)}={_pct_encode_bytes(v)}")
    return "&".join(out_parts).encode("ascii", errors="strict")


def _get_raw_path_bytes(request: Request) -> bytes:
    rp = request.scope.get("raw_path")
    if isinstance(rp, (bytes, bytearray)):
        return bytes(rp)
    # fallback to path string, but keep it stable
    return request.url.path.encode("utf-8", errors="surrogateescape")


def _get_query_bytes(request: Request) -> bytes:
    qs = request.scope.get("query_string")
    if isinstance(qs, (bytes, bytearray)):
        return bytes(qs)
    # fallback to decoded query string
    return (request.url.query or "").encode("utf-8", errors="surrogateescape")


def _headers_total_bytes(request: Request) -> int:
    hdrs = request.scope.get("headers")
    if isinstance(hdrs, list):
        total = 0
        for kv in hdrs:
            if isinstance(kv, (list, tuple)) and len(kv) == 2:
                k, v = kv
                if isinstance(k, (bytes, bytearray)):
                    total += len(k)
                if isinstance(v, (bytes, bytearray)):
                    total += len(v)
        return total
    return 0


async def _read_body_limited(
    request: Request,
    *,
    limit_bytes: int,
    enforce_content_length: bool = True,
) -> bytes:
    """
    Read request body with a hard limit and NO unsafe fallback to request.body().
    Ensures request._body is set on success, so downstream request.stream() will replay cached body.
    """
    lim = max(0, int(limit_bytes))

    cached = getattr(request, "_body", None)
    if isinstance(cached, (bytes, bytearray)):
        b = bytes(cached)
        if len(b) > lim:
            raise ValueError(R_BODY_TOO_LARGE)
        return b

    if enforce_content_length:
        cl = request.headers.get("content-length")
        if cl:
            try:
                n = int(cl.strip())
                if n > lim:
                    raise ValueError(R_BODY_TOO_LARGE)
            except ValueError:
                # invalid content-length -> fail closed (prevents weird proxy behavior)
                raise ValueError(R_BODY_READ_ERROR)

    total = 0
    chunks: List[bytes] = []
    try:
        async for chunk in request.stream():
            if not chunk:
                continue
            bch = bytes(chunk)
            total += len(bch)
            if total > lim:
                raise ValueError(R_BODY_TOO_LARGE)
            chunks.append(bch)
    except ValueError:
        raise
    except Exception:
        # NEVER fallback to unlimited request.body(): fail closed.
        raise ValueError(R_BODY_READ_ERROR)

    b = b"".join(chunks)
    if len(b) > lim:
        raise ValueError(R_BODY_TOO_LARGE)
    try:
        setattr(request, "_body", b)
    except Exception:
        pass
    return b


def _b64url_decode_json_segment(seg: str, *, max_chars: int, max_bytes: int) -> Optional[dict]:
    if not isinstance(seg, str) or len(seg) == 0:
        return None
    if len(seg) > int(max_chars):
        return None
    pad = "=" * ((4 - (len(seg) % 4)) % 4)
    try:
        raw = base64.urlsafe_b64decode(seg + pad)
    except Exception:
        return None
    if len(raw) > int(max_bytes):
        return None
    try:
        obj = _json_loads_strict(raw.decode("utf-8", errors="strict"))
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def _jwt_unverified_header(token: str, *, max_token_chars: int) -> Optional[dict]:
    if not isinstance(token, str):
        return None
    if len(token) > int(max_token_chars):
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    return _b64url_decode_json_segment(parts[0], max_chars=min(4096, int(max_token_chars)), max_bytes=64 * 1024)


def _claim_int(claims: dict, key: str) -> Optional[int]:
    v = claims.get(key)
    if v is None:
        return None
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return int(v)
    if isinstance(v, str):
        try:
            return int(v.strip())
        except Exception:
            return None
    return None


def _dedup_scopes_iter_bounded(
    claims: dict,
    claim_names: Tuple[str, ...],
    *,
    max_items_out: int,
    max_item_len: int,
    max_raw_items: int,
    max_scope_str_chars: int,
    strict_types: bool,
) -> Tuple[Optional[List[str]], bool]:
    """
    Returns (scopes_or_none, ok_types).
      - scopes_or_none: list of unique scopes (sorted) or None if none found
      - ok_types: False if type violation occurred and strict_types=True is desired to fail closed
    """
    seen = set()
    out: List[str] = []
    ok_types = True
    raw_seen = 0

    for k in claim_names:
        v = claims.get(k)
        if v is None:
            continue

        if isinstance(v, str):
            s = v[: max(0, int(max_scope_str_chars))]
            for part in s.split():
                if raw_seen >= int(max_raw_items):
                    break
                raw_seen += 1
                part = part.strip()
                if not part:
                    continue
                if len(part) > int(max_item_len):
                    part = part[: int(max_item_len)]
                if part not in seen:
                    seen.add(part)
                    out.append(part)
                    if len(out) >= int(max_items_out):
                        break
        elif isinstance(v, list):
            for item in v:
                if raw_seen >= int(max_raw_items):
                    break
                raw_seen += 1
                if not isinstance(item, str):
                    if strict_types:
                        ok_types = False
                    continue
                part = item.strip()
                if not part:
                    continue
                if len(part) > int(max_item_len):
                    part = part[: int(max_item_len)]
                if part not in seen:
                    seen.add(part)
                    out.append(part)
                    if len(out) >= int(max_items_out):
                        break
        else:
            if strict_types:
                ok_types = False

        if len(out) >= int(max_items_out):
            break

    if not out:
        return None, ok_types
    return sorted(out), ok_types


# ---------------------------------------------------------------------------
# Replay protection (nonce / jti) - default in-memory implementation
# ---------------------------------------------------------------------------

class ReplayStore:
    """
    Interface:
      - check_and_store(key, ttl_s) -> True if fresh (stored), False if replay.
    """
    def check_and_store(self, key: str, *, ttl_s: int) -> bool:  # pragma: no cover (interface)
        raise NotImplementedError


class InMemoryReplayStore(ReplayStore):
    """
    Bounded TTL set with approximate LRU eviction.
    Thread-safe, process-local. For multi-worker, replace with Redis-backed store.
    """
    def __init__(self, *, max_items: int, clock: Callable[[], float]):
        self._max = max(1024, int(max_items))
        self._clock = clock
        self._lock = threading.Lock()
        self._od: "collections.OrderedDict[str, float]" = collections.OrderedDict()

    def _gc(self, now: float) -> None:
        # Drop expired from oldest side.
        while self._od:
            _, exp = next(iter(self._od.items()))
            if exp > now:
                break
            self._od.popitem(last=False)

    def check_and_store(self, key: str, *, ttl_s: int) -> bool:
        k = (key or "").strip()
        if not k:
            return False
        ttl = max(1, int(ttl_s))
        now = float(self._clock())
        exp = now + float(ttl)
        with self._lock:
            self._gc(now)
            if k in self._od:
                # replay
                try:
                    self._od.move_to_end(k, last=True)
                except Exception:
                    pass
                return False
            self._od[k] = exp
            self._od.move_to_end(k, last=True)
            # Bound size
            while len(self._od) > self._max:
                self._od.popitem(last=False)
        return True


# ---------------------------------------------------------------------------
# Metrics (platform-hardened, multi-instance safe, authn/authz split)
# ---------------------------------------------------------------------------

if not _HAS_PROM:  # pragma: no cover
    class _Nop:
        def labels(self, *_, **__):
            return self
        def inc(self, *_ , **__):
            pass
        def observe(self, *_ , **__):
            pass
        def set(self, *_ , **__):
            pass
        def remove(self, *_ , **__):
            pass

    class _MetricsFamilies:  # type: ignore
        def __init__(self) -> None:
            self.authn_ok = _Nop()
            self.authn_fail = _Nop()
            self.authn_lat = _Nop()
            self.authz_forbidden = _Nop()
            self.auth_replay = _Nop()
            self.header_too_large = _Nop()
            self.body_too_large = _Nop()
            self.jwt_claim_fail = _Nop()
            self.jwks_hit = _Nop()
            self.jwks_miss = _Nop()
            self.jwks_fetch_lat = _Nop()
            self.jwks_fetch_fail = _Nop()
            self.jwks_refresh_inflight = _Nop()
            self.jwks_backoff_active = _Nop()
            self.jwks_last_success_age = _Nop()
            self.jwks_keys = _Nop()
            self.auth_mode_info = _Nop()
            self.auth_policy_info = _Nop()
            self.auth_body_bytes = _Nop()
            self.auth_query_chars = _Nop()
            self.auth_headers_total_bytes = _Nop()

    def build_metrics(registry: Optional["CollectorRegistry"] = None) -> "_MetricsFamilies":  # type: ignore
        return _MetricsFamilies()

else:
    def _get_existing_collector(reg: "CollectorRegistry", name: str) -> Optional[Any]:
        m = getattr(reg, "_names_to_collectors", None)
        if isinstance(m, dict):
            return m.get(name)
        return None

    def _mk_counter(reg: "CollectorRegistry", name: str, doc: str, labelnames: List[str]) -> "Counter":
        try:
            return Counter(name, doc, labelnames=labelnames, registry=reg)
        except ValueError:
            ex = _get_existing_collector(reg, name)
            if ex is None or not isinstance(ex, Counter):
                raise
            ln = getattr(ex, "_labelnames", None)
            if ln is not None and tuple(ln) != tuple(labelnames):
                raise
            return ex

    def _mk_gauge(reg: "CollectorRegistry", name: str, doc: str, labelnames: List[str]) -> "Gauge":
        try:
            return Gauge(name, doc, labelnames=labelnames, registry=reg)
        except ValueError:
            ex = _get_existing_collector(reg, name)
            if ex is None or not isinstance(ex, Gauge):
                raise
            ln = getattr(ex, "_labelnames", None)
            if ln is not None and tuple(ln) != tuple(labelnames):
                raise
            return ex

    def _mk_hist(reg: "CollectorRegistry", name: str, doc: str, labelnames: List[str], buckets: Tuple[float, ...]) -> "Histogram":
        try:
            return Histogram(name, doc, labelnames=labelnames, buckets=buckets, registry=reg)
        except ValueError:
            ex = _get_existing_collector(reg, name)
            if ex is None or not isinstance(ex, Histogram):
                raise
            ln = getattr(ex, "_labelnames", None)
            if ln is not None and tuple(ln) != tuple(labelnames):
                raise
            return ex

    class _MetricsFamilies:
        def __init__(self, reg: "CollectorRegistry") -> None:
            base = ["name", "version", "mode"]

            # AuthN
            self.authn_ok = _mk_counter(reg, "tcd_authn_ok_total", "Authentication OK", base)
            self.authn_fail = _mk_counter(reg, "tcd_authn_fail_total", "Authentication Fail", base + ["reason"])
            self.authn_lat = _mk_hist(
                reg,
                "tcd_authn_verify_latency_seconds",
                "Authentication verify latency (s)",
                base,
                buckets=(0.001, 0.002, 0.005, 0.010, 0.020, 0.050, 0.10, 0.20, 0.50, 1.0, 2.0),
            )

            # AuthZ
            self.authz_forbidden = _mk_counter(reg, "tcd_authz_forbidden_total", "Authorization forbidden (403)", base)

            # Security events / sizes
            self.auth_replay = _mk_counter(reg, "tcd_auth_replay_total", "Replay/nonce/jti rejection", base)
            self.header_too_large = _mk_counter(reg, "tcd_auth_header_too_large_total", "Header too large", base + ["header"])
            self.body_too_large = _mk_counter(reg, "tcd_auth_body_too_large_total", "Body too large", base)
            self.auth_body_bytes = _mk_hist(
                reg,
                "tcd_auth_body_bytes",
                "Body bytes read for auth (bytes)",
                base,
                buckets=(0, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576),
            )
            self.auth_query_chars = _mk_hist(
                reg,
                "tcd_auth_query_chars",
                "Query string length observed (chars/bytes)",
                base,
                buckets=(0, 16, 64, 256, 1024, 4096, 8192, 16384),
            )
            self.auth_headers_total_bytes = _mk_hist(
                reg,
                "tcd_auth_headers_total_bytes",
                "Total header bytes (approx)",
                base,
                buckets=(0, 256, 1024, 4096, 8192, 16384, 32768, 65536),
            )

            # JWT claim issues (bounded)
            self.jwt_claim_fail = _mk_counter(
                reg,
                "tcd_auth_jwt_claim_fail_total",
                "JWT claim/header validation fail",
                base + ["field"],
            )

            # JWKS cache/fetch
            self.jwks_hit = _mk_counter(reg, "tcd_auth_jwks_hit_total", "JWKS cache hit", base)
            self.jwks_miss = _mk_counter(reg, "tcd_auth_jwks_miss_total", "JWKS cache miss", base)
            self.jwks_fetch_lat = _mk_hist(
                reg,
                "tcd_auth_jwks_fetch_latency_seconds",
                "JWKS fetch latency (s)",
                base,
                buckets=(0.01, 0.02, 0.05, 0.10, 0.20, 0.50, 1.0, 2.0, 5.0),
            )
            self.jwks_fetch_fail = _mk_counter(reg, "tcd_auth_jwks_fetch_fail_total", "JWKS fetch failure", base + ["kind"])
            self.jwks_refresh_inflight = _mk_gauge(reg, "tcd_auth_jwks_refresh_inflight", "JWKS refresh inflight (0/1)", base)
            self.jwks_backoff_active = _mk_gauge(reg, "tcd_auth_jwks_refresh_backoff_active", "JWKS refresh backoff active (0/1)", base)
            self.jwks_last_success_age = _mk_gauge(reg, "tcd_auth_jwks_last_success_age_seconds", "Age since last successful JWKS fetch (s)", base)
            self.jwks_keys = _mk_gauge(reg, "tcd_auth_jwks_keys", "JWKS key count cached", base)

            # Mode info and policy info (remove old policy label to avoid leak)
            self.auth_mode_info = _mk_gauge(reg, "tcd_auth_mode_info", "Auth mode info (value=1)", base)
            self.auth_policy_info = _mk_gauge(reg, "tcd_auth_policy_info", "Auth policy info (value=1)", base + ["policy_digest"])

    def build_metrics(registry: Optional["CollectorRegistry"] = None) -> "_MetricsFamilies":
        reg = registry or REGISTRY
        return _MetricsFamilies(reg)


_DEFAULT_METRICS_LOCK = threading.Lock()
_DEFAULT_METRICS: Optional[_MetricsFamilies] = None

# LRU for policy info labels to avoid unbounded dict growth
_POLICY_INFO_LOCK = threading.Lock()
_POLICY_INFO_LRU: "collections.OrderedDict[Tuple[str, str, str], str]" = collections.OrderedDict()
_POLICY_INFO_LRU_MAX = 128


def _get_default_metrics() -> _MetricsFamilies:
    global _DEFAULT_METRICS
    with _DEFAULT_METRICS_LOCK:
        if _DEFAULT_METRICS is None:
            _DEFAULT_METRICS = build_metrics()
        return _DEFAULT_METRICS


@dataclass(slots=True)
class _MetricScope:
    fam: _MetricsFamilies
    name: str
    version: str
    mode: str

    def __post_init__(self) -> None:
        try:
            self.fam.auth_mode_info.labels(self.name, self.version, self.mode).set(1.0)
        except Exception:
            pass

    def _lv(self) -> Tuple[str, str, str]:
        return (self.name, self.version, self.mode)

    def _reason(self, reason: str) -> str:
        r = (reason or "").strip()
        return r if r in _ALLOWED_REASONS else R_OTHER

    def _field(self, field: str) -> str:
        f = (field or "").strip()
        return f if f in _ALLOWED_JWT_CLAIM_FIELDS else R_OTHER

    def _hdr(self, header: str) -> str:
        h = (header or "").strip().lower()
        return h if h in _ALLOWED_HEADERS_LABEL else "other"

    def ok(self) -> None:
        try:
            self.fam.authn_ok.labels(*self._lv()).inc()
        except Exception:
            pass

    def fail(self, reason: str) -> None:
        r = self._reason(reason)
        try:
            self.fam.authn_fail.labels(self.name, self.version, self.mode, r).inc()
        except Exception:
            pass

    def lat(self, seconds: float) -> None:
        try:
            self.fam.authn_lat.labels(*self._lv()).observe(max(0.0, float(seconds)))
        except Exception:
            pass

    def forbidden(self) -> None:
        try:
            self.fam.authz_forbidden.labels(*self._lv()).inc()
        except Exception:
            pass

    def replay(self) -> None:
        try:
            self.fam.auth_replay.labels(*self._lv()).inc()
        except Exception:
            pass

    def header_too_large(self, header: str) -> None:
        try:
            self.fam.header_too_large.labels(self.name, self.version, self.mode, self._hdr(header)).inc()
        except Exception:
            pass

    def body_too_large(self) -> None:
        try:
            self.fam.body_too_large.labels(*self._lv()).inc()
        except Exception:
            pass

    def body_bytes(self, n: int) -> None:
        try:
            self.fam.auth_body_bytes.labels(*self._lv()).observe(max(0.0, float(int(n))))
        except Exception:
            pass

    def query_chars(self, n: int) -> None:
        try:
            self.fam.auth_query_chars.labels(*self._lv()).observe(max(0.0, float(int(n))))
        except Exception:
            pass

    def headers_total_bytes(self, n: int) -> None:
        try:
            self.fam.auth_headers_total_bytes.labels(*self._lv()).observe(max(0.0, float(int(n))))
        except Exception:
            pass

    def jwt_claim_fail(self, field: str) -> None:
        try:
            self.fam.jwt_claim_fail.labels(self.name, self.version, self.mode, self._field(field)).inc()
        except Exception:
            pass

    def jwks_hit(self) -> None:
        try:
            self.fam.jwks_hit.labels(*self._lv()).inc()
        except Exception:
            pass

    def jwks_miss(self) -> None:
        try:
            self.fam.jwks_miss.labels(*self._lv()).inc()
        except Exception:
            pass

    def jwks_fetch_lat(self, seconds: float) -> None:
        try:
            self.fam.jwks_fetch_lat.labels(*self._lv()).observe(max(0.0, float(seconds)))
        except Exception:
            pass

    def jwks_fetch_fail(self, kind: str) -> None:
        k = (kind or "").strip()
        k = k if k in _ALLOWED_JWKS_FAIL_KINDS else "exception"
        try:
            self.fam.jwks_fetch_fail.labels(self.name, self.version, self.mode, k).inc()
        except Exception:
            pass

    def jwks_refresh_inflight(self, inflight: bool) -> None:
        try:
            self.fam.jwks_refresh_inflight.labels(*self._lv()).set(1.0 if inflight else 0.0)
        except Exception:
            pass

    def jwks_backoff_active(self, active: bool) -> None:
        try:
            self.fam.jwks_backoff_active.labels(*self._lv()).set(1.0 if active else 0.0)
        except Exception:
            pass

    def jwks_last_success_age(self, age_s: float) -> None:
        try:
            self.fam.jwks_last_success_age.labels(*self._lv()).set(max(0.0, float(age_s)))
        except Exception:
            pass

    def jwks_keys(self, n: int) -> None:
        try:
            self.fam.jwks_keys.labels(*self._lv()).set(float(max(0, int(n))))
        except Exception:
            pass

    def set_policy_digest(self, digest: str) -> None:
        lv = self._lv()
        d = _safe_text(digest, max_len=96)
        with _POLICY_INFO_LOCK:
            # LRU management
            old = _POLICY_INFO_LRU.get(lv)
            if old is not None and old != d:
                try:
                    self.fam.auth_policy_info.remove(lv[0], lv[1], lv[2], old)
                except Exception:
                    pass
            _POLICY_INFO_LRU[lv] = d
            _POLICY_INFO_LRU.move_to_end(lv, last=True)
            while len(_POLICY_INFO_LRU) > _POLICY_INFO_LRU_MAX:
                k_lv, k_old = _POLICY_INFO_LRU.popitem(last=False)
                try:
                    self.fam.auth_policy_info.remove(k_lv[0], k_lv[1], k_lv[2], k_old)
                except Exception:
                    pass
        try:
            self.fam.auth_policy_info.labels(lv[0], lv[1], lv[2], d).set(1.0)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# JWKS cache (JWT mode) - async-safe (no event loop blocking), redirect-safe, SSRF-governed,
# backoff+jitter, stale policy, bounded parsing, stampede control.
# ---------------------------------------------------------------------------

class _NoRedirect(HTTPRedirectHandler):  # type: ignore[misc]
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # pragma: no cover (stdlib hook)
        raise HTTPError(req.full_url, code, "redirect disabled", headers, fp)


class JWKSFetcher:
    """
    Optional injection: override how JWKS bytes are fetched (e.g. async http client, sidecar, file).
    Must be sync (called in worker thread).
    """
    def fetch(self, url: str, *, timeout_s: float, max_bytes: int) -> bytes:  # pragma: no cover (interface)
        raise NotImplementedError


class _StdlibJWKSFetcher(JWKSFetcher):
    def __init__(self) -> None:
        if not _HAS_URL:
            raise RuntimeError("urllib not available")
        self._opener = build_opener(_NoRedirect())

    def fetch(self, url: str, *, timeout_s: float, max_bytes: int) -> bytes:
        req = UrlRequest(
            url,
            headers={
                "User-Agent": "tcd-auth/2.0",
                "Accept": "application/json",
            },
            method="GET",
        )
        with self._opener.open(req, timeout=timeout_s) as resp:  # type: ignore[attr-defined]
            status = getattr(resp, "status", 200)
            if int(status) != 200:
                raise HTTPError(url, int(status), "bad status", getattr(resp, "headers", None), None)
            data = resp.read(int(max_bytes) + 1)
        if len(data) > int(max_bytes):
            raise ValueError("jwks too large")
        return data


class _JWKSCache:
    def __init__(
        self,
        *,
        url: Optional[str],
        inline_json: Optional[str],
        ttl_s: int,
        timeout_s: float,
        max_jwks_bytes: int,
        max_inline_jwks_chars: int,
        max_keys: int,
        max_kid_chars: int,
        max_jwk_field_chars: int,
        allowed_hosts: Optional[List[str]],
        allow_stale: bool,
        max_stale_s: int,
        wait_s: float,
        backoff_base_s: float,
        backoff_max_s: float,
        ms: _MetricScope,
        time_provider: Callable[[], float],
        fetcher: Optional[JWKSFetcher],
    ):
        raw_url = (url or "").strip()

        # Normalize/govern URL: https only; no userinfo; no query/fragment (avoid leaking secrets).
        if raw_url:
            u = urlsplit(raw_url)
            if u.scheme.lower() != "https":
                raise ValueError("JWKS URL must use https")
            if u.username or u.password:
                raise ValueError("JWKS URL must not include userinfo")
            if u.query or u.fragment:
                raise ValueError("JWKS URL must not include query/fragment")
            if not u.netloc:
                raise ValueError("JWKS URL missing host")
            host = u.hostname or ""
            if not host:
                raise ValueError("JWKS URL missing hostname")
            if allowed_hosts:
                ah = {h.strip().lower() for h in allowed_hosts if h and h.strip()}
                if host.lower() not in ah:
                    raise ValueError("JWKS URL host not in allowlist")
            # Basic SSRF guard: if host is an IP literal, forbid private/loopback by default
            try:
                ip = ipaddress.ip_address(host)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    raise ValueError("JWKS URL must not use private/loopback IP literal")
            except ValueError:
                # not an IP literal or other parse issue: allow (DNS-level SSRF should be handled by allowlist/policy).
                pass

        if raw_url and not _HAS_URL and fetcher is None:
            raise ValueError("JWKS URL configured but urllib not available and no fetcher provided")

        self._url = raw_url
        self._ttl = max(30, int(ttl_s))

        self._timeout = float(timeout_s)
        if (not _is_finite(self._timeout)) or self._timeout <= 0:
            self._timeout = 2.0

        self._max_jwks_bytes = max(32 * 1024, int(max_jwks_bytes))
        self._max_inline_chars = max(0, int(max_inline_jwks_chars))
        self._max_keys = max(1, int(max_keys))
        self._max_kid_chars = max(8, int(max_kid_chars))
        self._max_jwk_field_chars = max(64, int(max_jwk_field_chars))

        self._allow_stale = bool(allow_stale)
        self._max_stale_s = max(0, int(max_stale_s))
        self._wait_s = float(wait_s)
        if not _is_finite(self._wait_s) or self._wait_s < 0:
            self._wait_s = 0.1

        self._backoff_base_s = float(backoff_base_s)
        self._backoff_max_s = float(backoff_max_s)
        if (not _is_finite(self._backoff_base_s)) or self._backoff_base_s <= 0:
            self._backoff_base_s = 0.5
        if (not _is_finite(self._backoff_max_s)) or self._backoff_max_s <= 0:
            self._backoff_max_s = 30.0

        self._ms = ms
        self._now = time_provider

        self._lock = threading.RLock()
        self._fetch_lock = threading.Lock()
        self._kid_map: Dict[str, dict] = {}
        self._exp_at = 0.0
        self._stale_at = 0.0

        # fetch state
        self._next_fetch_at = 0.0
        self._fail_count = 0
        self._last_success_at = 0.0

        self._fetcher = fetcher or (_StdlibJWKSFetcher() if self._url else None)

        # Inline JSON (bounded and strict)
        self._inline = (inline_json or "").strip()
        if self._inline:
            if self._max_inline_chars > 0 and len(self._inline) > self._max_inline_chars:
                raise ValueError("inline JWKS too large")
            obj = _json_loads_strict(self._inline)
            self._kid_map = self._parse_jwks_obj(obj)
            # inline treated as long-lived but still refreshable if URL provided
            now = float(self._now())
            self._exp_at = now + 3600.0
            self._stale_at = now + 3600.0
            self._last_success_at = now

        self._publish_metrics()

    @property
    def url_for_digest(self) -> str:
        # already query/fragment free
        return self._url

    def _publish_metrics(self) -> None:
        try:
            with self._lock:
                n = len(self._kid_map)
                self._ms.jwks_keys(n)
                now = float(self._now())
                age = (now - self._last_success_at) if self._last_success_at > 0 else 1e9
                self._ms.jwks_last_success_age(age)
                self._ms.jwks_backoff_active(now < self._next_fetch_at)
        except Exception:
            pass

    def _parse_jwks_obj(self, obj: Any) -> Dict[str, dict]:
        if not isinstance(obj, dict):
            return {}
        keys = obj.get("keys")
        if not isinstance(keys, list):
            return {}
        out: Dict[str, dict] = {}
        cnt = 0
        for k in keys:
            if cnt >= self._max_keys:
                break
            if not isinstance(k, dict):
                continue
            kid = k.get("kid")
            if not isinstance(kid, str):
                continue
            kid = kid.strip()
            if not kid or len(kid) > self._max_kid_chars:
                continue
            # bound field sizes to prevent pathological JWKS payloads
            too_big = False
            for _, vv in k.items():
                if isinstance(vv, str) and len(vv) > self._max_jwk_field_chars:
                    too_big = True
                    break
                if isinstance(vv, list) and len(vv) > 128:
                    too_big = True
                    break
            if too_big:
                continue
            out[kid] = k
            cnt += 1
        return out

    def _compute_backoff(self) -> float:
        n = max(0, int(self._fail_count))
        base = self._backoff_base_s * (2.0 ** min(n, 10))
        base = min(base, self._backoff_max_s)
        # jitter in [0.9, 1.1]
        return base * (0.9 + 0.2 * random.random())

    def _fetch_once(self) -> str:
        """
        Fetch and update cache. Sync method; MUST be called in worker thread.
        Returns kind in allowed fail kind set.
        """
        if not self._url:
            return "lib_missing"

        now = float(self._now())
        with self._lock:
            if now < self._next_fetch_at:
                self._publish_metrics()
                return "backoff"

        if self._fetcher is None:
            return "lib_missing"

        t0 = time.perf_counter()
        kind = "ok"
        try:
            data = self._fetcher.fetch(self._url, timeout_s=self._timeout, max_bytes=self._max_jwks_bytes)
            try:
                obj = _json_loads_strict(data.decode("utf-8", errors="strict"))
            except Exception:
                kind = "bad_json"
                return kind
            kid_map = self._parse_jwks_obj(obj)
            if kid_map:
                with self._lock:
                    self._kid_map = kid_map
                    now2 = float(self._now())
                    self._exp_at = now2 + float(self._ttl)
                    # stale boundary: allow_stale extends beyond exp by max_stale_s
                    self._stale_at = self._exp_at + float(self._max_stale_s)
                    self._fail_count = 0
                    self._next_fetch_at = 0.0
                    self._last_success_at = now2
        except HTTPError:
            kind = "bad_status"
        except ValueError as e:
            if "too large" in str(e):
                kind = "too_large"
            else:
                kind = "exception"
        except Exception:
            kind = "exception"
        finally:
            dt = float(time.perf_counter() - t0)
            self._ms.jwks_fetch_lat(dt)
            if kind != "ok":
                self._ms.jwks_fetch_fail(kind)
                with self._lock:
                    self._fail_count += 1
                    self._next_fetch_at = float(self._now()) + self._compute_backoff()
            self._publish_metrics()

        return kind

    def _needs_refresh_locked(self, now: float) -> bool:
        return now >= self._exp_at and bool(self._url)

    def _stale_allowed_locked(self, now: float) -> bool:
        if not self._allow_stale:
            return False
        if self._max_stale_s <= 0:
            return False
        return now < self._stale_at

    async def _refresh_async_singleflight(self) -> None:
        if not self._url:
            return
        # Avoid blocking loop: do fetch in a thread. Enforce singleflight with fetch_lock.
        if not self._fetch_lock.acquire(blocking=False):
            return
        self._ms.jwks_refresh_inflight(True)
        try:
            await asyncio.to_thread(self._fetch_once)
        finally:
            self._ms.jwks_refresh_inflight(False)
            try:
                self._fetch_lock.release()
            except Exception:
                pass

    async def aget_jwk_dict(self, kid: str) -> Optional[dict]:
        kid_s = (kid or "").strip()
        if not kid_s or len(kid_s) > self._max_kid_chars:
            return None

        now = float(self._now())
        with self._lock:
            expired = now >= self._exp_at
            cur = self._kid_map.get(kid_s)
            if not expired:
                self._ms.jwks_hit()
                self._publish_metrics()
                return cur

            # expired
            if cur is not None and self._stale_allowed_locked(now):
                # stale hit: return current immediately; refresh best-effort
                self._ms.jwks_hit()
                self._publish_metrics()
                asyncio.create_task(self._refresh_async_singleflight())
                return cur

        # stale miss (or stale not allowed): try refresh and optionally wait
        self._ms.jwks_miss()
        self._publish_metrics()

        # Kick refresh (singleflight)
        started = False
        if self._fetch_lock.acquire(blocking=False):
            self._ms.jwks_refresh_inflight(True)
            started = True
            try:
                await asyncio.to_thread(self._fetch_once)
            finally:
                self._ms.jwks_refresh_inflight(False)
                try:
                    self._fetch_lock.release()
                except Exception:
                    pass
        else:
            # Another refresh in progress; wait a short bounded time then re-check.
            wait_s = max(0.0, float(self._wait_s))
            if wait_s > 0:
                end = time.perf_counter() + wait_s
                while time.perf_counter() < end:
                    await asyncio.sleep(0.01)
                    with self._lock:
                        got = self._kid_map.get(kid_s)
                        if got is not None and float(self._now()) < self._stale_at:
                            return got

        with self._lock:
            return self._kid_map.get(kid_s)

    async def aget_single_jwk_if_unambiguous(self) -> Optional[Tuple[str, dict]]:
        with self._lock:
            if len(self._kid_map) == 1:
                (kid, jwk_dict), = self._kid_map.items()
                return kid, jwk_dict
        return None


# ---------------------------------------------------------------------------
# Authenticator
# ---------------------------------------------------------------------------

class Authenticator:
    """
    Platform-hardened authenticator.

    - AuthN/AuthZ metric split.
    - Default no oracle: 401 doesn't expose internal reasons.
    - JWKS refresh runs in worker thread; async path remains non-blocking.
    - Replay defense: HMAC nonce (default-on for unsafe methods) and optional JWT jti.
    - Trusted proxy enforcement for XFCC.
    """

    def __init__(
        self,
        mode: str,
        *,
        # policy identity (metrics labels)
        name: str = "default",
        version: str = "v1",
        metrics: Optional[_MetricsFamilies] = None,

        # governance
        allow_disabled: bool = False,

        # output behavior
        expose_failure_reason_to_client: bool = False,
        auth_fail_delay_ms_max: int = 0,  # optional micro-jitter to reduce oracle timing (0 disables)

        # time + injections
        time_provider: Optional[Callable[[], float]] = None,
        jwks_fetcher: Optional[JWKSFetcher] = None,
        replay_store: Optional[ReplayStore] = None,
        event_sink: Optional[Callable[[Dict[str, Any]], None]] = None,

        # global request caps
        max_path_bytes: int = 2048,
        max_query_bytes: int = 8192,
        max_total_headers_bytes: int = 32 * 1024,

        # bearer
        bearer_tokens: Optional[List[str]] = None,
        max_bearer_token_chars: int = 2048,
        max_bearer_tokens: int = 256,

        # policy fingerprint salt (prevents offline dictionary over token/key hashes)
        policy_salt_hex: Optional[str] = None,

        # hmac
        hmac_keys: Optional[Dict[str, str]] = None,  # kid -> "hex1,hex2" rotation
        hmac_alg: str = "blake3_keyed",  # "blake3_keyed" | "hmac_sha256"
        max_skew_s: int = 300,
        hmac_require_nonce: bool = True,
        hmac_require_nonce_for_unsafe_methods: bool = True,
        nonce_ttl_s: Optional[int] = None,
        max_hmac_body_bytes: int = 1024 * 1024,
        max_sig_header_chars: int = 2048,
        max_kid_chars: int = 128,
        max_nonce_chars: int = 256,
        max_query_pairs: int = 128,
        max_query_key_bytes: int = 256,
        max_query_val_bytes: int = 1024,
        hmac_query_mode: str = "form",  # "form" (+ as space) | "rfc3986" (+ literal)
        max_header_value_chars: int = 256,

        # jwt
        jwt_iss: Optional[str] = None,
        jwt_iss_allowlist: Optional[List[str]] = None,
        jwt_aud: Optional[str] = None,
        jwt_aud_allowlist: Optional[List[str]] = None,
        jwks_url: Optional[str] = None,
        jwks_json: Optional[str] = None,
        jwks_cache_ttl_s: int = 600,
        jwks_timeout_s: float = 2.0,
        jwks_max_bytes: int = 256 * 1024,
        jwks_max_keys: int = 64,
        jwks_max_inline_chars: int = 256 * 1024,
        jwks_max_jwk_field_chars: int = 4096,
        jwks_allowed_hosts: Optional[List[str]] = None,
        jwks_allow_stale: bool = True,
        jwks_max_stale_s: int = 3600,
        jwks_wait_s: float = 0.15,
        jwks_backoff_base_s: float = 0.5,
        jwks_backoff_max_s: float = 30.0,

        jwt_leeway_s: int = 60,
        jwt_principal_claim: str = "sub",
        jwt_require_principal_claim: bool = True,
        jwt_scope_claims: Tuple[str, ...] = ("scp", "scope", "roles"),
        jwt_scope_strict: bool = False,
        jwt_allowed_algs: Optional[Tuple[str, ...]] = None,
        jwt_allowed_typs: Tuple[str, ...] = ("JWT", "at+jwt"),
        jwt_max_token_chars: int = 8192,
        jwt_require_exp: bool = True,
        jwt_allow_no_kid_single_key: bool = True,
        jwt_max_age_s: int = 24 * 3600,
        jwt_max_lifetime_s: int = 24 * 3600,
        jwt_require_jti: bool = False,
        jwt_replay_via_jti: bool = False,
        jwt_max_aud_items: int = 16,
        jwt_max_scopes_out: int = 64,
        jwt_max_scopes_raw_items: int = 256,
        jwt_max_scope_string_chars: int = 2048,
        jwt_max_iss_chars: int = 512,
        jwt_max_sub_chars: int = 512,
        jwt_max_jti_chars: int = 256,

        # mtls (Envoy XFCC)
        mtls_fp_allow: Optional[List[str]] = None,  # sha256 hex (64 chars)
        mtls_spiffe_prefixes: Optional[List[str]] = None,
        mtls_max_xfcc_chars: int = 16384,
        mtls_trusted_proxy_cidrs: Optional[List[str]] = None,
        mtls_require_proxy_verified_header: bool = False,
        mtls_proxy_verified_header_name: str = "x-envoy-mtls-verified",
        mtls_proxy_verified_header_value: str = "1",
        mtls_max_spiffe_chars: int = 512,
    ):
        m = (mode or "").lower().strip()
        if m not in ("disabled", "bearer", "hmac", "jwt", "mtls"):
            raise ValueError("auth mode must be one of disabled|bearer|hmac|jwt|mtls")
        if m == "disabled" and not bool(allow_disabled):
            raise ValueError("disabled mode not permitted unless allow_disabled=True")

        # Time providers
        self._now = time_provider or time.time
        if not callable(self._now):
            self._now = time.time

        # Failure delay jitter (optional oracle hardening)
        self._fail_delay_ms_max = max(0, int(auth_fail_delay_ms_max))

        self.mode = m
        self.name = _safe_text(name, max_len=64)
        self.version = _safe_text(version, max_len=32)

        self.expose_failure_reason_to_client = bool(expose_failure_reason_to_client)

        self._fam = metrics or _get_default_metrics()
        self._ms = _MetricScope(self._fam, self.name, self.version, self.mode)

        # event sink (structured audit/event integration)
        self._event_sink = event_sink

        # Global caps
        self.max_path_bytes = max(64, int(max_path_bytes))
        self.max_query_bytes = max(0, int(max_query_bytes))
        self.max_total_headers_bytes = max(1024, int(max_total_headers_bytes))

        self.max_bearer_token_chars = max(256, int(max_bearer_token_chars))
        self.max_bearer_tokens = max(1, int(max_bearer_tokens))

        # Policy salt (optional; secret, not exported)
        self._policy_salt: Optional[bytes] = None
        if policy_salt_hex:
            sb = _hex_bytes_limited(policy_salt_hex, max_hex_chars=256)
            if sb is None or len(sb) < 16:
                raise ValueError("policy_salt_hex must be valid hex and at least 16 bytes")
            self._policy_salt = sb

        # Bearer tokens: store fingerprints (not raw tokens); constant-time compare (bounded)
        self._bearer_fps: List[bytes] = []
        for t in (bearer_tokens or [])[: self.max_bearer_tokens]:
            if not isinstance(t, str):
                continue
            tok = t.strip()
            if not tok:
                continue
            self._bearer_fps.append(self._fingerprint_secret(_b(tok)))

        # HMAC config
        self.hmac_alg = (hmac_alg or "blake3_keyed").strip().lower()
        if self.hmac_alg not in ("blake3_keyed", "hmac_sha256"):
            raise ValueError("hmac_alg must be blake3_keyed or hmac_sha256")
        if self.mode == "hmac" and self.hmac_alg == "blake3_keyed" and not _HAS_BLAKE3:
            raise ValueError("hmac mode with blake3_keyed requires blake3 installed")

        self.max_kid_chars = max(8, int(max_kid_chars))
        self.max_nonce_chars = max(16, int(max_nonce_chars))
        self.max_sig_header_chars = max(256, int(max_sig_header_chars))
        self.max_hmac_body_bytes = max(0, int(max_hmac_body_bytes))
        self.max_skew_s = int(max(1, max_skew_s))

        self.max_query_pairs = max(1, int(max_query_pairs))
        self.max_query_key_bytes = max(16, int(max_query_key_bytes))
        self.max_query_val_bytes = max(16, int(max_query_val_bytes))

        qm = (hmac_query_mode or "form").strip().lower()
        self.hmac_query_mode = qm if qm in ("form", "rfc3986") else "form"

        self.max_header_value_chars = max(32, int(max_header_value_chars))

        self.hmac_require_nonce = bool(hmac_require_nonce)
        self.hmac_require_nonce_for_unsafe_methods = bool(hmac_require_nonce_for_unsafe_methods)

        # Replay store default (process-local); required for nonce/jti if enabled
        self._replay = replay_store or InMemoryReplayStore(max_items=100_000, clock=self._now)

        if nonce_ttl_s is None:
            # Default TTL covers skew window and some jitter
            self.nonce_ttl_s = max(60, 2 * self.max_skew_s + 60)
        else:
            self.nonce_ttl_s = max(1, int(nonce_ttl_s))

        # Parse HMAC keys: kid -> list[bytes] (32 bytes per key), bounded fanout
        self.hmac_keys: Dict[str, List[bytes]] = {}
        for kid, v in (hmac_keys or {}).items():
            kid_s = str(kid).strip()
            if (not kid_s) or len(kid_s) > self.max_kid_chars or (not _SAFE_KID_RE.fullmatch(kid_s)):
                raise ValueError("invalid hmac kid (charset/length)")
            parts = [p.strip() for p in str(v).split(",") if p.strip()]
            key_bytes: List[bytes] = []
            for p in parts[:8]:
                kb = _hex_bytes_limited(p, max_hex_chars=128)
                if kb is None:
                    raise ValueError("invalid hmac key hex")
                # For blake3 keyed, key must be 32 bytes; for hmac_sha256 we still enforce 32 bytes for uniformity
                if len(kb) != 32:
                    raise ValueError("hmac keys must be 32-byte values")
                key_bytes.append(kb)
            if key_bytes:
                self.hmac_keys[kid_s] = key_bytes

        # JWT config
        self.jwt_leeway_s = int(max(0, jwt_leeway_s))
        self.jwt_principal_claim = str(jwt_principal_claim or "sub")
        self.jwt_require_principal_claim = bool(jwt_require_principal_claim)
        self.jwt_scope_claims = tuple(jwt_scope_claims or ())
        self.jwt_scope_strict = bool(jwt_scope_strict)

        self.jwt_max_token_chars = max(512, int(jwt_max_token_chars))
        self.jwt_require_exp = bool(jwt_require_exp)
        self.jwt_allow_no_kid_single_key = bool(jwt_allow_no_kid_single_key)
        self.jwt_max_age_s = max(0, int(jwt_max_age_s))
        self.jwt_max_lifetime_s = max(0, int(jwt_max_lifetime_s))
        self.jwt_require_jti = bool(jwt_require_jti)
        self.jwt_replay_via_jti = bool(jwt_replay_via_jti) or bool(jwt_require_jti)
        self.jwt_max_aud_items = max(1, int(jwt_max_aud_items))
        self.jwt_max_scopes_out = max(1, int(jwt_max_scopes_out))
        self.jwt_max_scopes_raw_items = max(1, int(jwt_max_scopes_raw_items))
        self.jwt_max_scope_string_chars = max(16, int(jwt_max_scope_string_chars))
        self.jwt_max_iss_chars = max(16, int(jwt_max_iss_chars))
        self.jwt_max_sub_chars = max(16, int(jwt_max_sub_chars))
        self.jwt_max_jti_chars = max(16, int(jwt_max_jti_chars))

        # iss/aud allowlists
        self.jwt_iss = jwt_iss
        self.jwt_iss_allow = [s.strip() for s in (jwt_iss_allowlist or []) if isinstance(s, str) and s.strip()]
        if self.jwt_iss and self.jwt_iss not in self.jwt_iss_allow:
            self.jwt_iss_allow.append(self.jwt_iss)

        self.jwt_aud = jwt_aud
        self.jwt_aud_allow = [s.strip() for s in (jwt_aud_allowlist or []) if isinstance(s, str) and s.strip()]
        if self.jwt_aud and self.jwt_aud not in self.jwt_aud_allow:
            self.jwt_aud_allow.append(self.jwt_aud)

        # alg allowlist
        if jwt_allowed_algs is None:
            self.jwt_allowed_algs = ("RS256", "ES256", "EdDSA")
        else:
            self.jwt_allowed_algs = tuple(sorted({a.strip() for a in jwt_allowed_algs if isinstance(a, str) and a.strip()}))

        self.jwt_allowed_typs = tuple(sorted({t.strip() for t in jwt_allowed_typs if isinstance(t, str) and t.strip()}))

        if self.mode == "jwt":
            if not _HAS_JWCRYPTO:
                raise ValueError("jwt mode requires jwcrypto installed")
            if not jwks_url and not jwks_json:
                raise ValueError("jwt mode requires JWKS URL or inline JWKS JSON")

        # mTLS config
        self.mtls_max_xfcc_chars = max(1024, int(mtls_max_xfcc_chars))
        self.mtls_max_spiffe_chars = max(64, int(mtls_max_spiffe_chars))

        # trusted proxy CIDRs
        self._mtls_trusted_nets: List[ipaddress._BaseNetwork] = []
        for c in (mtls_trusted_proxy_cidrs or []):
            if not isinstance(c, str):
                continue
            cc = c.strip()
            if not cc:
                continue
            try:
                self._mtls_trusted_nets.append(ipaddress.ip_network(cc, strict=False))
            except Exception:
                raise ValueError("invalid mtls_trusted_proxy_cidrs entry")

        self.mtls_require_proxy_verified_header = bool(mtls_require_proxy_verified_header)
        self.mtls_proxy_verified_header_name = str(mtls_proxy_verified_header_name or "x-envoy-mtls-verified").strip().lower()
        self.mtls_proxy_verified_header_value = str(mtls_proxy_verified_header_value or "1").strip()

        # allowed fingerprints
        self.mtls_fp_allow = set()
        for fp in (mtls_fp_allow or []):
            if not isinstance(fp, str):
                continue
            f = fp.strip().lower()
            if f.startswith("0x"):
                f = f[2:]
            if len(f) != 64 or not _HEX_RE.fullmatch(f):
                raise ValueError("mtls_fp_allow entries must be 64 hex chars (sha256)")
            self.mtls_fp_allow.add(f)

        self.mtls_spiffe_prefixes = sorted({
            p.strip() for p in (mtls_spiffe_prefixes or []) if isinstance(p, str) and p.strip()
        })

        # JWKS cache (constructed always, used in jwt mode)
        self._jwks = _JWKSCache(
            url=jwks_url,
            inline_json=jwks_json,
            ttl_s=jwks_cache_ttl_s,
            timeout_s=jwks_timeout_s,
            max_jwks_bytes=jwks_max_bytes,
            max_inline_jwks_chars=jwks_max_inline_chars,
            max_keys=jwks_max_keys,
            max_kid_chars=self.max_kid_chars,
            max_jwk_field_chars=jwks_max_jwk_field_chars,
            allowed_hosts=jwks_allowed_hosts,
            allow_stale=bool(jwks_allow_stale),
            max_stale_s=int(jwks_max_stale_s),
            wait_s=float(jwks_wait_s),
            backoff_base_s=float(jwks_backoff_base_s),
            backoff_max_s=float(jwks_backoff_max_s),
            ms=self._ms,
            time_provider=self._now,
            fetcher=jwks_fetcher,
        )

        # Stable policy digest (include all security knobs)
        self._policy_digest = self._compute_policy_digest(
            jwks_cache_ttl_s=jwks_cache_ttl_s,
            jwks_timeout_s=jwks_timeout_s,
            jwks_max_bytes=jwks_max_bytes,
            jwks_max_keys=jwks_max_keys,
            jwks_max_inline_chars=jwks_max_inline_chars,
            jwks_max_jwk_field_chars=jwks_max_jwk_field_chars,
            jwks_allow_stale=bool(jwks_allow_stale),
            jwks_max_stale_s=int(jwks_max_stale_s),
            jwks_wait_s=float(jwks_wait_s),
            jwks_backoff_base_s=float(jwks_backoff_base_s),
            jwks_backoff_max_s=float(jwks_backoff_max_s),
        )
        self._ms.set_policy_digest(self._policy_digest)

    # ------------------------------------------------------------------ #
    # Fingerprints (secret-safe)
    # ------------------------------------------------------------------ #

    def _fingerprint_secret(self, secret: bytes) -> bytes:
        """
        Secret fingerprint for policy snapshots/digests:
          - if policy_salt present: HMAC-SHA256(policy_salt, secret)
          - else: SHA256(secret)
        Returned as raw bytes to avoid string conversion overhead.
        """
        if self._policy_salt:
            return hmac.new(self._policy_salt, secret, hashlib.sha256).digest()
        return hashlib.sha256(secret).digest()

    # ------------------------------------------------------------------ #
    # Policy digest
    # ------------------------------------------------------------------ #

    def _compute_policy_digest(self, **jwks_knobs: Any) -> str:
        bearer_hashes = sorted(_sha256_hex(fp) for fp in self._bearer_fps)
        hmac_hashes: Dict[str, List[str]] = {}
        for kid, keys in self.hmac_keys.items():
            # fingerprint keys, not raw
            hmac_hashes[kid] = sorted(_sha256_hex(self._fingerprint_secret(k)) for k in keys)

        mtls_fp_hashes = sorted(_sha256_hex(_b(fp)) for fp in self.mtls_fp_allow)

        payload: Dict[str, Any] = {
            "name": self.name,
            "version": self.version,
            "mode": self.mode,

            # global caps
            "max_path_bytes": self.max_path_bytes,
            "max_query_bytes": self.max_query_bytes,
            "max_total_headers_bytes": self.max_total_headers_bytes,

            # bearer
            "bearer_fingerprint_count": len(self._bearer_fps),
            "bearer_fingerprint_hashes": bearer_hashes,  # already salted if policy_salt present
            "max_bearer_token_chars": self.max_bearer_token_chars,
            "max_bearer_tokens": self.max_bearer_tokens,

            "policy_salt_present": bool(self._policy_salt is not None),

            # hmac
            "hmac_alg": self.hmac_alg,
            "hmac_hashes": hmac_hashes,
            "max_skew_s": self.max_skew_s,
            "hmac_require_nonce": self.hmac_require_nonce,
            "hmac_require_nonce_for_unsafe_methods": self.hmac_require_nonce_for_unsafe_methods,
            "nonce_ttl_s": self.nonce_ttl_s,
            "max_hmac_body_bytes": self.max_hmac_body_bytes,
            "max_sig_header_chars": self.max_sig_header_chars,
            "max_kid_chars": self.max_kid_chars,
            "max_nonce_chars": self.max_nonce_chars,
            "max_query_pairs": self.max_query_pairs,
            "max_query_key_bytes": self.max_query_key_bytes,
            "max_query_val_bytes": self.max_query_val_bytes,
            "hmac_query_mode": self.hmac_query_mode,
            "max_header_value_chars": self.max_header_value_chars,

            # jwt
            "jwt_iss_allow": sorted(self.jwt_iss_allow),
            "jwt_aud_allow": sorted(self.jwt_aud_allow),
            "jwt_leeway_s": self.jwt_leeway_s,
            "jwt_principal_claim": self.jwt_principal_claim,
            "jwt_require_principal_claim": self.jwt_require_principal_claim,
            "jwt_scope_claims": list(self.jwt_scope_claims),
            "jwt_scope_strict": self.jwt_scope_strict,
            "jwt_allowed_algs": list(self.jwt_allowed_algs),
            "jwt_allowed_typs": list(self.jwt_allowed_typs),
            "jwt_max_token_chars": self.jwt_max_token_chars,
            "jwt_require_exp": self.jwt_require_exp,
            "jwt_allow_no_kid_single_key": self.jwt_allow_no_kid_single_key,
            "jwt_max_age_s": self.jwt_max_age_s,
            "jwt_max_lifetime_s": self.jwt_max_lifetime_s,
            "jwt_require_jti": self.jwt_require_jti,
            "jwt_replay_via_jti": self.jwt_replay_via_jti,
            "jwt_max_aud_items": self.jwt_max_aud_items,
            "jwt_max_scopes_out": self.jwt_max_scopes_out,
            "jwt_max_scopes_raw_items": self.jwt_max_scopes_raw_items,
            "jwt_max_scope_string_chars": self.jwt_max_scope_string_chars,
            "jwt_max_iss_chars": self.jwt_max_iss_chars,
            "jwt_max_sub_chars": self.jwt_max_sub_chars,
            "jwt_max_jti_chars": self.jwt_max_jti_chars,
            "jwks_url": self._jwks.url_for_digest,

            # jwks knobs
            **jwks_knobs,

            # mtls
            "mtls_fp_hashes": mtls_fp_hashes,
            "mtls_spiffe_prefixes": list(self.mtls_spiffe_prefixes),
            "mtls_max_xfcc_chars": self.mtls_max_xfcc_chars,
            "mtls_trusted_proxy_cidrs": [str(n) for n in self._mtls_trusted_nets],
            "mtls_require_proxy_verified_header": self.mtls_require_proxy_verified_header,
            "mtls_proxy_verified_header_name": self.mtls_proxy_verified_header_name,
            "mtls_proxy_verified_header_value": self.mtls_proxy_verified_header_value,
            "mtls_max_spiffe_chars": self.mtls_max_spiffe_chars,
        }

        return canonical_kv_hash(payload, ctx="tcd:auth_policy", label="auth_policy")

    @property
    def policy_digest_hex(self) -> str:
        return self._policy_digest

    def policy_snapshot(self) -> Dict[str, Any]:
        bearer_hashes = sorted(_sha256_hex(fp) for fp in self._bearer_fps)
        hmac_hashes: Dict[str, List[str]] = {}
        for kid, keys in self.hmac_keys.items():
            hmac_hashes[kid] = sorted(_sha256_hex(self._fingerprint_secret(k)) for k in keys)
        mtls_fp_hashes = sorted(_sha256_hex(_b(fp)) for fp in self.mtls_fp_allow)

        return {
            "name": self.name,
            "version": self.version,
            "mode": self.mode,
            "policy_digest": self._policy_digest,

            "policy_salt_present": bool(self._policy_salt is not None),

            "bearer_fingerprint_count": len(self._bearer_fps),
            "bearer_fingerprint_hashes": bearer_hashes,
            "max_bearer_token_chars": self.max_bearer_token_chars,

            "hmac_alg": self.hmac_alg,
            "hmac_hashes": hmac_hashes,
            "max_skew_s": self.max_skew_s,
            "hmac_require_nonce": self.hmac_require_nonce,
            "nonce_ttl_s": self.nonce_ttl_s,
            "max_hmac_body_bytes": self.max_hmac_body_bytes,

            "jwt_iss_allow": list(self.jwt_iss_allow),
            "jwt_aud_allow": list(self.jwt_aud_allow),
            "jwt_allowed_algs": list(self.jwt_allowed_algs),
            "jwt_allowed_typs": list(self.jwt_allowed_typs),
            "jwks_url": self._jwks.url_for_digest,

            "mtls_fp_hashes": mtls_fp_hashes,
            "mtls_spiffe_prefixes": list(self.mtls_spiffe_prefixes),
            "mtls_trusted_proxy_cidrs": [str(n) for n in self._mtls_trusted_nets],
        }

    # ------------------------------------------------------------------ #
    # Core verify (never raises)
    # ------------------------------------------------------------------ #

    async def verify(self, request: Request) -> AuthResult:
        t0 = time.perf_counter()
        try:
            # Observability: header + query sizes
            try:
                self._ms.headers_total_bytes(_headers_total_bytes(request))
            except Exception:
                pass
            try:
                self._ms.query_chars(len(_get_query_bytes(request)))
            except Exception:
                pass

            # Global caps (fast reject)
            if self.max_total_headers_bytes > 0:
                if _headers_total_bytes(request) > self.max_total_headers_bytes:
                    self._ms.fail(R_HEADERS_TOO_LARGE)
                    return await self._maybe_delay(AuthResult(False, None, R_HEADERS_TOO_LARGE))

            raw_path = _get_raw_path_bytes(request)
            if len(raw_path) > self.max_path_bytes:
                self._ms.fail(R_PATH_TOO_LARGE)
                return await self._maybe_delay(AuthResult(False, None, R_PATH_TOO_LARGE))
            if b"\n" in raw_path or b"\r" in raw_path:
                self._ms.fail(R_PATH_INVALID)
                return await self._maybe_delay(AuthResult(False, None, R_PATH_INVALID))

            qbytes = _get_query_bytes(request)
            if self.max_query_bytes > 0 and len(qbytes) > self.max_query_bytes:
                self._ms.fail(R_QUERY_TOO_LARGE)
                return await self._maybe_delay(AuthResult(False, None, R_QUERY_TOO_LARGE))

            if self.mode == "disabled":
                ctx = AuthContext(
                    mode="disabled",
                    principal="anonymous",
                    scopes=["public"],
                    key_id=None,
                    raw={},
                    policy_digest=self._policy_digest,
                    issued_at=float(self._now()),
                    authn_strength="disabled",
                )
                self._ms.ok()
                return AuthResult(True, ctx)

            if self.mode == "bearer":
                res = await self._verify_bearer(request)
                return await self._maybe_delay(res)

            if self.mode == "hmac":
                res = await self._verify_hmac(request)
                return await self._maybe_delay(res)

            if self.mode == "jwt":
                res = await self._verify_jwt(request)
                return await self._maybe_delay(res)

            if self.mode == "mtls":
                res = await self._verify_mtls(request)
                return await self._maybe_delay(res)

            self._ms.fail(R_BAD_MODE)
            return await self._maybe_delay(AuthResult(False, None, R_BAD_MODE))
        except Exception:
            # Fail-closed: never let auth crash request path.
            self._ms.fail(R_MALFORMED)
            return await self._maybe_delay(AuthResult(False, None, R_MALFORMED))
        finally:
            self._ms.lat(time.perf_counter() - t0)

    async def _maybe_delay(self, res: AuthResult) -> AuthResult:
        # Optional micro-jitter for failure path to reduce timing oracle.
        if res.ok:
            return res
        if self._fail_delay_ms_max <= 0:
            return res
        d_ms = random.random() * float(self._fail_delay_ms_max)
        # Keep very small; do not block loop.
        await asyncio.sleep(d_ms / 1000.0)
        return res

    def _emit_event(self, kind: str, fields: Dict[str, Any]) -> None:
        if not self._event_sink:
            return
        try:
            payload = {
                "ts": float(self._now()),
                "name": self.name,
                "version": self.version,
                "mode": self.mode,
                "policy_digest": self._policy_digest,
                "kind": str(kind),
                **fields,
            }
            self._event_sink(payload)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Bearer mode
    # ------------------------------------------------------------------ #

    async def _verify_bearer(self, request: Request) -> AuthResult:
        auth = request.headers.get("authorization", "")
        if len(auth) > self.max_bearer_token_chars + 16:
            self._ms.header_too_large("authorization")
            self._ms.fail(R_HEADER_TOO_LARGE)
            return AuthResult(False, None, R_HEADER_TOO_LARGE)

        if not auth.lower().startswith("bearer "):
            self._ms.fail(R_MISSING)
            return AuthResult(False, None, R_MISSING)

        token = auth.split(" ", 1)[1].strip()
        if len(token) > self.max_bearer_token_chars:
            self._ms.fail(R_TOKEN_TOO_LARGE)
            return AuthResult(False, None, R_TOKEN_TOO_LARGE)

        # Constant-time-ish (bounded): always compute fingerprint and compare all entries without short-circuit.
        fp = self._fingerprint_secret(_b(token))
        ok_any = False
        for cand in self._bearer_fps:
            match = hmac.compare_digest(cand, fp)
            ok_any = ok_any or match  # match computed regardless of ok_any (no short-circuit in compare)
        if ok_any:
            ctx = AuthContext(
                mode="bearer",
                principal="bearer",
                scopes=["api"],
                key_id=None,
                raw={"authorization": "Bearer ***"},
                policy_digest=self._policy_digest,
                issued_at=float(self._now()),
                authn_strength="bearer",
            )
            self._ms.ok()
            return AuthResult(True, ctx)

        self._ms.fail(R_DENIED)
        return AuthResult(False, None, R_DENIED)

    # ------------------------------------------------------------------ #
    # HMAC mode (supports blake3_keyed or hmac_sha256)
    # ------------------------------------------------------------------ #

    def _parse_sig_header(self, sig_hdr: str) -> Optional[Tuple[str, str, int, str, Optional[str]]]:
        """
        Parse X-TCD-Signature header:

          "v1,t=<ts>,sig=<hex>[,n=<nonce>][,a=<alg>]"
          "v2,t=<ts>,sig=<hex>[,n=<nonce>][,a=<alg>]"
          "v3,t=<ts>,sig=<hex>[,n=<nonce>][,a=<alg>]"

        Returns (scheme, alg, ts, sig_hex_lower, nonce).
        """
        if not isinstance(sig_hdr, str) or not sig_hdr:
            return None
        if len(sig_hdr) > self.max_sig_header_chars:
            return None
        try:
            scheme, rest = sig_hdr.split(",", 1)
            scheme = scheme.strip().lower()
            if scheme not in ("v1", "v2", "v3"):
                return None

            parts: Dict[str, str] = {}
            for piece in rest.split(","):
                piece = piece.strip()
                if not piece or "=" not in piece:
                    continue
                k, v = piece.split("=", 1)
                k = k.strip().lower()
                if k in parts:
                    continue
                parts[k] = v.strip()

            if "t" not in parts or "sig" not in parts:
                return None

            ts = int(parts["t"])
            sig = parts["sig"].strip().lower()
            if len(sig) != 64 or not _HEX_RE.fullmatch(sig):
                return None

            nonce = parts.get("n")
            if nonce is not None:
                nonce = nonce.strip()
                if len(nonce) > self.max_nonce_chars:
                    return None
                # enforce safe charset (reduces header injection / log pollution)
                if not _SAFE_NONCE_RE.fullmatch(nonce):
                    return None

            alg = parts.get("a") or parts.get("alg") or ""
            alg = alg.strip().lower()
            if not alg:
                # no header alg => use configured
                alg = self.hmac_alg
            else:
                # map shorthands
                if alg in ("b3", "blake3"):
                    alg = "blake3_keyed"
                elif alg in ("hs256", "hmacsha256", "hmac-sha256"):
                    alg = "hmac_sha256"
            if alg not in ("blake3_keyed", "hmac_sha256"):
                return None

            return scheme, alg, ts, sig, nonce
        except Exception:
            return None

    def _canonical_hmac_payload_v1_bytes(self, ts: int, method: str, raw_path: bytes, body: bytes) -> bytes:
        return f"{ts}\n{method.upper()}\n".encode("ascii", errors="strict") + raw_path + b"\n" + (body or b"")

    def _canonical_hmac_payload_v2_bytes(
        self,
        ts: int,
        method: str,
        raw_path: bytes,
        query_bytes: bytes,
        headers: Mapping[str, str],
        body: bytes,
    ) -> Optional[bytes]:
        canon_query = _canonicalize_query_bytes(
            query_bytes,
            mode=self.hmac_query_mode,
            max_query_bytes=self.max_query_bytes,
            max_pairs=self.max_query_pairs,
            max_key_bytes=self.max_query_key_bytes,
            max_val_bytes=self.max_query_val_bytes,
        )
        if canon_query is None:
            return None

        # header subset without copying all headers
        def _hv(name: str) -> str:
            v = ""
            try:
                v = headers.get(name, "")  # type: ignore[arg-type]
            except Exception:
                # fallback: case variations
                try:
                    v = headers.get(name.lower(), "")  # type: ignore[arg-type]
                except Exception:
                    v = ""
            if not isinstance(v, str):
                v = str(v)
            v = v.replace("\r", " ").replace("\n", " ").strip()
            if len(v) > self.max_header_value_chars:
                return "__TOO_LARGE__"
            return v

        host = _hv("host")
        xcl = _hv("x-tcd-cluster")
        xenv = _hv("x-tcd-env")
        if "__TOO_LARGE__" in (host, xcl, xenv):
            return None

        canon_headers = f"host={host}|x-tcd-cluster={xcl}|x-tcd-env={xenv}".encode("utf-8", errors="strict")

        return (
            f"{ts}\n{method.upper()}\n".encode("ascii", errors="strict")
            + raw_path
            + b"\n"
            + canon_query
            + b"\n"
            + canon_headers
            + b"\n"
            + (body or b"")
        )

    def _canonical_hmac_payload_v3_bytes(
        self,
        ts: int,
        method: str,
        raw_path: bytes,
        query_bytes: bytes,
        headers: Mapping[str, str],
        body: bytes,
        *,
        kid: str,
        alg: str,
        scheme: str,
    ) -> Optional[bytes]:
        """
        v3: protocol-hardening:
          - bytes-level path/query binding;
          - includes kid/scheme/alg in the signed prelude (removes ambiguity).
        """
        base = self._canonical_hmac_payload_v2_bytes(ts, method, raw_path, query_bytes, headers, body)
        if base is None:
            return None
        prelude = f"{scheme}\nkid={kid}\nalg={alg}\n".encode("utf-8", errors="strict")
        return prelude + base

    def _sign(self, key32: bytes, payload: bytes, *, alg: str) -> str:
        if alg == "blake3_keyed":
            if not _HAS_BLAKE3:
                raise RuntimeError("blake3 not available")
            if len(key32) != 32:
                raise ValueError("blake3 key must be 32 bytes")
            h = blake3(key=key32)
            # domain separation fixed string
            ctx_b = b"tcd:hmac"
            h.update(len(ctx_b).to_bytes(4, "big") + ctx_b)
            h.update(payload)
            return h.hexdigest()
        # hmac_sha256
        return hmac.new(key32, payload, hashlib.sha256).hexdigest()

    async def _verify_hmac(self, request: Request) -> AuthResult:
        sig_hdr = request.headers.get("x-tcd-signature", "")
        if not sig_hdr:
            self._ms.fail(R_MISSING)
            return AuthResult(False, None, R_MISSING)
        if len(sig_hdr) > self.max_sig_header_chars:
            self._ms.header_too_large("x-tcd-signature")
            self._ms.fail(R_HEADER_TOO_LARGE)
            return AuthResult(False, None, R_HEADER_TOO_LARGE)

        kid = request.headers.get("x-tcd-key-id", "default")
        if not isinstance(kid, str):
            self._ms.fail(R_BAD_KID)
            return AuthResult(False, None, R_BAD_KID)
        kid = kid.strip()
        if (not kid) or len(kid) > self.max_kid_chars or (not _SAFE_KID_RE.fullmatch(kid)):
            self._ms.fail(R_BAD_KID)
            return AuthResult(False, None, R_BAD_KID)

        parsed = self._parse_sig_header(sig_hdr)
        if parsed is None:
            self._ms.fail(R_MALFORMED)
            return AuthResult(False, None, R_MALFORMED)
        scheme, alg, ts, sig_hex, nonce = parsed

        if alg != self.hmac_alg:
            # prevent algorithm confusion
            self._ms.fail(R_BAD_ALG)
            return AuthResult(False, None, R_BAD_ALG)

        keys = self.hmac_keys.get(kid)
        if not keys:
            self._ms.fail(R_UNKNOWN_KEY)
            return AuthResult(False, None, R_UNKNOWN_KEY)

        now = int(self._now())
        if abs(now - int(ts)) > self.max_skew_s:
            self._ms.fail(R_SKEW)
            return AuthResult(False, None, R_SKEW)

        # nonce requirement
        unsafe = request.method.upper() in ("POST", "PUT", "PATCH", "DELETE")
        if self.hmac_require_nonce and (not nonce) and ((not self.hmac_require_nonce_for_unsafe_methods) or unsafe):
            self._ms.fail(R_NONCE_REQUIRED)
            return AuthResult(False, None, R_NONCE_REQUIRED)

        if nonce:
            # replay check via store
            key = f"hmac:{kid}:{ts}:{nonce}"
            fresh = self._replay.check_and_store(key, ttl_s=self.nonce_ttl_s)
            if not fresh:
                self._ms.replay()
                self._ms.fail(R_REPLAY)
                self._emit_event("replay", {"kind": "hmac_nonce", "kid": kid})
                return AuthResult(False, None, R_REPLAY)

        # Read body with hard limit, no unsafe fallback
        try:
            raw_body = await _read_body_limited(
                request,
                limit_bytes=self.max_hmac_body_bytes,
                enforce_content_length=True,
            )
        except ValueError as e:
            if str(e) == R_BODY_TOO_LARGE:
                self._ms.body_too_large()
                self._ms.fail(R_BODY_TOO_LARGE)
                return AuthResult(False, None, R_BODY_TOO_LARGE)
            self._ms.fail(R_BODY_READ_ERROR)
            return AuthResult(False, None, R_BODY_READ_ERROR)

        self._ms.body_bytes(len(raw_body))

        raw_path = _get_raw_path_bytes(request)
        query_bytes = _get_query_bytes(request)

        # Build payload
        if scheme == "v1":
            payload = self._canonical_hmac_payload_v1_bytes(int(ts), request.method, raw_path, raw_body)
        elif scheme == "v2":
            payload2 = self._canonical_hmac_payload_v2_bytes(int(ts), request.method, raw_path, query_bytes, request.headers, raw_body)
            if payload2 is None:
                self._ms.fail(R_QUERY_INVALID)
                return AuthResult(False, None, R_QUERY_INVALID)
            payload = payload2
        else:  # v3
            payload3 = self._canonical_hmac_payload_v3_bytes(
                int(ts),
                request.method,
                raw_path,
                query_bytes,
                request.headers,
                raw_body,
                kid=kid,
                alg=self.hmac_alg,
                scheme=scheme,
            )
            if payload3 is None:
                self._ms.fail(R_QUERY_INVALID)
                return AuthResult(False, None, R_QUERY_INVALID)
            payload = payload3

        # Constant-time-ish across rotated keys:
        # IMPORTANT: compute match first, then aggregate (fixes short-circuit leakage).
        ok_any = False
        for kbytes in keys:
            try:
                calc = self._sign(kbytes, payload, alg=self.hmac_alg)
            except Exception:
                self._ms.fail(R_KEY_INVALID)
                return AuthResult(False, None, R_KEY_INVALID)
            match = hmac.compare_digest(calc, sig_hex)
            ok_any = ok_any or match

        if not ok_any:
            self._ms.fail(R_SIG_MISMATCH)
            return AuthResult(False, None, R_SIG_MISMATCH)

        ctx = AuthContext(
            mode="hmac",
            principal=f"hmac:{kid}",
            scopes=["api", "signed", f"kid:{kid}"],
            key_id=kid,
            raw={
                "x-tcd-signature": f"{scheme},***",
                "x-tcd-key-id": _safe_text(kid, max_len=64),
            },
            policy_digest=self._policy_digest,
            issued_at=float(self._now()),
            authn_strength="hmac",
        )
        self._ms.ok()
        return AuthResult(True, ctx)

    # ------------------------------------------------------------------ #
    # JWT mode
    # ------------------------------------------------------------------ #

    def _jwk_compatible_with_alg(self, jwk_dict: dict, alg: str) -> bool:
        # Enforce kty/crv consistency and use/key_ops semantics if present.
        try:
            kty = jwk_dict.get("kty")
            crv = jwk_dict.get("crv")
            use = jwk_dict.get("use")
            key_ops = jwk_dict.get("key_ops")

            if use and isinstance(use, str) and use not in ("sig",):
                return False
            if key_ops and isinstance(key_ops, list):
                # if key_ops exists, must allow verify
                if "verify" not in [str(x) for x in key_ops]:
                    return False

            if alg == "RS256":
                return kty == "RSA"
            if alg == "ES256":
                return (kty == "EC") and (crv in ("P-256", "secp256r1"))
            if alg == "EdDSA":
                return (kty == "OKP") and (crv in ("Ed25519", "Ed448"))
            # if alg not recognized, fail closed
            return False
        except Exception:
            return False

    async def _verify_jwt(self, request: Request) -> AuthResult:
        if not _HAS_JWCRYPTO:
            self._ms.fail(R_LIB_MISSING)
            return AuthResult(False, None, R_LIB_MISSING)

        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            self._ms.fail(R_MISSING)
            return AuthResult(False, None, R_MISSING)
        if len(auth) > self.jwt_max_token_chars + 16:
            self._ms.header_too_large("authorization")
            self._ms.fail(R_HEADER_TOO_LARGE)
            return AuthResult(False, None, R_HEADER_TOO_LARGE)

        token = auth.split(" ", 1)[1].strip()
        if len(token) > self.jwt_max_token_chars:
            self._ms.fail(R_TOKEN_TOO_LARGE)
            return AuthResult(False, None, R_TOKEN_TOO_LARGE)

        hdr = _jwt_unverified_header(token, max_token_chars=self.jwt_max_token_chars)
        if hdr is None:
            self._ms.jwt_claim_fail(CF_KID)
            self._ms.fail(R_BAD_HEADER)
            return AuthResult(False, None, R_BAD_HEADER)

        # typ/crit checks (fail closed)
        typ = hdr.get("typ")
        if typ is not None:
            if not isinstance(typ, str) or typ.strip() not in self.jwt_allowed_typs:
                self._ms.jwt_claim_fail(CF_TYP)
                self._ms.fail(R_BAD_HEADER)
                return AuthResult(False, None, R_BAD_HEADER)

        crit = hdr.get("crit")
        if crit is not None:
            # If crit present, we don't support any critical headers -> fail closed
            self._ms.jwt_claim_fail(CF_CRIT)
            self._ms.fail(R_BAD_HEADER)
            return AuthResult(False, None, R_BAD_HEADER)

        kid = hdr.get("kid")
        alg = hdr.get("alg")
        if isinstance(alg, str):
            alg = alg.strip()
        else:
            alg = None

        if not alg or alg.lower() == "none":
            self._ms.jwt_claim_fail(CF_ALG)
            self._ms.fail(R_BAD_ALG)
            return AuthResult(False, None, R_BAD_ALG)
        if self.jwt_allowed_algs and alg not in self.jwt_allowed_algs:
            self._ms.jwt_claim_fail(CF_ALG)
            self._ms.fail(R_BAD_ALG)
            return AuthResult(False, None, R_BAD_ALG)

        jwk_dict: Optional[dict] = None
        kid_used: Optional[str] = None

        if isinstance(kid, str) and kid.strip():
            kid_s = kid.strip()
            if len(kid_s) > self.max_kid_chars or (not _SAFE_KID_RE.fullmatch(kid_s)):
                self._ms.jwt_claim_fail(CF_KID)
                self._ms.fail(R_BAD_HEADER)
                return AuthResult(False, None, R_BAD_HEADER)
            kid_used = kid_s
            jwk_dict = await self._jwks.aget_jwk_dict(kid_s)
        else:
            if self.jwt_allow_no_kid_single_key:
                one = await self._jwks.aget_single_jwk_if_unambiguous()
                if one is not None:
                    kid_used, jwk_dict = one
            if jwk_dict is None:
                self._ms.jwt_claim_fail(CF_KID)
                self._ms.fail(R_NO_KID)
                return AuthResult(False, None, R_NO_KID)

        if not jwk_dict:
            self._ms.fail(R_NO_JWK)
            return AuthResult(False, None, R_NO_JWK)

        # If JWK declares alg, enforce consistency.
        jwk_alg = jwk_dict.get("alg")
        if isinstance(jwk_alg, str) and jwk_alg and jwk_alg != alg:
            self._ms.jwt_claim_fail(CF_ALG)
            self._ms.fail(R_BAD_ALG)
            return AuthResult(False, None, R_BAD_ALG)

        # Enforce jwk type compatibility for alg (kty/crv/use/key_ops)
        if not self._jwk_compatible_with_alg(jwk_dict, alg):
            self._ms.jwt_claim_fail(CF_ALG)
            self._ms.fail(R_BAD_ALG)
            return AuthResult(False, None, R_BAD_ALG)

        # Verify signature + parse claims (strict JSON)
        try:
            key = jwk.JWK(**jwk_dict)  # type: ignore
            t = jwt.JWT(key=key, jwt=token)  # verifies signature
            claims_any = _json_loads_strict(t.claims)
            if not isinstance(claims_any, dict):
                raise ValueError("claims not dict")
            claims: dict = claims_any
        except Exception:
            self._ms.jwt_claim_fail(CF_SIG)
            self._ms.fail(R_BAD_SIG)
            return AuthResult(False, None, R_BAD_SIG)

        now = int(self._now())
        leeway = int(self.jwt_leeway_s)

        # issuer allowlist (strict)
        iss = claims.get("iss")
        if iss is not None and (not isinstance(iss, str)):
            self._ms.jwt_claim_fail(CF_ISS)
            self._ms.fail(R_BAD_ISS)
            return AuthResult(False, None, R_BAD_ISS)

        if self.jwt_iss_allow:
            if not isinstance(iss, str) or iss not in self.jwt_iss_allow:
                self._ms.jwt_claim_fail(CF_ISS)
                self._ms.fail(R_BAD_ISS)
                return AuthResult(False, None, R_BAD_ISS)
            if len(iss) > self.jwt_max_iss_chars:
                self._ms.jwt_claim_fail(CF_ISS)
                self._ms.fail(R_BAD_ISS)
                return AuthResult(False, None, R_BAD_ISS)

        # audience allowlist and bounds
        if self.jwt_aud_allow:
            aud = claims.get("aud")
            ok_aud = False
            if isinstance(aud, list):
                if len(aud) > self.jwt_max_aud_items:
                    ok_aud = False
                else:
                    ok_aud = any(str(x) in self.jwt_aud_allow for x in aud)
            elif aud is not None:
                ok_aud = (str(aud) in self.jwt_aud_allow)
            if not ok_aud:
                self._ms.jwt_claim_fail(CF_AUD)
                self._ms.fail(R_BAD_AUD)
                return AuthResult(False, None, R_BAD_AUD)

        exp = _claim_int(claims, "exp")
        if self.jwt_require_exp and (exp is None or exp <= 0):
            self._ms.jwt_claim_fail(CF_EXP)
            self._ms.fail(R_NO_EXP)
            return AuthResult(False, None, R_NO_EXP)
        if exp is not None and exp > 0 and now > (exp + leeway):
            self._ms.jwt_claim_fail(CF_EXP)
            self._ms.fail(R_EXPIRED)
            return AuthResult(False, None, R_EXPIRED)

        nbf = _claim_int(claims, "nbf")
        if nbf is not None and nbf > 0 and (now + leeway) < nbf:
            self._ms.jwt_claim_fail(CF_NBF)
            self._ms.fail(R_NOT_YET)
            return AuthResult(False, None, R_NOT_YET)

        iat = _claim_int(claims, "iat")
        if iat is not None and iat > 0 and (iat - leeway) > now:
            self._ms.jwt_claim_fail(CF_IAT)
            self._ms.fail(R_IAT)
            return AuthResult(False, None, R_IAT)

        # Token max age (anti-theft, bounded)
        if self.jwt_max_age_s > 0:
            if iat is None or iat <= 0:
                # if max_age is required but iat missing, treat as bad claims
                self._ms.jwt_claim_fail(CF_IAT)
                self._ms.fail(R_BAD_CLAIMS)
                return AuthResult(False, None, R_BAD_CLAIMS)
            if (now - iat) > (self.jwt_max_age_s + leeway):
                self._ms.jwt_claim_fail(CF_IAT)
                self._ms.fail(R_TOO_OLD)
                return AuthResult(False, None, R_TOO_OLD)

        # Max lifetime: exp - iat
        if self.jwt_max_lifetime_s > 0 and exp and iat and exp > iat:
            if (exp - iat) > (self.jwt_max_lifetime_s + leeway):
                self._ms.jwt_claim_fail(CF_EXP)
                self._ms.fail(R_BAD_CLAIMS)
                return AuthResult(False, None, R_BAD_CLAIMS)

        # Principal claim
        sub_val = claims.get(self.jwt_principal_claim)
        if self.jwt_require_principal_claim:
            if not isinstance(sub_val, str) or not sub_val.strip():
                self._ms.jwt_claim_fail(CF_PRINCIPAL)
                self._ms.fail(R_NO_PRINCIPAL)
                return AuthResult(False, None, R_NO_PRINCIPAL)

        sub = _safe_text(sub_val if sub_val is not None else "jwt", max_len=self.jwt_max_sub_chars)
        if isinstance(iss, str) and iss:
            iss_s = _safe_text(iss, max_len=self.jwt_max_iss_chars)
            principal = f"jwt:{iss_s}/{sub}"
        else:
            principal = f"jwt:{sub}"

        # Optional replay via jti
        if self.jwt_replay_via_jti:
            jti = claims.get("jti")
            if not isinstance(jti, str) or not jti.strip():
                if self.jwt_require_jti:
                    self._ms.jwt_claim_fail(CF_JTI)
                    self._ms.fail(R_BAD_CLAIMS)
                    return AuthResult(False, None, R_BAD_CLAIMS)
            else:
                jti_s = jti.strip()
                if len(jti_s) > self.jwt_max_jti_chars:
                    self._ms.jwt_claim_fail(CF_JTI)
                    self._ms.fail(R_BAD_CLAIMS)
                    return AuthResult(False, None, R_BAD_CLAIMS)
                ttl = 0
                if exp and exp > now:
                    ttl = max(1, (exp - now) + leeway)
                else:
                    ttl = max(60, self.jwt_max_age_s or 3600)
                rk = f"jwt:{kid_used or ''}:{jti_s}"
                fresh = self._replay.check_and_store(rk, ttl_s=ttl)
                if not fresh:
                    self._ms.replay()
                    self._ms.jwt_claim_fail(CF_JTI)
                    self._ms.fail(R_JTI_REPLAY)
                    self._emit_event("replay", {"kind": "jwt_jti", "kid": kid_used or ""})
                    return AuthResult(False, None, R_JTI_REPLAY)

        # Scopes (bounded, optional strict typing)
        scopes, ok_types = _dedup_scopes_iter_bounded(
            claims,
            self.jwt_scope_claims,
            max_items_out=self.jwt_max_scopes_out,
            max_item_len=128,
            max_raw_items=self.jwt_max_scopes_raw_items,
            max_scope_str_chars=self.jwt_max_scope_string_chars,
            strict_types=self.jwt_scope_strict,
        )
        if self.jwt_scope_strict and not ok_types:
            self._ms.fail(R_BAD_CLAIMS)
            return AuthResult(False, None, R_BAD_CLAIMS)
        if not scopes:
            scopes = ["api"]

        ctx = AuthContext(
            mode="jwt",
            principal=principal,
            scopes=scopes,
            key_id=str(kid_used) if kid_used else None,
            raw={"authorization": "Bearer ***"},
            policy_digest=self._policy_digest,
            issued_at=float(self._now()),
            authn_strength="jwt",
        )
        self._ms.ok()
        return AuthResult(True, ctx)

    # ------------------------------------------------------------------ #
    # mTLS mode (XFCC)
    # ------------------------------------------------------------------ #

    def _client_ip_trusted(self, request: Request) -> bool:
        if not self._mtls_trusted_nets:
            # If no CIDRs configured, treat as unsafe-by-default in mtls mode:
            # you must configure trusted proxies explicitly for XFCC auth.
            return False
        host = ""
        try:
            if request.client:
                host = str(request.client.host)
        except Exception:
            host = ""
        try:
            ip = ipaddress.ip_address(host)
        except Exception:
            return False
        return any(ip in net for net in self._mtls_trusted_nets)

    def _split_unquoted(self, s: str, sep: str) -> List[str]:
        out: List[str] = []
        cur: List[str] = []
        in_q = False
        esc = False
        for ch in s:
            if in_q:
                cur.append(ch)
                if esc:
                    esc = False
                else:
                    if ch == "\\":
                        esc = True
                    elif ch == '"':
                        in_q = False
                continue
            if ch == '"':
                in_q = True
                cur.append(ch)
                continue
            if ch == sep:
                out.append("".join(cur))
                cur = []
            else:
                cur.append(ch)
        out.append("".join(cur))
        return out

    def _parse_xfcc_first_peer(self, xfcc: str) -> Tuple[Optional[Dict[str, str]], int]:
        """
        Robust-ish XFCC parser for first peer:
          - split peers by unquoted comma
          - split kv pairs by unquoted semicolon
          - supports quoted values with escapes
        Returns (parts, peer_count).
        """
        if not isinstance(xfcc, str) or not xfcc:
            return None, 0
        if len(xfcc) > self.mtls_max_xfcc_chars:
            return None, 0

        peers = self._split_unquoted(xfcc, ",")
        peer_count = len([p for p in peers if p.strip()])
        if not peers:
            return None, peer_count
        peer = peers[0].strip()
        if not peer:
            return None, peer_count

        parts: Dict[str, str] = {}
        for kv in self._split_unquoted(peer, ";"):
            kv = kv.strip()
            if not kv or "=" not in kv:
                continue
            k, v = kv.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
            if v.startswith('"') and v.endswith('"') and len(v) >= 2:
                inner = v[1:-1]
                inner = inner.replace('\\"', '"').replace("\\\\", "\\")
                v = inner
            parts[k] = v
        return (parts or None), peer_count

    async def _verify_mtls(self, request: Request) -> AuthResult:
        # Trusted proxy requirement (P0): never trust XFCC from untrusted sources.
        if not self._client_ip_trusted(request):
            self._ms.fail(R_XFCC_UNTRUSTED)
            return AuthResult(False, None, R_XFCC_UNTRUSTED)

        if self.mtls_require_proxy_verified_header:
            hv = request.headers.get(self.mtls_proxy_verified_header_name, "")
            if hv.strip() != self.mtls_proxy_verified_header_value:
                self._ms.fail(R_FORBIDDEN)
                return AuthResult(False, None, R_FORBIDDEN)

        xfcc = request.headers.get("x-forwarded-client-cert", "")
        if not xfcc:
            self._ms.fail(R_MISSING)
            return AuthResult(False, None, R_MISSING)
        if len(xfcc) > self.mtls_max_xfcc_chars:
            self._ms.header_too_large("x-forwarded-client-cert")
            self._ms.fail(R_HEADER_TOO_LARGE)
            return AuthResult(False, None, R_HEADER_TOO_LARGE)

        parts, peer_count = self._parse_xfcc_first_peer(xfcc)
        if peer_count > 1:
            # Not a security failure by itself, but useful signal.
            self._emit_event("xfcc_multiple_peers", {"peer_count": peer_count})

        if not parts:
            self._ms.fail(R_XFCC_PARSE)
            return AuthResult(False, None, R_XFCC_PARSE)

        # Envoy Hash is base64 of SHA256 digest bytes (32 bytes).
        fp_hex: Optional[str] = None
        hval = parts.get("hash")
        if hval:
            hv = hval.strip()
            if len(hv) > 1024:
                fp_hex = None
            else:
                decoded = None
                try:
                    decoded = base64.b64decode(hv, validate=True)
                except Exception:
                    try:
                        decoded = base64.urlsafe_b64decode(hv + "=" * ((4 - (len(hv) % 4)) % 4))
                    except Exception:
                        decoded = None
                if decoded is not None:
                    if len(decoded) == 32:
                        fp_hex = decoded.hex()
                    else:
                        fp_hex = None

        spiffe = parts.get("uri") or ""
        if spiffe and (not isinstance(spiffe, str)):
            spiffe = ""
        spiffe = spiffe.strip()
        if spiffe:
            if len(spiffe) > self.mtls_max_spiffe_chars:
                self._ms.fail(R_XFCC_SPIFFE)
                return AuthResult(False, None, R_XFCC_SPIFFE)
            if not spiffe.startswith("spiffe://") or (not _SAFE_SPIFFE_RE.fullmatch(spiffe)):
                self._ms.fail(R_XFCC_SPIFFE)
                return AuthResult(False, None, R_XFCC_SPIFFE)

        ok = False
        if fp_hex and fp_hex.lower() in self.mtls_fp_allow:
            ok = True
        if not ok and self.mtls_spiffe_prefixes and spiffe:
            ok = any(spiffe.startswith(pref) for pref in self.mtls_spiffe_prefixes)

        if not ok:
            if (not fp_hex) and (not spiffe):
                self._ms.fail(R_XFCC_HASH)
                return AuthResult(False, None, R_XFCC_HASH)
            self._ms.fail(R_DENIED)
            return AuthResult(False, None, R_DENIED)

        principal = _safe_text(spiffe, max_len=256) if spiffe else f"mtls:{(fp_hex or '')[:16]}"
        ctx = AuthContext(
            mode="mtls",
            principal=principal,
            scopes=["api", "mtls"],
            key_id=(fp_hex.lower() if fp_hex else None),
            raw={"x-forwarded-client-cert": "present"},
            policy_digest=self._policy_digest,
            issued_at=float(self._now()),
            authn_strength="mtls",
        )
        self._ms.ok()
        return AuthResult(True, ctx)


# ---------------------------------------------------------------------------
# Client helpers (HMAC signing) - v1/v2 compatible + v3 hardened
# ---------------------------------------------------------------------------

def client_sign_hmac(
    method: str,
    path: str,
    body_bytes: bytes,
    *,
    key_hex: str,
    ts: Optional[int] = None,
    nonce: Optional[str] = None,
    alg: str = "blake3_keyed",
) -> Tuple[str, int]:
    ts_int = int(ts if ts is not None else int(time.time()))
    key_b = _hex_bytes_limited(key_hex, max_hex_chars=128)
    if key_b is None or len(key_b) != 32:
        raise ValueError("key_hex must be 32-byte hex")

    raw_path = path.encode("utf-8", errors="surrogateescape")
    payload = f"{ts_int}\n{method.upper()}\n".encode("ascii") + raw_path + b"\n" + (body_bytes or b"")

    if alg == "blake3_keyed":
        if not _HAS_BLAKE3:
            raise RuntimeError("blake3 not available")
        h = blake3(key=key_b)
        ctx_b = b"tcd:hmac"
        h.update(len(ctx_b).to_bytes(4, "big") + ctx_b)
        h.update(payload)
        sig_hex = h.hexdigest()
        a = "b3"
    elif alg == "hmac_sha256":
        sig_hex = hmac.new(key_b, payload, hashlib.sha256).hexdigest()
        a = "hs256"
    else:
        raise ValueError("unsupported alg")

    if nonce:
        return f"v1,t={ts_int},sig={sig_hex},n={nonce},a={a}", ts_int
    return f"v1,t={ts_int},sig={sig_hex},a={a}", ts_int


def client_sign_hmac_v2(
    method: str,
    path: str,
    body_bytes: bytes,
    *,
    key_hex: str,
    ts: Optional[int] = None,
    nonce: Optional[str] = None,
    query: str = "",
    headers: Optional[Mapping[str, str]] = None,
    alg: str = "blake3_keyed",
    query_mode: str = "form",
    max_query_pairs: int = 128,
) -> Tuple[str, int]:
    ts_int = int(ts if ts is not None else int(time.time()))
    key_b = _hex_bytes_limited(key_hex, max_hex_chars=128)
    if key_b is None or len(key_b) != 32:
        raise ValueError("key_hex must be 32-byte hex")

    raw_path = path.encode("utf-8", errors="surrogateescape")
    query_b = (query or "").encode("utf-8", errors="surrogateescape")
    canon_query = _canonicalize_query_bytes(
        query_b,
        mode=("form" if (query_mode or "form").lower() != "rfc3986" else "rfc3986"),
        max_query_bytes=8192,
        max_pairs=max_query_pairs,
        max_key_bytes=256,
        max_val_bytes=1024,
    )
    if canon_query is None:
        raise ValueError("query invalid")

    hdrs = headers or {}
    host = str(hdrs.get("host", "")).strip()
    xcl = str(hdrs.get("x-tcd-cluster", "")).strip()
    xenv = str(hdrs.get("x-tcd-env", "")).strip()
    canon_headers = f"host={host}|x-tcd-cluster={xcl}|x-tcd-env={xenv}".encode("utf-8", errors="strict")

    payload = (
        f"{ts_int}\n{method.upper()}\n".encode("ascii")
        + raw_path
        + b"\n"
        + canon_query
        + b"\n"
        + canon_headers
        + b"\n"
        + (body_bytes or b"")
    )

    if alg == "blake3_keyed":
        if not _HAS_BLAKE3:
            raise RuntimeError("blake3 not available")
        h = blake3(key=key_b)
        ctx_b = b"tcd:hmac"
        h.update(len(ctx_b).to_bytes(4, "big") + ctx_b)
        h.update(payload)
        sig_hex = h.hexdigest()
        a = "b3"
    elif alg == "hmac_sha256":
        sig_hex = hmac.new(key_b, payload, hashlib.sha256).hexdigest()
        a = "hs256"
    else:
        raise ValueError("unsupported alg")

    if nonce:
        return f"v2,t={ts_int},sig={sig_hex},n={nonce},a={a}", ts_int
    return f"v2,t={ts_int},sig={sig_hex},a={a}", ts_int


def client_sign_hmac_v3(
    method: str,
    path: str,
    body_bytes: bytes,
    *,
    key_hex: str,
    kid: str,
    ts: Optional[int] = None,
    nonce: Optional[str] = None,
    query: str = "",
    headers: Optional[Mapping[str, str]] = None,
    alg: str = "blake3_keyed",
    query_mode: str = "form",
) -> Tuple[str, int]:
    """
    v3 hardening:
      - includes scheme/kid/alg in signed prelude;
      - bytes-level path/query binding.
    """
    if not _SAFE_KID_RE.fullmatch(kid or ""):
        raise ValueError("invalid kid")
    ts_int = int(ts if ts is not None else int(time.time()))
    key_b = _hex_bytes_limited(key_hex, max_hex_chars=128)
    if key_b is None or len(key_b) != 32:
        raise ValueError("key_hex must be 32-byte hex")

    raw_path = path.encode("utf-8", errors="surrogateescape")
    query_b = (query or "").encode("utf-8", errors="surrogateescape")
    canon_query = _canonicalize_query_bytes(
        query_b,
        mode=("form" if (query_mode or "form").lower() != "rfc3986" else "rfc3986"),
        max_query_bytes=8192,
        max_pairs=128,
        max_key_bytes=256,
        max_val_bytes=1024,
    )
    if canon_query is None:
        raise ValueError("query invalid")

    hdrs = headers or {}
    host = str(hdrs.get("host", "")).strip()
    xcl = str(hdrs.get("x-tcd-cluster", "")).strip()
    xenv = str(hdrs.get("x-tcd-env", "")).strip()
    canon_headers = f"host={host}|x-tcd-cluster={xcl}|x-tcd-env={xenv}".encode("utf-8", errors="strict")

    base = (
        f"{ts_int}\n{method.upper()}\n".encode("ascii")
        + raw_path
        + b"\n"
        + canon_query
        + b"\n"
        + canon_headers
        + b"\n"
        + (body_bytes or b"")
    )
    prelude = f"v3\nkid={kid}\nalg={alg}\n".encode("utf-8", errors="strict")
    payload = prelude + base

    if alg == "blake3_keyed":
        if not _HAS_BLAKE3:
            raise RuntimeError("blake3 not available")
        h = blake3(key=key_b)
        ctx_b = b"tcd:hmac"
        h.update(len(ctx_b).to_bytes(4, "big") + ctx_b)
        h.update(payload)
        sig_hex = h.hexdigest()
        a = "b3"
    elif alg == "hmac_sha256":
        sig_hex = hmac.new(key_b, payload, hashlib.sha256).hexdigest()
        a = "hs256"
    else:
        raise ValueError("unsupported alg")

    if nonce:
        return f"v3,t={ts_int},sig={sig_hex},n={nonce},a={a}", ts_int
    return f"v3,t={ts_int},sig={sig_hex},a={a}", ts_int


# ---------------------------------------------------------------------------
# Factory & FastAPI dependency
# ---------------------------------------------------------------------------

def build_authenticator_from_env() -> Authenticator:
    """
    Environment-driven config (platform hardened).

    Governance:
      - TCD_ENV=prod: by default disallow disabled/bearer/inline_jwks unless break-glass
        TCD_AUTH_BREAK_GLASS=1 is set.
      - TCD_AUTH_MODE REQUIRED unless (ALLOW_IMPLICIT_DISABLED && ALLOW_DISABLED).

    Oracle control:
      - TCD_AUTH_EXPOSE_FAILURE_REASON: default 0
    """
    fam = _get_default_metrics()

    tcd_env = (os.environ.get("TCD_ENV", "") or "").strip().lower()
    break_glass = _parse_bool_env("TCD_AUTH_BREAK_GLASS", False)

    allow_disabled = _parse_bool_env("TCD_AUTH_ALLOW_DISABLED", False)
    allow_implicit_disabled = _parse_bool_env("TCD_AUTH_ALLOW_IMPLICIT_DISABLED", False)
    allow_bearer = _parse_bool_env("TCD_AUTH_ALLOW_BEARER", False)
    allow_inline_jwks = _parse_bool_env("TCD_AUTH_ALLOW_INLINE_JWKS", False)

    # prod governance (L7-ish)
    if tcd_env in ("prod", "production") and not break_glass:
        allow_disabled = False
        allow_bearer = False
        allow_inline_jwks = False

    mode_env = os.environ.get("TCD_AUTH_MODE")
    if mode_env is None or not mode_env.strip():
        if allow_disabled and allow_implicit_disabled:
            mode = "disabled"
        else:
            raise ValueError("TCD_AUTH_MODE is required. For dev: set TCD_AUTH_MODE=disabled and TCD_AUTH_ALLOW_DISABLED=1.")
    else:
        mode = mode_env.strip().lower()

    # Strict allowed modes list
    strict_modes_env = os.environ.get("TCD_AUTH_STRICT_MODES", "")
    if strict_modes_env.strip():
        allowed = {m.strip().lower() for m in strict_modes_env.split(",") if m.strip()}
        if mode not in allowed:
            raise ValueError(f"TCD_AUTH_MODE={mode} not allowed; must be one of {sorted(allowed)}")

    if mode == "disabled" and not allow_disabled:
        raise ValueError("TCD_AUTH_MODE=disabled not permitted; set TCD_AUTH_ALLOW_DISABLED=1 explicitly")

    if mode == "bearer" and not allow_bearer:
        raise ValueError("TCD_AUTH_MODE=bearer not permitted; set TCD_AUTH_ALLOW_BEARER=1 explicitly")

    name = os.environ.get("TCD_AUTH_NAME", "default")
    version = os.environ.get("TCD_AUTH_VERSION", "v1")

    expose_reason = _parse_bool_env("TCD_AUTH_EXPOSE_FAILURE_REASON", False)
    fail_delay_ms = _parse_int_env("TCD_AUTH_FAIL_DELAY_MS_MAX", 0)

    max_path_bytes = _parse_int_env("TCD_AUTH_MAX_PATH_BYTES", 2048)
    max_query_bytes = _parse_int_env("TCD_AUTH_MAX_QUERY_BYTES", 8192)
    max_headers_bytes = _parse_int_env("TCD_AUTH_MAX_TOTAL_HEADERS_BYTES", 32 * 1024)

    policy_salt_hex = os.environ.get("TCD_AUTH_POLICY_SALT_HEX")

    # bearer
    bearer_tokens: List[str] = []
    if mode == "bearer":
        raw = os.environ.get("TCD_AUTH_BEARER_TOKENS", "")
        bearer_tokens = [t.strip() for t in raw.split(",") if t.strip()]

    max_skew = _parse_int_env("TCD_AUTH_MAX_SKEW_S", 300)
    if max_skew < 1:
        max_skew = 300

    # hmac
    hmac_keys: Dict[str, str] = {}
    if mode == "hmac":
        raw = os.environ.get("TCD_AUTH_HMAC_KEYS_JSON", "").strip()
        if not raw:
            raise ValueError("TCD_AUTH_HMAC_KEYS_JSON is required in hmac mode")
        obj = _json_loads_strict(raw)
        if not isinstance(obj, dict) or not obj:
            raise ValueError("TCD_AUTH_HMAC_KEYS_JSON must be JSON object {kid: \"hex[,hex2]\"}")
        for k, v in obj.items():
            for p in str(v).split(","):
                pp = p.strip()
                if not pp:
                    continue
                kb = _hex_bytes_limited(pp, max_hex_chars=128)
                if kb is None or len(kb) != 32:
                    raise ValueError("HMAC keys must be 32-byte hex values")
        hmac_keys = {str(k): str(v) for k, v in obj.items()}

    hmac_alg = (os.environ.get("TCD_AUTH_HMAC_ALG", "blake3_keyed") or "").strip().lower()
    hmac_require_nonce = _parse_bool_env("TCD_AUTH_HMAC_REQUIRE_NONCE", True)
    hmac_require_nonce_unsafe = _parse_bool_env("TCD_AUTH_HMAC_REQUIRE_NONCE_UNSAFE_ONLY", True)
    nonce_ttl_s = _parse_int_env("TCD_AUTH_NONCE_TTL_S", 0) or None
    max_hmac_body = _parse_int_env("TCD_AUTH_MAX_HMAC_BODY_BYTES", 1024 * 1024)
    max_sig_hdr = _parse_int_env("TCD_AUTH_MAX_SIG_HEADER_CHARS", 2048)
    max_kid_chars = _parse_int_env("TCD_AUTH_MAX_KID_CHARS", 128)
    max_nonce_chars = _parse_int_env("TCD_AUTH_MAX_NONCE_CHARS", 256)
    max_query_pairs = _parse_int_env("TCD_AUTH_MAX_QUERY_PAIRS", 128)
    hmac_query_mode = (os.environ.get("TCD_AUTH_HMAC_QUERY_MODE", "form") or "").strip().lower()

    # jwt
    jwt_iss = os.environ.get("TCD_AUTH_JWT_ISS")
    jwt_iss_allowlist_env = os.environ.get("TCD_AUTH_JWT_ISS_ALLOWLIST", "")
    jwt_iss_allowlist = [x.strip() for x in jwt_iss_allowlist_env.split(",") if x.strip()]

    jwt_aud = os.environ.get("TCD_AUTH_JWT_AUD")
    jwt_aud_allowlist_env = os.environ.get("TCD_AUTH_JWT_AUD_ALLOWLIST", "")
    jwt_aud_allowlist = [x.strip() for x in jwt_aud_allowlist_env.split(",") if x.strip()]

    jwks_url = os.environ.get("TCD_AUTH_JWKS_URL")
    jwks_json = os.environ.get("TCD_AUTH_JWKS_JSON")
    if mode == "jwt" and jwks_json and not allow_inline_jwks:
        raise ValueError("Inline JWKS disabled; set TCD_AUTH_ALLOW_INLINE_JWKS=1 explicitly")

    jwks_allowed_hosts_env = os.environ.get("TCD_AUTH_JWKS_ALLOWED_HOSTS", "")
    jwks_allowed_hosts = [x.strip() for x in jwks_allowed_hosts_env.split(",") if x.strip()]

    jwks_cache_ttl_s = _parse_int_env("TCD_AUTH_JWKS_CACHE_TTL_S", 600)
    jwks_timeout_s = _parse_float_env("TCD_AUTH_JWKS_TIMEOUT_S", 2.0)
    jwks_max_bytes = _parse_int_env("TCD_AUTH_JWKS_MAX_BYTES", 256 * 1024)
    jwks_max_keys = _parse_int_env("TCD_AUTH_JWKS_MAX_KEYS", 64)
    jwks_allow_stale = _parse_bool_env("TCD_AUTH_JWKS_ALLOW_STALE", True)
    jwks_max_stale_s = _parse_int_env("TCD_AUTH_JWKS_MAX_STALE_S", 3600)

    jwt_leeway_s = _parse_int_env("TCD_AUTH_JWT_LEEWAY_S", 60)
    jwt_principal_claim = os.environ.get("TCD_AUTH_JWT_PRINCIPAL_CLAIM", "sub")
    jwt_require_principal = _parse_bool_env("TCD_AUTH_JWT_REQUIRE_PRINCIPAL", True)

    jwt_scope_claims_env = os.environ.get("TCD_AUTH_JWT_SCOPE_CLAIMS", "scp,scope,roles")
    jwt_scope_claims = tuple(c.strip() for c in jwt_scope_claims_env.split(",") if c.strip())
    jwt_scope_strict = _parse_bool_env("TCD_AUTH_JWT_SCOPE_STRICT", False)

    jwt_allowed_algs_env = os.environ.get("TCD_AUTH_JWT_ALLOWED_ALGS", "RS256,ES256,EdDSA")
    jwt_allowed_algs: Tuple[str, ...] = tuple(a.strip() for a in jwt_allowed_algs_env.split(",") if a.strip())

    jwt_require_exp = _parse_bool_env("TCD_AUTH_JWT_REQUIRE_EXP", True)
    jwt_require_jti = _parse_bool_env("TCD_AUTH_JWT_REQUIRE_JTI", False)
    jwt_replay_via_jti = _parse_bool_env("TCD_AUTH_JWT_REPLAY_VIA_JTI", False)

    # mtls
    mtls_fp_allow_env = os.environ.get("TCD_AUTH_MTLS_FP_ALLOW", "")
    mtls_fp_allow = [x.strip().lower() for x in mtls_fp_allow_env.split(",") if x.strip()]

    mtls_spiffe_env = os.environ.get("TCD_AUTH_MTLS_SPIFFE_PREFIX", "")
    mtls_spiffe_prefixes = [x.strip() for x in mtls_spiffe_env.split(",") if x.strip()]

    mtls_trusted_cidrs_env = os.environ.get("TCD_AUTH_MTLS_TRUSTED_PROXY_CIDRS", "")
    mtls_trusted_proxy_cidrs = [x.strip() for x in mtls_trusted_cidrs_env.split(",") if x.strip()]

    mtls_require_verified = _parse_bool_env("TCD_AUTH_MTLS_REQUIRE_PROXY_VERIFIED_HEADER", False)

    # NOTE: replay store and event sink are not configured by env here; wire in code if needed.
    return Authenticator(
        mode=mode,
        name=name,
        version=version,
        metrics=fam,
        allow_disabled=allow_disabled,
        expose_failure_reason_to_client=expose_reason,
        auth_fail_delay_ms_max=fail_delay_ms,
        policy_salt_hex=policy_salt_hex,

        max_path_bytes=max_path_bytes,
        max_query_bytes=max_query_bytes,
        max_total_headers_bytes=max_headers_bytes,

        bearer_tokens=bearer_tokens,

        hmac_keys=hmac_keys,
        hmac_alg=hmac_alg,
        max_skew_s=max_skew,
        hmac_require_nonce=hmac_require_nonce,
        hmac_require_nonce_for_unsafe_methods=hmac_require_nonce_unsafe,
        nonce_ttl_s=nonce_ttl_s,
        max_hmac_body_bytes=max_hmac_body,
        max_sig_header_chars=max_sig_hdr,
        max_kid_chars=max_kid_chars,
        max_nonce_chars=max_nonce_chars,
        max_query_pairs=max_query_pairs,
        hmac_query_mode=hmac_query_mode,

        jwt_iss=jwt_iss,
        jwt_iss_allowlist=jwt_iss_allowlist,
        jwt_aud=jwt_aud,
        jwt_aud_allowlist=jwt_aud_allowlist,
        jwks_url=jwks_url,
        jwks_json=jwks_json,
        jwks_cache_ttl_s=jwks_cache_ttl_s,
        jwks_timeout_s=jwks_timeout_s,
        jwks_max_bytes=jwks_max_bytes,
        jwks_max_keys=jwks_max_keys,
        jwks_allowed_hosts=jwks_allowed_hosts,
        jwks_allow_stale=jwks_allow_stale,
        jwks_max_stale_s=jwks_max_stale_s,
        jwt_leeway_s=jwt_leeway_s,
        jwt_principal_claim=jwt_principal_claim,
        jwt_require_principal_claim=jwt_require_principal,
        jwt_scope_claims=jwt_scope_claims,
        jwt_scope_strict=jwt_scope_strict,
        jwt_allowed_algs=jwt_allowed_algs,
        jwt_require_exp=jwt_require_exp,
        jwt_require_jti=jwt_require_jti,
        jwt_replay_via_jti=jwt_replay_via_jti,

        mtls_fp_allow=mtls_fp_allow,
        mtls_spiffe_prefixes=mtls_spiffe_prefixes,
        mtls_trusted_proxy_cidrs=mtls_trusted_proxy_cidrs,
        mtls_require_proxy_verified_header=mtls_require_verified,
    )


def require_auth(
    authenticator: Authenticator,
    *,
    required_scopes: Optional[List[str]] = None,
) -> Callable[[Request], Awaitable[AuthContext]]:
    """
    FastAPI dependency factory (oracle-safe by default):
      - 401 always "unauthorized" unless authenticator.expose_failure_reason_to_client=True
      - 403 always "forbidden"
      - records authz_forbidden_total (does NOT pollute authn metrics)
    """
    required_scopes = [s.strip() for s in (required_scopes or []) if isinstance(s, str) and s.strip()]

    async def _dep(request: Request) -> AuthContext:
        res = await authenticator.verify(request)
        if not res.ok or not res.ctx:
            if authenticator.expose_failure_reason_to_client:
                detail = res.reason or "unauthorized"
            else:
                detail = "unauthorized"
            raise HTTPException(status_code=401, detail=detail)

        if required_scopes:
            have = set(res.ctx.scopes or [])
            need = set(required_scopes)
            if not need.issubset(have):
                authenticator._ms.forbidden()  # authz metric only
                raise HTTPException(status_code=403, detail="forbidden")

        return res.ctx

    return _dep


# ---------------------------------------------------------------------------
# Optional: Middleware (early reject + attach AuthContext)
# ---------------------------------------------------------------------------

class AuthMiddleware:
    """
    Optional ASGI middleware:
      - performs authentication early (before handlers/dependencies)
      - attaches ctx to request.state.auth_ctx
      - rejects unauthorized with oracle-safe responses

    Usage:
      app.add_middleware(AuthMiddleware, authenticator=auth, required_scopes=[...])
    """
    def __init__(self, app, *, authenticator: Authenticator, required_scopes: Optional[List[str]] = None):
        self.app = app
        self.auth = authenticator
        self.required_scopes = [s.strip() for s in (required_scopes or []) if isinstance(s, str) and s.strip()]

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)

        res = await self.auth.verify(request)
        if not res.ok or not res.ctx:
            detail = (res.reason or "unauthorized") if self.auth.expose_failure_reason_to_client else "unauthorized"
            await self._send_json(send, 401, {"detail": detail})
            return

        if self.required_scopes:
            have = set(res.ctx.scopes or [])
            need = set(self.required_scopes)
            if not need.issubset(have):
                self.auth._ms.forbidden()
                await self._send_json(send, 403, {"detail": "forbidden"})
                return

        # Attach to state for downstream
        try:
            scope.setdefault("state", {})
            scope["state"]["auth_ctx"] = res.ctx
        except Exception:
            pass

        await self.app(scope, receive, send)

    async def _send_json(self, send, status: int, obj: dict) -> None:
        body = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers = [(b"content-type", b"application/json; charset=utf-8")]
        await send({"type": "http.response.start", "status": int(status), "headers": headers})
        await send({"type": "http.response.body", "body": body, "more_body": False})