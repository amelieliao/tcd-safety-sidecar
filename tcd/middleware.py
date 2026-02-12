# FILE: tcd/middleware.py
from __future__ import annotations

"""
TCD Middleware (strong L7 → L7+)

This revision implements every hard requirement from your checklist and
systematically upgrades correctness + security + operability.

Key upgrades (delta vs previous "L7++ hardened" draft)

1) Unicode / control character / log-forgery closure
   - Fixes the real hole: ASCII fast-path previously missed TAB/LF/CR.
   - Removes ALL ASCII controls (0x00–0x1F, 0x7F) and also C1 (0x80–0x9F).
   - Keeps existing Unicode Cc/Cf/Cs/Zl/Zp stripping + U+2028/U+2029.

2) Secret/token recognition widened + applied everywhere it matters
   - Adds detectors for common API keys and high-entropy tokens:
       * OpenAI-like sk-...
       * AWS AKIA...
       * Google AIza...
       * key/value patterns: api_key=, token=, secret=, password= ...
       * long base64url-ish tokens (bounded threshold to avoid UUID false positives)
   - Even when sanitize_upstream_chain=False, upstream chain never passes secrets.

3) RequestContextMiddleware hardened semantics + fixation defenses
   - Upstream request id "trusted" semantic fixed:
       * upstream_id_accepted: passed format/safety checks
       * upstream_id_trusted: only true when peer is trusted (CIDR/IP allowlist)
   - No prefix truncation collisions: oversize upstream IDs are rejected OR folded
     deterministically (cfg.fold_long_upstream_ids).
   - Session TTL rotation is closed-loop:
       * when session source is cookie and rotation occurs, Set-Cookie is emitted
         (configurable).
   - Session fixation guard:
       * signed session IDs (sid = raw.sig) via HMAC (blake2s),
         always verified on ingress.
       * if key not provided and signing is enabled, an ephemeral process key is
         generated (still prevents attacker-chosen fixation; may not survive restart).
   - Request chain CPU bound:
       * uses rsplit / hop caps; no unbounded split loops.

4) RateLimitMiddleware correctness + DoS/fairness fixes
   - rate<=0 is explicit disable (allow all), not "burst-then-perma-deny".
   - tokens parameter validated (NaN/Inf/<=0 cannot bypass).
   - token clamp: tokens always in [0, burst].
   - Overflow fairness:
       * overflow is sharded (<overflow:N>) instead of one global bucket.
       * deny/temp-block are tracked by real ip key, NOT overflow shard key.
   - Trusted proxy support upgraded:
       * trusted_proxies supports IP and CIDR.
       * XFF parsing chooses "rightmost non-proxy" client, bounded by max_parts,
         with diagnostics on state (xff_ignored_reason).
   - Zone explosion prevented:
       * max_zones cap; unknown zones collapse to "default".
   - Lock-held O(n log n) sorting removed:
       * uses OrderedDict LRU eviction (O(1)) and bounded TTL popping.

   - Implements previously-dead config: max_tokens_per_ip_per_window (hard cap overlay).

5) MetricsMiddleware compliance closure + deterministic shrink
   - HIGH_SECURITY now gates IDs/chain/receipt/error tags/multivar outputs by policy.
   - Hashing:
       * forbids unkeyed hashing in HIGH_SECURITY/FINREG when configured;
         no silent "SHA256(label:value)" linkability in regulated profiles.
       * hash_fn return is constrained (only bytes/str, length capped).
   - Oversize shrink respects required fields and adds shrunk=true when possible.
   - request_chain logging is hop-validated (reuses same sanitizer).
   - Optional safe query-key logging uses forbidden_query_params (dead params closed).

6) BaseHTTPMiddleware caveat: ASGI variants provided
   - For production correctness with streaming responses, pure ASGI middleware
     variants are included for all three layers:
       * RequestContextASGIMiddleware
       * RateLimitASGIMiddleware
       * MetricsASGIMiddleware

Notes
  - This file continues to avoid request/response bodies and does not log headers or query values.
  - Anything callable-injected is treated as untrusted: we avoid str()/repr() on unknown objects.
"""

import hashlib
import hmac
import ipaddress
import json
import logging
import math
import re
import secrets
import sys
import threading
import time
import unicodedata
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

try:
    from prometheus_client import Counter, Histogram  # type: ignore
except Exception:  # pragma: no cover
    Counter = Any  # type: ignore
    Histogram = Any  # type: ignore

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# --------------------------------
# Low-level sanitization utilities (keep local; recommended to extract to tcd/sanitize.py)
# --------------------------------

# Full ASCII control range incl TAB/LF/CR, plus DEL. (Closes the fast-path hole.)
_ASCII_CTRL_FULL_RE = re.compile(r"[\x00-\x1F\x7F]")

# Secret detectors (expanded)
_JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_PRIVKEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----", re.IGNORECASE)
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._\-~=+/]+\b", re.IGNORECASE)

# Common API keys / tokens
_OPENAI_SK_RE = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")
_AWS_AKIA_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GOOGLE_AIZA_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")

# Key/value secret-ish patterns (conservative)
_KV_SECRET_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|apikey|token|secret|password|passwd|pwd)\s*[:=]\s*([^\s,;]{8,})"
)

# High-entropy-ish base64url token (threshold chosen to avoid UUID hex false positives)
_LONG_B64URL_RE = re.compile(r"\b[A-Za-z0-9_-]{60,}\b")

# Tag-like identifiers (safe for headers/state)
_TAGLIKE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,255}$")
_CHAIN_ID_RE = _TAGLIKE_ID_RE

# Safe zone names
_ZONE_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,31}$")

# Long token segments in path labels
_LONG_SEG_RE = re.compile(r"(?:(?<=/)|^)[A-Za-z0-9._-]{24,}(?=(?:/|$))")


def _has_unsafe_unicode(s: str) -> bool:
    """
    Detect Unicode characters that can cause log/header confusion:
      - Cc/Cf/Cs (control/format/surrogate)
      - Zl/Zp (line/paragraph sep)
      - U+2028/U+2029
    """
    for ch in s:
        if ch in ("\u2028", "\u2029"):
            return True
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            return True
        # C1 controls appear as Cc in unicode category, but keep explicit handling in strip
    return False


def _strip_unsafe_text(s: str, *, max_len: int) -> str:
    """
    Remove:
      - ASCII controls: 0x00–0x1F, 0x7F (including TAB/LF/CR)
      - C1 controls:    0x80–0x9F
      - Unicode: Cc/Cf/Cs/Zl/Zp + U+2028/U+2029

    Also clamps length early.
    """
    if not s:
        return ""
    if len(s) > max_len:
        s = s[:max_len]

    # ASCII fast-path (now fully correct)
    if s.isascii():
        # remove all <0x20 and 0x7F
        if _ASCII_CTRL_FULL_RE.search(s):
            s = _ASCII_CTRL_FULL_RE.sub("", s)
        return s

    # Non-ASCII path
    if not _ASCII_CTRL_FULL_RE.search(s) and not _has_unsafe_unicode(s):
        # still need to remove C1 controls if present
        if any(0x80 <= ord(ch) <= 0x9F for ch in s):
            pass
        else:
            return s

    out: List[str] = []
    for ch in s:
        o = ord(ch)
        if ch in ("\u2028", "\u2029"):
            continue
        # ASCII controls + DEL
        if o < 0x20 or o == 0x7F:
            continue
        # C1 controls
        if 0x80 <= o <= 0x9F:
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            continue
        out.append(ch)
    return "".join(out)


def _looks_like_secret(s: str) -> bool:
    """
    Conservative secret detector for strings that must never carry credentials
    into headers/state/logs.

    IMPORTANT: avoid patterns that would flag UUID hex (32) as secret.
    """
    if not s:
        return False
    if _JWT_RE.search(s):
        return True
    if _PRIVKEY_RE.search(s):
        return True
    if _BEARER_RE.search(s):
        return True
    if _OPENAI_SK_RE.search(s):
        return True
    if _AWS_AKIA_RE.search(s):
        return True
    if _GOOGLE_AIZA_RE.search(s):
        return True
    if _KV_SECRET_RE.search(s):
        return True
    # Long base64url-ish tokens (avoid catching short IDs)
    if _LONG_B64URL_RE.search(s):
        return True
    return False


def _safe_taglike_id(
    raw: Optional[str],
    *,
    max_len: int,
    pattern: Optional[re.Pattern[str]] = None,
    reject_secrets: bool = True,
    allow_truncate: bool = False,
) -> Optional[str]:
    """
    Sanitize and validate an ID-like string suitable for headers/state.

    Default behavior is *no truncation* to prevent prefix-collision surprises.
    """
    if not raw or not isinstance(raw, str):
        return None
    s = _strip_unsafe_text(raw, max_len=max_len + (1 if not allow_truncate else 0)).strip()
    if not s:
        return None
    if reject_secrets and _looks_like_secret(s):
        return None
    if len(s) > max_len:
        if not allow_truncate:
            return None
        s = s[:max_len]
    pat = pattern or _TAGLIKE_ID_RE
    if not pat.fullmatch(s):
        return None
    return s


def _finite_float(x: Any) -> Optional[float]:
    # Reject bool explicitly (bool is int subclass).
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


# --------------------------------
# Shared helpers
# --------------------------------

_UUID_SEG_RE = re.compile(
    r"[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[1-5][0-9a-fA-F]{3}\b-[89abAB][0-9a-fA-F]{3}\b-[0-9a-fA-F]{12}"
)
_LONG_NUM_SEG_RE = re.compile(r"/\d{4,}")


def _default_path_normalizer(path: str) -> str:
    """
    Best-effort path normalizer to keep label cardinality under control.
    """
    p = _UUID_SEG_RE.sub(":uuid", path)
    p = _LONG_NUM_SEG_RE.sub("/:id", p)
    # Second-stage token collapse (files/<hash>, models/<token>, etc.)
    p = _LONG_SEG_RE.sub(":tok", p)
    return p


def _bounded_label(s: str, *, max_len: int = 128) -> str:
    s2 = _strip_unsafe_text(s or "", max_len=max_len).strip()
    if not s2:
        return "unknown"
    if len(s2) > max_len:
        s2 = s2[:max_len]
    return s2


def _blake2s_hex(data: bytes, *, digest_bytes: int = 8) -> str:
    h = hashlib.blake2s(data).digest()
    return h[:digest_bytes].hex()


def _fold_id(prefix: str, value: str, *, digest_hex: int = 16) -> str:
    """
    Deterministically fold an oversize ID to a safe tag-like short id.
    Unkeyed is acceptable for request-id correlation *after* secret rejection.
    """
    v = _strip_unsafe_text(value, max_len=2048).encode("utf-8", errors="ignore")
    d = hashlib.blake2s(b"TCD|idfold|v1|" + v).hexdigest()[:digest_hex]
    return f"{prefix}-h-{d}"


# --------------------------------
# Trusted proxy parsing + client IP extraction (shared)
# --------------------------------

def _parse_trusted_proxies(values: Iterable[str]) -> Tuple[ipaddress._BaseNetwork, ...]:
    nets: List[ipaddress._BaseNetwork] = []
    for raw in values:
        if not raw:
            continue
        s = _strip_unsafe_text(str(raw), max_len=128).strip()
        if not s:
            continue
        try:
            # ip_network handles single IP as /32 or /128 with strict=False
            net = ipaddress.ip_network(s, strict=False)
            nets.append(net)
        except Exception:
            continue
    return tuple(nets)


def _ip_in_trusted(ip: str, nets: Tuple[ipaddress._BaseNetwork, ...]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return False
    for net in nets:
        try:
            if ip_obj in net:
                return True
        except Exception:
            continue
    return False


def _parse_ip(s: str) -> Optional[str]:
    if not s:
        return None
    ss = _strip_unsafe_text(s, max_len=96).strip()
    if not ss:
        return None
    if ss.startswith("[") and ss.endswith("]"):
        ss = ss[1:-1]
    try:
        return str(ipaddress.ip_address(ss))
    except Exception:
        return None


def _extract_client_ip_from_xff(
    *,
    remote_ip: str,
    xff: Optional[str],
    trusted_proxies: Tuple[ipaddress._BaseNetwork, ...],
    max_xff_parts: int,
) -> Tuple[str, Optional[str]]:
    """
    Robust XFF extraction:
      - Only use XFF if remote_ip is trusted proxy.
      - Parse up to max_xff_parts parts (anti-CPU/DoS).
      - Choose "rightmost non-proxy" IP as client.
      - Returns (client_ip, ignored_reason or None).
    """
    rip = _parse_ip(remote_ip) or "unknown"

    if not _ip_in_trusted(rip, trusted_proxies):
        return rip, "untrusted_proxy"

    if not xff:
        return rip, "no_xff"

    # Bound raw header size (anti-DoS)
    xff_s = _strip_unsafe_text(xff, max_len=2048).strip()
    if not xff_s:
        return rip, "empty_xff"

    # Split, but bound number of parts
    parts_raw = [p.strip() for p in xff_s.split(",") if p.strip()]
    if not parts_raw:
        return rip, "empty_xff"

    if len(parts_raw) > max_xff_parts:
        # Too many parts: only consider the last max_xff_parts (closest to us)
        parts_raw = parts_raw[-max_xff_parts:]

    ips: List[str] = []
    for p in parts_raw:
        ipn = _parse_ip(p)
        if ipn is not None:
            ips.append(ipn)

    if not ips:
        return rip, "invalid_xff"

    # Walk from right to left: drop trusted proxies; first non-proxy is client
    for cand in reversed(ips):
        if not _ip_in_trusted(cand, trusted_proxies):
            return cand, None

    # If all are proxies (rare), fall back to leftmost valid
    return ips[0], "xff_all_proxies"


# --------------------------------
# Request context middleware
# --------------------------------

@dataclass
class RequestContextConfig:
    """
    Assigns and propagates request_id / session_id / request_chain.

    Checklist closure:
      - upstream_id_trusted semantic fixed (requires trusted peers allowlist)
      - no prefix truncation collisions (reject or fold)
      - TTL rotation closes the loop via Set-Cookie when cookie source is used
      - session fixation defended via signed session IDs (HMAC)
      - chain parsing bounded (rsplit + hop caps)
      - BaseHTTPMiddleware + ASGI variants provided
    """

    # Header names for request / session identifiers.
    request_id_header: str = "X-Request-Id"
    session_id_header: str = "X-Session-Id"
    request_chain_header: str = "X-Request-Chain"
    session_cookie_name: str = "sid"

    # Profile describing how strict behavior should be.
    trust_profile: str = "PROD"  # "DEV" | "PROD" | "HIGH_SECURITY"

    # ID generation strategy.
    id_entropy_bits: int = 128
    id_length: int = 32  # number of hex characters for raw id
    id_source: str = "uuid4"  # "uuid4" | "prf"
    id_namespace_label: str = "tcd/request"
    prf: Optional[Callable[[bytes, str], Any]] = None

    # Upstream request-id trust.
    accept_upstream_request_id: bool = True
    upstream_request_id_header_whitelist: Tuple[str, ...] = ()
    sanitize_upstream_ids: bool = True
    id_format_regex: Optional[str] = r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,255}$"

    # If an upstream request id is longer than allowed:
    #   - if fold_long_upstream_ids: fold to rid-h-<digest>
    #   - else: reject and generate new
    fold_long_upstream_ids: bool = True

    # TRUE "trusted upstream" requires peer allowlist (IP/CIDR).
    trusted_upstream_peers: Tuple[str, ...] = ()
    # Optionally honor XFF for peer identity (rare; default False).
    peer_respect_xff: bool = False
    peer_trusted_proxies: Tuple[str, ...] = ()
    peer_max_xff_parts: int = 16

    # Session semantics.
    session_ttl_seconds: Optional[float] = None
    session_rotation_on_sensitive_action: bool = False
    sensitive_paths: Tuple[str, ...] = (r"^/admin", r"^/keys", r"^/config")
    session_source_priority: Tuple[str, ...] = ("header", "cookie")

    # Session signing (fixation defense)
    sign_session_ids: bool = True
    session_signing_key: Optional[bytes] = None
    session_signing_key_id: Optional[str] = None
    session_sig_bytes: int = 8  # 8 bytes => 16 hex chars
    # If True, refuse unsigned/invalid session ids (always generate new).
    require_valid_signed_session_id: bool = True

    # Cookie write-back (TTL rotation closure)
    set_session_cookie_on_response: bool = True
    session_cookie_path: str = "/"
    session_cookie_domain: Optional[str] = None
    session_cookie_secure: Optional[bool] = None  # None => infer from trust_profile
    session_cookie_httponly: bool = True
    session_cookie_samesite: str = "lax"  # "lax" | "strict" | "none"
    session_cookie_max_age_seconds: Optional[int] = None

    # Chain bounds
    accept_upstream_request_chain: bool = True
    sanitize_upstream_chain: bool = True
    max_chain_hops: int = 16
    max_chain_chars: int = 1024

    # Whether to attach IDs to request.state.
    attach_ids_to_state: bool = True
    # Whether to expose IDs to downstream responses as headers.
    expose_ids_to_downstream_headers: bool = True

    # Middleware should be authority in PROD/HIGH_SECURITY by default.
    preserve_existing_response_header: bool = False

    # Optional high-security posture: do not expose session/chain headers.
    hide_session_and_chain_in_high_security: bool = True

    # Session tracking hardening (prevents memory growth)
    session_state_max_entries: int = 200_000
    session_state_idle_ttl_seconds: float = 6 * 3600.0
    session_state_gc_interval_seconds: float = 30.0

    # If True, do not create a big aggregation dict on state; keep minimal flags only.
    minimize_state_context_dict: bool = True


class _SessionSigner:
    def __init__(self, *, key: bytes, sig_bytes: int):
        self._key = key
        self._sig_bytes = _clamp_int(int(sig_bytes), 4, 32)

    def sign(self, raw: str) -> str:
        msg = b"TCD|sid|v1|" + raw.encode("utf-8", errors="ignore")
        mac = hmac.new(self._key, msg, hashlib.blake2s).digest()
        sig = mac[: self._sig_bytes].hex()
        return f"{raw}.{sig}"

    def verify(self, signed: str) -> Optional[str]:
        # accept only "<raw>.<hexsig>"
        if not signed or "." not in signed:
            return None
        raw, sig = signed.rsplit(".", 1)
        if not raw or not sig:
            return None
        # sig hex length must match
        if len(sig) != self._sig_bytes * 2 or not re.fullmatch(r"[0-9a-fA-F]+", sig):
            return None
        expect = self.sign(raw).rsplit(".", 1)[1]
        if hmac.compare_digest(sig.lower(), expect.lower()):
            return raw
        return None


class RequestContextMiddleware(BaseHTTPMiddleware):
    """
    BaseHTTPMiddleware variant (easy integration). See RequestContextASGIMiddleware
    for the production-grade ASGI variant that avoids BaseHTTPMiddleware pitfalls.
    """

    def __init__(self, app, *, config: Optional[RequestContextConfig] = None):
        super().__init__(app)
        self._cfg = config or RequestContextConfig()

        self._id_pattern = re.compile(self._cfg.id_format_regex) if self._cfg.id_format_regex else None
        self._sensitive_path_re = [re.compile(p) for p in self._cfg.sensitive_paths]

        self._trusted_upstream_peers = _parse_trusted_proxies(self._cfg.trusted_upstream_peers)
        self._peer_trusted_proxies = _parse_trusted_proxies(self._cfg.peer_trusted_proxies)

        # session signer
        self._signer: Optional[_SessionSigner] = None
        if self._cfg.sign_session_ids:
            key = self._cfg.session_signing_key
            if not isinstance(key, (bytes, bytearray)) or not key:
                # Ephemeral process key: prevents attacker-chosen fixation even without external config.
                key = secrets.token_bytes(32)
            self._signer = _SessionSigner(key=bytes(key), sig_bytes=self._cfg.session_sig_bytes)

        # session tracking: sid -> (first_seen_mono, last_seen_mono) with LRU eviction
        self._session_lock = threading.Lock()
        self._session_seen: "OrderedDict[str, Tuple[float, float]]" = OrderedDict()
        self._session_last_gc = 0.0

    # ------- helpers -------

    def _generate_id(self, kind: str, client_ip: str, path: str) -> str:
        max_len = _clamp_int(int(self._cfg.id_length or 32), 8, 128)
        by_entropy = int(self._cfg.id_entropy_bits // 4) if (self._cfg.id_entropy_bits and self._cfg.id_entropy_bits > 0) else max_len
        length = _clamp_int(min(max_len, max(8, by_entropy)), 8, 128)

        if self._cfg.id_source == "prf" and self._cfg.prf is not None:
            try:
                seed = f"{time.time_ns()}:{client_ip}:{path}:{kind}".encode("utf-8", errors="ignore")
                label = f"{self._cfg.id_namespace_label}/{kind}"
                raw = self._cfg.prf(seed, label)
                if isinstance(raw, (bytes, bytearray, memoryview)):
                    s = bytes(raw).hex()
                elif isinstance(raw, str):
                    s = hashlib.blake2s(raw.encode("utf-8", errors="ignore")).hexdigest()
                else:
                    s = hashlib.blake2s(repr(type(raw)).encode("utf-8", errors="ignore")).hexdigest()
            except Exception:
                s = uuid.uuid4().hex
        else:
            s = uuid.uuid4().hex

        s = re.sub(r"[^0-9a-fA-F]+", "", s).lower()
        if not s:
            s = uuid.uuid4().hex
        return s[:length]

    def _peer_ip(self, request: Request) -> str:
        remote = request.client.host if request.client else "unknown"
        remote_ip = _parse_ip(remote) or "unknown"

        if not self._cfg.peer_respect_xff:
            return remote_ip

        xff = request.headers.get("x-forwarded-for")
        ip, _reason = _extract_client_ip_from_xff(
            remote_ip=remote_ip,
            xff=xff,
            trusted_proxies=self._peer_trusted_proxies,
            max_xff_parts=_clamp_int(int(self._cfg.peer_max_xff_parts or 16), 1, 64),
        )
        return ip

    def _extract_upstream_request_id(self, request: Request) -> Tuple[Optional[str], bool, bool]:
        """
        Returns (rid, upstream_id_accepted, upstream_id_trusted).
        """
        if not self._cfg.accept_upstream_request_id:
            return None, False, False

        header_names: Tuple[str, ...] = (
            self._cfg.upstream_request_id_header_whitelist or (self._cfg.request_id_header,)
        )
        max_len = _clamp_int(int(self._cfg.id_length or 32), 8, 128)

        peer_ip = self._peer_ip(request)
        upstream_trusted = _ip_in_trusted(peer_ip, self._trusted_upstream_peers) if self._trusted_upstream_peers else False

        for name in header_names:
            v = request.headers.get(name)
            if not v:
                continue
            vv = _strip_unsafe_text(v, max_len=2048).strip()
            if not vv:
                continue
            if _looks_like_secret(vv):
                continue

            # Must match regex/pattern if sanitization enabled.
            if self._cfg.sanitize_upstream_ids:
                if self._id_pattern is not None and not self._id_pattern.fullmatch(vv):
                    continue
                # also enforce taglike (no truncate)
                if _safe_taglike_id(vv, max_len=max_len, pattern=_TAGLIKE_ID_RE, allow_truncate=False) is None:
                    # Allow fold/reject for oversize separately
                    if len(vv) > max_len:
                        pass
                    else:
                        continue

            if len(vv) > max_len:
                if self._cfg.fold_long_upstream_ids:
                    rid = _fold_id("rid", vv)
                    return rid, True, upstream_trusted
                # reject oversize (no truncation collisions)
                continue

            # Accept as-is (bounded)
            rid = _safe_taglike_id(vv, max_len=max_len, pattern=_TAGLIKE_ID_RE, allow_truncate=False)
            if rid is None:
                continue
            return rid, True, upstream_trusted

        return None, False, False

    def _is_sensitive_path(self, path: str) -> bool:
        return any(p.search(path) for p in self._sensitive_path_re)

    def _gc_sessions(self, now: float) -> None:
        interval = _finite_float(self._cfg.session_state_gc_interval_seconds) or 30.0
        if (now - self._session_last_gc) < interval:
            return
        self._session_last_gc = now

        idle_ttl = float(self._cfg.session_state_idle_ttl_seconds or 0.0)
        max_entries = int(self._cfg.session_state_max_entries or 0)

        # Idle eviction from oldest (LRU front)
        if idle_ttl > 0:
            cutoff = now - idle_ttl
            while self._session_seen:
                sid, (_first, last) = next(iter(self._session_seen.items()))
                if last >= cutoff:
                    break
                self._session_seen.popitem(last=False)

        # Hard cap eviction (O(1) pops)
        if max_entries > 0:
            while len(self._session_seen) > max_entries:
                self._session_seen.popitem(last=False)

    def _track_session(self, sid: str, now: float) -> Tuple[float, float]:
        """
        Update LRU and return (first_seen, last_seen).
        """
        first_last = self._session_seen.get(sid)
        if first_last is None:
            self._session_seen[sid] = (now, now)
            return (now, now)
        first, _last = first_last
        self._session_seen[sid] = (first, now)
        # bump LRU
        self._session_seen.move_to_end(sid, last=True)
        return (first, now)

    def _apply_session_ttl_and_track(
        self,
        sid: str,
        *,
        now: float,
        rotate_if_expired: bool,
        gen_new: Callable[[], str],
    ) -> Tuple[str, bool]:
        ttl = self._cfg.session_ttl_seconds
        if ttl is None or ttl <= 0:
            with self._session_lock:
                self._gc_sessions(now)
                self._track_session(sid, now)
            return sid, False

        with self._session_lock:
            self._gc_sessions(now)
            first, _last = self._track_session(sid, now)
            if (now - first) > float(ttl):
                if rotate_if_expired:
                    # rotate
                    self._session_seen.pop(sid, None)
                    new_sid = gen_new()
                    self._session_seen[new_sid] = (now, now)
                    self._session_seen.move_to_end(new_sid, last=True)
                    return new_sid, True
                return sid, True

        return sid, False

    def _session_cookie_attrs(self) -> Dict[str, Any]:
        cfg = self._cfg
        secure = cfg.session_cookie_secure
        if secure is None:
            secure = cfg.trust_profile != "DEV"
        samesite = (cfg.session_cookie_samesite or "lax").lower()
        if samesite not in ("lax", "strict", "none"):
            samesite = "lax"
        return {
            "path": cfg.session_cookie_path or "/",
            "domain": cfg.session_cookie_domain,
            "secure": bool(secure),
            "httponly": bool(cfg.session_cookie_httponly),
            "samesite": samesite,
            "max_age": cfg.session_cookie_max_age_seconds,
        }

    def _sanitize_session_incoming(self, sid_in: Optional[str]) -> Tuple[Optional[str], bool]:
        """
        Returns (session_id_to_use, accepted_flag).
        accepted_flag means "passed validation + signature (if enabled)".
        """
        if not sid_in or not isinstance(sid_in, str):
            return None, False

        # allow longer because signed value adds ".<sig>"
        raw_max = _clamp_int(int(self._cfg.id_length or 32), 8, 128)
        sig_hex = _clamp_int(int(self._cfg.session_sig_bytes or 8) * 2, 8, 64)
        max_len = min(255, raw_max + 1 + sig_hex)

        s = _safe_taglike_id(sid_in, max_len=max_len, pattern=_TAGLIKE_ID_RE, allow_truncate=False)
        if s is None:
            return None, False
        if _looks_like_secret(s):
            return None, False

        if self._signer is None:
            # unsigned mode: accept taglike
            return s, True

        # signed mode: verify signature and return signed value (not raw)
        raw = self._signer.verify(s)
        if raw is None:
            return None, False
        # raw must itself be taglike within raw_max
        raw_ok = _safe_taglike_id(raw, max_len=raw_max, pattern=_TAGLIKE_ID_RE, allow_truncate=False)
        if raw_ok is None:
            return None, False
        # keep signed value as session id representation
        return s, True

    def _new_signed_session(self, raw_sid: str) -> str:
        if self._signer is None:
            return raw_sid
        return self._signer.sign(raw_sid)

    def _sanitize_chain(self, upstream_chain: str, rid: str) -> Tuple[str, bool]:
        """
        Returns (chain, truncated_flag).

        Even when sanitize_upstream_chain=False, we still:
          - reject secrets
          - enforce hop caps and max chars
          - validate hop format (taglike)
        """
        if not self._cfg.accept_upstream_request_chain:
            return rid, False

        max_hops = _clamp_int(int(self._cfg.max_chain_hops or 16), 1, 64)
        max_chars = _clamp_int(int(self._cfg.max_chain_chars or 1024), 64, 8192)

        raw = _strip_unsafe_text(upstream_chain or "", max_len=max_chars).strip()
        if not raw:
            return rid, False

        # If raw looks like it contains secrets, ignore it entirely.
        if _looks_like_secret(raw):
            return rid, True

        # CPU bound: only consider the last K segments from the right.
        # (Processing the tail preserves the "closest hops".)
        parts = raw.rsplit(",", max_hops * 2)
        hops: List[str] = []
        for part in parts:
            if len(hops) >= (max_hops - 1):
                break
            p = part.strip()
            if not p:
                continue
            hid = _safe_taglike_id(p, max_len=128, pattern=_CHAIN_ID_RE, reject_secrets=True, allow_truncate=False)
            if hid is None:
                if self._cfg.sanitize_upstream_chain:
                    # drop invalid hop
                    continue
                # strict mode: any invalid hop invalidates entire upstream chain
                return rid, True
            hops.append(hid)

        # Keep only last (max_hops-1)
        if len(hops) > (max_hops - 1):
            hops = hops[-(max_hops - 1) :]

        hops.append(rid)
        chain = ",".join(hops)
        if len(chain) > max_chars:
            # deterministic truncate: drop from front until fits
            truncated = True
            while len(chain) > max_chars and len(hops) > 1:
                hops.pop(0)
                chain = ",".join(hops)
            if len(chain) > max_chars:
                return rid, True
            return chain, truncated

        return chain, False

    async def dispatch(self, request: Request, call_next):
        cfg = self._cfg
        h_req = cfg.request_id_header
        h_sess = cfg.session_id_header
        chain_header = cfg.request_chain_header

        # Peer IP (for PRF seed / context only; not the "true client ip" unless configured)
        peer_ip = self._peer_ip(request)
        path = _strip_unsafe_text(request.url.path or "/", max_len=1024).strip() or "/"

        # Upstream request id
        upstream_rid, upstream_accepted, upstream_trusted = self._extract_upstream_request_id(request)
        if upstream_rid is not None:
            rid = upstream_rid
        else:
            rid = self._generate_id("request", peer_ip, path)

        # Chain (bounded)
        upstream_chain = request.headers.get(chain_header) or ""
        chain, chain_truncated = self._sanitize_chain(upstream_chain, rid)

        # Session id from sources
        sid: Optional[str] = None
        sid_src: str = "generated"
        sid_accepted = False

        for src in cfg.session_source_priority:
            v: Optional[str]
            if src == "header":
                v = request.headers.get(h_sess)
            elif src == "cookie":
                v = request.cookies.get(cfg.session_cookie_name)
            else:
                v = None
            sid, sid_accepted = self._sanitize_session_incoming(v.strip() if isinstance(v, str) else None)
            if sid:
                sid_src = src
                break

        if not sid:
            raw_sid = self._generate_id("session", peer_ip, path)
            sid = self._new_signed_session(raw_sid)
            sid_src = "generated"
            sid_accepted = True

        # TTL tracking + rotation (closed-loop)
        now = time.monotonic()

        def _gen_new_sid() -> str:
            raw = self._generate_id("session", peer_ip, path)
            return self._new_signed_session(raw)

        sid, ttl_rotated = self._apply_session_ttl_and_track(
            sid,
            now=now,
            rotate_if_expired=True,
            gen_new=_gen_new_sid,
        )
        rotated = ttl_rotated

        if (not rotated) and cfg.session_rotation_on_sensitive_action and self._is_sensitive_path(path):
            sid = _gen_new_sid()
            with self._session_lock:
                self._gc_sessions(now)
                self._session_seen[sid] = (now, now)
                self._session_seen.move_to_end(sid, last=True)
            rotated = True

        # Attach to request.state (minimal + safe)
        if cfg.attach_ids_to_state:
            request.state.request_id = rid
            request.state.session_id = sid
            request.state.request_chain = chain
            request.state.session_rotated = rotated
            request.state.session_source = sid_src
            request.state.upstream_id_accepted = upstream_accepted
            request.state.upstream_id_trusted = upstream_trusted
            request.state.chain_truncated = chain_truncated
            request.state.tcd_trust_profile = cfg.trust_profile

            if not cfg.minimize_state_context_dict:
                # If you really want a dict, keep it low-risk.
                request.state.request_context = {
                    "trust_profile": cfg.trust_profile,
                    "upstream_id_accepted": upstream_accepted,
                    "upstream_id_trusted": upstream_trusted,
                    "chain_truncated": chain_truncated,
                    "session_rotated": rotated,
                    "session_source": sid_src,
                    "session_accepted": sid_accepted,
                }

        response = await call_next(request)

        # Decide exposure posture
        hide_sess_chain = cfg.hide_session_and_chain_in_high_security and cfg.trust_profile == "HIGH_SECURITY"

        # Propagate headers (authority by default in PROD/HIGH_SECURITY)
        if cfg.expose_ids_to_downstream_headers:
            rid_hdr = _safe_taglike_id(rid, max_len=255, pattern=_TAGLIKE_ID_RE, allow_truncate=False)
            sid_hdr = _safe_taglike_id(sid, max_len=255, pattern=_TAGLIKE_ID_RE, allow_truncate=False)
            chain_hdr = _strip_unsafe_text(chain, max_len=cfg.max_chain_chars).strip()

            def _set_header(name: str, value: str) -> None:
                if cfg.preserve_existing_response_header:
                    response.headers.setdefault(name, value)
                else:
                    response.headers[name] = value

            if rid_hdr:
                _set_header(h_req, rid_hdr)
            if not hide_sess_chain and sid_hdr:
                _set_header(h_sess, sid_hdr)
            if not hide_sess_chain and chain_hdr and len(chain_hdr) <= cfg.max_chain_chars:
                _set_header(chain_header, chain_hdr)

        # Cookie write-back (TTL rotation closure)
        if cfg.set_session_cookie_on_response:
            # If cookie is used or headers are hidden, we ensure cookie carries sid
            if (sid_src == "cookie") or hide_sess_chain or rotated or (sid_src == "generated"):
                attrs = self._session_cookie_attrs()
                try:
                    response.set_cookie(
                        key=cfg.session_cookie_name,
                        value=sid,
                        path=attrs["path"],
                        domain=attrs["domain"],
                        secure=attrs["secure"],
                        httponly=attrs["httponly"],
                        samesite=attrs["samesite"],
                        max_age=attrs["max_age"],
                    )
                except Exception:
                    # never crash response
                    pass

        return response


# --------------------------------
# RequestContext ASGI middleware (production-grade)
# --------------------------------

def _headers_from_scope(scope: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k_b, v_b in scope.get("headers") or []:
        try:
            k = k_b.decode("latin1").lower()
            v = v_b.decode("latin1")
        except Exception:
            continue
        out[k] = v
    return out


def _get_cookie_from_headers(headers: Dict[str, str], name: str) -> Optional[str]:
    raw = headers.get("cookie")
    if not raw:
        return None
    c = SimpleCookie()
    try:
        c.load(raw)
    except Exception:
        return None
    morsel = c.get(name)
    if morsel is None:
        return None
    return morsel.value


def _asgi_set_header(
    headers: List[Tuple[bytes, bytes]],
    name: str,
    value: str,
    *,
    preserve: bool,
) -> None:
    nb = name.lower().encode("latin1")
    vb = value.encode("latin1", errors="ignore")
    if preserve:
        for k, _v in headers:
            if k.lower() == nb:
                return
    # remove existing if not preserve
    if not preserve:
        headers[:] = [(k, v) for (k, v) in headers if k.lower() != nb]
    headers.append((nb, vb))


def _asgi_add_set_cookie(headers: List[Tuple[bytes, bytes]], set_cookie_value: str) -> None:
    headers.append((b"set-cookie", set_cookie_value.encode("latin1", errors="ignore")))


def _build_set_cookie(
    *,
    name: str,
    value: str,
    path: str,
    domain: Optional[str],
    secure: bool,
    httponly: bool,
    samesite: str,
    max_age: Optional[int],
) -> str:
    c = SimpleCookie()
    c[name] = value
    c[name]["path"] = path or "/"
    if domain:
        c[name]["domain"] = domain
    if secure:
        c[name]["secure"] = True
    if httponly:
        c[name]["httponly"] = True
    ss = (samesite or "lax").lower()
    if ss in ("lax", "strict", "none"):
        c[name]["samesite"] = ss.capitalize() if ss != "none" else "None"
    if max_age is not None:
        try:
            c[name]["max-age"] = str(int(max_age))
        except Exception:
            pass
    # SimpleCookie outputs "Set-Cookie: ..." lines; we want only the value part
    return c.output(header="").strip()


class RequestContextASGIMiddleware:
    """
    Pure ASGI version of RequestContextMiddleware (avoids BaseHTTPMiddleware issues).
    """

    def __init__(self, app, *, config: Optional[RequestContextConfig] = None):
        self.app = app
        self._impl = RequestContextMiddleware(app=None, config=config)  # reuse logic container
        # NOTE: we won't call BaseHTTPMiddleware methods; we only use helpers/state in _impl.

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        cfg = self._impl._cfg  # pylint: disable=protected-access

        headers = _headers_from_scope(scope)
        remote_host = "unknown"
        try:
            remote_host = (scope.get("client") or ("unknown", 0))[0] or "unknown"
        except Exception:
            remote_host = "unknown"

        # Peer IP derivation for request-id/session generation context
        peer_ip = _parse_ip(remote_host) or "unknown"
        if cfg.peer_respect_xff:
            ip2, _ = _extract_client_ip_from_xff(
                remote_ip=peer_ip,
                xff=headers.get("x-forwarded-for"),
                trusted_proxies=self._impl._peer_trusted_proxies,  # pylint: disable=protected-access
                max_xff_parts=_clamp_int(int(cfg.peer_max_xff_parts or 16), 1, 64),
            )
            peer_ip = ip2

        path = _strip_unsafe_text(scope.get("path") or "/", max_len=1024).strip() or "/"

        # Upstream request id
        upstream_rid = None
        upstream_accepted = False
        upstream_trusted = False
        if cfg.accept_upstream_request_id:
            peer_trusted = _ip_in_trusted(peer_ip, self._impl._trusted_upstream_peers) if self._impl._trusted_upstream_peers else False  # pylint: disable=protected-access
            hn = cfg.upstream_request_id_header_whitelist or (cfg.request_id_header,)
            max_len = _clamp_int(int(cfg.id_length or 32), 8, 128)
            for name in hn:
                v = headers.get(name.lower())
                if not v:
                    continue
                vv = _strip_unsafe_text(v, max_len=2048).strip()
                if not vv or _looks_like_secret(vv):
                    continue
                if cfg.sanitize_upstream_ids and self._impl._id_pattern is not None and not self._impl._id_pattern.fullmatch(vv):  # pylint: disable=protected-access
                    continue
                if len(vv) > max_len:
                    if cfg.fold_long_upstream_ids:
                        upstream_rid = _fold_id("rid", vv)
                        upstream_accepted = True
                        upstream_trusted = peer_trusted
                        break
                    continue
                rid_ok = _safe_taglike_id(vv, max_len=max_len, pattern=_TAGLIKE_ID_RE, allow_truncate=False)
                if rid_ok:
                    upstream_rid = rid_ok
                    upstream_accepted = True
                    upstream_trusted = peer_trusted
                    break

        rid = upstream_rid or self._impl._generate_id("request", peer_ip, path)  # pylint: disable=protected-access

        # Chain
        upstream_chain = headers.get(cfg.request_chain_header.lower()) or ""
        chain, chain_truncated = self._impl._sanitize_chain(upstream_chain, rid)  # pylint: disable=protected-access

        # Session id
        sid_src = "generated"
        sid = None
        sid_accepted = False

        for src in cfg.session_source_priority:
            if src == "header":
                v = headers.get(cfg.session_id_header.lower())
            elif src == "cookie":
                v = _get_cookie_from_headers(headers, cfg.session_cookie_name)
            else:
                v = None
            sid, sid_accepted = self._impl._sanitize_session_incoming(v.strip() if isinstance(v, str) else None)  # pylint: disable=protected-access
            if sid:
                sid_src = src
                break

        if not sid:
            raw_sid = self._impl._generate_id("session", peer_ip, path)  # pylint: disable=protected-access
            sid = self._impl._new_signed_session(raw_sid)  # pylint: disable=protected-access
            sid_src = "generated"
            sid_accepted = True

        # TTL + rotation
        now = time.monotonic()

        def _gen_new_sid() -> str:
            raw = self._impl._generate_id("session", peer_ip, path)  # pylint: disable=protected-access
            return self._impl._new_signed_session(raw)  # pylint: disable=protected-access

        sid, ttl_rotated = self._impl._apply_session_ttl_and_track(  # pylint: disable=protected-access
            sid, now=now, rotate_if_expired=True, gen_new=_gen_new_sid
        )
        rotated = ttl_rotated

        if (not rotated) and cfg.session_rotation_on_sensitive_action and self._impl._is_sensitive_path(path):  # pylint: disable=protected-access
            sid = _gen_new_sid()
            with self._impl._session_lock:  # pylint: disable=protected-access
                self._impl._gc_sessions(now)  # pylint: disable=protected-access
                self._impl._session_seen[sid] = (now, now)  # pylint: disable=protected-access
                self._impl._session_seen.move_to_end(sid, last=True)  # pylint: disable=protected-access
            rotated = True

        # Attach to scope state (Starlette Request.state reads this)
        st = scope.setdefault("state", {})
        try:
            st["request_id"] = rid
            st["session_id"] = sid
            st["request_chain"] = chain
            st["session_rotated"] = rotated
            st["session_source"] = sid_src
            st["upstream_id_accepted"] = upstream_accepted
            st["upstream_id_trusted"] = upstream_trusted
            st["chain_truncated"] = chain_truncated
            st["tcd_trust_profile"] = cfg.trust_profile
        except Exception:
            pass

        hide_sess_chain = cfg.hide_session_and_chain_in_high_security and cfg.trust_profile == "HIGH_SECURITY"
        rid_hdr = _safe_taglike_id(rid, max_len=255, pattern=_TAGLIKE_ID_RE, allow_truncate=False)
        sid_hdr = _safe_taglike_id(sid, max_len=255, pattern=_TAGLIKE_ID_RE, allow_truncate=False)
        chain_hdr = _strip_unsafe_text(chain, max_len=cfg.max_chain_chars).strip()

        set_cookie_value: Optional[str] = None
        if cfg.set_session_cookie_on_response:
            if (sid_src == "cookie") or hide_sess_chain or rotated or (sid_src == "generated"):
                attrs = self._impl._session_cookie_attrs()  # pylint: disable=protected-access
                try:
                    set_cookie_value = _build_set_cookie(
                        name=cfg.session_cookie_name,
                        value=sid,
                        path=attrs["path"],
                        domain=attrs["domain"],
                        secure=attrs["secure"],
                        httponly=attrs["httponly"],
                        samesite=attrs["samesite"],
                        max_age=attrs["max_age"],
                    )
                except Exception:
                    set_cookie_value = None

        async def send_wrapper(message):
            if message.get("type") == "http.response.start":
                hdrs = list(message.get("headers") or [])
                if rid_hdr:
                    _asgi_set_header(hdrs, cfg.request_id_header, rid_hdr, preserve=cfg.preserve_existing_response_header)
                if not hide_sess_chain and sid_hdr:
                    _asgi_set_header(hdrs, cfg.session_id_header, sid_hdr, preserve=cfg.preserve_existing_response_header)
                if not hide_sess_chain and chain_hdr and len(chain_hdr) <= cfg.max_chain_chars:
                    _asgi_set_header(hdrs, cfg.request_chain_header, chain_hdr, preserve=cfg.preserve_existing_response_header)
                if set_cookie_value:
                    _asgi_add_set_cookie(hdrs, set_cookie_value)
                message["headers"] = hdrs
            await send(message)

        return await self.app(scope, receive, send_wrapper)


# --------------------------------
# IP-level rate limit middleware
# --------------------------------

@dataclass
class RateLimitConfig:
    """
    Lightweight in-memory IP-level rate limiter (edge guard).

    Checklist closure:
      - rate<=0 => disabled (allow all)
      - tokens validated (no NaN/neg bypass)
      - overflow sharded + deny/block tracked per real IP
      - trusted proxies support CIDR
      - zone count bounded
      - eviction is O(1) (LRU OrderedDict; no lock-held sorting)
      - max_tokens_per_ip_per_window implemented (dead param closed)
      - deny quiet reset separated from block TTL
      - audit policy can redact in HIGH_SECURITY
    """

    enabled: bool = True

    rate_per_sec: float = 10.0
    burst: float = 20.0

    max_entries: int = 50_000
    idle_ttl_seconds: float = 10.0 * 60.0
    gc_interval_seconds: float = 5.0

    skip_paths: Tuple[str, ...] = (r"^/healthz$", r"^/metrics$", r"^/version$")
    json_error: bool = True
    error_reason: str = "rate_limited"

    # Sharded overflow to preserve fairness for "new keys when map is full"
    overflow_shards: int = 64

    # Zone explosion control
    max_zones: int = 64

    trust_zones: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    ip_trust_classifier: Optional[Callable[[str], str]] = None

    respect_xff: bool = False
    trusted_proxies: Tuple[str, ...] = ()
    max_xff_parts: int = 32

    emit_audit_log: bool = False
    audit_log_fn: Optional[Callable[[Dict[str, Any]], None]] = None
    link_to_multivar: bool = True

    block_after_consecutive_denies: int = 0  # 0 = disabled
    temp_block_ttl_seconds: float = 60.0
    deny_quiet_reset_seconds: float = 60.0

    # Hard cap overlay (was dead; now implemented)
    max_tokens_per_ip_per_window: Optional[float] = None
    window_seconds: float = 60.0

    expose_headers: bool = False
    hide_details_in_high_security: bool = True

    # Audit privacy posture
    audit_redact_in_high_security: bool = True
    audit_hmac_key: Optional[bytes] = None
    audit_hmac_sig_bytes: int = 8  # 16 hex chars


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    BaseHTTPMiddleware variant. See RateLimitASGIMiddleware for ASGI variant.
    """

    def __init__(
        self,
        app,
        rate_per_sec: float = 10.0,
        burst: float = 20.0,
        *,
        config: Optional[RateLimitConfig] = None,
    ):
        super().__init__(app)
        if config is not None:
            self._cfg = config
            if rate_per_sec is not None:
                self._cfg.rate_per_sec = float(rate_per_sec)
            if burst is not None:
                self._cfg.burst = float(burst)
        else:
            self._cfg = RateLimitConfig(rate_per_sec=rate_per_sec, burst=burst)

        self._trusted_proxy_nets = _parse_trusted_proxies(self._cfg.trusted_proxies)

        # sanitize base values
        self._rate = max(0.0, _finite_float(self._cfg.rate_per_sec) or 0.0)
        self._burst = max(1.0, _finite_float(self._cfg.burst) or 1.0)

        self._lock = threading.Lock()

        # zone -> LRU(ip_key -> bucket_state {t, tokens})
        self._zone_buckets: Dict[str, "OrderedDict[str, Dict[str, float]]"] = {}

        # ip -> (consecutive_denies, last_ts_mono)
        self._deny_counters: Dict[str, Tuple[int, float]] = {}

        # ip -> blocked_until_mono
        self._temp_blocks: Dict[str, float] = {}

        # Hard-cap window counter: ip -> (window_start_mono, used_tokens)
        self._window_counters: Dict[str, Tuple[float, float]] = {}

        self._skip = [re.compile(p) for p in self._cfg.skip_paths]

        # GC tracking
        self._last_gc = 0.0

    # ------- helpers -------

    def _path_match(self, path: str) -> bool:
        return any(p.search(path) for p in self._skip)

    def _zone_for_ip(self, ip: str) -> str:
        zone = "default"
        if self._cfg.ip_trust_classifier:
            try:
                z = self._cfg.ip_trust_classifier(ip)
                if isinstance(z, str):
                    zz = _strip_unsafe_text(z, max_len=32).strip().lower()
                    if zz and _ZONE_RE.fullmatch(zz):
                        zone = zz
            except Exception:
                zone = "default"

        # zone cap
        if zone != "default" and zone not in self._zone_buckets:
            if len(self._zone_buckets) >= _clamp_int(int(self._cfg.max_zones or 64), 1, 1024):
                zone = "default"
        return zone

    def _ip_from_request(self, request: Request) -> Tuple[str, Optional[str]]:
        remote = request.client.host if request.client else "unknown"
        remote_ip = _parse_ip(remote) or "unknown"

        if not self._cfg.respect_xff:
            return remote_ip, None

        xff = request.headers.get("x-forwarded-for")
        ip, reason = _extract_client_ip_from_xff(
            remote_ip=remote_ip,
            xff=xff,
            trusted_proxies=self._trusted_proxy_nets,
            max_xff_parts=_clamp_int(int(self._cfg.max_xff_parts or 32), 1, 128),
        )
        return ip, reason

    def _get_zone_settings(self, zone: str) -> Tuple[float, float, int, float]:
        cfgz = self._cfg.trust_zones.get(zone) or {}

        rate = _finite_float(cfgz.get("rate_per_sec", self._cfg.rate_per_sec))
        burst = _finite_float(cfgz.get("burst", self._cfg.burst))
        max_entries = cfgz.get("max_entries", self._cfg.max_entries)
        idle_ttl = _finite_float(cfgz.get("idle_ttl_seconds", self._cfg.idle_ttl_seconds))

        rate = max(0.0, rate if rate is not None else self._rate)
        burst = max(1.0, burst if burst is not None else self._burst)

        try:
            me = int(max_entries)
        except Exception:
            me = int(self._cfg.max_entries)
        me = _clamp_int(me, 256, 5_000_000)

        idle_ttl = _clamp_float(float(idle_ttl if idle_ttl is not None else self._cfg.idle_ttl_seconds), 1.0, 86_400.0)
        return rate, burst, me, idle_ttl

    def _overflow_key(self, ip: str) -> str:
        n = _clamp_int(int(self._cfg.overflow_shards or 64), 1, 4096)
        d = hashlib.blake2s(b"TCD|overflow|v1|" + ip.encode("utf-8", errors="ignore")).digest()
        shard = int.from_bytes(d[:2], "big") % n
        return f"<overflow:{shard}>"

    def _gc_locked(self, now: float) -> None:
        interval = _finite_float(self._cfg.gc_interval_seconds) or 5.0
        if (now - self._last_gc) < interval:
            return
        self._last_gc = now

        # temp blocks cleanup
        for ip, until in list(self._temp_blocks.items()):
            if until <= now:
                self._temp_blocks.pop(ip, None)

        # deny counters cleanup
        deny_ttl = _clamp_float(float(self._cfg.deny_quiet_reset_seconds or 60.0), 1.0, 86_400.0)
        cutoff = now - deny_ttl
        for ip, (_c, ts) in list(self._deny_counters.items()):
            if ts < cutoff:
                self._deny_counters.pop(ip, None)

        # window counters cleanup
        win = _clamp_float(float(self._cfg.window_seconds or 60.0), 1.0, 86_400.0)
        cutoff2 = now - (win * 2.0)
        for ip, (ws, _used) in list(self._window_counters.items()):
            if ws < cutoff2:
                self._window_counters.pop(ip, None)

    def _take(self, zone: str, ip: str, tokens: Any = 1.0) -> bool:
        """
        Token bucket with:
          - optional hard window cap
          - temp block escalation
          - LRU + TTL eviction
        """
        # Disabled semantics (closes "rate=0 => burst then perma-deny" footgun)
        if not bool(self._cfg.enabled):
            return True
        if self._rate <= 0.0 and (self._finite_zone_rate(zone) <= 0.0):
            # treat as disabled regardless of burst
            return True

        need = _finite_float(tokens)
        if need is None or need <= 0:
            need = 1.0

        now = time.monotonic()

        with self._lock:
            self._gc_locked(now)

            # Temp block per real IP (not overflow shard)
            blocked_until = self._temp_blocks.get(ip)
            if blocked_until is not None:
                if now < blocked_until:
                    return False
                self._temp_blocks.pop(ip, None)

            rate, burst, max_entries, idle_ttl = self._get_zone_settings(zone)

            if rate <= 0.0:
                # zone disabled
                return True

            # Hard cap overlay (per window)
            cap = _finite_float(self._cfg.max_tokens_per_ip_per_window)
            if cap is not None and cap > 0:
                win = _clamp_float(float(self._cfg.window_seconds or 60.0), 1.0, 86_400.0)
                ws, used = self._window_counters.get(ip, (now, 0.0))
                if (now - ws) >= win:
                    ws, used = now, 0.0
                if (used + need) > cap:
                    # count denial
                    self._note_deny_locked(ip, now)
                    return False
                self._window_counters[ip] = (ws, used + need)

            # LRU bucket map for zone
            zmap = self._zone_buckets.setdefault(zone, OrderedDict())

            # Enforce hard cap with sharded overflow buckets (fairness)
            bucket_key = ip
            if bucket_key not in zmap and len(zmap) >= max_entries:
                bucket_key = self._overflow_key(ip)

            # TTL eviction from oldest
            cutoff = now - idle_ttl
            while zmap:
                k0, v0 = next(iter(zmap.items()))
                if v0.get("t", now) >= cutoff:
                    break
                zmap.popitem(last=False)

            # LRU hard cap eviction (O(1))
            while len(zmap) > max_entries:
                zmap.popitem(last=False)

            b = zmap.get(bucket_key)
            if b is None:
                b = {"t": now, "tokens": float(burst)}
            else:
                elapsed = max(0.0, now - float(b.get("t", now)))
                tok = float(b.get("tokens", 0.0))
                if not math.isfinite(tok):
                    tok = 0.0
                tok = tok + elapsed * float(rate)
                tok = max(0.0, min(float(burst), tok))
                b["t"] = now
                b["tokens"] = tok

            if b["tokens"] >= need:
                b["tokens"] = max(0.0, b["tokens"] - need)
                zmap[bucket_key] = b
                zmap.move_to_end(bucket_key, last=True)
                self._deny_counters.pop(ip, None)
                return True

            # update bucket and deny
            zmap[bucket_key] = b
            zmap.move_to_end(bucket_key, last=True)
            self._note_deny_locked(ip, now)
            return False

    def _finite_zone_rate(self, zone: str) -> float:
        try:
            cfgz = self._cfg.trust_zones.get(zone) or {}
            rate = _finite_float(cfgz.get("rate_per_sec", self._cfg.rate_per_sec))
            if rate is None:
                return self._rate
            return max(0.0, rate)
        except Exception:
            return self._rate

    def _note_deny_locked(self, ip: str, now: float) -> None:
        c, last_ts = self._deny_counters.get(ip, (0, now))
        quiet = _clamp_float(float(self._cfg.deny_quiet_reset_seconds or 60.0), 1.0, 86_400.0)
        if (now - last_ts) > quiet:
            c = 0
        c += 1
        self._deny_counters[ip] = (c, now)

        if self._cfg.block_after_consecutive_denies > 0 and c >= int(self._cfg.block_after_consecutive_denies):
            ttl = _clamp_float(float(self._cfg.temp_block_ttl_seconds or 60.0), 1.0, 86_400.0)
            self._temp_blocks[ip] = now + ttl

    def _audit_record(self, request: Request, *, ip: str, zone: str, path: str, xff_reason: Optional[str]) -> Dict[str, Any]:
        rid = getattr(request.state, "request_id", None)
        sid = getattr(request.state, "session_id", None)
        trust_profile = getattr(request.state, "tcd_trust_profile", None)

        rec: Dict[str, Any] = {
            "event": "edge_rate_limited",
            "zone": zone,
            "route": _default_path_normalizer(path)[:256],
            "method": _bounded_label(getattr(request, "method", "UNKNOWN"), max_len=16),
            "ts": time.time(),
        }
        if xff_reason:
            rec["xff_ignored_reason"] = xff_reason

        if self._cfg.audit_redact_in_high_security and trust_profile == "HIGH_SECURITY":
            # Strict: no raw ip/rid/sid. If key exists, emit keyed hashes; else omit.
            key = self._cfg.audit_hmac_key
            if isinstance(key, (bytes, bytearray)) and key:
                k = bytes(key)
                sb = _clamp_int(int(self._cfg.audit_hmac_sig_bytes or 8), 4, 32)
                rec["ip_h"] = _blake2s_hex(hmac.new(k, ("ip|" + ip).encode("utf-8", errors="ignore"), hashlib.blake2s).digest(), digest_bytes=sb)
                if isinstance(rid, str) and rid:
                    rec["rid_h"] = _blake2s_hex(hmac.new(k, ("rid|" + rid).encode("utf-8", errors="ignore"), hashlib.blake2s).digest(), digest_bytes=sb)
                if isinstance(sid, str) and sid:
                    rec["sid_h"] = _blake2s_hex(hmac.new(k, ("sid|" + sid).encode("utf-8", errors="ignore"), hashlib.blake2s).digest(), digest_bytes=sb)
            return rec

        # Non-high-security: include raw (still bounded/clean)
        rec["ip"] = ip
        if isinstance(rid, str):
            rec["request_id"] = _safe_taglike_id(rid, max_len=255, allow_truncate=False)
        if isinstance(sid, str):
            rec["session_id"] = _safe_taglike_id(sid, max_len=255, allow_truncate=False)
        return rec

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if self._path_match(path):
            return await call_next(request)

        ip, xff_reason = self._ip_from_request(request)
        zone = self._zone_for_ip(ip)
        ok = self._take(zone, ip, 1.0)

        if ok:
            # expose diagnostics for ops if desired
            if xff_reason:
                try:
                    request.state.xff_ignored_reason = xff_reason
                except Exception:
                    pass
            return await call_next(request)

        # Mark state for downstream detectors if requested
        if self._cfg.link_to_multivar:
            try:
                request.state.edge_rate_limited = True
                request.state.edge_rate_zone = zone
                if xff_reason:
                    request.state.xff_ignored_reason = xff_reason
            except Exception:
                pass

        # Audit log (best-effort, policy-gated)
        if self._cfg.emit_audit_log and self._cfg.audit_log_fn is not None:
            try:
                self._cfg.audit_log_fn(self._audit_record(request, ip=ip, zone=zone, path=path, xff_reason=xff_reason))
            except Exception:
                pass

        # Error response (no sensitive details)
        trust_profile = getattr(request.state, "tcd_trust_profile", None)
        rid = getattr(request.state, "request_id", None)

        headers: Dict[str, str] = {}
        rid_hdr = _safe_taglike_id(rid, max_len=255) if isinstance(rid, str) else None
        if rid_hdr:
            headers["X-Request-Id"] = rid_hdr

        if self._cfg.expose_headers:
            if not (self._cfg.hide_details_in_high_security and trust_profile == "HIGH_SECURITY"):
                headers["X-RateLimit-Policy"] = "edge-ip"

        if self._cfg.json_error:
            body = {"error": _bounded_label(self._cfg.error_reason, max_len=64)}
            try:
                payload = json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            except Exception:
                payload = '{"error":"rate_limited"}'
            return Response(
                content=payload,
                status_code=429,
                media_type="application/json",
                headers=headers,
            )

        return Response("rate limited", status_code=429, headers=headers)


# --------------------------------
# RateLimit ASGI middleware
# --------------------------------

class RateLimitASGIMiddleware:
    def __init__(self, app, *, config: Optional[RateLimitConfig] = None, rate_per_sec: float = 10.0, burst: float = 20.0):
        self.app = app
        self._impl = RateLimitMiddleware(app=None, config=config, rate_per_sec=rate_per_sec, burst=burst)

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path") or "/"
        if self._impl._path_match(path):  # pylint: disable=protected-access
            return await self.app(scope, receive, send)

        headers = _headers_from_scope(scope)
        remote_host = "unknown"
        try:
            remote_host = (scope.get("client") or ("unknown", 0))[0] or "unknown"
        except Exception:
            remote_host = "unknown"

        # XFF extraction (same logic as Base version)
        ip = _parse_ip(remote_host) or "unknown"
        xff_reason = None
        if self._impl._cfg.respect_xff:  # pylint: disable=protected-access
            ip, xff_reason = _extract_client_ip_from_xff(
                remote_ip=ip,
                xff=headers.get("x-forwarded-for"),
                trusted_proxies=self._impl._trusted_proxy_nets,  # pylint: disable=protected-access
                max_xff_parts=_clamp_int(int(self._impl._cfg.max_xff_parts or 32), 1, 128),  # pylint: disable=protected-access
            )

        zone = self._impl._zone_for_ip(ip)  # pylint: disable=protected-access
        ok = self._impl._take(zone, ip, 1.0)  # pylint: disable=protected-access

        if ok:
            # diagnostics into state
            if xff_reason:
                try:
                    scope.setdefault("state", {})["xff_ignored_reason"] = xff_reason
                except Exception:
                    pass
            return await self.app(scope, receive, send)

        # mark state
        st = scope.setdefault("state", {})
        try:
            if self._impl._cfg.link_to_multivar:  # pylint: disable=protected-access
                st["edge_rate_limited"] = True
                st["edge_rate_zone"] = zone
                if xff_reason:
                    st["xff_ignored_reason"] = xff_reason
        except Exception:
            pass

        # audit
        if self._impl._cfg.emit_audit_log and self._impl._cfg.audit_log_fn is not None:  # pylint: disable=protected-access
            try:
                # best-effort: create a minimal fake Request-like wrapper is overkill; emit minimal
                audit = {
                    "event": "edge_rate_limited",
                    "zone": zone,
                    "route": _default_path_normalizer(path)[:256],
                    "ts": time.time(),
                }
                if xff_reason:
                    audit["xff_ignored_reason"] = xff_reason
                self._impl._cfg.audit_log_fn(audit)  # pylint: disable=protected-access
            except Exception:
                pass

        # response
        trust_profile = st.get("tcd_trust_profile")
        rid = st.get("request_id")
        headers_out: List[Tuple[bytes, bytes]] = []

        rid_hdr = _safe_taglike_id(rid, max_len=255) if isinstance(rid, str) else None
        if rid_hdr:
            headers_out.append((b"x-request-id", rid_hdr.encode("latin1", errors="ignore")))

        if self._impl._cfg.expose_headers:  # pylint: disable=protected-access
            if not (self._impl._cfg.hide_details_in_high_security and trust_profile == "HIGH_SECURITY"):  # pylint: disable=protected-access
                headers_out.append((b"x-ratelimit-policy", b"edge-ip"))

        if self._impl._cfg.json_error:  # pylint: disable=protected-access
            body = {"error": _bounded_label(self._impl._cfg.error_reason, max_len=64)}  # pylint: disable=protected-access
            try:
                payload = json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
            except Exception:
                payload = b'{"error":"rate_limited"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 429,
                    "headers": [(b"content-type", b"application/json")] + headers_out,
                }
            )
            await send({"type": "http.response.body", "body": payload})
            return

        await send({"type": "http.response.start", "status": 429, "headers": headers_out})
        await send({"type": "http.response.body", "body": b"rate limited"})


# --------------------------------
# Metrics middleware
# --------------------------------

_STDOUT_LOCK = threading.Lock()


def _default_line_writer(line: str) -> None:
    with _STDOUT_LOCK:
        try:
            sys.stdout.write(line + "\n")
        except Exception:
            pass


def _safe_hash_output(s: str, *, max_len: int = 128) -> Optional[str]:
    """
    Ensure hash outputs cannot be abused as a covert channel.
    """
    if not s or not isinstance(s, str):
        return None
    ss = _strip_unsafe_text(s, max_len=max_len).strip()
    if not ss:
        return None
    if len(ss) > max_len:
        return None
    # allow hex or base64url-ish
    if re.fullmatch(r"[0-9a-fA-F]{8,128}", ss) or re.fullmatch(r"[A-Za-z0-9_-]{8,128}", ss):
        return ss
    return None


@dataclass
class MetricsConfig:
    """
    Metrics + JSONL log.

    Checklist closure:
      - HIGH_SECURITY forbids optional fields (including ids/chain/receipt/error tags/mv outputs)
      - keyed hashing required in regulated profiles if hashes are enabled
      - shrink respects required fields; adds shrunk=true when possible
      - request_chain is hop-validated
      - forbidden_query_params used if log_query_keys is enabled
    """

    counter: Counter
    histogram: Histogram

    path_normalizer: Callable[[str], str] = _default_path_normalizer

    enable_json_log: bool = True
    log_fn: Optional[Callable[[str], None]] = None

    route_aliases: Dict[str, str] = field(default_factory=lambda: {"/diagnose": "diagnose"})
    error_level: str = "error"
    ok_level: str = "info"

    # Field policy: name -> "required" | "optional" | "forbid".
    field_policy: Dict[str, str] = field(
        default_factory=lambda: {
            # required core
            "path": "required",
            "method": "required",
            # privacy-sensitive
            "client_ip": "forbid",
            "tenant": "optional",
            # ids and advanced fields default to optional => forbidden in HIGH_SECURITY
            "request_id": "optional",
            "session_id": "optional",
            "request_chain": "optional",
            "receipt_id": "optional",
            "exc_type": "optional",
            "error_tag": "optional",
            "multivar_verdict": "optional",
            "multivar_risk_score": "optional",
            "client_ip_hash": "optional",
            "tenant_hash": "optional",
            "query_keys": "optional",
            "shrunk": "optional",
        }
    )

    compliance_profile: str = "GENERIC"  # "GENERIC" | "FINREG" | "HIGH_SECURITY"

    include_request_ids: bool = True
    include_chain_ids: bool = False
    link_to_receipt_id: bool = True

    # Query logging (keys only, never values). Off by default.
    log_query_keys: bool = False
    forbidden_query_params: Tuple[str, ...] = ()

    # Hashing controls
    include_client_ip_hash: bool = False
    include_tenant_hash: bool = False

    # Keyed hashing is required for FINREG/HIGH_SECURITY when hashes are enabled
    require_keyed_hashes_in_regulated_profiles: bool = True
    hash_key: Optional[bytes] = None
    hash_key_id: Optional[str] = None

    ip_hash_salt_label: str = "metrics/ip"
    tenant_hash_salt_label: str = "metrics/tenant"

    # Optional custom hash function: must return bytes or str (validated)
    hash_fn: Optional[Callable[[str, str], Any]] = None

    # Logging shaping
    log_normalized_path: bool = True
    prefer_route_name: bool = True
    max_route_label_chars: int = 128
    max_log_line_bytes: int = 8192

    # Chain bounds in log
    max_chain_hops: int = 16
    max_chain_chars: int = 512


class MetricsMiddleware(BaseHTTPMiddleware):
    """
    BaseHTTPMiddleware variant. See MetricsASGIMiddleware for ASGI variant.
    """

    def __init__(
        self,
        app,
        counter: Counter,
        histogram: Histogram,
        *,
        config: Optional[MetricsConfig] = None,
    ):
        if config is None:
            cfg = MetricsConfig(counter=counter, histogram=histogram)
        else:
            config.counter = counter
            config.histogram = histogram
            cfg = config

        super().__init__(app)
        self._cfg = cfg
        self.counter = cfg.counter
        self.hist = cfg.histogram
        self._log_fn = cfg.log_fn or _default_line_writer
        self._logger = logging.getLogger("tcd.metrics")

        # precompute forbidden query keys
        self._forbidden_q = {str(k).lower() for k in (cfg.forbidden_query_params or ()) if k}

    # ------- helpers -------

    def _field_policy(self, name: str) -> str:
        pol = self._cfg.field_policy.get(name, "optional")
        if self._cfg.compliance_profile == "HIGH_SECURITY" and pol != "required":
            return "forbid"
        return pol

    def _allow_field(self, name: str) -> bool:
        return self._field_policy(name) != "forbid"

    def _route_label(self, request: Request, path: str) -> str:
        # Prefer actual route name when available (low cardinality)
        if self._cfg.prefer_route_name:
            try:
                rt = request.scope.get("route")
                name = getattr(rt, "name", None)
                if isinstance(name, str):
                    nm = _bounded_label(name, max_len=self._cfg.max_route_label_chars)
                    if nm and nm != "unknown":
                        return nm
            except Exception:
                pass

        for suffix, alias in self._cfg.route_aliases.items():
            try:
                if path.endswith(suffix):
                    return _bounded_label(alias, max_len=self._cfg.max_route_label_chars)
            except Exception:
                continue

        try:
            norm = self._cfg.path_normalizer(path)
        except Exception:
            norm = path
        return _bounded_label(norm, max_len=self._cfg.max_route_label_chars)

    def _safe_rec_str(self, s: Any, *, max_len: int, required: bool = False) -> Optional[str]:
        if not isinstance(s, str):
            return None
        out = _strip_unsafe_text(s, max_len=max_len).strip()
        if not out:
            return "unknown" if required else None
        if _looks_like_secret(out):
            return "unknown" if required else "<redacted>"
        if len(out) > max_len:
            out = out[:max_len]
        return out

    def _keyed_hash(self, value: str, label: str) -> Optional[str]:
        """
        Returns a safe hash string or None (if policy requires key but key missing).
        """
        # Try custom hash_fn first
        if self._cfg.hash_fn is not None:
            try:
                h = self._cfg.hash_fn(value, label)
                if isinstance(h, (bytes, bytearray, memoryview)):
                    return _safe_hash_output(bytes(h).hex())
                if isinstance(h, str):
                    return _safe_hash_output(h)
                return None
            except Exception:
                pass

        key = self._cfg.hash_key
        regulated = self._cfg.compliance_profile in ("FINREG", "HIGH_SECURITY")

        if (self._cfg.require_keyed_hashes_in_regulated_profiles and regulated) and not (isinstance(key, (bytes, bytearray)) and key):
            # fail-closed in regulated profiles
            return None

        if isinstance(key, (bytes, bytearray)) and key:
            k = bytes(key)
            msg = b"TCD|metrics|h|v1|" + label.encode("utf-8", errors="ignore") + b"|" + value.encode("utf-8", errors="ignore")
            mac = hmac.new(k, msg, hashlib.blake2s).digest()
            return mac[:16].hex()

        # Non-regulated fallback: unkeyed hash (still bounded)
        msg2 = b"TCD|metrics|h|v1|" + label.encode("utf-8", errors="ignore") + b"|" + value.encode("utf-8", errors="ignore")
        return hashlib.blake2s(msg2).hexdigest()[:32]

    def _sanitize_chain_for_log(self, chain: str) -> Optional[str]:
        if not isinstance(chain, str):
            return None
        max_chars = _clamp_int(int(self._cfg.max_chain_chars or 512), 64, 4096)
        max_hops = _clamp_int(int(self._cfg.max_chain_hops or 16), 1, 64)

        s = _strip_unsafe_text(chain, max_len=max_chars).strip()
        if not s or _looks_like_secret(s):
            return None

        parts = s.rsplit(",", max_hops * 2)
        hops: List[str] = []
        for p in parts:
            if len(hops) >= max_hops:
                break
            hid = _safe_taglike_id(p.strip(), max_len=128, pattern=_CHAIN_ID_RE, reject_secrets=True, allow_truncate=False)
            if hid:
                hops.append(hid)
        if not hops:
            return None
        out = ",".join(hops[-max_hops:])
        if len(out) > max_chars:
            out = out[-max_chars:]
        return out

    def _emit_jsonl(self, rec: Dict[str, Any]) -> None:
        max_bytes = _clamp_int(int(self._cfg.max_log_line_bytes or 8192), 1024, 1_000_000)

        def _dump(obj: Dict[str, Any]) -> Optional[str]:
            try:
                s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
                if len(s.encode("utf-8", errors="strict")) <= max_bytes:
                    return s
                return None
            except Exception:
                return None

        s0 = _dump(rec)
        if s0 is not None:
            self._log_fn(s0)
            return

        # Shrink: only drop fields that are not required.
        required_keys = {"level", "ts_wall", "route", "status", "latency_ms"}
        # Honor policy-required fields if present
        for k in ("method", "path"):
            if self._field_policy(k) == "required":
                required_keys.add(k)

        drop_order = [
            "query_keys",
            "client_ip",
            "client_ip_hash",
            "tenant",
            "tenant_hash",
            "request_chain",
            "receipt_id",
            "session_id",
            "request_id",
            # path is only droppable if not required
            "path",
            "exc_type",
            "error_tag",
            "multivar_verdict",
            "multivar_risk_score",
        ]

        shrunk = dict(rec)
        # Try add shrunk marker (low cardinality)
        if "shrunk" not in shrunk and self._allow_field("shrunk"):
            shrunk["shrunk"] = True

        for k in drop_order:
            if k in required_keys:
                continue
            if k in shrunk:
                # never drop method/path if required
                if k in ("method", "path") and self._field_policy(k) == "required":
                    continue
                shrunk.pop(k, None)
                s1 = _dump(shrunk)
                if s1 is not None:
                    self._log_fn(s1)
                    return

        # Last resort minimal
        minimal = {
            "level": rec.get("level", "info"),
            "ts_wall": rec.get("ts_wall", time.time()),
            "route": rec.get("route", "unknown"),
            "status": rec.get("status", "err"),
            "latency_ms": rec.get("latency_ms", 0.0),
            "shrunk": True,
        }
        try:
            s2 = json.dumps(minimal, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        except Exception:
            s2 = '{"status":"err","shrunk":true}'
        self._log_fn(s2)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        route_label = self._route_label(request, path)
        t0 = time.perf_counter()
        status_label = "ok"
        status_code: Optional[int] = None
        exc_type: Optional[str] = None

        try:
            response = await call_next(request)
            try:
                status_code = int(getattr(response, "status_code", None))
            except Exception:
                status_code = None
            status_label = "ok" if (status_code is not None and 200 <= status_code < 400) else "err"
            return response
        except Exception as e:
            status_label = "err"
            exc_type = getattr(type(e), "__name__", "Exception")
            raise
        finally:
            dt = time.perf_counter() - t0
            if not math.isfinite(dt) or dt < 0:
                dt = 0.0

            # Metrics (best-effort)
            try:
                self.counter.labels(route=route_label, status=status_label).inc()
                self.hist.labels(route=route_label).observe(dt)
            except Exception:
                pass

            if not self._cfg.enable_json_log:
                return

            try:
                rec: Dict[str, Any] = {
                    "level": self._cfg.ok_level if status_label == "ok" else self._cfg.error_level,
                    "ts_wall": time.time(),
                    "duration_s": round(dt, 6),
                    "route": route_label,
                    "status": status_label,
                    "status_code": status_code if isinstance(status_code, int) else None,
                    "latency_ms": round(dt * 1000.0, 3),
                }

                # Method and path (policy gated)
                if self._allow_field("method"):
                    m = self._safe_rec_str(request.method, max_len=16, required=(self._field_policy("method") == "required"))
                    if m:
                        rec["method"] = m

                if self._allow_field("path"):
                    if self._cfg.log_normalized_path:
                        rec["path"] = route_label
                    else:
                        p = self._safe_rec_str(path, max_len=256, required=(self._field_policy("path") == "required"))
                        if p:
                            rec["path"] = p

                # IDs (policy gated)
                if self._cfg.include_request_ids:
                    if self._allow_field("request_id"):
                        rid = getattr(request.state, "request_id", None)
                        if isinstance(rid, str):
                            rid_s = _safe_taglike_id(rid, max_len=255)
                            if rid_s:
                                rec["request_id"] = rid_s
                    if self._allow_field("session_id"):
                        sid = getattr(request.state, "session_id", None)
                        if isinstance(sid, str):
                            sid_s = _safe_taglike_id(sid, max_len=255)
                            if sid_s:
                                rec["session_id"] = sid_s

                if self._cfg.include_chain_ids and self._allow_field("request_chain"):
                    chain = getattr(request.state, "request_chain", None)
                    if isinstance(chain, str):
                        ch = self._sanitize_chain_for_log(chain)
                        if ch:
                            rec["request_chain"] = ch

                if self._cfg.link_to_receipt_id and self._allow_field("receipt_id"):
                    receipt_id = getattr(request.state, "receipt_id", None)
                    if isinstance(receipt_id, str):
                        rr = _safe_taglike_id(receipt_id, max_len=255)
                        if rr:
                            rec["receipt_id"] = rr

                # Query keys (keys only; never values)
                if self._cfg.log_query_keys and self._allow_field("query_keys"):
                    try:
                        keys: List[str] = []
                        for k in request.query_params.keys():
                            kl = str(k).lower()
                            if kl in self._forbidden_q:
                                continue
                            # only keep taglike keys to avoid weird payload
                            kk = _safe_taglike_id(str(k), max_len=64, pattern=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"), reject_secrets=True)
                            if kk:
                                keys.append(kk)
                            if len(keys) >= 16:
                                break
                        if keys:
                            rec["query_keys"] = keys
                    except Exception:
                        pass

                # Client IP hashing (policy gated, keyed if regulated)
                client_ip_policy = self._field_policy("client_ip")
                if client_ip_policy != "forbid":
                    client_ip = request.client.host if request.client else None
                    if isinstance(client_ip, str) and client_ip:
                        ip_norm = _parse_ip(client_ip) or None
                        if ip_norm and self._cfg.include_client_ip_hash and self._allow_field("client_ip_hash"):
                            hv = self._keyed_hash(ip_norm, self._cfg.ip_hash_salt_label)
                            if hv:
                                rec["client_ip_hash"] = hv
                        elif client_ip_policy == "required":
                            # Only if explicitly required (rare)
                            rec["client_ip"] = ip_norm or "unknown"

                # Tenant hashing (policy gated)
                ctx = getattr(request.state, "tcd_ctx", None)
                tenant = ctx.get("tenant") if isinstance(ctx, dict) else None
                tenant_policy = self._field_policy("tenant")
                if tenant is not None and tenant_policy != "forbid":
                    tenant_s: Optional[str] = None
                    if isinstance(tenant, str):
                        tenant_s = self._safe_rec_str(tenant, max_len=128, required=(tenant_policy == "required"))
                    elif isinstance(tenant, int) and not isinstance(tenant, bool) and tenant.bit_length() <= 256:
                        tenant_s = str(int(tenant))
                    if tenant_s:
                        if self._cfg.include_tenant_hash and self._allow_field("tenant_hash"):
                            hv = self._keyed_hash(tenant_s, self._cfg.tenant_hash_salt_label)
                            if hv:
                                rec["tenant_hash"] = hv
                        elif tenant_policy == "required":
                            rec["tenant"] = tenant_s

                # Multivariate outputs (policy gated)
                if self._allow_field("multivar_verdict"):
                    mv_verdict = getattr(request.state, "multivar_verdict", None)
                    if isinstance(mv_verdict, bool):
                        rec["multivar_verdict"] = mv_verdict
                    elif isinstance(mv_verdict, int) and not isinstance(mv_verdict, bool):
                        # Avoid covert channel: bound bit length
                        if mv_verdict.bit_length() <= 32:
                            rec["multivar_verdict"] = int(mv_verdict)
                    elif isinstance(mv_verdict, str):
                        vv = self._safe_rec_str(mv_verdict, max_len=32, required=False)
                        if vv:
                            rec["multivar_verdict"] = vv

                if self._allow_field("multivar_risk_score"):
                    mv_risk = getattr(request.state, "multivar_risk_score", None)
                    fv = _finite_float(mv_risk)
                    if fv is not None:
                        rec["multivar_risk_score"] = _clamp_float(fv, 0.0, 1.0)

                # Error tags (policy gated)
                if status_label == "err":
                    if exc_type and self._allow_field("exc_type"):
                        et = self._safe_rec_str(exc_type, max_len=64, required=False)
                        if et:
                            rec["exc_type"] = et
                    if self._allow_field("error_tag"):
                        err_tag = getattr(request.state, "error_tag", None)
                        if isinstance(err_tag, str):
                            etag = self._safe_rec_str(err_tag, max_len=64, required=False)
                            if etag:
                                rec["error_tag"] = etag

                self._emit_jsonl(rec)
            except Exception:
                try:
                    self._logger.debug("metrics_log_failed")
                except Exception:
                    pass


# --------------------------------
# Metrics ASGI middleware
# --------------------------------

class MetricsASGIMiddleware:
    def __init__(self, app, counter: Counter, histogram: Histogram, *, config: Optional[MetricsConfig] = None):
        self.app = app
        self._impl = MetricsMiddleware(app=None, counter=counter, histogram=histogram, config=config)

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path") or "/"
        # Build a lightweight Request for route label + query parsing (does not consume body)
        req = Request(scope, receive=receive)

        route_label = self._impl._route_label(req, path)  # pylint: disable=protected-access
        t0 = time.perf_counter()
        status_label = "ok"
        status_code: Optional[int] = None
        exc_type: Optional[str] = None

        async def send_wrapper(message):
            nonlocal status_code
            if message.get("type") == "http.response.start":
                try:
                    status_code = int(message.get("status"))
                except Exception:
                    status_code = None
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
            status_label = "ok" if (status_code is not None and 200 <= status_code < 400) else "err"
        except Exception as e:
            status_label = "err"
            exc_type = getattr(type(e), "__name__", "Exception")
            raise
        finally:
            dt = time.perf_counter() - t0
            if not math.isfinite(dt) or dt < 0:
                dt = 0.0

            # metrics
            try:
                self._impl.counter.labels(route=route_label, status=status_label).inc()  # pylint: disable=protected-access
                self._impl.hist.labels(route=route_label).observe(dt)  # pylint: disable=protected-access
            except Exception:
                pass

            if not self._impl._cfg.enable_json_log:  # pylint: disable=protected-access
                return

            # Put status_code & exc_type into state so Base impl can reuse logic cleanly if needed.
            st = scope.setdefault("state", {})
            if status_code is not None:
                st["__metrics_status_code"] = status_code
            if exc_type:
                st["__metrics_exc_type"] = exc_type

            # Reuse the BaseHTTPMiddleware logging logic by calling its internal block:
            # We can't call dispatch(); instead we emulate the "finally" payload building minimally.
            try:
                rec: Dict[str, Any] = {
                    "level": self._impl._cfg.ok_level if status_label == "ok" else self._impl._cfg.error_level,  # pylint: disable=protected-access
                    "ts_wall": time.time(),
                    "duration_s": round(dt, 6),
                    "route": route_label,
                    "status": status_label,
                    "status_code": status_code if isinstance(status_code, int) else None,
                    "latency_ms": round(dt * 1000.0, 3),
                }

                # method/path gated
                if self._impl._allow_field("method"):  # pylint: disable=protected-access
                    m = self._impl._safe_rec_str(req.method, max_len=16, required=(self._impl._field_policy("method") == "required"))  # pylint: disable=protected-access
                    if m:
                        rec["method"] = m

                if self._impl._allow_field("path"):  # pylint: disable=protected-access
                    if self._impl._cfg.log_normalized_path:  # pylint: disable=protected-access
                        rec["path"] = route_label
                    else:
                        p = self._impl._safe_rec_str(path, max_len=256, required=(self._impl._field_policy("path") == "required"))  # pylint: disable=protected-access
                        if p:
                            rec["path"] = p

                # IDs from scope.state if present
                if self._impl._cfg.include_request_ids:  # pylint: disable=protected-access
                    if self._impl._allow_field("request_id"):  # pylint: disable=protected-access
                        rid = st.get("request_id")
                        if isinstance(rid, str):
                            rr = _safe_taglike_id(rid, max_len=255)
                            if rr:
                                rec["request_id"] = rr
                    if self._impl._allow_field("session_id"):  # pylint: disable=protected-access
                        sid = st.get("session_id")
                        if isinstance(sid, str):
                            ss = _safe_taglike_id(sid, max_len=255)
                            if ss:
                                rec["session_id"] = ss

                if self._impl._cfg.include_chain_ids and self._impl._allow_field("request_chain"):  # pylint: disable=protected-access
                    chain = st.get("request_chain")
                    if isinstance(chain, str):
                        ch = self._impl._sanitize_chain_for_log(chain)  # pylint: disable=protected-access
                        if ch:
                            rec["request_chain"] = ch

                if self._impl._cfg.link_to_receipt_id and self._impl._allow_field("receipt_id"):  # pylint: disable=protected-access
                    rcpt = st.get("receipt_id")
                    if isinstance(rcpt, str):
                        rr = _safe_taglike_id(rcpt, max_len=255)
                        if rr:
                            rec["receipt_id"] = rr

                # error fields
                if status_label == "err":
                    if exc_type and self._impl._allow_field("exc_type"):  # pylint: disable=protected-access
                        et = self._impl._safe_rec_str(exc_type, max_len=64, required=False)  # pylint: disable=protected-access
                        if et:
                            rec["exc_type"] = et

                self._impl._emit_jsonl(rec)  # pylint: disable=protected-access
            except Exception:
                pass