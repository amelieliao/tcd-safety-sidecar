from __future__ import annotations

import base64
import json
import os
import time
import hmac
import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from fastapi import HTTPException
from starlette.requests import Request

try:
    from prometheus_client import Counter, Histogram, Gauge

    _HAS_PROM = True
except Exception:  # pragma: no cover
    _HAS_PROM = False

# Optional JWT libs (soft dependency)
try:
    from jwcrypto import jwk, jwt  # type: ignore

    _HAS_JWCRYPTO = True
except Exception:  # pragma: no cover
    _HAS_JWCRYPTO = False

try:
    # stdlib fetch to avoid extra deps
    from urllib.request import urlopen, Request as UrlReq  # type: ignore
    from urllib.error import URLError  # type: ignore

    _HAS_URL = True
except Exception:  # pragma: no cover
    _HAS_URL = False

from urllib.parse import parse_qsl, quote

from .kv import canonical_kv_hash


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@dataclass
class AuthContext:
    """
    Runtime authentication context passed into request handlers and downstream
    safety / e-process layers.

    Fields:
      - mode          : "disabled" | "bearer" | "hmac" | "jwt" | "mtls"
      - principal     : identity string (svc, tenant, SPIFFE URI, etc.)
      - scopes        : logical scopes/roles; used by require_auth() and
                        downstream decision engines
      - key_id        : key identifier for HMAC/JWT/mTLS (kid/fingerprint)
      - raw           : redacted raw header fields of interest
      - policy_digest : stable digest of the authenticator policy in effect
      - issued_at     : timestamp (seconds since epoch) when this context was
                        created; useful for receipts and replay analysis
    """

    mode: str
    principal: str
    scopes: List[str]
    key_id: Optional[str]
    raw: Dict[str, str]
    policy_digest: Optional[str] = None
    issued_at: float = 0.0


@dataclass
class AuthResult:
    ok: bool
    ctx: Optional[AuthContext]
    reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

if _HAS_PROM:
    _AUTH_OK = Counter("tcd_auth_ok_total", "Auth OK", ["mode"])
    _AUTH_FAIL = Counter("tcd_auth_fail_total", "Auth Fail", ["mode", "reason"])
    _AUTH_LAT = Histogram(
        "tcd_auth_verify_latency_seconds",
        "Auth verify latency (s)",
        buckets=(0.001, 0.002, 0.005, 0.010, 0.020, 0.050),
        labelnames=("mode",),
    )
    _AUTH_REPLAY = Counter(
        "tcd_auth_replay_total",
        "Replay/nonce rejection",
        ["mode"],
    )
    _AUTH_JWKS_HIT = Counter("tcd_auth_jwks_hit_total", "JWKS cache hit", [])
    _AUTH_JWKS_MISS = Counter("tcd_auth_jwks_miss_total", "JWKS cache miss", [])
    _AUTH_JWT_CLAIM_FAIL = Counter(
        "tcd_auth_jwt_claim_fail_total",
        "JWT claim validation fail",
        ["field"],
    )
    # Encodes which mode is active for this process; value is always 1.0.
    _AUTH_CFG = Gauge("tcd_auth_mode_info", "Auth mode coded as gauge", ["mode"])
else:  # pragma: no cover
    class _Nop:
        def labels(self, *_, **__):
            return self

        def inc(self, *_ , **__):
            pass

        def observe(self, *_ , **__):
            pass

        def set(self, *_ , **__):
            pass

    _AUTH_OK = _Nop()
    _AUTH_FAIL = _Nop()
    _AUTH_LAT = _Nop()
    _AUTH_REPLAY = _Nop()
    _AUTH_JWKS_HIT = _Nop()
    _AUTH_JWKS_MISS = _Nop()
    _AUTH_JWT_CLAIM_FAIL = _Nop()
    _AUTH_CFG = _Nop()


def _inc_ok(mode: str) -> None:
    _AUTH_OK.labels(mode).inc()


def _inc_fail(mode: str, reason: str) -> None:
    _AUTH_FAIL.labels(mode, reason).inc()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b(s: str) -> bytes:
    return s.encode("utf-8")


def _now() -> float:
    return time.time()


def _hmac_blake3(key: bytes, ctx: str, data: bytes) -> str:
    """Domain-separated keyed blake3; returns hex string."""
    from blake3 import blake3  # type: ignore

    h = blake3(key=key)
    if ctx:
        ctx_b = ctx.encode("utf-8")
        h.update(len(ctx_b).to_bytes(4, "big") + ctx_b)
    h.update(data)
    return h.hexdigest()


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _parse_bool_env(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _canonical_query(query: str) -> str:
    """
    Canonicalize a query string as key=value pairs sorted by (key, value),
    with percent-encoding normalized.

    Example:
      "b=2&a=1&a=0" -> "a=0&a=1&b=2"
    """
    if not query:
        return ""
    pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=False)
    pairs.sort(key=lambda kv: (kv[0], kv[1]))
    out: List[str] = []
    for k, v in pairs:
        kq = quote(k, safe="-._~")
        vq = quote(v, safe="-._~")
        out.append(f"{kq}={vq}")
    return "&".join(out)


def _canonical_headers_subset(
    headers: Mapping[str, str],
    names: Tuple[str, ...],
) -> str:
    """
    Canonicalize a fixed subset of headers into a stable string:

      "name1=value1|name2=value2|..."

    Lookup is case-insensitive; missing headers are rendered as empty values.
    """
    if not names:
        return ""
    lower_map: Dict[str, str] = {k.lower(): v for k, v in headers.items()}
    parts: List[str] = []
    for name in sorted({n.lower() for n in names}):
        val = lower_map.get(name, "")
        parts.append(f"{name}={val}")
    return "|".join(parts)


def _canonical_hmac_payload_v1(
    ts: int,
    method: str,
    path: str,
    body: bytes,
) -> bytes:
    """
    v1 HMAC payload:

      "<ts>\\n<METHOD>\\n<PATH>\\n" + <raw-body>
    """
    return _b(f"{ts}\n{method.upper()}\n{path}\n") + (body or b"")


def _canonical_hmac_payload_v2(
    ts: int,
    method: str,
    path: str,
    query: str,
    headers: Mapping[str, str],
    body: bytes,
) -> bytes:
    """
    v2 HMAC payload (stronger binding):

      "<ts>\\n<METHOD>\\n<PATH>\\n<CANON_QUERY>\\n<CANON_HEADERS>\\n" + <raw-body>

    where:
      - CANON_QUERY   = sorted "key=value&..." with normalized percent-encoding;
      - CANON_HEADERS = "host=...|x-tcd-cluster=...|x-tcd-env=...".
    """
    canon_query = _canonical_query(query)
    canon_headers = _canonical_headers_subset(
        headers,
        names=("host", "x-tcd-cluster", "x-tcd-env"),
    )
    return _b(
        f"{ts}\n{method.upper()}\n{path}\n{canon_query}\n{canon_headers}\n"
    ) + (body or b"")


# ---------------------------------------------------------------------------
# JWKS cache (for JWT mode)
# ---------------------------------------------------------------------------


class _JWKSCache:
    """
    Minimal JWKS cache for JWT verification.

    Responsibilities:
      - fetch keys from a remote URL or inline JSON;
      - cache kid->JWK mapping with a bounded TTL;
      - expose a read-only view for the authenticator.

    Trust model:
      - JWKS URL is expected to be managed by a high-trust identity provider;
      - TLS verification and outbound network policy are handled by the
        surrounding platform.

    This cache does not perform any custom TLS validation; that is a deployment
    concern. It enforces HTTPS for the JWKS URL at construction time.
    """

    def __init__(
        self,
        url: Optional[str],
        inline_json: Optional[str],
        ttl_s: int = 600,
        timeout_s: float = 2.0,
    ):
        raw_url = (url or "").strip()
        if raw_url and not raw_url.lower().startswith("https://"):
            raise ValueError("JWKS URL must use https")
        self._url = raw_url
        self._inline = (inline_json or "").strip()
        self._ttl = max(30, int(ttl_s))
        self._timeout = float(timeout_s)
        self._lock = threading.RLock()
        self._kid_map: Dict[str, dict] = {}
        self._exp_at = 0.0

        if self._inline:
            try:
                obj = json.loads(self._inline)
                self._kid_map = {
                    k["kid"]: k for k in obj.get("keys", []) if "kid" in k
                }
                self._exp_at = _now() + 3600.0
            except Exception:
                # ignore malformed inline keys; will fall back to URL if present
                self._kid_map = {}

    @property
    def url_for_digest(self) -> str:
        """Return a stable representation of the JWKS URL for policy digests."""
        return self._url

    def _fetch(self) -> None:
        if not self._url or not _HAS_URL:
            return
        try:
            req = UrlReq(self._url, headers={"User-Agent": "tcd-auth/1.0"})
            with urlopen(req, timeout=self._timeout) as resp:  # type: ignore
                data = resp.read()
            obj = json.loads(data.decode("utf-8"))
            kid_map = {
                k["kid"]: k for k in obj.get("keys", []) if "kid" in k
            }
            if kid_map:
                self._kid_map = kid_map
                self._exp_at = _now() + float(self._ttl)
        except Exception:
            # network or parse failure: keep old cache
            pass

    def get_jwk_dict(self, kid: str) -> Optional[dict]:
        with self._lock:
            if _now() >= self._exp_at:
                _AUTH_JWKS_MISS.inc()
                self._fetch()
            else:
                _AUTH_JWKS_HIT.inc()
            return self._kid_map.get(kid)


# ---------------------------------------------------------------------------
# Authenticator
# ---------------------------------------------------------------------------


class Authenticator:
    """
    Pluggable authenticator with production-safe modes:

      - bearer: static token allowlist (comma-separated)
      - hmac  : signed requests with timestamp + raw body (+ optional nonce)
      - jwt   : OIDC-style JWT with JWKS (iss/aud/exp/nbf checks)
      - mtls  : Envoy XFCC-based identity (SPIFFE/DNS/CN or fingerprint allowlist)

    Disabled mode is available for local dev/tests but should be explicitly
    allowed by configuration (see build_authenticator_from_env).

    This class is a control-plane object:
      - it defines the identity policy for the process;
      - it exposes a stable policy_digest() for receipts, e-process, and
        attestation layers;
      - it never returns raw secrets (tokens, keys) via public APIs.
    """

    def __init__(
        self,
        mode: str = "disabled",
        *,
        # bearer
        bearer_tokens: Optional[List[str]] = None,
        # hmac
        hmac_keys: Optional[Dict[str, str]] = None,  # key_id -> hex or "hex1,hex2" (rotation)
        max_skew_s: int = 300,
        nonce_check_cb: Optional[Callable[[str, int], bool]] = None,  # return True if nonce is fresh
        # jwt
        jwt_iss: Optional[str] = None,
        jwt_aud: Optional[str] = None,
        jwks_url: Optional[str] = None,
        jwks_json: Optional[str] = None,
        jwks_cache_ttl_s: int = 600,
        jwks_timeout_s: float = 2.0,
        jwt_leeway_s: int = 60,
        jwt_principal_claim: str = "sub",
        jwt_scope_claims: Tuple[str, ...] = ("scp", "scope", "roles"),
        jwt_allowed_algs: Optional[Tuple[str, ...]] = None,
        # mtls (Envoy XFCC)
        mtls_fp_allow: Optional[List[str]] = None,  # sha256 hex fingerprints (lowercase)
        mtls_spiffe_prefixes: Optional[List[str]] = None,  # e.g., ["spiffe://cluster/ns/"]
    ):
        m = (mode or "disabled").lower()
        if m not in ("disabled", "bearer", "hmac", "jwt", "mtls"):
            raise ValueError("auth mode must be one of disabled|bearer|hmac|jwt|mtls")
        self.mode = m

        # bearer
        self.bearer = set(t.strip() for t in (bearer_tokens or []) if t.strip())

        # hmac keys (support rotation by comma-separated hex list per kid)
        self.hmac_keys: Dict[str, List[str]] = {}
        for k, v in (hmac_keys or {}).items():
            parts = [p.strip().lower() for p in str(v).split(",") if p.strip()]
            for p in parts:
                # validate hex; any error raises
                _ = bytes.fromhex(p)
            self.hmac_keys[str(k)] = parts or []
        self.max_skew_s = int(max(1, max_skew_s))
        self.nonce_check_cb = nonce_check_cb

        # jwt
        self.jwt_iss = jwt_iss
        self.jwt_aud = jwt_aud
        self.jwt_leeway_s = int(max(0, jwt_leeway_s))
        self.jwt_principal_claim = jwt_principal_claim
        self.jwt_scope_claims = tuple(jwt_scope_claims or ())
        self.jwt_allowed_algs = tuple(
            sorted({a.strip() for a in (jwt_allowed_algs or ()) if a.strip()})
        )
        self._jwks = _JWKSCache(
            jwks_url,
            jwks_json,
            ttl_s=jwks_cache_ttl_s,
            timeout_s=jwks_timeout_s,
        )

        # mtls
        self.mtls_fp_allow = set(fp.lower() for fp in (mtls_fp_allow or []))
        self.mtls_spiffe_prefixes = [p.strip() for p in (mtls_spiffe_prefixes or []) if p.strip()]

        # Precompute a stable policy digest for this authenticator instance.
        self._policy_digest = self._compute_policy_digest()

        # Mode gauge for observability.
        _AUTH_CFG.labels(self.mode).set(1.0)

    # ------------------------------------------------------------------ #
    # Policy digest & snapshot (for receipts / attestation / ops)
    # ------------------------------------------------------------------ #

    def _compute_policy_digest(self) -> str:
        """
        Compute a stable, secret-free digest of the authentication policy.

        Secrets (bearer tokens, HMAC keys, fingerprints) are hashed before
        inclusion so that the digest can safely appear in logs, receipts,
        and attestation payloads.
        """
        # Hash bearer tokens.
        bearer_hashes = sorted(_sha256_hex(_b(t)) for t in self.bearer)

        # Hash HMAC keys per kid.
        hmac_hashes: Dict[str, List[str]] = {}
        for kid, keys in self.hmac_keys.items():
            hmac_hashes[kid] = sorted(_sha256_hex(bytes.fromhex(k)) for k in keys)

        # Hash mTLS fingerprints.
        mtls_fp_hashes = sorted(_sha256_hex(_b(fp)) for fp in self.mtls_fp_allow)

        payload: Dict[str, Any] = {
            "mode": self.mode,
            "bearer_hashes": bearer_hashes,
            "hmac_hashes": hmac_hashes,
            "jwt_iss": self.jwt_iss,
            "jwt_aud": self.jwt_aud,
            "jwt_principal_claim": self.jwt_principal_claim,
            "jwt_scope_claims": list(self.jwt_scope_claims),
            "jwt_allowed_algs": list(self.jwt_allowed_algs),
            "jwks_url": self._jwks.url_for_digest,
            "jwt_leeway_s": self.jwt_leeway_s,
            "mtls_fp_hashes": mtls_fp_hashes,
            "mtls_spiffe_prefixes": sorted(self.mtls_spiffe_prefixes),
            "max_skew_s": self.max_skew_s,
            "nonce_check_present": bool(self.nonce_check_cb is not None),
        }
        return canonical_kv_hash(
            payload,
            ctx="tcd:auth_policy",
            label="auth_policy",
        )

    @property
    def policy_digest_hex(self) -> str:
        """
        Stable digest describing this authenticator's policy.

        Intended usage:
          - embed into safety receipts and decision logs;
          - include in e-process envelopes;
          - include in runtime attestation payloads.

        Any change in this value should be treated as a change in identity
        / access policy for downstream systems.
        """
        return self._policy_digest

    def policy_snapshot(self) -> Dict[str, Any]:
        """
        Return a redacted, JSON-serializable view of the auth policy.

        This is suitable for SRE/debug dashboards and forensics:
          - exposes configuration knobs and allowlists in hashed form;
          - never exposes raw credentials.
        """
        bearer_hashes = sorted(_sha256_hex(_b(t)) for t in self.bearer)
        hmac_hashes: Dict[str, List[str]] = {}
        for kid, keys in self.hmac_keys.items():
            hmac_hashes[kid] = sorted(_sha256_hex(bytes.fromhex(k)) for k in keys)
        mtls_fp_hashes = sorted(_sha256_hex(_b(fp)) for fp in self.mtls_fp_allow)

        return {
            "mode": self.mode,
            "policy_digest": self._policy_digest,
            "bearer_hashes": bearer_hashes,
            "hmac_hashes": hmac_hashes,
            "jwt_iss": self.jwt_iss,
            "jwt_aud": self.jwt_aud,
            "jwt_principal_claim": self.jwt_principal_claim,
            "jwt_scope_claims": list(self.jwt_scope_claims),
            "jwt_allowed_algs": list(self.jwt_allowed_algs),
            "jwks_url": self._jwks.url_for_digest,
            "jwt_leeway_s": self.jwt_leeway_s,
            "mtls_fp_hashes": mtls_fp_hashes,
            "mtls_spiffe_prefixes": list(self.mtls_spiffe_prefixes),
            "max_skew_s": self.max_skew_s,
            "nonce_check_present": bool(self.nonce_check_cb is not None),
        }

    # ------------------------------------------------------------------ #
    # Core verify
    # ------------------------------------------------------------------ #

    async def verify(self, request: Request) -> AuthResult:
        """
        Main entry point for request authentication.

        Contract:
          - returns AuthResult(ok=True, ctx=AuthContext, reason=None) on success;
          - ctx.policy_digest is always set to self.policy_digest_hex;
          - measure latency via Prometheus so abuse and anomalies can be
            detected at the edge.

        Mode semantics:
          - disabled : bypass identity checks; only for dev/tests;
          - bearer   : static allowlist of opaque tokens;
          - hmac     : signed requests with bounded time skew and optional nonce;
          - jwt      : signature + iss/aud/exp/nbf checks via JWKS;
          - mtls     : XFCC-based client identity via fingerprint or SPIFFE URI.
        """
        t0 = _now()
        try:
            if self.mode == "disabled":
                ctx = AuthContext(
                    mode="disabled",
                    principal="anonymous",
                    scopes=["public"],
                    key_id=None,
                    raw={},
                    policy_digest=self._policy_digest,
                    issued_at=_now(),
                )
                _inc_ok(self.mode)
                return AuthResult(True, ctx)

            if self.mode == "bearer":
                return await self._verify_bearer(request)

            if self.mode == "hmac":
                return await self._verify_hmac(request)

            if self.mode == "jwt":
                return await self._verify_jwt(request)

            if self.mode == "mtls":
                return await self._verify_mtls(request)

            _inc_fail(self.mode, "bad_mode")
            return AuthResult(False, None, "bad auth mode")
        finally:
            _AUTH_LAT.labels(self.mode).observe(max(0.0, _now() - t0))

    # ------------------------------------------------------------------ #
    # Modes
    # ------------------------------------------------------------------ #

    async def _verify_bearer(self, request: Request) -> AuthResult:
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            _inc_fail("bearer", "missing")
            return AuthResult(False, None, "missing bearer")

        token = auth.split(" ", 1)[1].strip()
        if token in self.bearer:
            ctx = AuthContext(
                mode="bearer",
                principal="bearer",
                scopes=["api"],
                key_id=None,
                raw={"authorization": "Bearer ***"},
                policy_digest=self._policy_digest,
                issued_at=_now(),
            )
            _inc_ok("bearer")
            return AuthResult(True, ctx)

        _inc_fail("bearer", "denied")
        return AuthResult(False, None, "invalid bearer")

    async def _verify_hmac(self, request: Request) -> AuthResult:
        """
        Header format:

          v1:
            X-TCD-Signature: v1,t=<unix_ts>,sig=<hex>[,n=<nonce>]
          v2:
            X-TCD-Signature: v2,t=<unix_ts>,sig=<hex>[,n=<nonce>]

          X-TCD-Key-Id: <kid>           (optional; defaults to "default")

        Payload (v1):

          "<ts>\\n<METHOD>\\n<PATH>\\n" + <raw-body>

        Payload (v2):

          "<ts>\\n<METHOD>\\n<PATH>\\n<CANON_QUERY>\\n<CANON_HEADERS>\\n" + <raw-body>

        where:
          - CANON_QUERY   = sorted "key=value&..." with normalized percent-encoding;
          - CANON_HEADERS = "host=...|x-tcd-cluster=...|x-tcd-env=...".

        Hash:

          blake3(key=secret, ctx="tcd:hmac")

        Notes:
          - Supports key rotation: multiple hex keys per kid, tried in
            constant time.
          - Optional replay nonces: if nonce is present and nonce_check_cb
            is provided, it must return True for a fresh nonce.
        """
        sig_hdr = request.headers.get("x-tcd-signature", "")
        kid = request.headers.get("x-tcd-key-id", "default")
        if not sig_hdr:
            _inc_fail("hmac", "missing")
            return AuthResult(False, None, "missing signature")

        try:
            scheme, rest = sig_hdr.split(",", 1)
            scheme = scheme.strip().lower()
            parts = dict(
                p.split("=", 1)
                for p in [x.strip() for x in rest.split(",")]
                if "=" in p
            )
            ts = int(parts.get("t", "0"))
            sig = parts.get("sig", "")
            nonce = parts.get("n")
        except Exception:
            _inc_fail("hmac", "malformed")
            return AuthResult(False, None, "malformed signature header")

        if scheme not in ("v1", "v2"):
            _inc_fail("hmac", "bad_scheme")
            return AuthResult(False, None, "bad signature scheme")

        if kid not in self.hmac_keys or not self.hmac_keys[kid]:
            _inc_fail("hmac", "unknown_key")
            return AuthResult(False, None, "unknown key")

        # Replay window.
        now = int(_now())
        if abs(now - ts) > self.max_skew_s:
            _inc_fail("hmac", "skew")
            return AuthResult(False, None, "timestamp out of window")

        # Optional nonce check.
        if nonce and self.nonce_check_cb is not None:
            try:
                fresh = bool(self.nonce_check_cb(nonce, ts))
            except Exception:
                fresh = False
            if not fresh:
                _AUTH_REPLAY.labels("hmac").inc()
                return AuthResult(False, None, "replay")

        # Reconstruct payload based on scheme.
        raw_body = await request.body()
        if scheme == "v1":
            payload = _canonical_hmac_payload_v1(
                ts,
                request.method,
                request.url.path,
                raw_body or b"",
            )
        else:  # v2
            payload = _canonical_hmac_payload_v2(
                ts,
                request.method,
                request.url.path,
                request.url.query or "",
                request.headers,
                raw_body or b"",
            )

        # Try all candidate keys in constant-time style.
        ok_any = False
        for secret_hex in self.hmac_keys[kid]:
            calc = _hmac_blake3(bytes.fromhex(secret_hex), "tcd:hmac", payload)
            ok_this = hmac.compare_digest(calc, sig.lower())
            ok_any = ok_any or ok_this

        if not ok_any:
            _inc_fail("hmac", "mismatch")
            return AuthResult(False, None, "signature mismatch")

        # Scope can be further refined by kid in downstream policy.
        scopes = ["api", "signed", f"kid:{kid}"]
        principal = f"hmac:{kid}"
        ctx = AuthContext(
            mode="hmac",
            principal=principal,
            scopes=scopes,
            key_id=kid,
            raw={
                "x-tcd-signature": f"{scheme},***",
                "x-tcd-key-id": kid,
            },
            policy_digest=self._policy_digest,
            issued_at=_now(),
        )
        _inc_ok("hmac")
        return AuthResult(True, ctx)

    async def _verify_jwt(self, request: Request) -> AuthResult:
        if not _HAS_JWCRYPTO:
            _inc_fail("jwt", "lib_missing")
            return AuthResult(False, None, "jwt verifier not available")

        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            _inc_fail("jwt", "missing")
            return AuthResult(False, None, "missing bearer")

        token = auth.split(" ", 1)[1].strip()
        # Header parse to get kid and alg.
        try:
            hdr = jwt.JWT(header=jwt.get_unverified_header(token))  # type: ignore
            kid = hdr.header.get("kid")
            alg = hdr.header.get("alg")
        except Exception:
            _inc_fail("jwt", "bad_header")
            return AuthResult(False, None, "bad jwt header")

        # Optional alg whitelist.
        if self.jwt_allowed_algs and alg not in self.jwt_allowed_algs:
            _AUTH_JWT_CLAIM_FAIL.labels("alg").inc()
            _inc_fail("jwt", "alg")
            return AuthResult(False, None, "bad alg")

        jwk_dict = self._jwks.get_jwk_dict(str(kid)) if kid else None
        if not jwk_dict:
            _inc_fail("jwt", "no_jwk")
            return AuthResult(False, None, "no jwk for kid")

        # If JWK declares alg, enforce consistency with header alg.
        jwk_alg = jwk_dict.get("alg")
        if jwk_alg and alg and jwk_alg != alg:
            _AUTH_JWT_CLAIM_FAIL.labels("alg").inc()
            _inc_fail("jwt", "alg")
            return AuthResult(False, None, "bad alg")

        try:
            key = jwk.JWK(**jwk_dict)  # type: ignore
            t = jwt.JWT(key=key, jwt=token)  # verifies signature
            claims = json.loads(t.claims)
        except Exception:
            _inc_fail("jwt", "bad_sig")
            return AuthResult(False, None, "invalid signature")

        # Claims checks.
        iss = claims.get("iss")
        aud = claims.get("aud")
        exp = int(claims.get("exp", 0) or 0)
        nbf = int(claims.get("nbf", 0) or 0)
        now = int(_now())

        if self.jwt_iss and iss != self.jwt_iss:
            _AUTH_JWT_CLAIM_FAIL.labels("iss").inc()
            _inc_fail("jwt", "iss")
            return AuthResult(False, None, "bad iss")

        if self.jwt_aud:
            if isinstance(aud, list):
                if self.jwt_aud not in aud:
                    _AUTH_JWT_CLAIM_FAIL.labels("aud").inc()
                    _inc_fail("jwt", "aud")
                    return AuthResult(False, None, "bad aud")
            else:
                if str(aud) != self.jwt_aud:
                    _AUTH_JWT_CLAIM_FAIL.labels("aud").inc()
                    _inc_fail("jwt", "aud")
                    return AuthResult(False, None, "bad aud")

        if exp and now > (exp + self.jwt_leeway_s):
            _AUTH_JWT_CLAIM_FAIL.labels("exp").inc()
            _inc_fail("jwt", "exp")
            return AuthResult(False, None, "expired")

        if nbf and now + self.jwt_leeway_s < nbf:
            _AUTH_JWT_CLAIM_FAIL.labels("nbf").inc()
            _inc_fail("jwt", "nbf")
            return AuthResult(False, None, "not yet valid")

        sub = str(claims.get(self.jwt_principal_claim) or "jwt")
        # Principal carries a jwt: prefix and iss if available.
        if iss:
            principal = f"jwt:{iss}/{sub}"
        else:
            principal = f"jwt:{sub}"

        scopes: List[str] = []
        for k in self.jwt_scope_claims:
            v = claims.get(k)
            if isinstance(v, str):
                scopes += [s for s in v.split() if s]
            elif isinstance(v, list):
                scopes += [str(s) for s in v]
        scopes = list(sorted(set(scopes))) or ["api"]

        ctx = AuthContext(
            mode="jwt",
            principal=principal,
            scopes=scopes,
            key_id=str(kid),
            raw={"authorization": "Bearer ***"},
            policy_digest=self._policy_digest,
            issued_at=_now(),
        )
        _inc_ok("jwt")
        return AuthResult(True, ctx)

    async def _verify_mtls(self, request: Request) -> AuthResult:
        """
        Envoy/Ingress-terminated mTLS via X-Forwarded-Client-Cert.

        Trust model:
          - only trusted front proxies are allowed to inject XFCC;
          - external clients must not be able to set this header directly;
          - downstream services must not overwrite XFCC.

        Accept if either fingerprint is allowed OR SPIFFE prefix matches.
        """
        xfcc = request.headers.get("x-forwarded-client-cert", "")
        if not xfcc:
            _inc_fail("mtls", "missing")
            return AuthResult(False, None, "missing xfcc")

        # Envoy XFCC: key=value pairs separated by ';', multiple peer certs
        # separated by ','; we only look at the first peer.
        peer = xfcc.split(",", 1)[0]
        parts: Dict[str, str] = {}
        for kv in peer.split(";"):
            kv = kv.strip()
            if not kv or "=" not in kv:
                continue
            k, v = kv.split("=", 1)
            v = v.strip().strip('"')
            parts[k.strip()] = v

        # Hash is SHA256 (base64).
        fp_hex = None
        if "Hash" in parts:
            try:
                fp_hex = hashlib.sha256(
                    base64.b64decode(parts["Hash"])
                ).hexdigest()
            except Exception:
                fp_hex = None

        spiffe = parts.get("URI") or ""
        ok = False
        if fp_hex and fp_hex.lower() in self.mtls_fp_allow:
            ok = True
        if not ok and self.mtls_spiffe_prefixes:
            ok = any(spiffe.startswith(pref) for pref in self.mtls_spiffe_prefixes)

        if not ok:
            _inc_fail("mtls", "denied")
            return AuthResult(False, None, "mtls denied")

        principal = spiffe if spiffe else f"mtls:{(fp_hex or '')[:12]}"
        scopes = ["api", "mtls"]
        ctx = AuthContext(
            mode="mtls",
            principal=principal,
            scopes=scopes,
            key_id=(fp_hex or None),
            raw={"x-forwarded-client-cert": "present"},
            policy_digest=self._policy_digest,
            issued_at=_now(),
        )
        _inc_ok("mtls")
        return AuthResult(True, ctx)


# ---------------------------------------------------------------------------
# Client helpers (HMAC signing)
# ---------------------------------------------------------------------------


def client_sign_hmac(
    method: str,
    path: str,
    body_bytes: bytes,
    *,
    key_hex: str,
    ts: Optional[int] = None,
    nonce: Optional[str] = None,
) -> Tuple[str, int]:
    """
    Helper for clients/tests to construct X-TCD-Signature (v1).

    Canonicalization (v1):

      payload = "<ts>\\n<METHOD>\\n<PATH>\\n" + <raw-body>

    Returns (header_value, ts).
    """
    ts_int = int(ts if ts is not None else _now())
    payload = _canonical_hmac_payload_v1(
        ts_int,
        method,
        path,
        body_bytes or b"",
    )
    sig_hex = _hmac_blake3(bytes.fromhex(key_hex), "tcd:hmac", payload)
    if nonce:
        return f"v1,t={ts_int},sig={sig_hex},n={nonce}", ts_int
    return f"v1,t={ts_int},sig={sig_hex}", ts_int


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
) -> Tuple[str, int]:
    """
    Helper for clients/tests to construct X-TCD-Signature (v2).

    Canonicalization (v2):

      payload = "<ts>\\n<METHOD>\\n<PATH>\\n<CANON_QUERY>\\n<CANON_HEADERS>\\n" + <raw-body>

    where:
      - CANON_QUERY   = sorted "key=value&..." over the provided query string;
      - CANON_HEADERS = "host=...|x-tcd-cluster=...|x-tcd-env=..." from the
                        provided headers mapping (case-insensitive).

    Returns (header_value, ts).
    """
    ts_int = int(ts if ts is not None else _now())
    hdrs = headers or {}
    payload = _canonical_hmac_payload_v2(
        ts_int,
        method,
        path,
        query,
        hdrs,
        body_bytes or b"",
    )
    sig_hex = _hmac_blake3(bytes.fromhex(key_hex), "tcd:hmac", payload)
    if nonce:
        return f"v2,t={ts_int},sig={sig_hex},n={nonce}", ts_int
    return f"v2,t={ts_int},sig={sig_hex}", ts_int


# ---------------------------------------------------------------------------
# Factory & FastAPI dependency
# ---------------------------------------------------------------------------


def build_authenticator_from_env() -> Authenticator:
    """
    Environment-driven config.

    This is the primary entry point for wiring the authenticator as a
    process-wide identity policy object. For stricter deployments you
    can control allowed modes via:

      TCD_AUTH_STRICT_MODES       : optional comma list of modes allowed
                                    for this process (e.g., "hmac,jwt,mtls")
      TCD_AUTH_ALLOW_DISABLED     : default "1"; set to "0" to disallow
                                    mode=disabled in this environment.
      TCD_AUTH_ALLOW_BEARER       : default "0"; set to "1" if bearer mode
                                    is allowed (typically only in dev).

    Base options:

      TCD_AUTH_MODE               : disabled | bearer | hmac | jwt | mtls

      # bearer
      TCD_AUTH_BEARER_TOKENS      : comma-separated allowlist (bearer mode)

      # hmac
      TCD_AUTH_HMAC_KEYS_JSON     : {"default":"<hexkey[,hexkey2]>", "kid2":"<hex[,hex2]>"}
      TCD_AUTH_MAX_SKEW_S         : default 300
      TCD_AUTH_ENABLE_NONCE       : 1/0 (nonce check requires app to wire nonce_check_cb)

      # jwt
      TCD_AUTH_JWT_ISS            : expected iss
      TCD_AUTH_JWT_AUD            : expected aud (string or member of list)
      TCD_AUTH_JWKS_URL           : https://.../jwks.json
      TCD_AUTH_JWKS_JSON          : inline JWKS (optional, usually tests)
      TCD_AUTH_ALLOW_INLINE_JWKS  : default "0"; set to "1" to permit inline JWKS
      TCD_AUTH_JWKS_CACHE_TTL_S   : default 600
      TCD_AUTH_JWKS_TIMEOUT_S     : default 2.0
      TCD_AUTH_JWT_LEEWAY_S       : default 60
      TCD_AUTH_JWT_PRINCIPAL_CLAIM: default sub
      TCD_AUTH_JWT_SCOPE_CLAIMS   : comma list, default "scp,scope,roles"
      TCD_AUTH_JWT_ALLOWED_ALGS   : optional comma list (e.g., "RS256,ES256")

      # mtls (Envoy XFCC)
      TCD_AUTH_MTLS_FP_ALLOW      : comma-separated sha256 hex fingerprints
      TCD_AUTH_MTLS_SPIFFE_PREFIX : comma-separated allowed SPIFFE URI prefixes
    """
    mode = os.environ.get("TCD_AUTH_MODE", "disabled").strip().lower()

    # Optional governance: restrict which modes are allowed in this environment.
    strict_modes_env = os.environ.get("TCD_AUTH_STRICT_MODES", "")
    if strict_modes_env.strip():
        allowed = {
            m.strip().lower()
            for m in strict_modes_env.split(",")
            if m.strip()
        }
        if mode not in allowed:
            raise ValueError(
                f"TCD_AUTH_MODE={mode} not allowed; "
                f"must be one of {sorted(allowed)} from TCD_AUTH_STRICT_MODES"
            )

    # Optional guard: disallow disabled mode unless explicitly permitted.
    allow_disabled = _parse_bool_env("TCD_AUTH_ALLOW_DISABLED", True)
    if mode == "disabled" and not allow_disabled:
        raise ValueError(
            "TCD_AUTH_MODE=disabled is not permitted in this environment; "
            "set TCD_AUTH_ALLOW_DISABLED=1 to override explicitly"
        )

    # Optional guard: disallow bearer mode unless explicitly permitted.
    allow_bearer = _parse_bool_env("TCD_AUTH_ALLOW_BEARER", False)
    if mode == "bearer" and not allow_bearer:
        raise ValueError(
            "TCD_AUTH_MODE=bearer is not permitted in this environment; "
            "set TCD_AUTH_ALLOW_BEARER=1 to override explicitly"
        )

    max_skew = int(os.environ.get("TCD_AUTH_MAX_SKEW_S", "300"))

    # bearer
    bearer_tokens: List[str] = []
    if mode == "bearer":
        raw = os.environ.get("TCD_AUTH_BEARER_TOKENS", "")
        bearer_tokens = [t.strip() for t in raw.split(",") if t.strip()]

    # hmac
    hmac_keys: Dict[str, str] = {}
    if mode == "hmac":
        raw = os.environ.get("TCD_AUTH_HMAC_KEYS_JSON", "").strip()
        if not raw:
            raise ValueError("TCD_AUTH_HMAC_KEYS_JSON is required in hmac mode")
        try:
            obj = json.loads(raw)
            if not isinstance(obj, dict) or not obj:
                raise ValueError
            for k, v in obj.items():
                for p in str(v).split(","):
                    if p.strip():
                        _ = bytes.fromhex(p.strip())
            hmac_keys = {str(k): str(v) for k, v in obj.items()}
        except Exception:
            raise ValueError(
                "TCD_AUTH_HMAC_KEYS_JSON must be a JSON object of {kid: \"hex[,hex2]\"}"
            )

    # jwt
    jwt_iss = os.environ.get("TCD_AUTH_JWT_ISS")
    jwt_aud = os.environ.get("TCD_AUTH_JWT_AUD")
    jwks_url = os.environ.get("TCD_AUTH_JWKS_URL")
    jwks_json = os.environ.get("TCD_AUTH_JWKS_JSON")
    allow_inline_jwks = _parse_bool_env("TCD_AUTH_ALLOW_INLINE_JWKS", False)
    if mode == "jwt" and jwks_json and not allow_inline_jwks:
        raise ValueError(
            "Inline JWKS (TCD_AUTH_JWKS_JSON) is disabled; "
            "set TCD_AUTH_ALLOW_INLINE_JWKS=1 to permit it explicitly"
        )

    jwks_cache_ttl_s = int(os.environ.get("TCD_AUTH_JWKS_CACHE_TTL_S", "600"))
    jwks_timeout_s = float(os.environ.get("TCD_AUTH_JWKS_TIMEOUT_S", "2.0"))
    jwt_leeway_s = int(os.environ.get("TCD_AUTH_JWT_LEEWAY_S", "60"))
    jwt_principal_claim = os.environ.get("TCD_AUTH_JWT_PRINCIPAL_CLAIM", "sub")
    jwt_scope_claims_env = os.environ.get(
        "TCD_AUTH_JWT_SCOPE_CLAIMS", "scp,scope,roles"
    )
    jwt_scope_claims = tuple(
        c.strip() for c in jwt_scope_claims_env.split(",") if c.strip()
    )
    jwt_allowed_algs_env = os.environ.get("TCD_AUTH_JWT_ALLOWED_ALGS", "")
    jwt_allowed_algs: Tuple[str, ...] = tuple(
        a.strip()
        for a in jwt_allowed_algs_env.split(",")
        if a.strip()
    )

    # mtls
    mtls_fp_allow_env = os.environ.get("TCD_AUTH_MTLS_FP_ALLOW", "")
    mtls_fp_allow = [
        x.strip().lower() for x in mtls_fp_allow_env.split(",") if x.strip()
    ]
    mtls_spiffe_env = os.environ.get("TCD_AUTH_MTLS_SPIFFE_PREFIX", "")
    mtls_spiffe_prefixes = [
        x.strip() for x in mtls_spiffe_env.split(",") if x.strip()
    ]

    # NOTE: nonce_check_cb cannot be provided via env; wire it in code if needed.
    return Authenticator(
        mode=mode,
        bearer_tokens=bearer_tokens,
        hmac_keys=hmac_keys,
        max_skew_s=max_skew,
        nonce_check_cb=None,
        jwt_iss=jwt_iss,
        jwt_aud=jwt_aud,
        jwks_url=jwks_url,
        jwks_json=jwks_json,
        jwks_cache_ttl_s=jwks_cache_ttl_s,
        jwks_timeout_s=jwks_timeout_s,
        jwt_leeway_s=jwt_leeway_s,
        jwt_principal_claim=jwt_principal_claim,
        jwt_scope_claims=jwt_scope_claims,
        jwt_allowed_algs=jwt_allowed_algs,
        mtls_fp_allow=mtls_fp_allow,
        mtls_spiffe_prefixes=mtls_spiffe_prefixes,
    )


def require_auth(
    authenticator: Authenticator,
    *,
    required_scopes: Optional[List[str]] = None,
) -> Callable[[Request], AuthContext]:
    """
    FastAPI dependency factory.

    Usage:

      auth = build_authenticator_from_env()
      app = FastAPI()

      @app.post("/diagnose")
      async def diagnose(
          req: DiagnoseRequest,
          ctx: AuthContext = Depends(require_auth(auth)),
      ):
          # ctx.policy_digest can be threaded into receipts / e-process

    required_scopes is a simple scope subset check; for more complex
    policies, combine it with downstream decision engines.
    """
    required_scopes = list(required_scopes or [])

    async def _dep(request: Request) -> AuthContext:
        res = await authenticator.verify(request)
        if not res.ok or not res.ctx:
            detail = res.reason or "unauthorized"
            raise HTTPException(status_code=401, detail=detail)
        if required_scopes and not set(required_scopes).issubset(set(res.ctx.scopes)):
            _inc_fail(authenticator.mode, "forbidden")
            raise HTTPException(status_code=403, detail="forbidden")
        return res.ctx

    return _dep