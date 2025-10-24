# FILE: tcd/auth.py
from __future__ import annotations

import base64
import json
import os
import time
import hmac
import hashlib
import threading
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from fastapi import HTTPException
from starlette.requests import Request

try:
    from prometheus_client import Counter, Histogram, Gauge
    _HAS_PROM = True
except Exception:
    _HAS_PROM = False

# Optional JWT libs (soft dependency)
try:
    from jwcrypto import jwk, jwt
    _HAS_JWCRYPTO = True
except Exception:
    _HAS_JWCRYPTO = False

try:
    # stdlib fetch to avoid extra deps
    from urllib.request import urlopen, Request as UrlReq  # type: ignore
    from urllib.error import URLError  # type: ignore
    _HAS_URL = True
except Exception:
    _HAS_URL = False


# ---------- Models ----------

@dataclass
class AuthContext:
    mode: str                # "disabled" | "bearer" | "hmac" | "jwt" | "mtls"
    principal: str           # e.g., "svc:gateway" / "tenant:alice" / "spiffe://..."
    scopes: List[str]        # logical scopes/roles
    key_id: Optional[str]    # for hmac/jwt key tracking (kid/fp)
    raw: Dict[str, str]      # redacted raw header fields of interest


@dataclass
class AuthResult:
    ok: bool
    ctx: Optional[AuthContext]
    reason: Optional[str] = None


# ---------- Metrics ----------

if _HAS_PROM:
    _AUTH_OK = Counter("tcd_auth_ok_total", "Auth OK", ["mode"])
    _AUTH_FAIL = Counter("tcd_auth_fail_total", "Auth Fail", ["mode", "reason"])
    _AUTH_LAT = Histogram(
        "tcd_auth_verify_latency_seconds", "Auth verify latency (s)",
        buckets=(0.001, 0.002, 0.005, 0.010, 0.020, 0.050), labelnames=("mode",)
    )
    _AUTH_REPLAY = Counter("tcd_auth_replay_total", "Replay/nonce rejection", ["mode"])
    _AUTH_JWKS_HIT = Counter("tcd_auth_jwks_hit_total", "JWKS cache hit", [])
    _AUTH_JWKS_MISS = Counter("tcd_auth_jwks_miss_total", "JWKS cache miss", [])
    _AUTH_JWT_CLAIM_FAIL = Counter("tcd_auth_jwt_claim_fail_total", "JWT claim validation fail", ["field"])
    _AUTH_CFG = Gauge("tcd_auth_mode_info", "Auth mode coded as gauge", ["mode"])
else:
    class _Nop:
        def labels(self, *_, **__): return self
        def inc(self, *_ , **__): pass
        def observe(self, *_ , **__): pass
        def set(self, *_ , **__): pass
    _AUTH_OK = _Nop(); _AUTH_FAIL = _Nop(); _AUTH_LAT = _Nop()
    _AUTH_REPLAY = _Nop(); _AUTH_JWKS_HIT = _Nop(); _AUTH_JWKS_MISS = _Nop()
    _AUTH_JWT_CLAIM_FAIL = _Nop(); _AUTH_CFG = _Nop()


def _inc_ok(mode: str) -> None:
    _AUTH_OK.labels(mode).inc()


def _inc_fail(mode: str, reason: str) -> None:
    _AUTH_FAIL.labels(mode, reason).inc()


# ---------- Helpers ----------

def _b(s: str) -> bytes:
    return s.encode("utf-8")


def _now() -> float:
    return time.time()


def _hmac_blake3(key: bytes, ctx: str, data: bytes) -> str:
    """Domain-separated keyed blake3; returns hex."""
    # Lazily import to avoid hard dep if not used
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
    return v.strip() in ("1", "true", "TRUE", "yes", "on")


# ---------- JWKS cache (for JWT mode) ----------

class _JWKSCache:
    def __init__(self, url: Optional[str], inline_json: Optional[str], ttl_s: int = 600, timeout_s: float = 2.0):
        self._url = (url or "").strip()
        self._inline = (inline_json or "").strip()
        self._ttl = max(30, int(ttl_s))
        self._timeout = float(timeout_s)
        self._lock = threading.RLock()
        self._kid_map: Dict[str, dict] = {}
        self._exp_at = 0.0

        if self._inline:
            try:
                obj = json.loads(self._inline)
                self._kid_map = {k["kid"]: k for k in obj.get("keys", []) if "kid" in k}
                self._exp_at = _now() + 3600.0
            except Exception:
                # ignore, will attempt fetch if URL is present
                self._kid_map = {}

    def _fetch(self) -> None:
        if not self._url or not _HAS_URL:
            return
        try:
            req = UrlReq(self._url, headers={"User-Agent": "tcd-auth/1.0"})
            with urlopen(req, timeout=self._timeout) as resp:  # type: ignore
                data = resp.read()
            obj = json.loads(data.decode("utf-8"))
            kid_map = {k["kid"]: k for k in obj.get("keys", []) if "kid" in k}
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


# ---------- Authenticator ----------

class Authenticator:
    """
    Pluggable authenticator with production-safe modes:
      - bearer: static token allowlist (comma-separated)
      - hmac:   signed requests with timestamp + raw body (+ optional nonce)
      - jwt:    OIDC-style JWT with JWKS (iss/aud/exp/nbf checks)
      - mtls:   Envoy XFCC-based identity (SPIFFE/DNS/CN or fingerprint allowlist)
    Disabled mode is allowed for local dev/tests.
    """

    def __init__(
        self,
        mode: str = "disabled",
        *,
        # bearer
        bearer_tokens: Optional[List[str]] = None,
        # hmac
        hmac_keys: Optional[Dict[str, str]] = None,   # key_id -> hex or "hex1,hex2" (rotation)
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
        # mtls (Envoy XFCC)
        mtls_fp_allow: Optional[List[str]] = None,    # sha256 hex fingerprints (lowercase)
        mtls_spiffe_prefixes: Optional[List[str]] = None,  # e.g., ["spiffe://cluster/ns/"]
    ):
        m = (mode or "disabled").lower()
        if m not in ("disabled", "bearer", "hmac", "jwt", "mtls"):
            raise ValueError("auth mode must be one of disabled|bearer|hmac|jwt|mtls")
        self.mode = m

        # bearer
        self.bearer = set([t.strip() for t in (bearer_tokens or []) if t.strip()])

        # hmac keys (support rotation by comma-separated hex list per kid)
        self.hmac_keys: Dict[str, List[str]] = {}
        for k, v in (hmac_keys or {}).items():
            parts = [p.strip().lower() for p in str(v).split(",") if p.strip()]
            # validate hex
            for p in parts:
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
        self._jwks = _JWKSCache(jwks_url, jwks_json, ttl_s=jwks_cache_ttl_s, timeout_s=jwks_timeout_s)

        # mtls
        self.mtls_fp_allow = set([fp.lower() for fp in (mtls_fp_allow or [])])
        self.mtls_spiffe_prefixes = [p.strip() for p in (mtls_spiffe_prefixes or []) if p.strip()]

        # mode gauge for observability
        _AUTH_CFG.labels(self.mode).set(1.0)

    # ---- core verify ----

    async def verify(self, request: Request) -> AuthResult:
        t0 = _now()
        try:
            if self.mode == "disabled":
                ctx = AuthContext(mode="disabled", principal="anonymous", scopes=["public"], key_id=None, raw={})
                _inc_ok(self.mode); return AuthResult(True, ctx)

            if self.mode == "bearer":
                res = await self._verify_bearer(request); return res

            if self.mode == "hmac":
                res = await self._verify_hmac(request); return res

            if self.mode == "jwt":
                res = await self._verify_jwt(request); return res

            if self.mode == "mtls":
                res = await self._verify_mtls(request); return res

            _inc_fail(self.mode, "bad_mode")
            return AuthResult(False, None, "bad auth mode")
        finally:
            _AUTH_LAT.labels(self.mode).observe(max(0.0, _now() - t0))

    # ---- modes ----

    async def _verify_bearer(self, request: Request) -> AuthResult:
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            _inc_fail("bearer", "missing")
            return AuthResult(False, None, "missing bearer")
        token = auth.split(" ", 1)[1].strip()
        if token in self.bearer:
            ctx = AuthContext(mode="bearer", principal="bearer", scopes=["api"], key_id=None, raw={"authorization": "***"})
            _inc_ok("bearer")
            return AuthResult(True, ctx)
        _inc_fail("bearer", "denied")
        return AuthResult(False, None, "invalid bearer")

    async def _verify_hmac(self, request: Request) -> AuthResult:
        """
        Header format:
          X-TCD-Signature: v1,t=<unix_ts>,sig=<hex>[,n=<nonce>]
          X-TCD-Key-Id: <kid>           (optional; defaults to "default")
        Payload signed bytes: "<ts>\n<METHOD>\n<PATH>\n" + <raw-body>
        Hash: blake3(key=secret, ctx="tcd:hmac")
        Notes:
          - Supports key rotation: multiple hex keys per kid (comma-separated) tried in constant time.
          - Optional replay nonces: if nonce present and nonce_check_cb provided, it must return True.
        """
        sig_hdr = request.headers.get("x-tcd-signature", "")
        kid = request.headers.get("x-tcd-key-id", "default")
        if not sig_hdr:
            _inc_fail("hmac", "missing")
            return AuthResult(False, None, "missing signature")

        try:
            scheme, rest = sig_hdr.split(",", 1)
            if scheme.strip().lower() != "v1":
                _inc_fail("hmac", "bad_scheme")
                return AuthResult(False, None, "bad signature scheme")
            parts = dict(p.split("=", 1) for p in [x.strip() for x in rest.split(",")] if "=" in x)
            ts = int(parts.get("t", "0"))
            sig = parts.get("sig", "")
            nonce = parts.get("n")
        except Exception:
            _inc_fail("hmac", "malformed")
            return AuthResult(False, None, "malformed signature header")

        if kid not in self.hmac_keys or not self.hmac_keys[kid]:
            _inc_fail("hmac", "unknown_key")
            return AuthResult(False, None, "unknown key")

        # replay window
        now = int(_now())
        if abs(now - ts) > self.max_skew_s:
            _inc_fail("hmac", "skew")
            return AuthResult(False, None, "timestamp out of window")

        # optional nonce check
        if nonce and self.nonce_check_cb is not None:
            try:
                fresh = bool(self.nonce_check_cb(nonce, ts))
            except Exception:
                fresh = False
            if not fresh:
                _AUTH_REPLAY.labels("hmac").inc()
                return AuthResult(False, None, "replay")

        # reconstruct payload
        raw = await request.body()
        payload = _b(f"{ts}\n{request.method.upper()}\n{request.url.path}\n") + (raw or b"")

        # try all candidate keys in constant time
        calc_any = ""
        ok_any = False
        for secret_hex in self.hmac_keys[kid]:
            calc = _hmac_blake3(bytes.fromhex(secret_hex), "tcd:hmac", payload)
            # aggregate equality in constant-time style
            ok_this = hmac.compare_digest(calc, sig.lower())
            ok_any = ok_any or ok_this
            calc_any = calc  # keep last to avoid branches

        if not ok_any:
            _inc_fail("hmac", "mismatch")
            return AuthResult(False, None, "signature mismatch")

        principal = f"hmac:{kid}"
        ctx = AuthContext(
            mode="hmac", principal=principal, scopes=["api", "signed"], key_id=kid,
            raw={"x-tcd-signature": "v1,***", "x-tcd-key-id": kid}
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
        try:
            # header parse (unverified) to get kid
            hdr = jwt.JWT(header=jwt.get_unverified_header(token))  # type: ignore
            kid = hdr.header.get("kid")
        except Exception:
            _inc_fail("jwt", "bad_header")
            return AuthResult(False, None, "bad jwt header")

        jwk_dict = self._jwks.get_jwk_dict(str(kid)) if kid else None
        if not jwk_dict:
            _inc_fail("jwt", "no_jwk")
            return AuthResult(False, None, "no jwk for kid")

        try:
            key = jwk.JWK(**jwk_dict)  # type: ignore
            t = jwt.JWT(key=key, jwt=token)  # verifies signature
            claims = json.loads(t.claims)
        except Exception:
            _inc_fail("jwt", "bad_sig")
            return AuthResult(False, None, "invalid signature")

        # claims checks
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

        principal = str(claims.get(self.jwt_principal_claim) or "jwt")
        scopes: List[str] = []
        for k in self.jwt_scope_claims:
            v = claims.get(k)
            if isinstance(v, str):
                scopes += [s for s in v.split() if s]
            elif isinstance(v, list):
                scopes += [str(s) for s in v]
        scopes = list(sorted(set(scopes))) or ["api"]

        ctx = AuthContext(mode="jwt", principal=principal, scopes=scopes, key_id=str(kid), raw={"authorization": "Bearer ***"})
        _inc_ok("jwt")
        return AuthResult(True, ctx)

    async def _verify_mtls(self, request: Request) -> AuthResult:
        """
        Envoy/Ingress-terminated mTLS via X-Forwarded-Client-Cert.
        Accept if either fingerprint is allowed OR SPIFFE prefix matches.
        """
        xfcc = request.headers.get("x-forwarded-client-cert", "")
        if not xfcc:
            _inc_fail("mtls", "missing")
            return AuthResult(False, None, "missing xfcc")

        # Envoy XFCC: key=value pairs separated by ';', multiple peer certs separated by ','
        peer = xfcc.split(",", 1)[0]
        parts: Dict[str, str] = {}
        for kv in peer.split(";"):
            kv = kv.strip()
            if not kv or "=" not in kv:
                continue
            k, v = kv.split("=", 1)
            v = v.strip().strip('"')
            parts[k.strip()] = v

        # Hash is SHA256 (base64)
        fp_hex = None
        if "Hash" in parts:
            try:
                fp_hex = hashlib.sha256(base64.b64decode(parts["Hash"])).hexdigest()
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
        ctx = AuthContext(mode="mtls", principal=principal, scopes=scopes, key_id=(fp_hex or None), raw={"x-forwarded-client-cert": "present"})
        _inc_ok("mtls")
        return AuthResult(True, ctx)


# ---------- Client helper (HMAC signing) ----------

def client_sign_hmac(method: str, path: str, body_bytes: bytes, *, key_hex: str, ts: Optional[int] = None, nonce: Optional[str] = None) -> Tuple[str, int]:
    """
    Helper for clients/tests to construct X-TCD-Signature (v1).
    Returns header_value, ts
    """
    ts = int(ts if ts is not None else _now())
    payload = _b(f"{ts}\n{method.upper()}\n{path}\n") + (body_bytes or b"")
    sig_hex = _hmac_blake3(bytes.fromhex(key_hex), "tcd:hmac", payload)
    if nonce:
        return f"v1,t={ts},sig={sig_hex},n={nonce}", ts
    return f"v1,t={ts},sig={sig_hex}", ts


# ---------- Factory & FastAPI dependency ----------

def build_authenticator_from_env() -> Authenticator:
    """
    Environment-driven config:

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
      TCD_AUTH_JWKS_JSON          : inline JWKS (optional, for tests)
      TCD_AUTH_JWKS_CACHE_TTL_S   : default 600
      TCD_AUTH_JWKS_TIMEOUT_S     : default 2.0
      TCD_AUTH_JWT_LEEWAY_S       : default 60
      TCD_AUTH_JWT_PRINCIPAL_CLAIM: default sub
      TCD_AUTH_JWT_SCOPE_CLAIMS   : comma list, default "scp,scope,roles"

      # mtls (Envoy XFCC)
      TCD_AUTH_MTLS_FP_ALLOW      : comma-separated sha256 hex fingerprints
      TCD_AUTH_MTLS_SPIFFE_PREFIX : comma-separated allowed SPIFFE URI prefixes
    """
    mode = os.environ.get("TCD_AUTH_MODE", "disabled").strip().lower()
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
            # validate hex (and optional rotation lists)
            for k, v in obj.items():
                for p in str(v).split(","):
                    _ = bytes.fromhex(p.strip())
            hmac_keys = {str(k): str(v) for k, v in obj.items()}
        except Exception:
            raise ValueError("TCD_AUTH_HMAC_KEYS_JSON must be a JSON object of {kid: \"hex[,hex2]\"}")

    # jwt
    jwt_iss = os.environ.get("TCD_AUTH_JWT_ISS")
    jwt_aud = os.environ.get("TCD_AUTH_JWT_AUD")
    jwks_url = os.environ.get("TCD_AUTH_JWKS_URL")
    jwks_json = os.environ.get("TCD_AUTH_JWKS_JSON")
    jwks_cache_ttl_s = int(os.environ.get("TCD_AUTH_JWKS_CACHE_TTL_S", "600"))
    jwks_timeout_s = float(os.environ.get("TCD_AUTH_JWKS_TIMEOUT_S", "2.0"))
    jwt_leeway_s = int(os.environ.get("TCD_AUTH_JWT_LEEWAY_S", "60"))
    jwt_principal_claim = os.environ.get("TCD_AUTH_JWT_PRINCIPAL_CLAIM", "sub")
    jwt_scope_claims_env = os.environ.get("TCD_AUTH_JWT_SCOPE_CLAIMS", "scp,scope,roles")
    jwt_scope_claims = tuple([c.strip() for c in jwt_scope_claims_env.split(",") if c.strip()])

    # mtls
    mtls_fp_allow_env = os.environ.get("TCD_AUTH_MTLS_FP_ALLOW", "")
    mtls_fp_allow = [x.strip().lower() for x in mtls_fp_allow_env.split(",") if x.strip()]
    mtls_spiffe_env = os.environ.get("TCD_AUTH_MTLS_SPIFFE_PREFIX", "")
    mtls_spiffe_prefixes = [x.strip() for x in mtls_spiffe_env.split(",") if x.strip()]

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
      async def diagnose(req: DiagnoseRequest, ctx: AuthContext = Depends(require_auth(auth))):
          ...
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