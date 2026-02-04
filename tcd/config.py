from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import re
import stat
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

from pydantic import BaseModel, Field

try:
    # pydantic v2
    from pydantic import ConfigDict  # type: ignore
except Exception:  # pragma: no cover
    ConfigDict = None  # type: ignore

from .kv import canonical_kv_hash

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Versioning / policy identity (digest anchor)
# ---------------------------------------------------------------------------

# Bump whenever Settings schema semantics / normalization / governance rules change.
_SETTINGS_ENGINE_VERSION = "settings_v3"

# ---------------------------------------------------------------------------
# Optional Prometheus metrics (low cardinality)
# ---------------------------------------------------------------------------

try:
    from prometheus_client import REGISTRY, CollectorRegistry, Counter, Gauge  # type: ignore

    _HAS_PROM = True
except Exception:  # pragma: no cover
    _HAS_PROM = False


if not _HAS_PROM:  # pragma: no cover
    class _No:
        def labels(self, *_, **__):
            return self

        def inc(self, *_):
            pass

        def set(self, *_):
            pass

    class _Metrics:
        def __init__(self) -> None:
            self.load_total = _No()
            self.refresh_total = _No()
            self.set_total = _No()
            self.break_glass_enabled = _No()
            self.constraint_block_total = _No()
            self.yaml_too_large_total = _No()
            self.yaml_permission_denied_total = _No()
            self.yaml_parse_fail_total = _No()
            self.signature_fail_total = _No()
            self.refresh_skipped_unchanged_total = _No()

    def build_metrics(registry: Optional["CollectorRegistry"] = None) -> "_Metrics":  # type: ignore
        return _Metrics()

else:
    _LOAD_RESULTS = frozenset({"ok", "fail"})
    _LOAD_SOURCES = frozenset({"defaults", "yaml", "json", "env", "runtime"})
    _REFRESH_RESULTS = frozenset({"applied", "noop", "failed"})
    _SET_RESULTS = frozenset({"applied", "rejected", "failed"})
    _BLOCK_KINDS = frozenset({"immutable", "directional", "alpha_delta", "risk_band", "ledger_downgrade", "signature", "format"})

    def _get_existing(reg: "CollectorRegistry", name: str) -> Optional[Any]:
        m = getattr(reg, "_names_to_collectors", None)
        return m.get(name) if isinstance(m, dict) else None

    def _mk_counter(reg: "CollectorRegistry", name: str, doc: str, labels: Tuple[str, ...]) -> "Counter":
        try:
            return Counter(name, doc, labelnames=list(labels), registry=reg)
        except ValueError:
            ex = _get_existing(reg, name)
            if ex is None or not isinstance(ex, Counter):
                raise
            return ex

    def _mk_gauge(reg: "CollectorRegistry", name: str, doc: str, labels: Tuple[str, ...]) -> "Gauge":
        try:
            return Gauge(name, doc, labelnames=list(labels), registry=reg)
        except ValueError:
            ex = _get_existing(reg, name)
            if ex is None or not isinstance(ex, Gauge):
                raise
            return ex

    class _Metrics:
        def __init__(self, reg: "CollectorRegistry") -> None:
            self.load_total = _mk_counter(
                reg,
                "tcd_settings_load_total",
                "Settings load attempts",
                ("result", "source"),
            )
            self.refresh_total = _mk_counter(
                reg,
                "tcd_settings_refresh_total",
                "ReloadableSettings.refresh outcomes",
                ("result",),
            )
            self.set_total = _mk_counter(
                reg,
                "tcd_settings_set_total",
                "ReloadableSettings.set outcomes",
                ("result",),
            )
            self.break_glass_enabled = _mk_gauge(
                reg,
                "tcd_settings_break_glass_enabled",
                "Break-glass enabled (1/0)",
                tuple(),
            )
            self.constraint_block_total = _mk_counter(
                reg,
                "tcd_settings_constraint_block_total",
                "Blocked changes by constraint kind",
                ("kind",),
            )
            self.yaml_too_large_total = _mk_counter(
                reg,
                "tcd_settings_yaml_too_large_total",
                "YAML ignored due to size limit",
                tuple(),
            )
            self.yaml_permission_denied_total = _mk_counter(
                reg,
                "tcd_settings_yaml_permission_denied_total",
                "YAML ignored due to insecure permissions",
                tuple(),
            )
            self.yaml_parse_fail_total = _mk_counter(
                reg,
                "tcd_settings_yaml_parse_fail_total",
                "YAML parse failures",
                tuple(),
            )
            self.signature_fail_total = _mk_counter(
                reg,
                "tcd_settings_signature_fail_total",
                "Signature verification failures",
                tuple(),
            )
            self.refresh_skipped_unchanged_total = _mk_counter(
                reg,
                "tcd_settings_refresh_skipped_unchanged_total",
                "refresh_if_changed skipped because source fingerprints unchanged",
                tuple(),
            )

    def build_metrics(registry: Optional["CollectorRegistry"] = None) -> "_Metrics":
        return _Metrics(registry or REGISTRY)


_DEFAULT_METRICS_LOCK = threading.Lock()
_DEFAULT_METRICS: Optional[_Metrics] = None


def _metrics() -> _Metrics:
    global _DEFAULT_METRICS
    with _DEFAULT_METRICS_LOCK:
        if _DEFAULT_METRICS is None:
            _DEFAULT_METRICS = build_metrics()
        return _DEFAULT_METRICS


# ---------------------------------------------------------------------------
# Hardening constants
# ---------------------------------------------------------------------------

# YAML/JSON config size guard (bytes). Overridable by env TCD_CONFIG_MAX_BYTES.
_DEFAULT_CONFIG_MAX_BYTES = 1_000_000
_MAX_CONFIG_MAX_BYTES = 10_000_000

# YAML pre-scan guards (structure explosion)
_DEFAULT_MAX_LINES = 50_000
_DEFAULT_MAX_INDENT = 256
_DEFAULT_MAX_ANCHORS = 64
_DEFAULT_MAX_ALIASES = 128

# String length caps (avoid log/digest amplification, control char injection).
_MAX_STR_SMALL = 64
_MAX_STR_MED = 256
_MAX_STR_LARGE = 2048

# Alpha bounds: smaller is stricter. Cap overly-large alpha to avoid accidental relaxations.
_MIN_ALPHA = 1e-8
_MAX_ALPHA = 0.25

# Rate limits / misc numeric caps (prevent absurd configs).
_MAX_RATE = 1_000_000.0
_MAX_TOKEN_COST_DIV = 1e9

# ledger namespace constraints
_LEDGER_NS_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

# Sanitize keys/strings: remove control chars + normalize whitespace incl CR/LF/TAB
_CTRL_RE = re.compile(r"[\x00-\x1F\x7F]+")

# Per-process salt for env fingerprinting (prevents offline guessing)
_ENV_FP_SALT = os.urandom(16)

# ---------------------------------------------------------------------------
# Security / governance field sets
# ---------------------------------------------------------------------------

# Fields that must NEVER be set by YAML/env/runtime overrides. They are derived.
_DERIVED_FIELDS: FrozenSet[str] = frozenset(
    {
        "config_signed",
        "config_signer_id",
        "config_bundle_digest",
        "config_origin",
    }
)

# Immutable fields governance (runtime): always preserved unless break-glass.
_RUNTIME_BASE_IMMUTABLE_FIELDS: FrozenSet[str] = frozenset(
    {
        "debug",
        "config_version",
        "pq_required_global",
        "receipts_enabled",
        "immutable_fields",
        "risk_score_semantics",
    }
)

# Boot-immutable fields: never overridden by YAML/env/runtime. Only loader can derive.
_BOOT_IMMUTABLE_FIELDS: FrozenSet[str] = frozenset(
    {
        "config_signed",
        "config_signer_id",
        "config_bundle_digest",
    }
)

# Bool strictness direction mapping:
#   stricter_value=True  => True is stricter, block True->False unless break-glass
#   stricter_value=False => False is stricter, block False->True unless break-glass
_BOOL_STRICTER_VALUE: Dict[str, bool] = {
    # Security/enforcement: enabling is stricter
    "pq_required_global": True,
    "decision_engine_enabled": True,
    "detector_enabled": True,
    "receipts_enabled": True,
    # Observability/network surfaces: disabling is stricter
    "debug": False,
    "allow_runtime_override": False,
    "prom_http_enable": False,
    "otel_enable": False,
    "gpu_enable": False,
    "trust_graph_enabled": False,
}

# Alpha fields: smaller is stricter
_ALPHA_FIELDS: FrozenSet[str] = frozenset({"alpha", "eprocess_alpha_default"})

# ledger backend strictness rank (higher = stricter / more auditable)
_LEDGER_STRICTNESS: Dict[str, int] = {"sql": 3, "kv": 3, "memory": 2, "noop": 0}

# Allowed ledger backends
_ALLOWED_LEDGER_BACKENDS: FrozenSet[str] = frozenset({"memory", "kv", "sql", "noop"})

# Config formats
_ALLOWED_CONFIG_FORMATS: FrozenSet[str] = frozenset({"yaml", "json"})

# ---------------------------------------------------------------------------
# Helpers: sanitization / stable encoding / env parsing
# ---------------------------------------------------------------------------


def _sanitize_text(x: Any, *, max_len: int) -> str:
    s = "" if x is None else str(x)
    s = _CTRL_RE.sub(" ", s).strip()
    s = re.sub(r"\s+", " ", s)  # collapse whitespace
    if len(s) > max_len:
        s = s[:max_len]
    return s


def _parse_bool(x: Any, default: bool) -> bool:
    if isinstance(x, bool):
        return x
    if isinstance(x, (int, float)) and math.isfinite(float(x)):
        return bool(int(x))
    if isinstance(x, str):
        v = x.strip().lower()
        if v in ("1", "true", "yes", "on"):
            return True
        if v in ("0", "false", "no", "off"):
            return False
    return bool(default)


def _parse_int(x: Any, default: int) -> int:
    try:
        return int(str(x).strip())
    except Exception:
        return int(default)


def _parse_float(x: Any, default: float) -> float:
    try:
        v = float(str(x).strip())
        return v if math.isfinite(v) else float(default)
    except Exception:
        return float(default)


def _env_get(name: str) -> Optional[str]:
    raw = os.environ.get(name)
    if raw is None:
        return None
    raw = raw.strip()
    return raw if raw != "" else None


def _env_bool(name: str, default: bool) -> Tuple[bool, bool]:
    raw = _env_get(name)
    if raw is None:
        return bool(default), False
    return _parse_bool(raw, default), True


def _env_int(name: str, default: int) -> Tuple[int, bool]:
    raw = _env_get(name)
    if raw is None:
        return int(default), False
    return _parse_int(raw, default), True


def _env_float(name: str, default: float) -> Tuple[float, bool]:
    raw = _env_get(name)
    if raw is None:
        return float(default), False
    return _parse_float(raw, default), True


def _env_str(name: str, default: str, *, max_len: int) -> Tuple[str, bool]:
    raw = _env_get(name)
    if raw is None:
        return _sanitize_text(default, max_len=max_len), False
    return _sanitize_text(raw, max_len=max_len), True


def _hmac_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _env_fingerprint(pairs: Iterable[Tuple[str, str]]) -> str:
    """
    HMAC fingerprint of (key, value_hash) pairs using process-local salt.
    Prevents leaking raw values while still detecting changes in-process.
    """
    items = sorted((str(k), str(v)) for k, v in pairs)
    h = hmac.new(_ENV_FP_SALT, digestmod=hashlib.sha256)
    for k, v in items:
        h.update(k.encode("utf-8"))
        h.update(b"=")
        h.update(v.encode("utf-8"))
        h.update(b";")
    return h.hexdigest()


def _stable_jsonable(obj: Any) -> Any:
    """
    Convert to a stable JSON-like structure:
      - frozenset/set/tuple -> sorted list
      - floats -> rounded to 12 decimals
      - dict -> keys sorted recursively
    """
    if isinstance(obj, (set, frozenset, tuple, list)):
        xs = [_stable_jsonable(x) for x in obj]
        try:
            return sorted(xs)
        except Exception:
            return xs
    if isinstance(obj, float):
        if not math.isfinite(obj):
            return None
        return round(float(obj), 12)
    if isinstance(obj, (int, bool)) or obj is None:
        return obj
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        out = {}
        for k in sorted(obj.keys(), key=lambda x: str(x)):
            out[str(k)] = _stable_jsonable(obj[k])
        return out
    return _sanitize_text(obj, max_len=_MAX_STR_LARGE)


# ---------------------------------------------------------------------------
# Break-glass (strong gating + nonce + cooldown + max TTL)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BreakGlassState:
    enabled: bool
    reason_public: str
    expires_epoch: float
    nonce: int
    token_sha256: str  # hex digest of token, never store token itself


def _format_break_glass_reason(raw: str) -> str:
    """
    Accept only controlled formats; otherwise return a short hash bucket.
      - ticket:<id>
      - incident:<id>
    """
    s = _sanitize_text(raw, max_len=_MAX_STR_MED)
    if not s:
        return ""
    m = re.match(r"^(ticket|incident):([A-Za-z0-9._-]{3,64})$", s)
    if m:
        return f"{m.group(1)}:{m.group(2)}"
    # hash-bucket
    return "reason_sha256:" + hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def _break_glass_state(now: Optional[float] = None) -> BreakGlassState:
    """
    Strict break-glass requirements (L6):
      - TOKEN present (>=16 chars)
      - ACK == f"I_UNDERSTAND_{_SETTINGS_ENGINE_VERSION}"
      - REASON present (controlled format; otherwise hashed bucket)
      - EXPIRES_EPOCH required and (expires-now) <= MAX_TTL
      - NONCE required and integer > 0 (monotonic enforced by ReloadableSettings)
    """
    ts = float(time.time() if now is None else now)

    token = _env_get("TCD_BREAK_GLASS_TOKEN") or ""
    ack = _env_get("TCD_BREAK_GLASS_ACK") or ""
    reason_raw = _env_get("TCD_BREAK_GLASS_REASON") or ""
    expires_raw = _env_get("TCD_BREAK_GLASS_EXPIRES_EPOCH") or ""
    nonce_raw = _env_get("TCD_BREAK_GLASS_NONCE") or ""

    # required
    try:
        expires = float(expires_raw)
    except Exception:
        expires = float("nan")
    try:
        nonce = int(nonce_raw)
    except Exception:
        nonce = 0

    max_ttl_s, _ = _env_int("TCD_BREAK_GLASS_MAX_TTL_S", 24 * 3600)
    max_ttl_s = max(60, min(int(max_ttl_s), 7 * 24 * 3600))

    token_ok = bool(token) and len(token) >= 16
    ack_ok = (ack.strip() == f"I_UNDERSTAND_{_SETTINGS_ENGINE_VERSION}")
    reason_public = _format_break_glass_reason(reason_raw)
    reason_ok = bool(reason_public)
    expires_ok = math.isfinite(expires) and (expires > ts) and ((expires - ts) <= float(max_ttl_s))
    nonce_ok = nonce > 0

    enabled = bool(token_ok and ack_ok and reason_ok and expires_ok and nonce_ok)
    token_sha = hashlib.sha256(token.encode("utf-8")).hexdigest() if token_ok else ""

    return BreakGlassState(
        enabled=enabled,
        reason_public=reason_public,
        expires_epoch=float(expires) if math.isfinite(expires) else 0.0,
        nonce=int(nonce) if nonce_ok else 0,
        token_sha256=token_sha,
    )


# ---------------------------------------------------------------------------
# Governance mode (prod/dev) + strictness toggles
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Governance:
    env: str
    strict: bool
    fail_fast: bool
    config_required: bool
    signature_required: bool
    config_format: str  # "yaml"|"json"
    min_ledger_backend: str  # e.g. "memory" or "kv"
    allow_insecure_otel_localhost: bool


def _governance() -> Governance:
    env, _ = _env_str("TCD_ENV", "dev", max_len=_MAX_STR_SMALL)
    env = env.lower()

    # strict defaults by environment (can be overridden)
    strict_default = (env == "prod")
    strict, used = _env_bool("TCD_STRICT_CONFIG", strict_default)

    # fail-fast mostly for boot
    fail_fast_default = (env == "prod")
    fail_fast, _ = _env_bool("TCD_CONFIG_FAIL_FAST", fail_fast_default)

    # require config file in prod unless explicitly disabled
    config_required_default = (env == "prod")
    config_required, _ = _env_bool("TCD_CONFIG_REQUIRED", config_required_default)

    # signature required in prod unless explicitly disabled
    sig_required_default = (env == "prod")
    signature_required, _ = _env_bool("TCD_CONFIG_SIGNATURE_REQUIRED", sig_required_default)

    fmt, _ = _env_str("TCD_CONFIG_FORMAT", "yaml", max_len=_MAX_STR_SMALL)
    fmt = fmt.lower()
    if fmt not in _ALLOWED_CONFIG_FORMATS:
        fmt = "yaml"

    # ledger strictness governance: default forbid noop; in prod prefer memory minimum
    min_backend, _ = _env_str("TCD_LEDGER_MIN_BACKEND", "memory" if env != "prod" else "memory", max_len=_MAX_STR_SMALL)
    min_backend = min_backend.lower()
    if min_backend not in _ALLOWED_LEDGER_BACKENDS:
        min_backend = "memory"

    allow_insecure_local, _ = _env_bool("TCD_ALLOW_INSECURE_OTEL_LOCALHOST", False)

    return Governance(
        env=env,
        strict=bool(strict),
        fail_fast=bool(fail_fast),
        config_required=bool(config_required),
        signature_required=bool(signature_required),
        config_format=fmt,
        min_ledger_backend=min_backend,
        allow_insecure_otel_localhost=bool(allow_insecure_local),
    )


# ---------------------------------------------------------------------------
# Signature verification (derived fields)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SignatureResult:
    required: bool
    verified: bool
    method: str
    signer_id: str
    bundle_digest: str
    error: str


def _read_small_file_bytes(path: str, *, max_bytes: int) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Read up to max_bytes+1 from a file using os.open + fstat (TOCTTOU-resistant).
    Returns (bytes|None, error|None).
    """
    path = _sanitize_text(path, max_len=_MAX_STR_LARGE)
    if not path:
        return None, "empty_path"

    # Reject symlink (best-effort cross-platform)
    try:
        if os.path.islink(path):
            return None, "symlink_disallowed"
    except Exception:
        pass

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= getattr(os, "O_NOFOLLOW")

    try:
        st1 = os.stat(path, follow_symlinks=False)  # type: ignore[call-arg]
    except Exception:
        return None, "stat_failed"

    fd: Optional[int] = None
    try:
        fd = os.open(path, flags)
        st2 = os.fstat(fd)

        # TOCTTOU guard: inode/device must match
        if (st1.st_ino != st2.st_ino) or (st1.st_dev != st2.st_dev):
            return None, "tocttou_inode_mismatch"

        with os.fdopen(fd, "rb") as f:
            fd = None
            data = f.read(int(max_bytes) + 1)
            if len(data) > int(max_bytes):
                return None, "file_too_large"
            return data, None
    except Exception:
        try:
            if fd is not None:
                os.close(fd)
        except Exception:
            pass
        return None, "read_failed"


def _check_config_file_permissions(path: str) -> Tuple[bool, str]:
    """
    Permission hardening:
      - must not be world-writable
      - must be owned by root or current uid (configurable patterns can be added later)
      - parent dir must not be world-writable unless sticky bit set
    """
    path = _sanitize_text(path, max_len=_MAX_STR_LARGE)
    if not path:
        return False, "empty_path"

    try:
        st = os.stat(path, follow_symlinks=False)  # type: ignore[call-arg]
    except Exception:
        return False, "stat_failed"

    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o002:
        return False, "world_writable"

    uid = os.getuid() if hasattr(os, "getuid") else None
    if uid is not None and st.st_uid not in (0, uid):
        return False, "bad_owner"

    # parent dir checks
    try:
        parent = os.path.dirname(path) or "."
        pst = os.stat(parent, follow_symlinks=False)  # type: ignore[call-arg]
        pmode = stat.S_IMODE(pst.st_mode)
        if (pmode & 0o002) and not (pmode & stat.S_ISVTX):
            return False, "parent_world_writable_no_sticky"
    except Exception:
        # If can't check, be conservative only in strict mode (handled by caller)
        return False, "parent_stat_failed"

    return True, "ok"


def _verify_signature_hmac_sha256(raw: bytes) -> Tuple[bool, str, str]:
    """
    Verify HMAC-SHA256 signature of raw bytes.

    Env:
      - TCD_CONFIG_HMAC_KEY_HEX (required)
      - signature: TCD_CONFIG_HMAC_SIG_HEX OR file at TCD_CONFIG_SIG_PATH

    Returns: (verified, signer_id, error)
    """
    key_hex = _env_get("TCD_CONFIG_HMAC_KEY_HEX") or ""
    sig_hex = _env_get("TCD_CONFIG_HMAC_SIG_HEX") or ""
    sig_path = _env_get("TCD_CONFIG_SIG_PATH") or ""
    signer_id = _sanitize_text(_env_get("TCD_CONFIG_SIGNER_ID") or "hmac", max_len=_MAX_STR_SMALL)

    try:
        key = bytes.fromhex(key_hex.strip().removeprefix("0x").removeprefix("0X"))
    except Exception:
        return False, "", "bad_hmac_key_hex"
    if len(key) < 16:
        return False, "", "hmac_key_too_short"

    if not sig_hex and sig_path:
        sb, err = _read_small_file_bytes(sig_path, max_bytes=4096)
        if sb is None:
            return False, "", f"sig_read_failed:{err}"
        sig_hex = _sanitize_text(sb.decode("utf-8", errors="replace"), max_len=_MAX_STR_MED)

    sig_hex = sig_hex.strip().removeprefix("0x").removeprefix("0X")
    if not sig_hex:
        return False, "", "missing_signature"

    try:
        want = bytes.fromhex(sig_hex)
    except Exception:
        return False, "", "bad_signature_hex"

    got = hmac.new(key, raw, hashlib.sha256).digest()
    if hmac.compare_digest(got, want):
        return True, signer_id, ""
    return False, "", "signature_mismatch"


def _verify_signature(raw: Optional[bytes], *, gov: Governance) -> SignatureResult:
    """
    Built-in signature verification. Extendable via ReloadableSettings(signature_verifier=...).
    """
    required = bool(gov.signature_required)
    if raw is None:
        return SignatureResult(required=required, verified=not required, method="none", signer_id="", bundle_digest="", error="no_raw")

    bundle_digest = hashlib.sha256(raw).hexdigest()

    method, _ = _env_str("TCD_CONFIG_SIGNATURE_METHOD", "hmac_sha256_hex", max_len=_MAX_STR_SMALL)
    method = method.lower()

    if method in ("none", ""):
        ok = (not required)
        return SignatureResult(required=required, verified=ok, method="none", signer_id="", bundle_digest=bundle_digest, error=("required_but_none" if required else ""))

    if method in ("hmac", "hmac_sha256", "hmac_sha256_hex"):
        verified, signer_id, err = _verify_signature_hmac_sha256(raw)
        return SignatureResult(required=required, verified=bool(verified), method="hmac_sha256", signer_id=signer_id, bundle_digest=bundle_digest, error=err)

    # Unknown signature method
    return SignatureResult(required=required, verified=not required, method=method, signer_id="", bundle_digest=bundle_digest, error="unknown_signature_method")


# ---------------------------------------------------------------------------
# YAML/JSON parsing (bounded + pre-scan)
# ---------------------------------------------------------------------------

def _yaml_prescan(text: str) -> Tuple[bool, str]:
    """
    Guard against structure explosion BEFORE yaml.safe_load.
    """
    max_lines, _ = _env_int("TCD_CONFIG_MAX_LINES", _DEFAULT_MAX_LINES)
    max_indent, _ = _env_int("TCD_CONFIG_MAX_INDENT", _DEFAULT_MAX_INDENT)
    max_anchors, _ = _env_int("TCD_CONFIG_MAX_ANCHORS", _DEFAULT_MAX_ANCHORS)
    max_aliases, _ = _env_int("TCD_CONFIG_MAX_ALIASES", _DEFAULT_MAX_ALIASES)

    max_lines = max(1000, min(int(max_lines), 200_000))
    max_indent = max(32, min(int(max_indent), 1024))
    max_anchors = max(0, min(int(max_anchors), 10_000))
    max_aliases = max(0, min(int(max_aliases), 20_000))

    lines = text.splitlines()
    if len(lines) > max_lines:
        return False, "too_many_lines"

    max_seen_indent = 0
    anchors = 0
    aliases = 0

    # cheap scans
    for ln in lines:
        # indent
        sp = len(ln) - len(ln.lstrip(" "))
        if sp > max_seen_indent:
            max_seen_indent = sp
        # anchors/aliases (approx)
        anchors += ln.count("&")
        aliases += ln.count("*")
        if anchors > max_anchors:
            return False, "too_many_anchors"
        if aliases > max_aliases:
            return False, "too_many_aliases"

    if max_seen_indent > max_indent:
        return False, "indent_too_deep"

    return True, "ok"


def _parse_config_mapping(raw: bytes, fmt: str) -> Tuple[Dict[str, Any], Optional[str]]:
    """
    Parse bytes into top-level mapping with strict constraints.
    """
    try:
        text = raw.decode("utf-8", errors="strict")
    except Exception:
        # If non-UTF8, reject in strict; caller decides strictness
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            return {}, "decode_failed"

    if fmt == "json":
        try:
            doc = json.loads(text)
        except Exception:
            return {}, "json_parse_failed"
        if not isinstance(doc, dict):
            return {}, "json_not_mapping"
        return doc, None

    # yaml
    ok, reason = _yaml_prescan(text)
    if not ok:
        return {}, f"yaml_prescan:{reason}"
    if yaml is None:
        return {}, "yaml_unavailable"
    try:
        doc = yaml.safe_load(text)
    except Exception:
        return {}, "yaml_parse_failed"
    if not isinstance(doc, dict):
        return {}, "yaml_not_mapping"
    return doc, None


# ---------------------------------------------------------------------------
# Settings model (frozen, pydantic v1/v2 compatible)
# ---------------------------------------------------------------------------

class Settings(BaseModel):
    # --- Core / identity (provenance-ish) --------------------------------
    debug: bool = Field(default=True)
    version: str = Field(default="dev", max_length=_MAX_STR_SMALL)
    app_name: str = Field(default="TCD Safety Sidecar", max_length=_MAX_STR_MED)
    author: str = Field(default="Amelie Liao", max_length=_MAX_STR_MED)

    # Derived provenance (MUST NOT be set by YAML/env/runtime)
    config_origin: str = Field(default="defaults", max_length=_MAX_STR_SMALL)
    config_signer_id: str = Field(default="", max_length=_MAX_STR_MED)
    config_signed: bool = Field(default=False)
    config_bundle_digest: str = Field(default="", max_length=128)

    # --- Runtime features -------------------------------------------------
    gpu_enable: bool = Field(default=False)

    receipts_enabled: bool = Field(default=False)

    # Metrics / observability
    prometheus_port: int = Field(default=8001, ge=0, le=65535)
    prom_http_enable: bool = Field(default=True)

    otel_enable: bool = Field(default=False)
    otel_endpoint: str = Field(default="", max_length=_MAX_STR_LARGE)

    # --- Global SLO / statistical control --------------------------------
    alpha: float = Field(default=0.05, gt=_MIN_ALPHA, le=_MAX_ALPHA)
    slo_latency_ms: float = Field(default=200.0, ge=1.0, le=120_000.0)
    config_version: str = Field(default="v0.1", max_length=_MAX_STR_SMALL)

    # --- HTTP rate limiting (token bucket) --------------------------------
    http_rate_capacity: float = Field(default=60.0, ge=0.0, le=_MAX_RATE)
    http_rate_refill_per_s: float = Field(default=30.0, ge=0.0, le=_MAX_RATE)

    # --- Token cost normalization -----------------------------------------
    token_cost_divisor_default: float = Field(default=50.0, gt=0.0, le=_MAX_TOKEN_COST_DIV)

    # --- PQ policy --------------------------------------------------------
    pq_required_global: bool = Field(default=False)
    pq_min_scheme: str = Field(default="dilithium2", max_length=_MAX_STR_SMALL)
    pq_audit_enabled: bool = Field(default=False)

    # --- e-process policy -------------------------------------------------
    eprocess_alpha_default: float = Field(default=0.05, gt=_MIN_ALPHA, le=_MAX_ALPHA)
    eprocess_alpha_max_delta_per_reload: float = Field(default=0.02, gt=0.0, le=0.5)
    eprocess_min_wealth: float = Field(default=0.0, ge=0.0, le=1e12)
    eprocess_policy_ref: str = Field(default="tcd-default-eprocess-policy", max_length=_MAX_STR_MED)

    # --- Governance toggles ----------------------------------------------
    decision_engine_enabled: bool = Field(default=True)
    detector_enabled: bool = Field(default=True)
    trust_graph_enabled: bool = Field(default=False)

    # Risk band semantics: drives directional constraints on low/high thresholds
    risk_score_semantics: str = Field(default="higher_is_riskier", max_length=_MAX_STR_SMALL)

    default_risk_band_low: float = Field(default=0.20, ge=0.0, le=1.0)
    default_risk_band_high: float = Field(default=0.80, ge=0.0, le=1.0)

    # --- Ledger / persistence hints ---------------------------------------
    ledger_backend: str = Field(default="memory", max_length=_MAX_STR_SMALL)  # memory|kv|sql|noop
    ledger_namespace: str = Field(default="tcd-default", max_length=_MAX_STR_SMALL)

    # --- Runtime override safety ------------------------------------------
    allow_runtime_override: bool = Field(default=True)

    immutable_fields: FrozenSet[str] = Field(
        default=frozenset({"debug", "config_version", "pq_required_global", "receipts_enabled", "risk_score_semantics"})
    )

    # pydantic v2
    if ConfigDict is not None:  # pragma: no cover
        model_config = ConfigDict(extra="forbid", frozen=True)

    # pydantic v1
    class Config:  # pragma: no cover
        extra = "forbid"
        allow_mutation = False

    # ---- helpers ----

    @classmethod
    def field_names(cls) -> FrozenSet[str]:
        mf = getattr(cls, "model_fields", None)
        if isinstance(mf, dict):  # v2
            return frozenset(mf.keys())
        ff = getattr(cls, "__fields__", None)  # v1
        if isinstance(ff, dict):
            return frozenset(ff.keys())
        return frozenset()

    def effective_hash(self) -> str:
        """
        Hash of *behavior-affecting* fields only (excludes provenance fields like author/config_origin/signature metadata).
        """
        payload = _stable_jsonable(_model_dump_any(self))
        exclude = {"version", "app_name", "author", "config_origin", "config_signer_id", "config_signed", "config_bundle_digest"}
        eff = {k: v for k, v in payload.items() if k not in exclude}
        eff["settings_engine_version"] = _SETTINGS_ENGINE_VERSION
        return canonical_kv_hash(eff, ctx="tcd:settings:effective", label="settings_effective")

    def provenance_hash(self) -> str:
        """
        Hash including provenance-ish fields. Useful for auditing source/signature changes.
        """
        payload = _stable_jsonable(_model_dump_any(self))
        payload["settings_engine_version"] = _SETTINGS_ENGINE_VERSION
        return canonical_kv_hash(payload, ctx="tcd:settings:provenance", label="settings_provenance")

    # Backward compatible name: treat config_hash as effective hash
    def config_hash(self) -> str:
        return self.effective_hash()


# ---------------------------------------------------------------------------
# Model dump helper (pydantic v1/v2)
# ---------------------------------------------------------------------------

def _model_dump_any(m: BaseModel) -> Dict[str, Any]:
    try:
        return m.model_dump(mode="json")  # type: ignore[attr-defined]
    except Exception:
        try:
            return m.dict()
        except Exception:
            return {}


# ---------------------------------------------------------------------------
# Normalization & cross-field constraints (single-source-of-truth)
# ---------------------------------------------------------------------------

def _validate_endpoint_ssrf_safe(url: str, *, gov: Governance) -> Tuple[bool, str]:
    """
    Minimal SSRF guard for otel_endpoint:
      - allow https always
      - allow http only if localhost and gov.allow_insecure_otel_localhost
      - disallow file/ftp/gopher/etc
      - disallow userinfo
      - disallow literal private/loopback/link-local IPs
    """
    from urllib.parse import urlparse

    u = _sanitize_text(url, max_len=_MAX_STR_LARGE)
    if not u:
        return False, "empty"

    p = urlparse(u)
    scheme = (p.scheme or "").lower()
    if scheme not in ("https", "http"):
        return False, "bad_scheme"

    if p.username or p.password:
        return False, "userinfo_disallowed"

    host = (p.hostname or "").strip().lower()
    if not host:
        return False, "no_host"

    # localhost exception
    if scheme == "http":
        if not gov.allow_insecure_otel_localhost:
            return False, "http_disallowed"
        if host not in ("localhost", "127.0.0.1", "::1"):
            return False, "http_non_localhost_disallowed"

    # ip literal checks
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            return False, "ip_disallowed"
    except Exception:
        # hostname: allow (full DNS resolution policy is out-of-scope for stdlib-only loader)
        pass

    return True, "ok"


def _normalize_settings_dict(raw: Mapping[str, Any], *, base: Settings, gov: Governance) -> Tuple[Dict[str, Any], List[str], List[str]]:
    """
    Normalize untrusted-ish dict into safe values that Settings(**d) will accept.
    Returns: (normalized_dict, warnings, errors)
    """
    warnings: List[str] = []
    errors: List[str] = []

    allowed = Settings.field_names()
    base_d = _model_dump_any(base)
    d: Dict[str, Any] = dict(base_d)

    # Only accept known keys
    for k, v in raw.items():
        if k in allowed:
            d[k] = v

    # Enforce derived fields (caller sets later)
    for k in _DERIVED_FIELDS | _BOOT_IMMUTABLE_FIELDS:
        if k in d:
            # keep base value; derived is applied separately
            d[k] = base_d.get(k)

    # booleans
    for bkey in (
        "debug",
        "gpu_enable",
        "receipts_enabled",
        "prom_http_enable",
        "otel_enable",
        "pq_required_global",
        "pq_audit_enabled",
        "decision_engine_enabled",
        "detector_enabled",
        "trust_graph_enabled",
        "allow_runtime_override",
        "config_signed",
    ):
        d[bkey] = _parse_bool(d.get(bkey), bool(base_d.get(bkey, False)))

    # ints
    port = _parse_int(d.get("prometheus_port"), int(base_d.get("prometheus_port", 8001)))
    port = max(0, min(int(port), 65535))
    d["prometheus_port"] = port

    # floats bounded + rounded
    def _clamp_float(name: str, lo: float, hi: float) -> None:
        v = _parse_float(d.get(name), float(base_d.get(name, 0.0)))
        if not math.isfinite(v):
            warnings.append(f"{name}:nonfinite")
            v = float(base_d.get(name, 0.0))
        v = max(lo, min(hi, v))
        d[name] = round(float(v), 12)

    _clamp_float("alpha", _MIN_ALPHA, _MAX_ALPHA)
    _clamp_float("slo_latency_ms", 1.0, 120_000.0)
    _clamp_float("http_rate_capacity", 0.0, _MAX_RATE)
    _clamp_float("http_rate_refill_per_s", 0.0, _MAX_RATE)
    _clamp_float("token_cost_divisor_default", _MIN_ALPHA, _MAX_TOKEN_COST_DIV)  # reuse min guard
    _clamp_float("eprocess_alpha_default", _MIN_ALPHA, _MAX_ALPHA)
    _clamp_float("eprocess_alpha_max_delta_per_reload", 1e-12, 0.5)
    _clamp_float("eprocess_min_wealth", 0.0, 1e12)

    # risk bands: clamp and order
    low = float(d.get("default_risk_band_low", 0.2))
    high = float(d.get("default_risk_band_high", 0.8))
    if not (math.isfinite(low) and math.isfinite(high)):
        warnings.append("risk_band:nonfinite")
        low = float(base_d.get("default_risk_band_low", 0.2))
        high = float(base_d.get("default_risk_band_high", 0.8))
    low = min(max(low, 0.0), 1.0)
    high = min(max(high, 0.0), 1.0)
    if low > high:
        low, high = high, low
    d["default_risk_band_low"] = round(low, 12)
    d["default_risk_band_high"] = round(high, 12)

    # strings sanitized
    def _s(name: str, max_len: int) -> None:
        d[name] = _sanitize_text(d.get(name, base_d.get(name, "")), max_len=max_len)

    _s("version", _MAX_STR_SMALL)
    _s("app_name", _MAX_STR_MED)
    _s("author", _MAX_STR_MED)
    _s("config_origin", _MAX_STR_SMALL)
    _s("config_signer_id", _MAX_STR_MED)
    _s("otel_endpoint", _MAX_STR_LARGE)
    _s("config_version", _MAX_STR_SMALL)
    _s("pq_min_scheme", _MAX_STR_SMALL)
    _s("eprocess_policy_ref", _MAX_STR_MED)
    _s("ledger_backend", _MAX_STR_SMALL)
    _s("ledger_namespace", _MAX_STR_SMALL)
    _s("risk_score_semantics", _MAX_STR_SMALL)

    # risk semantics allowlist
    sem = str(d.get("risk_score_semantics") or "").lower()
    if sem not in ("higher_is_riskier", "lower_is_riskier"):
        warnings.append("risk_score_semantics:invalid")
        sem = str(base_d.get("risk_score_semantics", "higher_is_riskier"))
    d["risk_score_semantics"] = sem

    # ledger backend allowlist
    lb = str(d.get("ledger_backend") or "").lower()
    if lb not in _ALLOWED_LEDGER_BACKENDS:
        warnings.append("ledger_backend:invalid")
        lb = str(base_d.get("ledger_backend", "memory"))
    d["ledger_backend"] = lb

    # ledger namespace regex
    ns = str(d.get("ledger_namespace") or "")
    if not _LEDGER_NS_RE.match(ns):
        warnings.append("ledger_namespace:invalid")
        d["ledger_namespace"] = str(base_d.get("ledger_namespace", "tcd-default"))

    # cross-field: prom_http_enable False => port 0
    if not bool(d.get("prom_http_enable", True)):
        d["prometheus_port"] = 0

    # cross-field: otel_enable True => endpoint must be valid and SSRF safe
    if bool(d.get("otel_enable", False)):
        ok, reason = _validate_endpoint_ssrf_safe(str(d.get("otel_endpoint") or ""), gov=gov)
        if not ok:
            errors.append(f"otel_endpoint:{reason}")

    # immutable_fields: must be subset of known fields; must include runtime baseline; cap size
    raw_immut = d.get("immutable_fields", base_d.get("immutable_fields", frozenset()))
    items: List[str] = []
    max_items = 64
    if isinstance(raw_immut, (set, frozenset, list, tuple)):
        for x in raw_immut:
            if len(items) >= max_items:
                break
            s = _sanitize_text(x, max_len=_MAX_STR_SMALL)
            if s in allowed:
                items.append(s)
    elif isinstance(raw_immut, str):
        for part in raw_immut.split(","):
            if len(items) >= max_items:
                break
            s = _sanitize_text(part, max_len=_MAX_STR_SMALL)
            if s in allowed:
                items.append(s)

    imm = frozenset(items) | _RUNTIME_BASE_IMMUTABLE_FIELDS
    d["immutable_fields"] = imm

    return d, warnings, errors


# ---------------------------------------------------------------------------
# Policy engine: evaluate candidate w/ constraints (single entrypoint)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EvalContext:
    is_boot: bool
    is_runtime_override: bool
    break_glass: BreakGlassState
    gov: Governance


@dataclass(frozen=True)
class EvalResult:
    ok: bool
    settings: Settings
    changed_fields: Tuple[str, ...]
    blocked: Tuple[Tuple[str, str], ...]  # (field, kind)
    warnings: Tuple[str, ...]
    errors: Tuple[str, ...]


def _ledger_strictness(backend: str) -> int:
    return int(_LEDGER_STRICTNESS.get(str(backend).lower(), 0))


def _apply_directional(
    field: str,
    old_value: Any,
    new_value: Any,
    *,
    ctx: EvalContext,
    alpha_max_delta: float,
    old_settings: Settings,
) -> Tuple[Any, Optional[str]]:
    """
    Returns (value, blocked_kind_if_any)
    """
    bg = ctx.break_glass.enabled

    # bool directional
    if field in _BOOL_STRICTER_VALUE and isinstance(old_value, bool) and isinstance(new_value, bool):
        stricter_true = bool(_BOOL_STRICTER_VALUE[field])

        def is_relaxation(old: bool, new: bool) -> bool:
            if stricter_true:
                return old is True and new is False
            return old is False and new is True

        if is_relaxation(old_value, new_value) and not bg:
            return old_value, "directional"
        return new_value, None

    # alpha directional
    if field in _ALPHA_FIELDS and isinstance(old_value, (int, float)) and isinstance(new_value, (int, float)):
        old_f = float(old_value)
        new_f = float(new_value)
        if not (math.isfinite(old_f) and math.isfinite(new_f)):
            return old_value, "directional"

        old_f = min(max(old_f, _MIN_ALPHA), _MAX_ALPHA)
        new_f = min(max(new_f, _MIN_ALPHA), _MAX_ALPHA)

        # per-reload delta bound for e-process alpha (both directions) unless break-glass
        if field == "eprocess_alpha_default" and not bg:
            if abs(new_f - old_f) > float(alpha_max_delta):
                return old_f, "alpha_delta"

        # tightening allowed
        if new_f <= old_f:
            return new_f, None

        # relaxation only under break-glass
        return (new_f, None) if bg else (old_f, "directional")

    # ledger backend downgrade protection (audit strength)
    if field == "ledger_backend":
        old_b = str(old_value or "").lower()
        new_b = str(new_value or "").lower()
        if new_b not in _ALLOWED_LEDGER_BACKENDS:
            return old_value, "directional"
        # minimum backend from governance
        min_rank = _ledger_strictness(ctx.gov.min_ledger_backend)
        if _ledger_strictness(new_b) < min_rank and not bg:
            return old_value, "ledger_downgrade"
        # prevent downgrade relative to old unless break-glass
        if _ledger_strictness(new_b) < _ledger_strictness(old_b) and not bg:
            return old_value, "ledger_downgrade"
        return new_b, None

    # risk band directional (depends on semantics)
    if field in ("default_risk_band_low", "default_risk_band_high"):
        try:
            old_f = float(old_value)
            new_f = float(new_value)
        except Exception:
            return old_value, "risk_band"
        if not (math.isfinite(old_f) and math.isfinite(new_f)):
            return old_value, "risk_band"

        sem = str(old_settings.risk_score_semantics or "higher_is_riskier").lower()
        # semantics treated immutable by default; if it changes, it must be break-glass.
        if sem not in ("higher_is_riskier", "lower_is_riskier"):
            sem = "higher_is_riskier"

        if field == "default_risk_band_low":
            # stricter = increase low threshold (both semantics in our definition)
            if (new_f < old_f) and (not bg):
                return old_f, "risk_band"
            return new_f, None

        # high threshold:
        if sem == "higher_is_riskier":
            # stricter = decrease high threshold
            if (new_f > old_f) and (not bg):
                return old_f, "risk_band"
            return new_f, None
        else:
            # lower_is_riskier: stricter = increase high threshold (harder to be low risk)
            if (new_f < old_f) and (not bg):
                return old_f, "risk_band"
            return new_f, None

    return new_value, None


def evaluate_candidate(old: Settings, candidate: Settings, *, ctx: EvalContext) -> EvalResult:
    """
    Single-source-of-truth evaluator for:
      - boot guardrails (old=base defaults)
      - refresh (old=current)
      - set (old=current, candidate=override-applied)
    """
    blocked: List[Tuple[str, str]] = []
    warnings: List[str] = []
    errors: List[str] = []

    old_d = _model_dump_any(old)
    cand_d = _model_dump_any(candidate)

    # break-glass gauge
    try:
        _metrics().break_glass_enabled.set(1.0 if ctx.break_glass.enabled else 0.0)
    except Exception:
        pass

    # immutable_fields tighten-only unless break-glass
    old_immut = set(old.immutable_fields or frozenset())
    cand_immut = set(candidate.immutable_fields or frozenset())

    if not ctx.break_glass.enabled:
        merged_immut = frozenset(old_immut | cand_immut | _RUNTIME_BASE_IMMUTABLE_FIELDS)
    else:
        merged_immut = frozenset(cand_immut | _RUNTIME_BASE_IMMUTABLE_FIELDS)

    cand_d["immutable_fields"] = merged_immut

    # boot-immutable & derived fields: never allow external mutation
    for k in _BOOT_IMMUTABLE_FIELDS:
        cand_d[k] = old_d.get(k)

    # preserve immutable fields unless break-glass
    immutables = set(merged_immut if not ctx.break_glass.enabled else _RUNTIME_BASE_IMMUTABLE_FIELDS)

    alpha_delta = float(old_d.get("eprocess_alpha_max_delta_per_reload", 0.02))
    if not (math.isfinite(alpha_delta) and alpha_delta > 0.0):
        alpha_delta = 0.02

    # enforce fieldwise constraints
    for key, old_value in old_d.items():
        if key not in cand_d:
            cand_d[key] = old_value
            continue

        if (not ctx.break_glass.enabled) and (key in immutables):
            if cand_d.get(key) != old_value:
                blocked.append((key, "immutable"))
                try:
                    _metrics().constraint_block_total.labels("immutable").inc()
                except Exception:
                    pass
            cand_d[key] = old_value
            continue

        # derived fields are enforced separately by loader; keep candidate's if loader set it
        if key in _DERIVED_FIELDS:
            continue

        v, blk = _apply_directional(
            key,
            old_value,
            cand_d.get(key),
            ctx=ctx,
            alpha_max_delta=alpha_delta,
            old_settings=old,
        )
        if blk:
            blocked.append((key, blk))
            try:
                _metrics().constraint_block_total.labels(blk).inc()
            except Exception:
                pass
        cand_d[key] = v

    # normalize again to ensure cross-field invariants after constraints
    gov = ctx.gov
    base_for_norm = old if not ctx.is_boot else old
    norm_d, norm_warn, norm_err = _normalize_settings_dict(cand_d, base=base_for_norm, gov=gov)
    warnings.extend(norm_warn)
    errors.extend(norm_err)

    # construct Settings; never throw
    try:
        final = Settings(**norm_d)
    except Exception:
        errors.append("validation_failed_after_constraints")
        final = old

    # ledger backend strict min already enforced in directional; keep
    # risk band ordering already normalized; keep

    # compute changed_fields using effective hash comparison by field (names only)
    changed: List[str] = []
    final_d = _model_dump_any(final)
    for k in final_d.keys():
        if k in {"config_origin", "author", "app_name", "version"}:
            # provenance-ish fields excluded from "effective changed_fields" list
            continue
        if final_d.get(k) != old_d.get(k):
            changed.append(k)
    if len(changed) > 64:
        changed = changed[:64] + ["..."]

    ok = (len(errors) == 0)
    return EvalResult(
        ok=ok,
        settings=final,
        changed_fields=tuple(sorted(changed)),
        blocked=tuple(blocked),
        warnings=tuple(warnings[:64]),
        errors=tuple(errors[:64]),
    )


# ---------------------------------------------------------------------------
# Load result / provenance meta (fixes "silent fallback" problem)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LoadMeta:
    ts: float
    env: str
    strict: bool
    format: str
    yaml_path_hash: str
    file_mtime_ns: int
    file_inode: int
    file_size: int
    file_digest: str
    env_fingerprint: str
    env_applied_keys_hash: str
    signature: SignatureResult
    break_glass: BreakGlassState


@dataclass(frozen=True)
class LoadResult:
    ok: bool
    settings: Settings
    errors: Tuple[str, ...]
    warnings: Tuple[str, ...]
    sources: Tuple[str, ...]  # subset of {"defaults","yaml","json","env","runtime"}
    meta: LoadMeta


# ---------------------------------------------------------------------------
# Loader: returns LoadResult (NEVER silently returns defaults as "ok")
# ---------------------------------------------------------------------------

def _default_base_settings(gov: Governance) -> Settings:
    """
    Prod-safe defaults (per your checklist): in prod, default-close debug + runtime overrides + prom_http.
    """
    base = Settings()
    if gov.env == "prod":
        d = _model_dump_any(base)
        d["debug"] = False
        d["allow_runtime_override"] = False
        d["prom_http_enable"] = False
        d["prometheus_port"] = 0
        # keep other defaults unless explicitly overridden
        try:
            return Settings(**d)
        except Exception:
            return base
    return base


def _load_settings_result(
    *,
    gov: Optional[Governance] = None,
    signature_verifier: Optional[Callable[[bytes, Governance], SignatureResult]] = None,
    is_boot: bool,
) -> LoadResult:
    """
    Load Settings from defaults + file + env with strict, observable semantics.
    - Never "pretend ok": if parse/validate/signature fails, ok=False and errors populated.
    """
    fam = _metrics()
    g = gov or _governance()
    base = _default_base_settings(g)

    errors: List[str] = []
    warnings: List[str] = []
    sources: List[str] = ["defaults"]

    bg = _break_glass_state()
    # break-glass enabled itself is recorded in meta and gauge; monotonic nonce checked in ReloadableSettings

    # config path & format
    cfg_path, _ = _env_str("TCD_CONFIG_PATH", "", max_len=_MAX_STR_LARGE)

    if g.config_required and not cfg_path:
        errors.append("config_required_missing")

    fmt = g.config_format

    max_bytes, _ = _env_int("TCD_CONFIG_MAX_BYTES", _DEFAULT_CONFIG_MAX_BYTES)
    max_bytes = max(1, min(int(max_bytes), _MAX_CONFIG_MAX_BYTES))

    raw_bytes: Optional[bytes] = None
    parse_doc: Dict[str, Any] = {}

    file_mtime_ns = 0
    file_inode = 0
    file_size = 0
    file_digest = ""

    # Load file if provided
    if cfg_path:
        # Permission checks
        perm_ok, perm_reason = _check_config_file_permissions(cfg_path)
        if not perm_ok:
            # In strict mode, treat as error; in lenient, warn and ignore
            if g.strict:
                errors.append(f"config_permission:{perm_reason}")
                try:
                    fam.yaml_permission_denied_total.inc()
                except Exception:
                    pass
            else:
                warnings.append(f"config_permission:{perm_reason}")
                try:
                    fam.yaml_permission_denied_total.inc()
                except Exception:
                    pass
        else:
            # bounded read
            rb, rerr = _read_small_file_bytes(cfg_path, max_bytes=max_bytes)
            if rb is None:
                if rerr == "file_too_large":
                    try:
                        fam.yaml_too_large_total.inc()
                    except Exception:
                        pass
                if g.strict:
                    errors.append(f"config_read:{rerr}")
                else:
                    warnings.append(f"config_read:{rerr}")
            else:
                raw_bytes = rb
                try:
                    st = os.stat(cfg_path, follow_symlinks=False)  # type: ignore[call-arg]
                    file_mtime_ns = int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))
                    file_inode = int(getattr(st, "st_ino", 0))
                    file_size = int(getattr(st, "st_size", len(rb)))
                except Exception:
                    pass
                file_digest = hashlib.sha256(rb).hexdigest()

                # parse mapping
                doc, perr = _parse_config_mapping(rb, fmt=fmt)
                if perr is not None:
                    try:
                        fam.yaml_parse_fail_total.inc()
                    except Exception:
                        pass
                    if g.strict:
                        errors.append(f"config_parse:{perr}")
                    else:
                        warnings.append(f"config_parse:{perr}")
                else:
                    parse_doc = doc
                    sources.append("json" if fmt == "json" else "yaml")

    # signature verification: derived fields
    sig: SignatureResult
    if raw_bytes is None:
        # no raw => cannot verify, but might still be ok in non-required mode
        sig = SignatureResult(
            required=bool(g.signature_required),
            verified=not bool(g.signature_required),
            method="none",
            signer_id="",
            bundle_digest="",
            error="no_raw",
        )
        if g.signature_required and cfg_path:
            errors.append("signature_required_but_no_raw")
    else:
        verifier = signature_verifier
        if verifier is not None:
            try:
                sig = verifier(raw_bytes, g)
            except Exception:
                sig = _verify_signature(raw_bytes, gov=g)
                errors.append("signature_verifier_exception")
        else:
            sig = _verify_signature(raw_bytes, gov=g)

        if sig.required and not sig.verified:
            try:
                fam.signature_fail_total.inc()
            except Exception:
                pass
            errors.append(f"signature_failed:{sig.error}")

    # Merge base + file doc
    merged: Dict[str, Any] = dict(_model_dump_any(base))

    # Filter doc keys:
    # - only accept known keys
    # - reject derived/boot-immutable keys from file
    allowed = Settings.field_names()
    for k, v in parse_doc.items():
        kk = _sanitize_text(k, max_len=_MAX_STR_MED)
        if kk not in allowed:
            continue
        if kk in _DERIVED_FIELDS or kk in _BOOT_IMMUTABLE_FIELDS:
            # never accept from config
            warnings.append(f"ignored_derived_key:{kk}")
            continue
        merged[kk] = v

    # Environment overrides (bounded). Some keys are env-locked.
    env_locked_fields: FrozenSet[str] = frozenset(
        {
            "pq_required_global",
            "receipts_enabled",
            "config_version",
            "immutable_fields",
            # derived/boot-immutable:
            *tuple(_DERIVED_FIELDS),
            *tuple(_BOOT_IMMUTABLE_FIELDS),
        }
    )

    applied_env_keys: List[str] = []
    env_pairs_for_fp: List[Tuple[str, str]] = []

    def _apply_env(name: str, key: str, val: Any, used: bool) -> None:
        nonlocal merged
        if not used:
            return
        if key in env_locked_fields:
            warnings.append(f"env_locked:{key}")
            return
        merged[key] = val
        applied_env_keys.append(name)
        # value fingerprint uses hash only
        env_pairs_for_fp.append((name, hashlib.sha256(str(val).encode("utf-8")).hexdigest()[:16]))

    # Apply env overrides
    v, used = _env_bool("TCD_DEBUG", bool(merged.get("debug", True)))
    _apply_env("TCD_DEBUG", "debug", v, used)

    s, used = _env_str("TCD_VERSION", str(merged.get("version", "dev")), max_len=_MAX_STR_SMALL)
    _apply_env("TCD_VERSION", "version", s, used)

    v, used = _env_bool("TCD_GPU_ENABLE", bool(merged.get("gpu_enable", False)))
    _apply_env("TCD_GPU_ENABLE", "gpu_enable", v, used)

    v, used = _env_bool("TCD_RECEIPTS_ENABLE", bool(merged.get("receipts_enabled", False)))
    _apply_env("TCD_RECEIPTS_ENABLE", "receipts_enabled", v, used)

    port, used = _env_int("TCD_PROM_PORT", int(merged.get("prometheus_port", 8001)))
    if used:
        port = max(0, min(int(port), 65535))
    _apply_env("TCD_PROM_PORT", "prometheus_port", port, used)

    v, used = _env_bool("TCD_PROM_HTTP_ENABLE", bool(merged.get("prom_http_enable", True)))
    _apply_env("TCD_PROM_HTTP_ENABLE", "prom_http_enable", v, used)

    v, used = _env_bool("TCD_OTEL_ENABLE", bool(merged.get("otel_enable", False)))
    _apply_env("TCD_OTEL_ENABLE", "otel_enable", v, used)

    s, used = _env_str("TCD_OTEL_ENDPOINT", str(merged.get("otel_endpoint", "")), max_len=_MAX_STR_LARGE)
    _apply_env("TCD_OTEL_ENDPOINT", "otel_endpoint", s, used)

    alpha, used = _env_float("TCD_ALPHA", float(merged.get("alpha", 0.05)))
    if used:
        _apply_env("TCD_ALPHA", "alpha", alpha, True)

    slo, used = _env_float("TCD_SLO_MS", float(merged.get("slo_latency_ms", 200.0)))
    if used:
        _apply_env("TCD_SLO_MS", "slo_latency_ms", slo, True)

    cap, used = _env_float("TCD_HTTP_RATE_CAP", float(merged.get("http_rate_capacity", 60.0)))
    if used:
        _apply_env("TCD_HTTP_RATE_CAP", "http_rate_capacity", cap, True)

    refill, used = _env_float("TCD_HTTP_RATE_REFILL", float(merged.get("http_rate_refill_per_s", 30.0)))
    if used:
        _apply_env("TCD_HTTP_RATE_REFILL", "http_rate_refill_per_s", refill, True)

    tcost, used = _env_float("TCD_TOKEN_COST_DIVISOR", float(merged.get("token_cost_divisor_default", 50.0)))
    if used:
        _apply_env("TCD_TOKEN_COST_DIVISOR", "token_cost_divisor_default", tcost, True)

    s, used = _env_str("TCD_PQ_MIN_SCHEME", str(merged.get("pq_min_scheme", "dilithium2")), max_len=_MAX_STR_SMALL)
    _apply_env("TCD_PQ_MIN_SCHEME", "pq_min_scheme", s, used)

    v, used = _env_bool("TCD_PQ_AUDIT_ENABLED", bool(merged.get("pq_audit_enabled", False)))
    _apply_env("TCD_PQ_AUDIT_ENABLED", "pq_audit_enabled", v, used)

    ealpha, used = _env_float("TCD_EPROC_ALPHA", float(merged.get("eprocess_alpha_default", 0.05)))
    if used:
        _apply_env("TCD_EPROC_ALPHA", "eprocess_alpha_default", ealpha, True)

    edelta, used = _env_float("TCD_EPROC_ALPHA_MAX_DELTA", float(merged.get("eprocess_alpha_max_delta_per_reload", 0.02)))
    if used:
        _apply_env("TCD_EPROC_ALPHA_MAX_DELTA", "eprocess_alpha_max_delta_per_reload", edelta, True)

    eminw, used = _env_float("TCD_EPROC_MIN_WEALTH", float(merged.get("eprocess_min_wealth", 0.0)))
    if used:
        _apply_env("TCD_EPROC_MIN_WEALTH", "eprocess_min_wealth", eminw, True)

    s, used = _env_str("TCD_EPROC_POLICY_REF", str(merged.get("eprocess_policy_ref", "")), max_len=_MAX_STR_MED)
    _apply_env("TCD_EPROC_POLICY_REF", "eprocess_policy_ref", s, used)

    v, used = _env_bool("TCD_DECISION_ENGINE_ENABLED", bool(merged.get("decision_engine_enabled", True)))
    _apply_env("TCD_DECISION_ENGINE_ENABLED", "decision_engine_enabled", v, used)

    v, used = _env_bool("TCD_DETECTOR_ENABLED", bool(merged.get("detector_enabled", True)))
    _apply_env("TCD_DETECTOR_ENABLED", "detector_enabled", v, used)

    v, used = _env_bool("TCD_TRUST_GRAPH_ENABLED", bool(merged.get("trust_graph_enabled", False)))
    _apply_env("TCD_TRUST_GRAPH_ENABLED", "trust_graph_enabled", v, used)

    s, used = _env_str("TCD_LEDGER_BACKEND", str(merged.get("ledger_backend", "memory")), max_len=_MAX_STR_SMALL)
    _apply_env("TCD_LEDGER_BACKEND", "ledger_backend", s, used)

    s, used = _env_str("TCD_LEDGER_NAMESPACE", str(merged.get("ledger_namespace", "tcd-default")), max_len=_MAX_STR_SMALL)
    _apply_env("TCD_LEDGER_NAMESPACE", "ledger_namespace", s, used)

    v, used = _env_bool("TCD_ALLOW_RUNTIME_OVERRIDE", bool(merged.get("allow_runtime_override", True)))
    _apply_env("TCD_ALLOW_RUNTIME_OVERRIDE", "allow_runtime_override", v, used)

    s, used = _env_str("TCD_RISK_SCORE_SEMANTICS", str(merged.get("risk_score_semantics", "higher_is_riskier")), max_len=_MAX_STR_SMALL)
    _apply_env("TCD_RISK_SCORE_SEMANTICS", "risk_score_semantics", s, used)

    low, used_low = _env_float("TCD_RISK_BAND_LOW", float(merged.get("default_risk_band_low", 0.2)))
    high, used_high = _env_float("TCD_RISK_BAND_HIGH", float(merged.get("default_risk_band_high", 0.8)))
    if used_low:
        _apply_env("TCD_RISK_BAND_LOW", "default_risk_band_low", low, True)
    if used_high:
        _apply_env("TCD_RISK_BAND_HIGH", "default_risk_band_high", high, True)

    if applied_env_keys:
        sources.append("env")

    # config_origin derived from sources
    origin = "+".join(sources)
    merged["config_origin"] = origin

    # derived signature fields
    merged["config_signed"] = bool(sig.verified)
    merged["config_signer_id"] = sig.signer_id
    merged["config_bundle_digest"] = sig.bundle_digest

    # normalize
    norm_d, norm_warn, norm_err = _normalize_settings_dict(merged, base=base, gov=g)
    warnings.extend(norm_warn)
    errors.extend(norm_err)

    # build candidate settings; if this fails, ok=False (no silent ok)
    try:
        candidate = Settings(**norm_d)
    except Exception:
        candidate = base
        errors.append("validation_failed")

    # boot-time guardrails: do not relax relative to base defaults unless break-glass
    ctx = EvalContext(is_boot=is_boot, is_runtime_override=False, break_glass=bg, gov=g)
    eval_res = evaluate_candidate(base, candidate, ctx=ctx)
    if not eval_res.ok:
        errors.extend(list(eval_res.errors))
    candidate_final = eval_res.settings

    # overall ok decision:
    ok = (len(errors) == 0)

    # metrics: load_total for sources
    # choose primary source tag for counter (one per load)
    source_tag = "defaults"
    if "json" in sources:
        source_tag = "json"
    elif "yaml" in sources:
        source_tag = "yaml"
    elif "env" in sources:
        source_tag = "env"

    try:
        fam.load_total.labels("ok" if ok else "fail", source_tag).inc()
    except Exception:
        pass

    env_applied_keys_hash = hashlib.sha256(",".join(sorted(applied_env_keys))[:4096].encode("utf-8")).hexdigest()
    env_fp = _env_fingerprint(env_pairs_for_fp)

    meta = LoadMeta(
        ts=float(time.time()),
        env=g.env,
        strict=bool(g.strict),
        format=str(fmt),
        yaml_path_hash=hashlib.sha256(_sanitize_text(cfg_path, max_len=_MAX_STR_LARGE).encode("utf-8")).hexdigest()[:16] if cfg_path else "",
        file_mtime_ns=int(file_mtime_ns),
        file_inode=int(file_inode),
        file_size=int(file_size),
        file_digest=str(file_digest),
        env_fingerprint=str(env_fp),
        env_applied_keys_hash=str(env_applied_keys_hash),
        signature=sig,
        break_glass=bg,
    )

    return LoadResult(
        ok=ok,
        settings=candidate_final,
        errors=tuple(errors[:128]),
        warnings=tuple(warnings[:128]),
        sources=tuple(sources),
        meta=meta,
    )


# ---------------------------------------------------------------------------
# ReloadableSettings (thread-safe + never-throw refresh/set + no-op stability)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ApplyReport:
    ok: bool
    applied: bool
    noop: bool
    changed_fields: Tuple[str, ...]
    blocked: Tuple[Tuple[str, str], ...]
    errors: Tuple[str, ...]
    warnings: Tuple[str, ...]
    meta: Optional[LoadMeta]


class ReloadableSettings:
    """
    Thread-safe wrapper around Settings with controlled refresh/override.

    Key guarantees (per checklist):
      - refresh()/set() never throw.
      - refresh() does NOT commit / does NOT bump revision if load failed.
      - revision bumps only when effective_hash changes.
      - get_state() returns an atomic (settings, revision, state_digest) snapshot.
      - break-glass nonce monotonic + cooldown enforced in-process.
    """

    def __init__(
        self,
        initial: Settings,
        *,
        metrics: Optional[_Metrics] = None,
        signature_verifier: Optional[Callable[[bytes, Governance], SignatureResult]] = None,
        audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        gov: Optional[Governance] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._metrics = metrics or _metrics()
        self._signature_verifier = signature_verifier
        self._audit_sink = audit_sink
        self._gov = gov or _governance()

        self._settings = initial
        self._revision = 0
        self._last_error: str = ""
        self._last_report: Optional[ApplyReport] = None
        self._last_load_meta: Optional[LoadMeta] = None

        # break-glass controls (monotonic nonce + cooldown)
        self._last_bg_nonce: int = 0
        self._last_bg_enable_ts: float = 0.0

        # caching for refresh_if_changed
        self._last_source_fp: Optional[Tuple[str, int, int, str]] = None  # (file_digest, mtime_ns, inode, env_fp)

    def get(self) -> Settings:
        with self._lock:
            return self._settings

    def revision(self) -> int:
        with self._lock:
            return int(self._revision)

    def get_state(self) -> Tuple[Settings, int, str]:
        with self._lock:
            st = self._settings
            rev = int(self._revision)
            digest = self.state_digest()
            return st, rev, digest

    def state_digest(self) -> str:
        with self._lock:
            payload = {
                "settings_engine_version": _SETTINGS_ENGINE_VERSION,
                "effective_hash": self._settings.effective_hash(),
                "revision": int(self._revision),
            }
            return canonical_kv_hash(payload, ctx="tcd:settings_state", label="settings_state")

    def provenance_digest(self) -> str:
        with self._lock:
            payload = {
                "settings_engine_version": _SETTINGS_ENGINE_VERSION,
                "provenance_hash": self._settings.provenance_hash(),
                "revision": int(self._revision),
            }
            return canonical_kv_hash(payload, ctx="tcd:settings_provenance_state", label="settings_provenance_state")

    def last_error(self) -> str:
        with self._lock:
            return self._last_error

    def last_report(self) -> Optional[ApplyReport]:
        with self._lock:
            return self._last_report

    def last_load_meta(self) -> Optional[LoadMeta]:
        with self._lock:
            return self._last_load_meta

    def _emit_audit(self, kind: str, report: ApplyReport) -> None:
        if not self._audit_sink:
            return
        try:
            payload = {
                "ts": float(time.time()),
                "kind": str(kind),
                "env": self._gov.env,
                "break_glass": bool(report.meta.break_glass.enabled) if report.meta else False,
                "settings_effective_hash": self._settings.effective_hash(),
                "settings_provenance_hash": self._settings.provenance_hash(),
                "revision": int(self._revision),
                "applied": bool(report.applied),
                "noop": bool(report.noop),
                "changed_fields": list(report.changed_fields),
                "blocked": [list(x) for x in report.blocked],
                "errors": list(report.errors),
                "warnings": list(report.warnings),
                "meta": {
                    "format": report.meta.format,
                    "file_digest": report.meta.file_digest,
                    "env_fingerprint": report.meta.env_fingerprint,
                    "signature": {
                        "required": report.meta.signature.required,
                        "verified": report.meta.signature.verified,
                        "method": report.meta.signature.method,
                        "signer_id": report.meta.signature.signer_id,
                        "bundle_digest": report.meta.signature.bundle_digest,
                        "error": report.meta.signature.error,
                    },
                    "break_glass_reason": report.meta.break_glass.reason_public,
                    "break_glass_expires": report.meta.break_glass.expires_epoch,
                    "break_glass_nonce": report.meta.break_glass.nonce,
                }
                if report.meta
                else None,
            }
            self._audit_sink(payload)
        except Exception:
            pass

    def _enforce_break_glass_nonce_and_cooldown(self, bg: BreakGlassState) -> BreakGlassState:
        """
        Enforce monotonic nonce and cooldown in-process.
        """
        if not bg.enabled:
            return bg

        cooldown_s, _ = _env_int("TCD_BREAK_GLASS_COOLDOWN_S", 3600)
        cooldown_s = max(60, min(int(cooldown_s), 24 * 3600))

        now = float(time.time())
        # nonce must strictly increase
        if bg.nonce <= self._last_bg_nonce:
            try:
                self._metrics.constraint_block_total.labels("signature").inc()
            except Exception:
                pass
            return BreakGlassState(
                enabled=False,
                reason_public=bg.reason_public,
                expires_epoch=bg.expires_epoch,
                nonce=bg.nonce,
                token_sha256=bg.token_sha256,
            )

        # cooldown: only allow enabling if enough time passed since last enable
        if self._last_bg_enable_ts > 0.0 and (now - self._last_bg_enable_ts) < float(cooldown_s):
            return BreakGlassState(
                enabled=False,
                reason_public=bg.reason_public,
                expires_epoch=bg.expires_epoch,
                nonce=bg.nonce,
                token_sha256=bg.token_sha256,
            )

        # accept
        self._last_bg_nonce = int(bg.nonce)
        self._last_bg_enable_ts = now
        return bg

    def refresh(self) -> Settings:
        """
        Reload configuration from file and environment.

        Never throws. If load failed (ok=False), keep old and DO NOT bump revision.
        """
        with self._lock:
            old = self._settings
            try:
                lr = _load_settings_result(
                    gov=self._gov,
                    signature_verifier=self._signature_verifier,
                    is_boot=False,
                )
            except Exception:
                self._last_error = "refresh_load_exception"
                try:
                    self._metrics.refresh_total.labels("failed").inc()
                except Exception:
                    pass
                _log.warning("refresh load exception; keeping old settings", exc_info=True)
                return old

            # break-glass enforce nonce/cooldown
            bg = self._enforce_break_glass_nonce_and_cooldown(lr.meta.break_glass)
            ctx = EvalContext(is_boot=False, is_runtime_override=False, break_glass=bg, gov=self._gov)

            if not lr.ok:
                self._last_error = "refresh_load_failed"
                self._last_load_meta = lr.meta
                try:
                    self._metrics.refresh_total.labels("failed").inc()
                except Exception:
                    pass

                rep = ApplyReport(
                    ok=False,
                    applied=False,
                    noop=True,
                    changed_fields=tuple(),
                    blocked=tuple(),
                    errors=lr.errors,
                    warnings=lr.warnings,
                    meta=lr.meta,
                )
                self._last_report = rep
                self._emit_audit("refresh_failed", rep)
                return old

            # Apply constraints relative to old
            er = evaluate_candidate(old, lr.settings, ctx=ctx)

            # If evaluation produced errors, treat as failed refresh (no commit)
            if not er.ok:
                self._last_error = "refresh_eval_failed"
                self._last_load_meta = lr.meta
                try:
                    self._metrics.refresh_total.labels("failed").inc()
                except Exception:
                    pass
                rep = ApplyReport(
                    ok=False,
                    applied=False,
                    noop=True,
                    changed_fields=er.changed_fields,
                    blocked=er.blocked,
                    errors=er.errors,
                    warnings=tuple(set(list(lr.warnings) + list(er.warnings)))[:128],
                    meta=lr.meta,
                )
                self._last_report = rep
                self._emit_audit("refresh_eval_failed", rep)
                return old

            # No-op detection by effective hash (per checklist)
            old_h = old.effective_hash()
            new_h = er.settings.effective_hash()
            if new_h == old_h:
                self._last_error = ""
                self._last_load_meta = lr.meta
                try:
                    self._metrics.refresh_total.labels("noop").inc()
                except Exception:
                    pass
                rep = ApplyReport(
                    ok=True,
                    applied=False,
                    noop=True,
                    changed_fields=tuple(),
                    blocked=er.blocked,
                    errors=tuple(),
                    warnings=tuple(set(list(lr.warnings) + list(er.warnings)))[:128],
                    meta=lr.meta,
                )
                self._last_report = rep
                self._emit_audit("refresh_noop", rep)
                return old

            # Commit
            self._settings = er.settings
            self._revision += 1
            self._last_error = ""
            self._last_load_meta = lr.meta
            try:
                self._metrics.refresh_total.labels("applied").inc()
            except Exception:
                pass

            rep = ApplyReport(
                ok=True,
                applied=True,
                noop=False,
                changed_fields=er.changed_fields,
                blocked=er.blocked,
                errors=tuple(),
                warnings=tuple(set(list(lr.warnings) + list(er.warnings)))[:128],
                meta=lr.meta,
            )
            self._last_report = rep
            self._emit_audit("refresh_applied", rep)
            return self._settings

    def refresh_if_changed(self) -> Settings:
        """
        Skip refresh if file+env fingerprints are unchanged (low-cost, avoids churn).
        """
        with self._lock:
            # compute current source fingerprint cheaply: stat+env (no full parse)
            gov = self._gov
            cfg_path, _ = _env_str("TCD_CONFIG_PATH", "", max_len=_MAX_STR_LARGE)

            file_digest = ""
            mtime_ns = 0
            inode = 0
            if cfg_path:
                try:
                    st = os.stat(cfg_path, follow_symlinks=False)  # type: ignore[call-arg]
                    mtime_ns = int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))
                    inode = int(getattr(st, "st_ino", 0))
                except Exception:
                    pass

                # best-effort small digest by reading bounded header (not full file)
                rb, _ = _read_small_file_bytes(cfg_path, max_bytes=4096)
                if rb:
                    file_digest = hashlib.sha256(rb).hexdigest()

            # env fingerprint (use only relevant env keys)
            env_keys = [
                "TCD_DEBUG",
                "TCD_VERSION",
                "TCD_GPU_ENABLE",
                "TCD_PROM_PORT",
                "TCD_PROM_HTTP_ENABLE",
                "TCD_OTEL_ENABLE",
                "TCD_OTEL_ENDPOINT",
                "TCD_ALPHA",
                "TCD_SLO_MS",
                "TCD_HTTP_RATE_CAP",
                "TCD_HTTP_RATE_REFILL",
                "TCD_TOKEN_COST_DIVISOR",
                "TCD_PQ_MIN_SCHEME",
                "TCD_PQ_AUDIT_ENABLED",
                "TCD_EPROC_ALPHA",
                "TCD_EPROC_ALPHA_MAX_DELTA",
                "TCD_EPROC_MIN_WEALTH",
                "TCD_EPROC_POLICY_REF",
                "TCD_DECISION_ENGINE_ENABLED",
                "TCD_DETECTOR_ENABLED",
                "TCD_TRUST_GRAPH_ENABLED",
                "TCD_LEDGER_BACKEND",
                "TCD_LEDGER_NAMESPACE",
                "TCD_ALLOW_RUNTIME_OVERRIDE",
                "TCD_RISK_SCORE_SEMANTICS",
                "TCD_RISK_BAND_LOW",
                "TCD_RISK_BAND_HIGH",
                # break-glass changes should force refresh attempt
                "TCD_BREAK_GLASS_TOKEN",
                "TCD_BREAK_GLASS_ACK",
                "TCD_BREAK_GLASS_REASON",
                "TCD_BREAK_GLASS_EXPIRES_EPOCH",
                "TCD_BREAK_GLASS_NONCE",
            ]
            pairs = []
            for k in env_keys:
                v = _env_get(k) or ""
                pairs.append((k, hashlib.sha256(v.encode("utf-8")).hexdigest()[:16]))
            env_fp = _env_fingerprint(pairs)

            fp = (file_digest, int(mtime_ns), int(inode), env_fp)
            if self._last_source_fp is not None and fp == self._last_source_fp:
                try:
                    self._metrics.refresh_skipped_unchanged_total.inc()
                    self._metrics.refresh_total.labels("noop").inc()
                except Exception:
                    pass
                return self._settings

            self._last_source_fp = fp
            return self.refresh()

    def set(self, **overrides: Any) -> Settings:
        """
        Apply restricted in-memory overrides.

        Per checklist:
          - never throws
          - allow_runtime_override=False => rejected unless break-glass
          - derived fields cannot be set
          - revision only bumps if effective_hash changes
          - blocked relaxations observable
        """
        with self._lock:
            current = self._settings
            bg = self._enforce_break_glass_nonce_and_cooldown(_break_glass_state())
            ctx = EvalContext(is_boot=False, is_runtime_override=True, break_glass=bg, gov=self._gov)

            if (not current.allow_runtime_override) and (not bg.enabled):
                try:
                    self._metrics.set_total.labels("rejected").inc()
                except Exception:
                    pass
                rep = ApplyReport(
                    ok=False,
                    applied=False,
                    noop=True,
                    changed_fields=tuple(),
                    blocked=(("allow_runtime_override", "immutable"),),
                    errors=("runtime_override_disabled",),
                    warnings=tuple(),
                    meta=None,
                )
                self._last_report = rep
                self._emit_audit("set_rejected", rep)
                return current

            # Apply overrides on a dict copy, but refuse derived/boot-immutable keys
            try:
                cur_d = dict(_model_dump_any(current))
                allowed = Settings.field_names()
                for k, v in overrides.items():
                    kk = _sanitize_text(k, max_len=_MAX_STR_MED)
                    if kk not in allowed:
                        continue
                    if kk in _DERIVED_FIELDS or kk in _BOOT_IMMUTABLE_FIELDS:
                        try:
                            self._metrics.constraint_block_total.labels("immutable").inc()
                        except Exception:
                            pass
                        continue
                    cur_d[kk] = v

                # mark origin (provenance only)
                cur_d["config_origin"] = "runtime_override"

                norm_d, warn, err = _normalize_settings_dict(cur_d, base=current, gov=self._gov)
                if err:
                    try:
                        self._metrics.set_total.labels("failed").inc()
                    except Exception:
                        pass
                    rep = ApplyReport(
                        ok=False,
                        applied=False,
                        noop=True,
                        changed_fields=tuple(),
                        blocked=tuple(),
                        errors=tuple(err),
                        warnings=tuple(warn),
                        meta=None,
                    )
                    self._last_report = rep
                    self._emit_audit("set_failed", rep)
                    return current

                candidate = Settings(**norm_d)
            except Exception:
                self._last_error = "set_failed_exception"
                try:
                    self._metrics.set_total.labels("failed").inc()
                except Exception:
                    pass
                _log.warning("set() failed; keeping old settings", exc_info=True)
                return current

            er = evaluate_candidate(current, candidate, ctx=ctx)
            if not er.ok:
                try:
                    self._metrics.set_total.labels("rejected").inc()
                except Exception:
                    pass
                rep = ApplyReport(
                    ok=False,
                    applied=False,
                    noop=True,
                    changed_fields=er.changed_fields,
                    blocked=er.blocked,
                    errors=er.errors,
                    warnings=er.warnings,
                    meta=None,
                )
                self._last_report = rep
                self._emit_audit("set_rejected", rep)
                return current

            # no-op by effective hash
            if er.settings.effective_hash() == current.effective_hash():
                try:
                    self._metrics.set_total.labels("rejected").inc()
                except Exception:
                    pass
                rep = ApplyReport(
                    ok=True,
                    applied=False,
                    noop=True,
                    changed_fields=tuple(),
                    blocked=er.blocked,
                    errors=tuple(),
                    warnings=er.warnings,
                    meta=None,
                )
                self._last_report = rep
                self._emit_audit("set_noop", rep)
                return current

            # commit
            self._settings = er.settings
            self._revision += 1
            self._last_error = ""
            try:
                self._metrics.set_total.labels("applied").inc()
            except Exception:
                pass

            rep = ApplyReport(
                ok=True,
                applied=True,
                noop=False,
                changed_fields=er.changed_fields,
                blocked=er.blocked,
                errors=tuple(),
                warnings=er.warnings,
                meta=None,
            )
            self._last_report = rep
            self._emit_audit("set_applied", rep)
            return self._settings


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def make_reloadable_settings(
    *,
    metrics: Optional[_Metrics] = None,
    signature_verifier: Optional[Callable[[bytes, Governance], SignatureResult]] = None,
    audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> ReloadableSettings:
    """
    Boot loader. Per checklist:
      - strict mode may fail-fast (governed by TCD_STRICT_CONFIG + TCD_CONFIG_FAIL_FAST + TCD_ENV)
      - otherwise starts with defaults but surfaces ok/errors via logs and last_report/meta
    """
    gov = _governance()
    lr = _load_settings_result(gov=gov, signature_verifier=signature_verifier, is_boot=True)

    if not lr.ok:
        # strict mode behavior: fail-fast if configured
        if gov.strict and gov.fail_fast:
            raise RuntimeError(f"Settings load failed in strict mode: errors={list(lr.errors)[:8]}")
        _log.warning("Settings load failed; starting with constrained defaults. errors=%s", list(lr.errors)[:8])

    rs = ReloadableSettings(
        initial=lr.settings,
        metrics=metrics,
        signature_verifier=signature_verifier,
        audit_sink=audit_sink,
        gov=gov,
    )
    # store boot meta/report for observability
    with rs._lock:
        rs._last_load_meta = lr.meta
        rs._last_report = ApplyReport(
            ok=lr.ok,
            applied=True,
            noop=False,
            changed_fields=tuple(),
            blocked=tuple(),
            errors=lr.errors,
            warnings=lr.warnings,
            meta=lr.meta,
        )
        rs._emit_audit("boot_load", rs._last_report)

    return rs