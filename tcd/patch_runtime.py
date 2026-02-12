# FILE: tcd/patch_runtime.py
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union, Literal

# ----------------------------------------------------------------------
# External, optional dependencies (agent, attestor, hashing, telemetry)
# ----------------------------------------------------------------------

try:
    from .agent import ControlAgent, ActionResult, ExecutionMode
except Exception:  # pragma: no cover
    ControlAgent = Any  # type: ignore
    ActionResult = Any  # type: ignore
    ExecutionMode = Any  # type: ignore

try:
    from .attest import Attestor
    from .kv import RollingHasher
except Exception:  # pragma: no cover
    Attestor = None  # type: ignore
    RollingHasher = None  # type: ignore

try:
    from .trust_graph import SubjectKey
except Exception:  # pragma: no cover
    @dataclass
    class SubjectKey:  # type: ignore
        tenant: str = ""
        user: str = ""
        session: str = ""
        model_id: str = ""

        def as_id(self) -> str:
            parts = [
                f"tenant={self.tenant or '*'}",
                f"user={self.user or '*'}",
                f"session={self.session or '*'}",
                f"model={self.model_id or '*'}",
            ]
            return "|".join(parts)

try:
    from .otel_exporter import TCDOtelExporter
except Exception:  # pragma: no cover
    TCDOtelExporter = Any  # type: ignore


# ----------------------------------------------------------------------
# Hardening helpers
# ----------------------------------------------------------------------

_ASCII_CTRL_RE = re.compile(r"[\x00-\x1F\x7F]")

# FIXED: escape '-' to avoid range '.'..':' which accidentally included '/'
_SAFE_KEY_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.:\-]{0,127}$")
_SAFE_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9_.:\-]{0,63}$")

# Conservative secret detection (values)
_JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_PRIVKEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----", re.IGNORECASE)
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._\-~=+/]+\b", re.IGNORECASE)
_BASIC_RE = re.compile(r"\bBasic\s+[A-Za-z0-9+/=]{16,}\b", re.IGNORECASE)
_KV_SECRET_RE = re.compile(r"(?i)\b(?:api[_-]?key|apikey|token|secret|password|passwd|pwd)\s*[:=]\s*([^\s,;]{8,})")

# Conservative sensitive-key detection (keys)
_SENSITIVE_KEY_TOKENS = (
    "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
    "authorization", "auth", "cookie", "set_cookie", "session",
    "private", "ssh", "pem", "bearer", "key",
)

# Artifact digest patterns: allow oci/sha256 etc.
_ARTIFACT_DIGEST_RE = re.compile(r"^(?:(sha256|sha512|blake3):)?[0-9a-fA-F]{32,128}$")


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


def _safe_str_only(v: Any, *, max_len: int, default: str = "") -> str:
    if not isinstance(v, str):
        return default
    s = _strip_unsafe_text(v, max_len=max_len).strip()
    return s if s else default


def _looks_like_secret(s: str) -> bool:
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
    if _KV_SECRET_RE.search(s):
        return True
    return False


def _safe_label(x: Any, *, default: str = "unknown") -> str:
    s = _safe_str_only(x, max_len=64, default=default).lower()
    if not _SAFE_LABEL_RE.fullmatch(s):
        return default
    return s


def _safe_key(x: Any, *, default: Optional[str] = None) -> Optional[str]:
    s = _safe_str_only(x, max_len=128, default="")
    if not s:
        return default
    s2 = s.strip().lower()
    if not _SAFE_KEY_RE.fullmatch(s2):
        return default
    return s2


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


def _clamp_int(v: int, lo: int, hi: int) -> int:
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def _parse_key_material(s: Optional[str]) -> Optional[bytes]:
    """
    Parse key material from:
      - hex (even length) or "hex:<...>"
      - base64/urlbase64: "b64:<...>"
      - raw: "raw:<...>" (discouraged)
    """
    if not isinstance(s, str):
        return None
    ss = _strip_unsafe_text(s, max_len=4096).strip()
    if not ss:
        return None

    if ss.lower().startswith("hex:"):
        hx = ss[4:].strip()
        if re.fullmatch(r"[0-9a-fA-F]{16,4096}", hx) and len(hx) % 2 == 0:
            try:
                return bytes.fromhex(hx)
            except Exception:
                return None
        return None

    if ss.lower().startswith("b64:"):
        b = ss[4:].strip()
        try:
            pad = "=" * ((4 - (len(b) % 4)) % 4)
            return base64.urlsafe_b64decode((b + pad).encode("utf-8", errors="ignore"))
        except Exception:
            return None

    if ss.lower().startswith("raw:"):
        return ss[4:].encode("utf-8", errors="ignore")

    # plain hex
    if re.fullmatch(r"[0-9a-fA-F]{16,4096}", ss) and len(ss) % 2 == 0:
        try:
            return bytes.fromhex(ss)
        except Exception:
            return None

    # base64
    try:
        pad = "=" * ((4 - (len(ss) % 4)) % 4)
        return base64.urlsafe_b64decode((ss + pad).encode("utf-8", errors="ignore"))
    except Exception:
        return None


def _kdf(master: bytes, label: str) -> bytes:
    return hmac.new(master, label.encode("utf-8", errors="ignore"), hashlib.sha256).digest()


class _JsonBudget:
    __slots__ = ("max_nodes", "max_items", "max_depth", "max_str", "nodes", "str_used")

    def __init__(self, *, max_nodes: int, max_items: int, max_depth: int, max_str: int):
        self.max_nodes = max_nodes
        self.max_items = max_items
        self.max_depth = max_depth
        self.max_str = max_str
        self.nodes = 0
        self.str_used = 0

    def take_node(self) -> bool:
        self.nodes += 1
        return self.nodes <= self.max_nodes

    def take_str(self, n: int) -> bool:
        self.str_used += n
        return self.str_used <= self.max_str


def _is_sensitive_key(k: str) -> bool:
    # k assumed lower and safe_key already
    for t in _SENSITIVE_KEY_TOKENS:
        if t in k:
            return True
    return False


def _json_sanitize(
    obj: Any,
    *,
    budget: _JsonBudget,
    depth: int,
    redact_secrets: bool,
    redact_sensitive_keys: bool = True,
    allowed_keys: Optional[set[str]] = None,
) -> Any:
    """
    JSON-safe bounded sanitizer.
    Hardening choices:
      - Only accepts built-in dict for mappings (avoid custom Mapping .items() side effects).
      - Does NOT call __str__/__repr__ on unknown objects.
      - Optional key allowlist + sensitive-key redaction.
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
        s = _strip_unsafe_text(obj, max_len=512)
        if redact_secrets and _looks_like_secret(s):
            s = "[redacted]"
        if len(s) > 512:
            s = s[:512] + "...[truncated]"
        if not budget.take_str(len(s)):
            return "[truncated]"
        return s
    if isinstance(obj, (bytes, bytearray)):
        return f"[bytes:{len(obj)}]"

    if depth >= budget.max_depth:
        return "[truncated-depth]"

    # Only accept built-in dict to avoid custom mapping side effects
    if type(obj) is dict:
        out: Dict[str, Any] = {}
        n = 0
        for k, v in obj.items():
            if n >= budget.max_items:
                out["_tcd_truncated"] = True
                break
            kk = _safe_key(k, default=None)
            if kk is None:
                continue
            if allowed_keys is not None and kk not in allowed_keys:
                continue
            if redact_sensitive_keys and _is_sensitive_key(kk):
                out[kk] = "[redacted]"
                n += 1
                continue
            out[kk] = _json_sanitize(
                v,
                budget=budget,
                depth=depth + 1,
                redact_secrets=redact_secrets,
                redact_sensitive_keys=redact_sensitive_keys,
                allowed_keys=None,  # key allowlist applies at top-level or explicit sites
            )
            n += 1
        return out

    if isinstance(obj, (list, tuple)):
        out_list = []
        for i, v in enumerate(obj):
            if i >= budget.max_items:
                out_list.append("[truncated]")
                break
            out_list.append(
                _json_sanitize(
                    v,
                    budget=budget,
                    depth=depth + 1,
                    redact_secrets=redact_secrets,
                    redact_sensitive_keys=redact_sensitive_keys,
                    allowed_keys=None,
                )
            )
        return out_list

    # Other Mapping / custom objects: do not iterate (avoid side effects)
    return f"[type:{type(obj).__name__}]"


def _safe_mode_label(mode: Any) -> Optional[str]:
    """
    L7 rule: only accept Enum or str. Do not getattr arbitrary objects.
    """
    if mode is None:
        return None
    if isinstance(mode, Enum):
        v = mode.value
        if isinstance(v, str):
            return _safe_str_only(v, max_len=64, default="unknown")
        # if Enum value isn't str, fallback to name
        n = mode.name
        if isinstance(n, str):
            return _safe_str_only(n, max_len=64, default="unknown")
        return "unknown"
    if isinstance(mode, str):
        return _safe_str_only(mode, max_len=64, default="unknown")
    return None


def _mode_is_production_like(mode: Any) -> bool:
    lab = _safe_mode_label(mode)
    if not lab:
        return False
    s = lab.lower()
    return ("prod" in s) or ("production" in s)


def _mode_is_canary_like(mode: Any) -> bool:
    lab = _safe_mode_label(mode)
    if not lab:
        return False
    s = lab.lower()
    return ("canary" in s) or ("staged" in s) or ("stage" in s)


def _result_duration_ms(result: Any, *, allow_callables: bool) -> float:
    """
    L7 default: do NOT call callables (avoid executing agent-provided code).
    Supports numeric attributes:
      - duration_ms
      - duration_s / duration_sec
    Optional: allow_callables=True will also call duration_ms() if callable.
    """
    if result is None:
        return 0.0

    dm = getattr(result, "duration_ms", None)
    try:
        if allow_callables and callable(dm):
            v = _finite_float(dm())
            return float(v) if v is not None else 0.0
        v = _finite_float(dm)
        if v is not None:
            return float(v)
    except Exception:
        pass

    ds = getattr(result, "duration_s", None)
    v2 = _finite_float(ds)
    if v2 is not None:
        return float(v2) * 1000.0

    ds2 = getattr(result, "duration_sec", None)
    v3 = _finite_float(ds2)
    if v3 is not None:
        return float(v3) * 1000.0

    return 0.0


# ----------------------------------------------------------------------
# Patch enums and identities
# ----------------------------------------------------------------------


class PatchStatus(str, Enum):
    PENDING = "pending"
    APPLIED = "applied"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"
    # Optional staged lifecycle (disabled by default via config.enable_staged_rollout)
    CANARY_APPLIED = "canary_applied"
    PROMOTED = "promoted"
    PROMOTION_FAILED = "promotion_failed"


class PatchRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class PatchKind(str, Enum):
    POLICY = "policy"
    MODEL = "model"
    RUNTIME_CONFIG = "runtime_config"
    BINARY = "binary"
    INFRA = "infra"
    OTHER = "other"


@dataclass
class OperatorId:
    operator_id: str
    roles: List[str] = field(default_factory=list)

    @property
    def hash_id(self) -> str:
        # NOTE: runtime will produce real HMAC hash; this remains sanitized only.
        return _safe_str_only(self.operator_id, max_len=128, default="unknown")


# ----------------------------------------------------------------------
# Core descriptors and state
# ----------------------------------------------------------------------


@dataclass
class PatchDescriptor:
    patch_id: str
    subject_id: str  # default is hashed/pseudonymous subject id in L7 config
    patch_kind: PatchKind = PatchKind.RUNTIME_CONFIG
    description: str = ""
    origin: str = ""
    created_ts: float = field(default_factory=lambda: time.time())
    checksum: str = ""
    risk_level: PatchRiskLevel = PatchRiskLevel.LOW

    artifact_digest: Optional[str] = None
    artifact_source: Optional[str] = None
    artifact_sbom_id: Optional[str] = None
    build_pipeline_id: Optional[str] = None
    commit_hash: Optional[str] = None

    allowed_envs: Optional[List[str]] = None
    allowed_trust_zones: Optional[List[str]] = None
    max_scope: Optional[Dict[str, int]] = None

    change_ticket_id: Optional[str] = None
    required_approvals: int = 0

    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        budget = _JsonBudget(max_nodes=512, max_items=128, max_depth=4, max_str=16_000)
        md = _json_sanitize(self.metadata, budget=budget, depth=0, redact_secrets=True)
        return {
            "patch_id": self.patch_id,
            "subject_id": self.subject_id,
            "patch_kind": self.patch_kind.value,
            "description": self.description,
            "origin": self.origin,
            "created_ts": self.created_ts,
            "checksum": self.checksum,
            "risk_level": self.risk_level.value,
            "artifact_digest": self.artifact_digest,
            "artifact_source": self.artifact_source,
            "artifact_sbom_id": self.artifact_sbom_id,
            "build_pipeline_id": self.build_pipeline_id,
            "commit_hash": self.commit_hash,
            "allowed_envs": list(self.allowed_envs) if self.allowed_envs is not None else None,
            "allowed_trust_zones": list(self.allowed_trust_zones) if self.allowed_trust_zones is not None else None,
            "max_scope": dict(self.max_scope) if self.max_scope is not None else None,
            "change_ticket_id": self.change_ticket_id,
            "required_approvals": int(self.required_approvals),
            "metadata": md if isinstance(md, dict) else {},
        }


@dataclass
class PatchReceiptRef:
    receipt_head: Optional[str] = None
    receipt_body: Optional[str] = None
    receipt_sig: Optional[str] = None
    verify_key: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_head": self.receipt_head,
            "receipt_body": self.receipt_body,
            "receipt_sig": self.receipt_sig,
            "verify_key": self.verify_key,
        }


@dataclass
class PatchState:
    descriptor: PatchDescriptor
    status: PatchStatus = PatchStatus.PENDING

    last_update_ts: float = field(default_factory=lambda: time.time())

    # Human-safe message (audit only), plus structured code for telemetry.
    last_error: Optional[str] = None
    last_error_code: Optional[str] = None
    last_error_type: Optional[str] = None

    applied_ts: Optional[float] = None
    rolled_back_ts: Optional[float] = None

    apply_receipt: Optional[PatchReceiptRef] = None
    rollback_receipt: Optional[PatchReceiptRef] = None

    created_by: Optional[str] = None  # operator_id_hash
    approvals: List[Dict[str, Any]] = field(default_factory=list)
    last_operator_id_hash: Optional[str] = None

    apply_attempts: int = 0
    rollback_attempts: int = 0

    # Sanitized footprint only (never raw agent objects)
    apply_targets: Optional[Dict[str, Any]] = None
    canary_success: Optional[bool] = None
    promotion_ts: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        # Deep JSON-safe outputs to avoid shared refs / mutation.
        budget = _JsonBudget(max_nodes=1024, max_items=256, max_depth=6, max_str=32_000)
        approvals_safe = _json_sanitize(self.approvals, budget=budget, depth=0, redact_secrets=True)
        targets_safe = _json_sanitize(self.apply_targets, budget=budget, depth=0, redact_secrets=True) if self.apply_targets else None
        return {
            "descriptor": self.descriptor.to_dict(),
            "status": self.status.value,
            "last_update_ts": self.last_update_ts,
            "last_error": self.last_error,
            "last_error_code": self.last_error_code,
            "last_error_type": self.last_error_type,
            "applied_ts": self.applied_ts,
            "rolled_back_ts": self.rolled_back_ts,
            "apply_receipt": self.apply_receipt.to_dict() if self.apply_receipt else None,
            "rollback_receipt": self.rollback_receipt.to_dict() if self.rollback_receipt else None,
            "created_by": self.created_by,
            "approvals": approvals_safe if isinstance(approvals_safe, list) else [],
            "last_operator_id_hash": self.last_operator_id_hash,
            "apply_attempts": int(self.apply_attempts),
            "rollback_attempts": int(self.rollback_attempts),
            "apply_targets": targets_safe if isinstance(targets_safe, dict) else None,
            "canary_success": self.canary_success,
            "promotion_ts": self.promotion_ts,
        }


# ----------------------------------------------------------------------
# Configuration and policy
# ----------------------------------------------------------------------

AuthorizeFn = Callable[[str, Union[PatchDescriptor, PatchState, Mapping[str, Any]], Optional[OperatorId], Optional[str]], None]
EAllocatorFn = Callable[[PatchState, ActionResult], Dict[str, float]]

AuthorizeViewMode = Literal["snapshot", "dict_readonly"]


@dataclass
class PatchRuntimeConfig:
    """
    Strong L7+ hardened PatchRuntimeConfig.
    """

    schema_version: int = 1

    # Core behaviour
    auto_rollback_on_failure: bool = True
    max_patches: int = 1_000

    # Eviction policy
    max_patches_evict_only_terminal: bool = True
    allow_evict_in_flight: bool = False  # L7 default: never evict in-flight patches

    # Patch blob limits (DoS control)
    max_patch_blob_bytes: int = 10_000_000  # 10MB

    # Hash algorithm
    hash_alg: str = "blake3"
    allow_legacy_sha1: bool = False
    require_hash_alg_available: bool = True  # L7: no silent downgrade
    allow_hash_fallback: bool = False        # if True and require_hash_alg_available False, fallback allowed

    receipts_enable: bool = True

    patch_id_prefix: str = "patch"
    patch_id_checksum_chars: int = 20
    patch_id_random_suffix_chars: int = 8

    apply_kind: str = "apply_patch"
    rollback_kind: str = "rollback"

    # Risk-aware execution defaults
    canary_mode_default: Optional[Any] = None
    production_mode_default: Optional[Any] = None

    require_canary_for_high_risk: bool = True
    block_high_risk_production_explicit_mode: bool = True
    # L7: If HIGH risk requires canary, explicit_mode must also be canary-like (not just "not prod")
    require_explicit_canary_like_for_high_risk: bool = True
    # L7: if runtime cannot resolve an execution mode, fail closed
    require_mode_resolution: bool = True

    # Governance
    max_pending_per_subject: int = 32
    allow_duplicate_checksums: bool = False

    # Approval policy
    required_approvals_by_risk: Dict[str, int] = field(default_factory=lambda: {"low": 0, "medium": 1, "high": 2})
    # L7: metadata cannot reduce required approvals below policy default
    allow_metadata_override_required_approvals: bool = False
    allow_metadata_lower_required_approvals: bool = False  # only meaningful if override enabled

    max_approvals_per_patch: int = 128
    require_distinct_approvers: bool = True

    # L7 default: disallow post-apply approvals (audit漂白)
    allow_approvals_after_pending: bool = False
    enforce_operator_role_membership: bool = True

    allow_reapply: bool = False
    allow_rollback_without_prior_apply: bool = True

    # Scope enforcement
    require_targets_for_scope_enforcement: bool = True

    # Targets storage policy
    targets_store_mode: Literal["none", "summary", "sanitized"] = "summary"
    targets_budget_nodes: int = 512
    targets_budget_items: int = 128
    targets_budget_depth: int = 4
    targets_budget_str: int = 16_000

    # Metadata input policy (reduce attack surface)
    metadata_budget_nodes: int = 1024
    metadata_budget_items: int = 256
    metadata_budget_depth: int = 6
    metadata_budget_str: int = 32_000
    metadata_allowed_keys: Optional[List[str]] = field(default_factory=lambda: [
        "artifact_digest", "artifact_source", "artifact_sbom_id",
        "build_pipeline_id", "commit_hash",
        "allowed_envs", "allowed_trust_zones",
        "max_scope", "change_ticket_id",
        "required_approvals",
    ])

    # ID pseudonymization (subject/operator)
    pseudonymize_subject_id: bool = True
    pseudonymize_operator_id: bool = True

    # Shared or per-id keys (hex/b64/raw). If absent, runtime uses ephemeral key.
    id_hash_key: Optional[str] = None
    subject_hash_key: Optional[str] = None
    operator_hash_key: Optional[str] = None

    # Minimum key bytes for HMAC keys in strict profiles
    min_id_hash_key_bytes: int = 16

    # Truncate hex length for id hashes
    id_hash_hex_chars: int = 32

    # Allow clear IDs only in specific environments (e.g., "dev")
    include_clear_ids: bool = False
    clear_id_env_allowlist: List[str] = field(default_factory=lambda: ["dev"])

    # e-process / evidence defaults
    e_default_value: float = 1.0
    e_default_alpha_alloc: float = 0.0
    e_default_alpha_wealth: float = 0.0
    e_default_threshold: float = 0.0
    e_allocator: Optional[EAllocatorFn] = None
    e_process_id: Optional[str] = None

    # Telemetry / audit integration
    telemetry: Optional[TCDOtelExporter] = None
    telemetry_emit_register_events: bool = True
    telemetry_emit_approve_events: bool = True
    telemetry_emit_apply_events: bool = True
    telemetry_emit_rollback_events: bool = True

    # Telemetry should prefer structured errors
    telemetry_include_error_message: bool = False

    audit_hook: Optional[Callable[[str, Dict[str, Any]], None]] = None
    audit_hook_bytes: Optional[Callable[[str, bytes], None]] = None
    audit_payload_max_bytes: int = 16_384

    minimize_receipt_metadata: bool = False
    minimize_telemetry_metadata: bool = False

    # Authorization / environment
    authorize_fn: Optional[AuthorizeFn] = None
    authorize_view_mode: AuthorizeViewMode = "snapshot"  # "snapshot" preserves compatibility
    environment: str = "prod"
    trust_zone: str = "default"
    allow_environment_override: bool = False

    # Supply-chain / attestation controls
    verify_artifact_on_register: bool = False
    require_verified_artifact_on_register: bool = False

    verify_artifact_on_apply: bool = True
    require_verified_artifact_on_apply: bool = True
    require_artifact_digest_on_apply: bool = False

    # Receipt storage strategy
    receipt_store_mode: Literal["head_only", "head_sig", "full"] = "head_sig"
    max_total_receipt_bytes: int = 5_000_000

    # User-provided strings governance
    reason_max_len: int = 256
    description_max_len: int = 512
    origin_max_len: int = 256

    # Result callable policy
    allow_callables_in_result: bool = False

    # Optional staged rollout lifecycle (off by default to preserve semantics)
    enable_staged_rollout: bool = False

    def normalized_copy(self) -> "PatchRuntimeConfig":
        c = PatchRuntimeConfig()

        c.schema_version = int(self.schema_version or 1)

        c.auto_rollback_on_failure = bool(self.auto_rollback_on_failure)
        c.max_patches = _clamp_int(int(self.max_patches or 1_000), 1, 1_000_000)

        c.max_patches_evict_only_terminal = bool(self.max_patches_evict_only_terminal)
        c.allow_evict_in_flight = bool(self.allow_evict_in_flight)

        c.max_patch_blob_bytes = _clamp_int(int(self.max_patch_blob_bytes or 10_000_000), 1_024, 1_000_000_000)

        c.hash_alg = _safe_str_only(self.hash_alg, max_len=32, default="blake3").lower()
        c.allow_legacy_sha1 = bool(self.allow_legacy_sha1)
        c.require_hash_alg_available = bool(self.require_hash_alg_available)
        c.allow_hash_fallback = bool(self.allow_hash_fallback)

        if c.hash_alg == "sha1" and not c.allow_legacy_sha1:
            raise ValueError("hash_alg='sha1' is not allowed unless allow_legacy_sha1=True.")

        c.receipts_enable = bool(self.receipts_enable)

        c.patch_id_prefix = _safe_label(self.patch_id_prefix, default="patch")
        c.patch_id_checksum_chars = _clamp_int(int(self.patch_id_checksum_chars or 20), 8, 64)
        c.patch_id_random_suffix_chars = _clamp_int(int(self.patch_id_random_suffix_chars or 8), 4, 32)

        c.apply_kind = _safe_label(self.apply_kind, default="apply_patch")
        c.rollback_kind = _safe_label(self.rollback_kind, default="rollback")

        c.canary_mode_default = self.canary_mode_default
        c.production_mode_default = self.production_mode_default

        c.require_canary_for_high_risk = bool(self.require_canary_for_high_risk)
        c.block_high_risk_production_explicit_mode = bool(self.block_high_risk_production_explicit_mode)
        c.require_explicit_canary_like_for_high_risk = bool(self.require_explicit_canary_like_for_high_risk)
        c.require_mode_resolution = bool(self.require_mode_resolution)

        c.max_pending_per_subject = _clamp_int(int(self.max_pending_per_subject or 32), 0, 1_000_000)
        c.allow_duplicate_checksums = bool(self.allow_duplicate_checksums)

        # approvals by risk
        rar: Dict[str, int] = {}
        if isinstance(self.required_approvals_by_risk, Mapping):
            for k, v in self.required_approvals_by_risk.items():
                kk = _safe_label(k, default="")
                if kk in {"low", "medium", "high"}:
                    try:
                        rar[kk] = _clamp_int(int(v), 0, 100)
                    except Exception:
                        pass
        if not rar:
            rar = {"low": 0, "medium": 1, "high": 2}
        c.required_approvals_by_risk = rar

        c.allow_metadata_override_required_approvals = bool(self.allow_metadata_override_required_approvals)
        c.allow_metadata_lower_required_approvals = bool(self.allow_metadata_lower_required_approvals)

        c.max_approvals_per_patch = _clamp_int(int(self.max_approvals_per_patch or 128), 1, 10_000)
        c.require_distinct_approvers = bool(self.require_distinct_approvers)

        c.allow_approvals_after_pending = bool(self.allow_approvals_after_pending)
        c.enforce_operator_role_membership = bool(self.enforce_operator_role_membership)

        c.allow_reapply = bool(self.allow_reapply)
        c.allow_rollback_without_prior_apply = bool(self.allow_rollback_without_prior_apply)

        c.require_targets_for_scope_enforcement = bool(self.require_targets_for_scope_enforcement)

        c.targets_store_mode = self.targets_store_mode if self.targets_store_mode in ("none", "summary", "sanitized") else "summary"
        c.targets_budget_nodes = _clamp_int(int(self.targets_budget_nodes or 512), 64, 10_000)
        c.targets_budget_items = _clamp_int(int(self.targets_budget_items or 128), 16, 10_000)
        c.targets_budget_depth = _clamp_int(int(self.targets_budget_depth or 4), 1, 16)
        c.targets_budget_str = _clamp_int(int(self.targets_budget_str or 16_000), 1_024, 1_000_000)

        c.metadata_budget_nodes = _clamp_int(int(self.metadata_budget_nodes or 1024), 64, 20_000)
        c.metadata_budget_items = _clamp_int(int(self.metadata_budget_items or 256), 16, 20_000)
        c.metadata_budget_depth = _clamp_int(int(self.metadata_budget_depth or 6), 1, 32)
        c.metadata_budget_str = _clamp_int(int(self.metadata_budget_str or 32_000), 1_024, 5_000_000)

        if isinstance(self.metadata_allowed_keys, list) and self.metadata_allowed_keys:
            keys = []
            for x in self.metadata_allowed_keys:
                if isinstance(x, str):
                    k = _safe_key(x, default=None)
                    if k:
                        keys.append(k)
            c.metadata_allowed_keys = keys or None
        else:
            c.metadata_allowed_keys = None

        c.pseudonymize_subject_id = bool(self.pseudonymize_subject_id)
        c.pseudonymize_operator_id = bool(self.pseudonymize_operator_id)

        c.id_hash_key = _safe_str_only(self.id_hash_key, max_len=4096, default="") if isinstance(self.id_hash_key, str) else None
        if c.id_hash_key == "":
            c.id_hash_key = None
        c.subject_hash_key = _safe_str_only(self.subject_hash_key, max_len=4096, default="") if isinstance(self.subject_hash_key, str) else None
        if c.subject_hash_key == "":
            c.subject_hash_key = None
        c.operator_hash_key = _safe_str_only(self.operator_hash_key, max_len=4096, default="") if isinstance(self.operator_hash_key, str) else None
        if c.operator_hash_key == "":
            c.operator_hash_key = None

        c.min_id_hash_key_bytes = _clamp_int(int(self.min_id_hash_key_bytes or 16), 8, 64)
        c.id_hash_hex_chars = _clamp_int(int(self.id_hash_hex_chars or 32), 8, 64)

        c.include_clear_ids = bool(self.include_clear_ids)
        if isinstance(self.clear_id_env_allowlist, list) and self.clear_id_env_allowlist:
            c.clear_id_env_allowlist = [_safe_label(x, default="") for x in self.clear_id_env_allowlist if isinstance(x, str)]
            c.clear_id_env_allowlist = [x for x in c.clear_id_env_allowlist if x]
            if not c.clear_id_env_allowlist:
                c.clear_id_env_allowlist = ["dev"]
        else:
            c.clear_id_env_allowlist = ["dev"]

        # e-process
        c.e_default_value = float(_finite_float(self.e_default_value) or 1.0)
        c.e_default_alpha_alloc = float(_finite_float(self.e_default_alpha_alloc) or 0.0)
        c.e_default_alpha_wealth = float(_finite_float(self.e_default_alpha_wealth) or 0.0)
        c.e_default_threshold = float(_finite_float(self.e_default_threshold) or 0.0)
        c.e_allocator = self.e_allocator
        c.e_process_id = _safe_str_only(self.e_process_id, max_len=128, default="") if isinstance(self.e_process_id, str) else None
        if c.e_process_id == "":
            c.e_process_id = None

        # telemetry/audit
        c.telemetry = self.telemetry
        c.telemetry_emit_register_events = bool(self.telemetry_emit_register_events)
        c.telemetry_emit_approve_events = bool(self.telemetry_emit_approve_events)
        c.telemetry_emit_apply_events = bool(self.telemetry_emit_apply_events)
        c.telemetry_emit_rollback_events = bool(self.telemetry_emit_rollback_events)

        c.telemetry_include_error_message = bool(self.telemetry_include_error_message)

        c.audit_hook = self.audit_hook
        c.audit_hook_bytes = self.audit_hook_bytes
        c.audit_payload_max_bytes = _clamp_int(int(self.audit_payload_max_bytes or 16_384), 1_024, 10_000_000)

        c.minimize_receipt_metadata = bool(self.minimize_receipt_metadata)
        c.minimize_telemetry_metadata = bool(self.minimize_telemetry_metadata)

        # auth/env
        c.authorize_fn = self.authorize_fn
        c.authorize_view_mode = self.authorize_view_mode if self.authorize_view_mode in ("snapshot", "dict_readonly") else "snapshot"
        c.environment = _safe_label(self.environment, default="prod")
        c.trust_zone = _safe_label(self.trust_zone, default="default")
        c.allow_environment_override = bool(self.allow_environment_override)

        # supply-chain
        c.verify_artifact_on_register = bool(self.verify_artifact_on_register)
        c.require_verified_artifact_on_register = bool(self.require_verified_artifact_on_register)
        c.verify_artifact_on_apply = bool(self.verify_artifact_on_apply)
        c.require_verified_artifact_on_apply = bool(self.require_verified_artifact_on_apply)
        c.require_artifact_digest_on_apply = bool(self.require_artifact_digest_on_apply)

        # receipts
        c.receipt_store_mode = self.receipt_store_mode if self.receipt_store_mode in ("head_only", "head_sig", "full") else "head_sig"
        c.max_total_receipt_bytes = _clamp_int(int(self.max_total_receipt_bytes or 5_000_000), 0, 1_000_000_000)

        # text fields
        c.reason_max_len = _clamp_int(int(self.reason_max_len or 256), 0, 4096)
        c.description_max_len = _clamp_int(int(self.description_max_len or 512), 0, 16_384)
        c.origin_max_len = _clamp_int(int(self.origin_max_len or 256), 0, 16_384)

        c.allow_callables_in_result = bool(self.allow_callables_in_result)
        c.enable_staged_rollout = bool(self.enable_staged_rollout)

        return c

    def to_dict(self) -> Dict[str, Any]:
        # bounded + stable
        payload = {
            "schema_version": int(self.schema_version),
            "auto_rollback_on_failure": bool(self.auto_rollback_on_failure),
            "max_patches": int(self.max_patches),
            "max_patches_evict_only_terminal": bool(self.max_patches_evict_only_terminal),
            "allow_evict_in_flight": bool(self.allow_evict_in_flight),
            "max_patch_blob_bytes": int(self.max_patch_blob_bytes),
            "hash_alg": str(self.hash_alg),
            "allow_legacy_sha1": bool(self.allow_legacy_sha1),
            "require_hash_alg_available": bool(self.require_hash_alg_available),
            "allow_hash_fallback": bool(self.allow_hash_fallback),
            "receipts_enable": bool(self.receipts_enable),
            "patch_id_prefix": str(self.patch_id_prefix),
            "patch_id_checksum_chars": int(self.patch_id_checksum_chars),
            "patch_id_random_suffix_chars": int(self.patch_id_random_suffix_chars),
            "apply_kind": str(self.apply_kind),
            "rollback_kind": str(self.rollback_kind),
            "require_canary_for_high_risk": bool(self.require_canary_for_high_risk),
            "block_high_risk_production_explicit_mode": bool(self.block_high_risk_production_explicit_mode),
            "require_explicit_canary_like_for_high_risk": bool(self.require_explicit_canary_like_for_high_risk),
            "require_mode_resolution": bool(self.require_mode_resolution),
            "max_pending_per_subject": int(self.max_pending_per_subject),
            "allow_duplicate_checksums": bool(self.allow_duplicate_checksums),
            "required_approvals_by_risk": dict(self.required_approvals_by_risk),
            "allow_metadata_override_required_approvals": bool(self.allow_metadata_override_required_approvals),
            "allow_metadata_lower_required_approvals": bool(self.allow_metadata_lower_required_approvals),
            "max_approvals_per_patch": int(self.max_approvals_per_patch),
            "require_distinct_approvers": bool(self.require_distinct_approvers),
            "allow_approvals_after_pending": bool(self.allow_approvals_after_pending),
            "enforce_operator_role_membership": bool(self.enforce_operator_role_membership),
            "allow_reapply": bool(self.allow_reapply),
            "allow_rollback_without_prior_apply": bool(self.allow_rollback_without_prior_apply),
            "require_targets_for_scope_enforcement": bool(self.require_targets_for_scope_enforcement),
            "targets_store_mode": str(self.targets_store_mode),
            "pseudonymize_subject_id": bool(self.pseudonymize_subject_id),
            "pseudonymize_operator_id": bool(self.pseudonymize_operator_id),
            "include_clear_ids": bool(self.include_clear_ids),
            "clear_id_env_allowlist": list(self.clear_id_env_allowlist),
            "environment": str(self.environment),
            "trust_zone": str(self.trust_zone),
            "verify_artifact_on_apply": bool(self.verify_artifact_on_apply),
            "require_verified_artifact_on_apply": bool(self.require_verified_artifact_on_apply),
            "require_artifact_digest_on_apply": bool(self.require_artifact_digest_on_apply),
            "receipt_store_mode": str(self.receipt_store_mode),
            "audit_payload_max_bytes": int(self.audit_payload_max_bytes),
            "minimize_receipt_metadata": bool(self.minimize_receipt_metadata),
            "minimize_telemetry_metadata": bool(self.minimize_telemetry_metadata),
            "authorize_view_mode": str(self.authorize_view_mode),
            "allow_callables_in_result": bool(self.allow_callables_in_result),
            "enable_staged_rollout": bool(self.enable_staged_rollout),
        }
        return payload

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "PatchRuntimeConfig":
        """
        Strict-ish loader: unknown keys ignored; types/clamps enforced via normalized_copy.
        """
        if type(d) is not dict:
            raise TypeError("PatchRuntimeConfig.from_dict expects a dict-like mapping")

        cfg = PatchRuntimeConfig()
        # whitelist assignment
        for k, v in d.items():
            if not isinstance(k, str):
                continue
            kk = k.strip()
            if not hasattr(cfg, kk):
                continue
            try:
                setattr(cfg, kk, v)
            except Exception:
                continue
        return cfg.normalized_copy()


# ----------------------------------------------------------------------
# Runtime
# ----------------------------------------------------------------------


class PatchRuntime:
    """
    PatchRuntime coordinates safe patch registration, approval, apply and rollback.
    """

    def __init__(
        self,
        agent: Optional[ControlAgent] = None,
        attestor: Optional[Attestor] = None,
        *,
        config: Optional[PatchRuntimeConfig] = None,
    ) -> None:
        self._cfg = (config or PatchRuntimeConfig()).normalized_copy()
        self._agent = agent
        self._attestor = attestor if self._cfg.receipts_enable else None

        # Locks:
        #  - _lock protects registry structures
        #  - per-patch lock protects patch state mutation
        self._lock = threading.RLock()
        self._patch_locks: Dict[str, threading.RLock] = {}
        self._in_flight: Dict[str, int] = {}

        # Registry
        self._patches: Dict[str, PatchState] = {}
        self._order: List[str] = []

        # Index for dedup (subject_id, checksum) -> patch_id
        self._by_subject_checksum: Dict[Tuple[str, str], str] = {}

        # Receipt total bytes accounting
        self._receipt_bytes_total = 0

        # Resolve effective hashing algorithm (no silent downgrade by default)
        self._effective_hash_alg = self._resolve_effective_hash_alg()

        # Derive ID hashing keys (subject/operator)
        self._id_keys = self._derive_id_keys()

        # Cache config fingerprint for audit correlation (includes effective alg & capability flags)
        self._cfg_fp = self._fingerprint_runtime_config()

    # ------------------------------------------------------------------
    # Public API: registration / lookup / approval
    # ------------------------------------------------------------------

    def register_patch(
        self,
        subject: SubjectKey,
        *,
        patch_blob: bytes,
        description: str,
        origin: str,
        risk_level: PatchRiskLevel = PatchRiskLevel.LOW,
        metadata: Optional[Dict[str, Any]] = None,
        patch_kind: PatchKind = PatchKind.RUNTIME_CONFIG,
        operator: Optional[OperatorId] = None,
        environment: Optional[str] = None,
    ) -> PatchState:
        cfg = self._cfg

        if not isinstance(patch_blob, (bytes, bytearray)):
            raise TypeError("patch_blob must be bytes")
        if len(patch_blob) > cfg.max_patch_blob_bytes:
            raise ValueError(f"patch_blob too large: {len(patch_blob)} bytes (limit={cfg.max_patch_blob_bytes})")

        # Authoritative environment/trust zone (caller cannot spoof enforcement)
        enforce_env = cfg.environment
        report_env = _safe_label(environment, default=enforce_env) if isinstance(environment, str) else enforce_env

        # Subject id clear -> hashed subject id (default)
        subject_id_clear = _strip_unsafe_text(subject.as_id() if isinstance(subject.as_id(), str) else "", max_len=512).strip()
        if not subject_id_clear:
            raise ValueError("subject.as_id() produced empty/invalid subject_id")

        subject_id = self._subject_id(subject_id_clear, env=enforce_env)

        # Sanitize metadata early (JSON-safe + key allowlist)
        md = self._sanitize_patch_metadata(metadata or {})

        # Coerce enums safely
        if not isinstance(patch_kind, PatchKind):
            try:
                patch_kind = PatchKind(str(patch_kind))
            except Exception:
                patch_kind = PatchKind.RUNTIME_CONFIG
        if not isinstance(risk_level, PatchRiskLevel):
            try:
                risk_level = PatchRiskLevel(str(risk_level))
            except Exception:
                risk_level = PatchRiskLevel.LOW

        desc = _safe_str_only(description, max_len=cfg.description_max_len, default="")
        if _looks_like_secret(desc):
            desc = "[redacted]"
        org = _safe_str_only(origin, max_len=cfg.origin_max_len, default="")
        if _looks_like_secret(org):
            org = "[redacted]"

        checksum = self._compute_checksum(subject_id, patch_blob)

        # Deduplicate on checksum per subject unless duplicates allowed.
        if not cfg.allow_duplicate_checksums:
            with self._lock:
                existing_id = self._by_subject_checksum.get((subject_id, checksum))
                if existing_id is not None:
                    st = self._patches.get(existing_id)
                    if st is not None:
                        # L7: dedup path must still authorize (at least read permission)
                        self._authorize("register", st, operator, enforce_env)
                        self._emit_audit_event(
                            "tcd.patch.register.dedup",
                            {
                                "cfg_fp": self._cfg_fp,
                                "patch_id": st.descriptor.patch_id,
                                "subject_id": st.descriptor.subject_id,
                                "checksum": checksum,
                                "environment": enforce_env,
                                "reported_environment": report_env,
                                "trust_zone": cfg.trust_zone,
                                "operator_id_hash": self._operator_id_hash(operator) if operator else None,
                            },
                        )
                        return self._snapshot_state(st, env=enforce_env)

        # required approvals: policy default by risk
        metadata_req = self._metadata_required_approvals(md)
        policy_default = int(cfg.required_approvals_by_risk.get(risk_level.value, 0))
        req_approvals = self._compute_required_approvals(policy_default, metadata_req)

        allowed_envs = self._normalize_label_list(md.get("allowed_envs"))
        allowed_tz = self._normalize_label_list(md.get("allowed_trust_zones"))
        max_scope = self._normalize_max_scope(md.get("max_scope"))

        # patch_id collision-safe (no overwrite)
        with self._lock:
            patch_id = self._make_unique_patch_id_locked(checksum, allow_random_suffix=cfg.allow_duplicate_checksums)

        descriptor = PatchDescriptor(
            patch_id=patch_id,
            subject_id=subject_id,
            patch_kind=patch_kind,
            description=desc,
            origin=org,
            created_ts=time.time(),
            checksum=checksum,
            risk_level=risk_level,
            artifact_digest=self._normalize_artifact_digest(md.get("artifact_digest")),
            artifact_source=_safe_str_only(md.get("artifact_source"), max_len=128, default="") or None,
            artifact_sbom_id=_safe_str_only(md.get("artifact_sbom_id"), max_len=256, default="") or None,
            build_pipeline_id=_safe_str_only(md.get("build_pipeline_id"), max_len=256, default="") or None,
            commit_hash=_safe_str_only(md.get("commit_hash"), max_len=256, default="") or None,
            allowed_envs=allowed_envs,
            allowed_trust_zones=allowed_tz,
            max_scope=max_scope,
            change_ticket_id=_safe_str_only(md.get("change_ticket_id"), max_len=256, default="") or None,
            required_approvals=req_approvals,
            metadata=md,
        )

        # Attach clear IDs only in allowed dev envs
        if self._should_include_clear_ids(enforce_env):
            descriptor.metadata["subject_id_clear"] = _strip_unsafe_text(subject_id_clear, max_len=512)

        # Authorization hook (L7: pass safe view)
        self._authorize("register", descriptor, operator, enforce_env)

        # Optional artifact attestation at register time (may escalate risk & approvals)
        self._verify_artifact_on_register(descriptor, metadata_req=metadata_req)

        state = PatchState(
            descriptor=descriptor,
            status=PatchStatus.PENDING,
            created_by=self._operator_id_hash(operator) if operator else None,
            last_operator_id_hash=self._operator_id_hash(operator) if operator else None,
        )

        with self._lock:
            self._register_state_locked(state)

        self._emit_telemetry_register(state, operator=operator, environment=enforce_env)
        self._emit_audit_event(
            "tcd.patch.register",
            {
                "cfg_fp": self._cfg_fp,
                "patch_id": descriptor.patch_id,
                "subject_id": descriptor.subject_id,
                "patch_kind": descriptor.patch_kind.value,
                "risk_level": descriptor.risk_level.value,
                "environment": enforce_env,
                "reported_environment": report_env,
                "trust_zone": cfg.trust_zone,
                "operator_id_hash": state.created_by,
                "change_ticket_id": descriptor.change_ticket_id,
                "required_approvals": descriptor.required_approvals,
                "effective_hash_alg": self._effective_hash_alg,
            },
        )

        return self._snapshot_state(state, env=enforce_env)

    def approve_patch(
        self,
        patch_id: str,
        *,
        operator: OperatorId,
        role: str,
        reason: str = "",
        environment: Optional[str] = None,
    ) -> PatchState:
        cfg = self._cfg
        enforce_env = cfg.environment
        report_env = _safe_label(environment, default=enforce_env) if isinstance(environment, str) else enforce_env

        lock, state = self._acquire_patch(patch_id)
        try:
            # approvals only for pending unless explicitly allowed
            if state.status != PatchStatus.PENDING and not cfg.allow_approvals_after_pending:
                raise ValueError(f"cannot approve patch_id={patch_id} when status={state.status.value}")

            self._authorize("approve", state, operator, enforce_env)

            op_hash = self._operator_id_hash(operator)
            r = _safe_label(role, default="unknown")
            rs = _safe_str_only(reason, max_len=cfg.reason_max_len, default="")
            if _looks_like_secret(rs):
                rs = "[redacted]"

            # role membership enforcement (normalized)
            if cfg.enforce_operator_role_membership:
                roles_norm = { _safe_label(x, default="") for x in operator.roles if isinstance(x, str) }
                roles_norm.discard("")
                if r not in roles_norm:
                    raise PermissionError("approval role is not in operator.roles")

            now = time.time()
            state.last_update_ts = now
            state.last_operator_id_hash = op_hash

            # bounded approvals
            if len(state.approvals) >= cfg.max_approvals_per_patch:
                raise ValueError(f"too many approvals recorded for patch_id={patch_id}")

            record = {
                "operator_id_hash": op_hash,
                "role": r,
                "reason": rs,
                "ts": now,
                "postmortem": bool(state.status != PatchStatus.PENDING),
                "apply_attempts_at_approval": int(state.apply_attempts),
            }

            # distinct approvers
            if cfg.require_distinct_approvers:
                for a in state.approvals:
                    if a.get("operator_id_hash") == op_hash:
                        a.update(record)
                        break
                else:
                    state.approvals.append(record)
            else:
                state.approvals.append(record)

            self._emit_telemetry_approve(state, operator=operator, environment=enforce_env)
            self._emit_audit_event(
                "tcd.patch.approve",
                {
                    "cfg_fp": self._cfg_fp,
                    "patch_id": patch_id,
                    "subject_id": state.descriptor.subject_id,
                    "risk_level": state.descriptor.risk_level.value,
                    "environment": enforce_env,
                    "reported_environment": report_env,
                    "trust_zone": cfg.trust_zone,
                    "operator_id_hash": op_hash,
                    "role": r,
                    "reason": rs,
                    "approval_count": self._approval_count_distinct(state),
                    "required_approvals": int(state.descriptor.required_approvals),
                    "postmortem": bool(record["postmortem"]),
                },
            )

            return self._snapshot_state(state, env=enforce_env)
        finally:
            self._release_patch(patch_id, lock)

    def get_patch(self, patch_id: str) -> Optional[PatchState]:
        lock, state = self._acquire_patch(patch_id, must_exist=False)
        if state is None:
            return None
        try:
            return self._snapshot_state(state, env=self._cfg.environment)
        finally:
            self._release_patch(patch_id, lock)

    def list_patches(self) -> List[PatchState]:
        # snapshot patch ids first
        with self._lock:
            ids = [pid for pid in self._order if pid in self._patches]

        out: List[PatchState] = []
        for pid in ids:
            st = self.get_patch(pid)
            if st is not None:
                out.append(st)
        return out

    # ------------------------------------------------------------------
    # Apply / rollback orchestration
    # ------------------------------------------------------------------

    def apply_patch(
        self,
        patch_id: str,
        *,
        dry_run: bool = False,
        mode: Optional[ExecutionMode] = None,
        reason: str = "",
        operator: Optional[OperatorId] = None,
        environment: Optional[str] = None,
    ) -> Tuple[PatchState, Optional[PatchReceiptRef], Optional[ActionResult]]:
        cfg = self._cfg
        enforce_env = cfg.environment
        report_env = _safe_label(environment, default=enforce_env) if isinstance(environment, str) else enforce_env

        lock, state = self._acquire_patch(patch_id)
        try:
            now = time.time()
            state.last_update_ts = now
            state.apply_attempts += 1
            if operator is not None:
                state.last_operator_id_hash = self._operator_id_hash(operator)

            # status gating
            if state.status in (PatchStatus.APPLIED, PatchStatus.PROMOTED, PatchStatus.CANARY_APPLIED) and not cfg.allow_reapply:
                raise ValueError(f"patch_id={patch_id} is already applied (reapply disabled)")
            if state.status == PatchStatus.ROLLED_BACK and not cfg.allow_reapply:
                raise ValueError(f"patch_id={patch_id} was rolled back (reapply disabled)")

            # Authorization and environment/trust constraints
            self._authorize("apply", state, operator, enforce_env)
            self._enforce_env_trust_scope(state, enforce_env)

            # L7: verify artifact BEFORE approvals (risk may escalate here)
            if not self._verify_artifact_on_apply(state):
                self._emit_telemetry_apply(state=state, ok=False, dry_run=dry_run, mode=None, environment=enforce_env)
                self._emit_audit_event(
                    "tcd.patch.apply.artifact_blocked",
                    {
                        "cfg_fp": self._cfg_fp,
                        "patch_id": patch_id,
                        "subject_id": state.descriptor.subject_id,
                        "risk_level": state.descriptor.risk_level.value,
                        "environment": enforce_env,
                        "reported_environment": report_env,
                        "trust_zone": cfg.trust_zone,
                        "operator_id_hash": state.last_operator_id_hash,
                        "error_code": state.last_error_code,
                    },
                )
                return self._snapshot_state(state, env=enforce_env), None, None

            # Approval enforcement AFTER potential risk escalation
            self._enforce_approvals_before_apply(state)

            # mode rules
            self._validate_apply_mode(state, dry_run=dry_run, explicit_mode=mode)

            if not self._agent:
                self._fail(state, code="NO_AGENT", msg="ControlAgent not configured")
                self._emit_audit_event(
                    "tcd.patch.apply.error",
                    {
                        "cfg_fp": self._cfg_fp,
                        "patch_id": patch_id,
                        "subject_id": state.descriptor.subject_id,
                        "environment": enforce_env,
                        "reported_environment": report_env,
                        "trust_zone": cfg.trust_zone,
                        "operator_id_hash": state.last_operator_id_hash,
                        "error_code": state.last_error_code,
                    },
                )
                self._emit_telemetry_apply(state=state, ok=False, dry_run=dry_run, mode=None, environment=enforce_env)
                return self._snapshot_state(state, env=enforce_env), None, None

            chosen_mode = self._choose_mode_for_apply(state=state, dry_run=dry_run, explicit_mode=mode)

            rs = _safe_str_only(reason, max_len=cfg.reason_max_len, default="")
            if _looks_like_secret(rs):
                rs = "[redacted]"

            metadata = self._make_agent_metadata(state=state, reason=rs, action_kind="apply")

            # execute agent with exception safety (avoid leaking str(e))
            result: Optional[ActionResult]
            try:
                result = self._agent.apply_patch(  # type: ignore[union-attr]
                    patch_id=patch_id,
                    dry_run=bool(dry_run),
                    mode=chosen_mode,
                    metadata=metadata,
                )
            except Exception as e:
                self._fail(state, code="AGENT_EXCEPTION", err_type=type(e).__name__)
                result = None

            ok = bool(getattr(result, "ok", False)) if result is not None else False

            if ok:
                # staged lifecycle optional
                if cfg.enable_staged_rollout and _mode_is_canary_like(chosen_mode):
                    state.status = PatchStatus.CANARY_APPLIED
                else:
                    state.status = PatchStatus.APPLIED

                state.applied_ts = getattr(result, "finished_at", now) if result is not None else now
                state.last_error = None
                state.last_error_code = None
                state.last_error_type = None

                raw_targets = getattr(result, "targets", None) if result is not None else None
                state.apply_targets = self._store_targets(raw_targets)
                state.canary_success = getattr(result, "canary_success", None) if result is not None else None
                state.promotion_ts = getattr(result, "promotion_ts", None) if result is not None else None
            else:
                self._fail(state, code="APPLY_FAILED")

            # Enforce max_scope after execution (fail-safe governance)
            if ok and state.descriptor.max_scope:
                violated, vmsg = self._check_scope_violation(state.descriptor.max_scope, state.apply_targets)
                if violated:
                    ok = False
                    self._fail(state, code="SCOPE_VIOLATION", msg=vmsg)
                    if cfg.auto_rollback_on_failure and not dry_run:
                        rb_state, rb_receipt, _ = self.rollback_patch(
                            patch_id=patch_id,
                            reason="auto rollback after scope violation",
                            operator=operator,
                            environment=enforce_env,
                        )
                        state.rollback_receipt = rb_receipt
                        state.status = rb_state.status
                        state.rolled_back_ts = rb_state.rolled_back_ts

            # Receipts (best-effort)
            if result is not None:
                state.apply_receipt = self._issue_patch_receipt(kind=cfg.apply_kind, state=state, result=result)
            else:
                state.apply_receipt = None

            # Auto rollback on failure (non-dry-run)
            if (not ok) and cfg.auto_rollback_on_failure and not dry_run:
                rb_state, rb_receipt, _ = self.rollback_patch(
                    patch_id=patch_id,
                    reason="auto rollback after failed apply",
                    operator=operator,
                    environment=enforce_env,
                )
                state.rollback_receipt = rb_receipt
                state.status = rb_state.status
                state.rolled_back_ts = rb_state.rolled_back_ts

            duration_ms = _result_duration_ms(result, allow_callables=cfg.allow_callables_in_result)
            self._emit_telemetry_apply(state=state, ok=ok, dry_run=dry_run, mode=chosen_mode, environment=enforce_env)
            self._emit_audit_event(
                "tcd.patch.apply",
                {
                    "cfg_fp": self._cfg_fp,
                    "patch_id": patch_id,
                    "subject_id": state.descriptor.subject_id,
                    "status": state.status.value,
                    "dry_run": bool(dry_run),
                    "mode": _safe_mode_label(chosen_mode),
                    "risk_level": state.descriptor.risk_level.value,
                    "environment": enforce_env,
                    "reported_environment": report_env,
                    "trust_zone": cfg.trust_zone,
                    "operator_id_hash": state.last_operator_id_hash,
                    "reason": rs,
                    "ok": bool(ok),
                    "error_code": state.last_error_code,
                    "error_type": state.last_error_type,
                    "duration_ms": float(duration_ms),
                    "apply_attempts": int(state.apply_attempts),
                },
            )

            return self._snapshot_state(state, env=enforce_env), self._snapshot_receipt(state.apply_receipt), result
        finally:
            self._release_patch(patch_id, lock)

    def rollback_patch(
        self,
        patch_id: str,
        *,
        reason: str = "",
        mode: Optional[ExecutionMode] = None,
        operator: Optional[OperatorId] = None,
        environment: Optional[str] = None,
    ) -> Tuple[PatchState, Optional[PatchReceiptRef], Optional[ActionResult]]:
        cfg = self._cfg
        enforce_env = cfg.environment
        report_env = _safe_label(environment, default=enforce_env) if isinstance(environment, str) else enforce_env

        lock, state = self._acquire_patch(patch_id)
        try:
            now = time.time()
            state.last_update_ts = now
            state.rollback_attempts += 1
            if operator is not None:
                state.last_operator_id_hash = self._operator_id_hash(operator)

            self._authorize("rollback", state, operator, enforce_env)
            self._enforce_env_trust_scope(state, enforce_env)

            if not cfg.allow_rollback_without_prior_apply:
                if state.status not in (PatchStatus.APPLIED, PatchStatus.CANARY_APPLIED, PatchStatus.PROMOTED) and state.applied_ts is None:
                    raise ValueError(f"cannot rollback patch_id={patch_id} without prior apply")

            if not self._agent:
                self._fail(state, code="NO_AGENT", msg="ControlAgent not configured")
                self._emit_audit_event(
                    "tcd.patch.rollback.error",
                    {
                        "cfg_fp": self._cfg_fp,
                        "patch_id": patch_id,
                        "subject_id": state.descriptor.subject_id,
                        "environment": enforce_env,
                        "reported_environment": report_env,
                        "trust_zone": cfg.trust_zone,
                        "operator_id_hash": state.last_operator_id_hash,
                        "error_code": state.last_error_code,
                    },
                )
                self._emit_telemetry_rollback(state=state, ok=False, mode=None, environment=enforce_env)
                return self._snapshot_state(state, env=enforce_env), None, None

            chosen_mode = self._choose_mode_for_rollback(state=state, explicit_mode=mode)

            rs = _safe_str_only(reason, max_len=cfg.reason_max_len, default="")
            if _looks_like_secret(rs):
                rs = "[redacted]"

            metadata = self._make_agent_metadata(state=state, reason=rs, action_kind="rollback")

            result: Optional[ActionResult]
            try:
                result = self._agent.rollback(  # type: ignore[union-attr]
                    patch_id=patch_id,
                    mode=chosen_mode,
                    metadata=metadata,
                )
            except Exception as e:
                self._fail(state, code="AGENT_EXCEPTION", err_type=type(e).__name__)
                result = None

            ok = bool(getattr(result, "ok", False)) if result is not None else False

            if ok:
                state.status = PatchStatus.ROLLED_BACK
                state.rolled_back_ts = getattr(result, "finished_at", now) if result is not None else now
                state.last_error = None
                state.last_error_code = None
                state.last_error_type = None
            else:
                self._fail(state, code="ROLLBACK_FAILED")

            receipt = self._issue_patch_receipt(kind=cfg.rollback_kind, state=state, result=result) if result is not None else None
            state.rollback_receipt = receipt

            duration_ms = _result_duration_ms(result, allow_callables=cfg.allow_callables_in_result)
            self._emit_telemetry_rollback(state=state, ok=ok, mode=chosen_mode, environment=enforce_env)
            self._emit_audit_event(
                "tcd.patch.rollback",
                {
                    "cfg_fp": self._cfg_fp,
                    "patch_id": patch_id,
                    "subject_id": state.descriptor.subject_id,
                    "status": state.status.value,
                    "mode": _safe_mode_label(chosen_mode),
                    "risk_level": state.descriptor.risk_level.value,
                    "environment": enforce_env,
                    "reported_environment": report_env,
                    "trust_zone": cfg.trust_zone,
                    "operator_id_hash": state.last_operator_id_hash,
                    "reason": rs,
                    "ok": bool(ok),
                    "error_code": state.last_error_code,
                    "error_type": state.last_error_type,
                    "duration_ms": float(duration_ms),
                    "rollback_attempts": int(state.rollback_attempts),
                },
            )

            return self._snapshot_state(state, env=enforce_env), self._snapshot_receipt(receipt), result
        finally:
            self._release_patch(patch_id, lock)

    # ------------------------------------------------------------------
    # Internal helpers: locking and registry
    # ------------------------------------------------------------------

    def _acquire_patch(self, patch_id: str, *, must_exist: bool = True) -> Tuple[threading.RLock, Optional[PatchState]]:
        """
        L7: in-flight protected acquire so eviction can't remove while operating.
        """
        with self._lock:
            st = self._patches.get(patch_id)
            if st is None:
                if must_exist:
                    raise KeyError(f"unknown patch_id={patch_id}")
                # still return a lock to satisfy signature; unused
                dummy = threading.RLock()
                return dummy, None

            lock = self._patch_locks.get(patch_id)
            if lock is None:
                lock = threading.RLock()
                self._patch_locks[patch_id] = lock

            self._in_flight[patch_id] = int(self._in_flight.get(patch_id, 0)) + 1

        lock.acquire()
        return lock, st

    def _release_patch(self, patch_id: str, lock: threading.RLock) -> None:
        try:
            lock.release()
        finally:
            with self._lock:
                cur = int(self._in_flight.get(patch_id, 0))
                if cur <= 1:
                    self._in_flight.pop(patch_id, None)
                else:
                    self._in_flight[patch_id] = cur - 1

    def _register_state_locked(self, state: PatchState) -> None:
        cfg = self._cfg
        patch_id = state.descriptor.patch_id
        subject_id = state.descriptor.subject_id
        checksum = state.descriptor.checksum

        # Enforce per-subject pending limit via scan (strict correctness > micro perf)
        if state.status == PatchStatus.PENDING and cfg.max_pending_per_subject > 0:
            pending = 0
            for s in self._patches.values():
                if s.descriptor.subject_id == subject_id and s.status == PatchStatus.PENDING:
                    pending += 1
                    if pending >= cfg.max_pending_per_subject:
                        raise ValueError(
                            f"too many pending patches for subject_id={subject_id!r}; limit={cfg.max_pending_per_subject}"
                        )

        if patch_id not in self._patches:
            self._order.append(patch_id)
            self._patch_locks.setdefault(patch_id, threading.RLock())

        self._patches[patch_id] = state

        if not cfg.allow_duplicate_checksums:
            self._by_subject_checksum.setdefault((subject_id, checksum), patch_id)

        self._evict_if_needed_locked()

    def _evict_if_needed_locked(self) -> None:
        cfg = self._cfg
        if len(self._order) <= cfg.max_patches:
            return

        def is_terminal(st: PatchState) -> bool:
            return st.status in {PatchStatus.FAILED, PatchStatus.ROLLED_BACK, PatchStatus.PROMOTION_FAILED}

        excess = len(self._order) - cfg.max_patches
        evicted = 0
        new_order: List[str] = []

        for pid in self._order:
            if evicted >= excess:
                new_order.append(pid)
                continue

            st = self._patches.get(pid)
            if st is None:
                evicted += 1
                continue

            # L7: do not evict in-flight unless explicitly allowed
            if (not cfg.allow_evict_in_flight) and int(self._in_flight.get(pid, 0)) > 0:
                new_order.append(pid)
                continue

            if cfg.max_patches_evict_only_terminal and not is_terminal(st):
                new_order.append(pid)
                continue

            self._remove_patch_locked(pid)
            evicted += 1

        self._order = [pid for pid in new_order if pid in self._patches]

        if len(self._patches) > cfg.max_patches:
            raise RuntimeError(
                f"max_patches exceeded but eviction is restricted; current={len(self._patches)}, max={cfg.max_patches}"
            )

    def _remove_patch_locked(self, patch_id: str) -> None:
        st = self._patches.pop(patch_id, None)
        self._patch_locks.pop(patch_id, None)
        self._in_flight.pop(patch_id, None)

        if st is None:
            return

        key = (st.descriptor.subject_id, st.descriptor.checksum)
        mapped = self._by_subject_checksum.get(key)
        if mapped == patch_id:
            self._by_subject_checksum.pop(key, None)

    def prune_terminal(self, *, max_remove: int = 256) -> int:
        """
        Explicit prune API (safer than mixing eviction in hot paths).
        """
        cfg = self._cfg
        removed = 0
        with self._lock:
            for pid in list(self._order):
                if removed >= max_remove:
                    break
                st = self._patches.get(pid)
                if st is None:
                    continue
                if int(self._in_flight.get(pid, 0)) > 0 and not cfg.allow_evict_in_flight:
                    continue
                if st.status in {PatchStatus.FAILED, PatchStatus.ROLLED_BACK, PatchStatus.PROMOTION_FAILED}:
                    self._remove_patch_locked(pid)
                    removed += 1
            self._order = [pid for pid in self._order if pid in self._patches]
        return removed

    # ------------------------------------------------------------------
    # Internal helpers: hashing / ids / fingerprint
    # ------------------------------------------------------------------

    def _resolve_effective_hash_alg(self) -> str:
        cfg = self._cfg
        requested = (cfg.hash_alg or "blake3").lower()

        if requested == "blake3":
            if RollingHasher is not None:
                return "blake3"
            # try python blake3 package if present
            try:
                import blake3  # type: ignore
                _ = blake3.blake3(b"test").hexdigest()
                return "blake3"
            except Exception:
                if cfg.require_hash_alg_available:
                    raise ValueError("hash_alg='blake3' requested but no RollingHasher or blake3 module available")
                if cfg.allow_hash_fallback:
                    return "blake2s"
                raise ValueError("hash_alg='blake3' unavailable and fallback disabled")

        if requested in ("sha256", "sha1"):
            return requested

        # Unknown -> sha256 (stable + available)
        return "sha256"

    def _fingerprint_runtime_config(self) -> str:
        """
        L7: fingerprint covers more behavior fields and includes effective_hash_alg + hook presence.
        """
        cfg = self._cfg
        payload = cfg.to_dict()
        payload.update({
            "effective_hash_alg": self._effective_hash_alg,
            "rolling_hasher_present": bool(RollingHasher is not None),
            "authorize_fn_present": bool(cfg.authorize_fn is not None),
            "audit_hook_present": bool(cfg.audit_hook is not None),
            "audit_hook_bytes_present": bool(cfg.audit_hook_bytes is not None),
            "e_allocator_present": bool(cfg.e_allocator is not None),
            "telemetry_present": bool(cfg.telemetry is not None),
        })
        b = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        return hashlib.sha256(b).hexdigest()

    def _derive_id_keys(self) -> Dict[str, bytes]:
        """
        Derive stable per-purpose HMAC keys.
        Priority:
          - subject_hash_key / operator_hash_key
          - id_hash_key (shared)
          - ephemeral (per-runtime) if none provided
        """
        cfg = self._cfg

        # base material
        base = _parse_key_material(cfg.id_hash_key) if cfg.id_hash_key else None
        if base is None:
            base = os.urandom(32)

        # subject/operator overrides
        subj_base = _parse_key_material(cfg.subject_hash_key) if cfg.subject_hash_key else base
        op_base = _parse_key_material(cfg.operator_hash_key) if cfg.operator_hash_key else base

        if subj_base is None:
            subj_base = base
        if op_base is None:
            op_base = base

        if len(subj_base) < cfg.min_id_hash_key_bytes or len(op_base) < cfg.min_id_hash_key_bytes:
            raise ValueError("id hash key material too short for L7 policy")

        return {
            "subject": _kdf(subj_base, "tcd:subject_id"),
            "operator": _kdf(op_base, "tcd:operator_id"),
        }

    def _hmac_hex(self, key: bytes, msg: str) -> str:
        cfg = self._cfg
        h = hmac.new(key, msg.encode("utf-8", errors="ignore"), hashlib.sha256).hexdigest()
        n = cfg.id_hash_hex_chars
        if n <= 0:
            return h
        return h[:n]

    def _should_include_clear_ids(self, env: str) -> bool:
        cfg = self._cfg
        if not cfg.include_clear_ids:
            return False
        return _safe_label(env, default="") in set(cfg.clear_id_env_allowlist)

    def _subject_id(self, clear: str, *, env: str) -> str:
        cfg = self._cfg
        if not cfg.pseudonymize_subject_id:
            return _strip_unsafe_text(clear, max_len=512)
        return self._hmac_hex(self._id_keys["subject"], clear)

    def _operator_id_hash(self, operator: Optional[OperatorId]) -> Optional[str]:
        if operator is None:
            return None
        clear = _safe_str_only(operator.operator_id, max_len=512, default="")
        if not clear:
            return "unknown"
        if not self._cfg.pseudonymize_operator_id:
            return clear
        return self._hmac_hex(self._id_keys["operator"], clear)

    # ------------------------------------------------------------------
    # Internal helpers: checksum and identifiers
    # ------------------------------------------------------------------

    def _compute_checksum(self, subject_id: str, patch_blob: bytes) -> str:
        """
        Domain-separated, length-delimited:
          ("tcd:patch", subject_id, patch_blob)
        """
        subj_b = subject_id.encode("utf-8", errors="ignore")
        prefix = b"tcd:patch\0"
        subj_len = len(subj_b).to_bytes(4, "big", signed=False)
        blob_len = len(patch_blob).to_bytes(8, "big", signed=False)

        alg = self._effective_hash_alg

        if alg == "blake3":
            if RollingHasher is not None:
                h = RollingHasher(alg="blake3", ctx="tcd:patch")
                h.update_bytes(prefix)
                h.update_bytes(subj_len)
                h.update_bytes(subj_b)
                h.update_bytes(blob_len)
                h.update_bytes(patch_blob)
                return h.hex()
            # python blake3 module
            import blake3  # type: ignore
            h3 = blake3.blake3()
            h3.update(prefix)
            h3.update(subj_len)
            h3.update(subj_b)
            h3.update(blob_len)
            h3.update(patch_blob)
            return h3.hexdigest()

        if alg == "sha1":
            if not self._cfg.allow_legacy_sha1:
                raise ValueError("hash_alg='sha1' disabled by default")
            h2 = hashlib.sha1()
        elif alg == "sha256":
            h2 = hashlib.sha256()
        else:
            # blake2s fallback
            h2 = hashlib.blake2s(digest_size=32)

        h2.update(prefix)
        h2.update(subj_len)
        h2.update(subj_b)
        h2.update(blob_len)
        h2.update(patch_blob)
        return h2.hexdigest()

    def _make_patch_id(self, checksum: str, *, unique: bool) -> str:
        short = checksum[: self._cfg.patch_id_checksum_chars] if checksum else "unknown"
        pid = f"{self._cfg.patch_id_prefix}-{short}"
        if unique:
            nbytes = max(2, self._cfg.patch_id_random_suffix_chars // 2)
            suffix = os.urandom(nbytes).hex()[: self._cfg.patch_id_random_suffix_chars]
            pid = f"{pid}-{suffix}"
        return pid

    def _make_unique_patch_id_locked(self, checksum: str, *, allow_random_suffix: bool) -> str:
        """
        L7: collisions must not overwrite existing patches.
        """
        base = self._make_patch_id(checksum, unique=False)
        if base not in self._patches:
            return base

        # if same checksum prefix collides with existing, add suffix until unique
        for _ in range(32):
            pid = self._make_patch_id(checksum, unique=True)
            if pid not in self._patches:
                return pid

        # last resort: add longer suffix
        pid = f"{base}-{os.urandom(8).hex()}"
        if pid in self._patches:
            raise RuntimeError("failed to allocate unique patch_id after many attempts")
        return pid

    # ------------------------------------------------------------------
    # Internal helpers: approvals / risk escalation / constraints
    # ------------------------------------------------------------------

    def _approval_count_distinct(self, state: PatchState) -> int:
        seen = set()
        for a in state.approvals:
            hid = a.get("operator_id_hash")
            if isinstance(hid, str) and hid:
                seen.add(hid)
        return len(seen)

    def _enforce_approvals_before_apply(self, state: PatchState) -> None:
        required = max(0, int(state.descriptor.required_approvals))
        if required <= 0:
            return
        count = self._approval_count_distinct(state) if self._cfg.require_distinct_approvers else len(state.approvals)
        if count < required:
            raise PermissionError(
                f"patch_id={state.descriptor.patch_id} requires {required} approvals, but only {count} recorded"
            )

    def _enforce_env_trust_scope(self, state: PatchState, env: str) -> None:
        cfg = self._cfg
        if state.descriptor.allowed_envs:
            allowed = {x.lower() for x in state.descriptor.allowed_envs if isinstance(x, str)}
            if env.lower() not in allowed:
                raise PermissionError(f"patch_id={state.descriptor.patch_id} not allowed in env={env!r}")

        if state.descriptor.allowed_trust_zones:
            allowed = {x.lower() for x in state.descriptor.allowed_trust_zones if isinstance(x, str)}
            if cfg.trust_zone.lower() not in allowed:
                raise PermissionError(f"patch_id={state.descriptor.patch_id} not allowed in trust_zone={cfg.trust_zone!r}")

    def _risk_rank(self, lvl: PatchRiskLevel) -> int:
        return {"low": 0, "medium": 1, "high": 2}.get(lvl.value, 0)

    def _compute_required_approvals(self, policy_default: int, metadata_req: Optional[int]) -> int:
        cfg = self._cfg
        req = max(0, int(policy_default))
        if cfg.allow_metadata_override_required_approvals and metadata_req is not None:
            mr = max(0, int(metadata_req))
            if cfg.allow_metadata_lower_required_approvals:
                req = mr
            else:
                req = max(req, mr)
        return req

    def _metadata_required_approvals(self, md: Dict[str, Any]) -> Optional[int]:
        ra = md.get("required_approvals")
        try:
            if ra is None:
                return None
            return _clamp_int(int(ra), 0, 100)
        except Exception:
            return None

    def _maybe_escalate_risk(self, descriptor: PatchDescriptor, new_level: PatchRiskLevel, *, reason: str, metadata_req: Optional[int]) -> None:
        cfg = self._cfg
        if self._risk_rank(new_level) <= self._risk_rank(descriptor.risk_level):
            return

        descriptor.risk_level = new_level
        # required approvals must move with risk
        policy_default = int(cfg.required_approvals_by_risk.get(new_level.value, 0))
        descriptor.required_approvals = max(
            int(descriptor.required_approvals),
            self._compute_required_approvals(policy_default, metadata_req),
        )

        # record escalation reason
        lst = descriptor.metadata.get("risk_escalations")
        if not isinstance(lst, list):
            lst = []
        if len(lst) < 16:
            lst.append({"ts": time.time(), "to": new_level.value, "reason": _safe_label(reason, default="unknown")})
        descriptor.metadata["risk_escalations"] = lst

    # ------------------------------------------------------------------
    # Internal helpers: mode selection & validation
    # ------------------------------------------------------------------

    def _validate_apply_mode(self, state: PatchState, *, dry_run: bool, explicit_mode: Optional[ExecutionMode]) -> None:
        cfg = self._cfg
        # explicit_mode must be Enum or str (L7)
        if explicit_mode is not None and not isinstance(explicit_mode, (str, Enum)):
            raise TypeError("explicit_mode must be an Enum or str")

        # HIGH risk canary enforcement
        if (
            cfg.require_canary_for_high_risk
            and state.descriptor.risk_level == PatchRiskLevel.HIGH
            and not dry_run
        ):
            if explicit_mode is not None:
                if cfg.block_high_risk_production_explicit_mode and _mode_is_production_like(explicit_mode):
                    raise PermissionError("HIGH risk patch cannot use production-like explicit_mode; must use canary/staged")
                if cfg.require_explicit_canary_like_for_high_risk and not _mode_is_canary_like(explicit_mode):
                    raise PermissionError("HIGH risk patch explicit_mode must be canary-like (canary/staged)")
            else:
                # no explicit mode: we must be able to resolve a canary mode
                if self._choose_canary_mode() is None and cfg.require_mode_resolution:
                    raise PermissionError("HIGH risk patch requires canary mode, but no canary mode is available")

    def _choose_canary_mode(self) -> Optional[Any]:
        if self._cfg.canary_mode_default is not None:
            return self._cfg.canary_mode_default
        if hasattr(ExecutionMode, "CANARY"):
            m = getattr(ExecutionMode, "CANARY")
            if isinstance(m, (Enum, str)):
                return m
        return None

    def _choose_production_mode(self) -> Optional[Any]:
        if self._cfg.production_mode_default is not None:
            return self._cfg.production_mode_default
        if hasattr(ExecutionMode, "PRODUCTION"):
            m = getattr(ExecutionMode, "PRODUCTION")
            if isinstance(m, (Enum, str)):
                return m
        return None

    def _choose_mode_for_apply(self, *, state: PatchState, dry_run: bool, explicit_mode: Optional[ExecutionMode]) -> Any:
        if explicit_mode is not None:
            return explicit_mode

        if dry_run:
            m = self._choose_canary_mode()
            if m is not None:
                return m
            if self._cfg.require_mode_resolution:
                raise PermissionError("dry_run requires safe/canary mode but none is available")
            return None

        if state.descriptor.risk_level == PatchRiskLevel.HIGH and self._cfg.require_canary_for_high_risk:
            m = self._choose_canary_mode()
            if m is not None:
                return m
            if self._cfg.require_mode_resolution:
                raise PermissionError("HIGH risk apply requires canary mode but none is available")
            return None

        m = self._choose_production_mode()
        if m is not None:
            return m
        if self._cfg.require_mode_resolution:
            raise PermissionError("production mode not available")
        return None

    def _choose_mode_for_rollback(self, *, state: PatchState, explicit_mode: Optional[ExecutionMode]) -> Any:
        if explicit_mode is not None:
            if not isinstance(explicit_mode, (str, Enum)):
                raise TypeError("explicit_mode must be an Enum or str")
            return explicit_mode
        m = self._choose_production_mode()
        if m is not None:
            return m
        if self._cfg.require_mode_resolution:
            raise PermissionError("rollback requires production mode but none is available")
        return None

    # ------------------------------------------------------------------
    # Internal helpers: metadata / targets / scope checks
    # ------------------------------------------------------------------

    def _normalize_label_list(self, v: Any) -> Optional[List[str]]:
        if v is None:
            return None
        items: List[str] = []
        if isinstance(v, (list, tuple)):
            for x in v:
                if isinstance(x, str):
                    lab = _safe_label(x, default="")
                    if lab:
                        items.append(lab)
        elif isinstance(v, str):
            lab = _safe_label(v, default="")
            if lab:
                items.append(lab)
        else:
            return None

        seen = set()
        out = []
        for x in items:
            if x in seen:
                continue
            seen.add(x)
            out.append(x)
        return out or None

    def _normalize_max_scope(self, v: Any) -> Optional[Dict[str, int]]:
        if type(v) is not dict:
            return None
        out: Dict[str, int] = {}
        n = 0
        for k, val in v.items():
            if n >= 64:
                break
            kk = _safe_key(k, default=None)
            if kk is None:
                continue
            try:
                iv = int(val)
            except Exception:
                continue
            out[kk] = _clamp_int(iv, 0, 1_000_000_000)
            n += 1
        return out or None

    def _check_scope_violation(self, max_scope: Dict[str, int], targets: Any) -> Tuple[bool, str]:
        """
        L7: if require_targets_for_scope_enforcement and targets missing/invalid => violation.
        """
        if not max_scope:
            return False, ""

        if not isinstance(targets, dict):
            if self._cfg.require_targets_for_scope_enforcement:
                return True, "max_scope enforcement requires targets, but targets were missing/invalid"
            return False, ""

        for k, limit in max_scope.items():
            tv = targets.get(k)
            if tv is None:
                # If strict scope enforcement: missing key counts as 0 (not violation)
                continue
            count: Optional[int] = None
            if isinstance(tv, (list, tuple, set)):
                count = len(tv)
            else:
                fv = _finite_float(tv)
                if fv is not None:
                    count = int(fv)
            if count is not None and count > int(limit):
                return True, f"max_scope violated for {k}: {count} > {int(limit)}"
        return False, ""

    def _store_targets(self, raw_targets: Any) -> Optional[Dict[str, Any]]:
        cfg = self._cfg
        if cfg.targets_store_mode == "none":
            return None

        if cfg.targets_store_mode == "summary":
            if not isinstance(raw_targets, dict):
                return None
            # summary counts only
            out: Dict[str, Any] = {}
            for k, v in raw_targets.items():
                kk = _safe_key(k, default=None)
                if not kk:
                    continue
                if _is_sensitive_key(kk):
                    continue
                if isinstance(v, (list, tuple, set)):
                    out[kk] = len(v)
                else:
                    fv = _finite_float(v)
                    if fv is not None:
                        out[kk] = int(fv)
            return out or None

        # sanitized
        if type(raw_targets) is not dict:
            return None
        budget = _JsonBudget(
            max_nodes=cfg.targets_budget_nodes,
            max_items=cfg.targets_budget_items,
            max_depth=cfg.targets_budget_depth,
            max_str=cfg.targets_budget_str,
        )
        safe = _json_sanitize(raw_targets, budget=budget, depth=0, redact_secrets=True, redact_sensitive_keys=True)
        return safe if isinstance(safe, dict) else None

    def _sanitize_patch_metadata(self, md: Mapping[str, Any]) -> Dict[str, Any]:
        """
        L7: accept only built-in dict as input mapping; apply allowlist.
        """
        if type(md) is not dict:
            return {}

        allowed = None
        if self._cfg.metadata_allowed_keys:
            allowed = {k for k in self._cfg.metadata_allowed_keys if isinstance(k, str)}
        budget = _JsonBudget(
            max_nodes=self._cfg.metadata_budget_nodes,
            max_items=self._cfg.metadata_budget_items,
            max_depth=self._cfg.metadata_budget_depth,
            max_str=self._cfg.metadata_budget_str,
        )
        safe = _json_sanitize(
            md,
            budget=budget,
            depth=0,
            redact_secrets=True,
            redact_sensitive_keys=True,
            allowed_keys=allowed,
        )
        return safe if isinstance(safe, dict) else {}

    def _normalize_artifact_digest(self, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = _safe_str_only(v, max_len=256, default="")
        if not s:
            return None
        s = s.strip()
        # normalize
        s2 = s.lower()
        if not _ARTIFACT_DIGEST_RE.fullmatch(s2):
            # mark invalid but do not accept as digest
            return None
        return s2

    # ------------------------------------------------------------------
    # Internal helpers: authorization
    # ------------------------------------------------------------------

    def _authorize(
        self,
        action: str,
        obj: Union[PatchDescriptor, PatchState],
        operator: Optional[OperatorId],
        environment: Optional[str],
    ) -> None:
        fn = self._cfg.authorize_fn
        if not fn:
            return

        # L7: pass safe view (snapshot or readonly dict)
        op_view = None
        if operator is not None:
            # operator_id is passed as hashed to avoid PII leakage
            op_view = OperatorId(operator_id=self._operator_id_hash(operator) or "unknown",
                                 roles=[_safe_label(x, default="") for x in operator.roles if isinstance(x, str)])

        if self._cfg.authorize_view_mode == "dict_readonly":
            view = self._make_authorize_dict(action, obj, environment)
            fn(action, MappingProxyType(view), op_view, environment)
            return

        # snapshot mode (compatibility): deep snapshot so external mutation cannot affect internal state
        if isinstance(obj, PatchState):
            fn(action, self._snapshot_state(obj, env=self._cfg.environment), op_view, environment)
        else:
            fn(action, self._snapshot_descriptor(obj, env=self._cfg.environment), op_view, environment)

    def _make_authorize_dict(self, action: str, obj: Union[PatchDescriptor, PatchState], env: Optional[str]) -> Dict[str, Any]:
        if isinstance(obj, PatchState):
            d = obj.descriptor
            return {
                "action": _safe_label(action, default="action"),
                "patch_id": d.patch_id,
                "subject_id": d.subject_id,
                "patch_kind": d.patch_kind.value,
                "risk_level": d.risk_level.value,
                "status": obj.status.value,
                "required_approvals": int(d.required_approvals),
                "approval_count": int(self._approval_count_distinct(obj)),
                "environment": _safe_label(env, default=self._cfg.environment) if isinstance(env, str) else self._cfg.environment,
                "trust_zone": self._cfg.trust_zone,
            }
        return {
            "action": _safe_label(action, default="action"),
            "patch_id": obj.patch_id,
            "subject_id": obj.subject_id,
            "patch_kind": obj.patch_kind.value,
            "risk_level": obj.risk_level.value,
            "required_approvals": int(obj.required_approvals),
            "environment": _safe_label(env, default=self._cfg.environment) if isinstance(env, str) else self._cfg.environment,
            "trust_zone": self._cfg.trust_zone,
        }

    # ------------------------------------------------------------------
    # Internal helpers: artifact verification & risk escalation
    # ------------------------------------------------------------------

    def _verify_artifact_on_register(self, descriptor: PatchDescriptor, *, metadata_req: Optional[int]) -> None:
        cfg = self._cfg
        if not self._attestor or not cfg.verify_artifact_on_register:
            return

        digest = descriptor.artifact_digest or descriptor.metadata.get("artifact_digest")
        digest = self._normalize_artifact_digest(digest)
        if digest is None:
            return

        verifier = getattr(self._attestor, "verify_artifact", None)
        if not callable(verifier):
            return

        try:
            result = verifier(digest, descriptor.metadata)
        except Exception:
            status = "error"
            attestation_id = None
        else:
            status = result.get("status", "unknown") if isinstance(result, dict) else "unknown"
            attestation_id = result.get("attestation_id") if isinstance(result, dict) else None

        status_s = _safe_label(status, default="unknown")
        descriptor.metadata["attestation_status"] = status_s
        if isinstance(attestation_id, str) and attestation_id:
            descriptor.metadata["attestation_id"] = _strip_unsafe_text(attestation_id, max_len=256)

        if cfg.require_verified_artifact_on_register and status_s != "verified":
            # escalate risk and also block registration
            self._maybe_escalate_risk(descriptor, PatchRiskLevel.HIGH, reason="attestation_unverified_register", metadata_req=metadata_req)
            raise ValueError("artifact verification failed at register time")

        if status_s != "verified":
            self._maybe_escalate_risk(descriptor, PatchRiskLevel.HIGH, reason="attestation_unverified_register", metadata_req=metadata_req)

    def _verify_artifact_on_apply(self, state: PatchState) -> bool:
        cfg = self._cfg
        if not self._attestor or not cfg.verify_artifact_on_apply:
            return True

        digest_raw = state.descriptor.artifact_digest or state.descriptor.metadata.get("artifact_digest")
        digest = self._normalize_artifact_digest(digest_raw)

        if digest is None:
            if cfg.require_artifact_digest_on_apply:
                self._fail(state, code="ARTIFACT_DIGEST_MISSING")
                return False
            return True

        verifier = getattr(self._attestor, "verify_artifact", None)
        if not callable(verifier):
            return True

        try:
            result = verifier(digest, state.descriptor.metadata)
        except Exception:
            status = "error"
            attestation_id = None
        else:
            status = result.get("status", "unknown") if isinstance(result, dict) else "unknown"
            attestation_id = result.get("attestation_id") if isinstance(result, dict) else None

        status_s = _safe_label(status, default="unknown")
        # write back whitelist fields only
        state.descriptor.metadata["attestation_status"] = status_s
        if isinstance(attestation_id, str) and attestation_id:
            state.descriptor.metadata["attestation_id"] = _strip_unsafe_text(attestation_id, max_len=256)

        # risk escalation must sync approvals
        metadata_req = self._metadata_required_approvals(state.descriptor.metadata)
        if status_s != "verified":
            self._maybe_escalate_risk(state.descriptor, PatchRiskLevel.HIGH, reason="attestation_unverified_apply", metadata_req=metadata_req)

        if cfg.require_verified_artifact_on_apply and status_s != "verified":
            self._fail(state, code="ATTESTATION_BLOCKED")
            return False

        return True

    # ------------------------------------------------------------------
    # Internal helpers: receipts & budgets
    # ------------------------------------------------------------------

    def _issue_patch_receipt(self, *, kind: str, state: PatchState, result: ActionResult) -> Optional[PatchReceiptRef]:
        cfg = self._cfg
        if self._attestor is None:
            return None

        try:
            ok = bool(getattr(result, "ok", False))
            action = getattr(result, "action", None)
            action_s = _safe_str_only(action, max_len=64, default="") if isinstance(action, str) else ""
            mode_s = _safe_mode_label(getattr(result, "mode", None))

            payload = {
                "kind": _safe_label(kind, default="op"),
                "patch_id": state.descriptor.patch_id,
                "subject_id": state.descriptor.subject_id,
                "patch_kind": state.descriptor.patch_kind.value,
                "status": state.status.value,
                "risk_level": state.descriptor.risk_level.value,
                "origin": state.descriptor.origin,
                "ok": bool(ok),
                "action": action_s,
                "mode": mode_s,
                "duration_ms": float(_result_duration_ms(result, allow_callables=cfg.allow_callables_in_result)),
                "error_code": state.last_error_code,
                "error_type": state.last_error_type,
            }

            patch_meta = {
                "patch_id": state.descriptor.patch_id,
                "subject_id": state.descriptor.subject_id,
                "checksum": state.descriptor.checksum,
                "risk_level": state.descriptor.risk_level.value,
                "patch_kind": state.descriptor.patch_kind.value,
            } if cfg.minimize_receipt_metadata else state.descriptor.to_dict()

            req_obj = {"ts": time.time(), "patch": patch_meta}
            comp_obj = payload

            # e-process snapshot (validated)
            e_fields: Dict[str, float] = {}
            if cfg.e_allocator is not None:
                try:
                    out = cfg.e_allocator(state, result)
                    if isinstance(out, dict):
                        e_fields = out
                except Exception:
                    e_fields = {}

            def f(key: str, default: float) -> float:
                v = _finite_float(e_fields.get(key))
                return float(v) if v is not None else float(default)

            e_obj = {
                "e_value": f("e_value", cfg.e_default_value),
                "alpha_alloc": f("alpha_alloc", cfg.e_default_alpha_alloc),
                "alpha_wealth": f("alpha_wealth", cfg.e_default_alpha_wealth),
                "threshold": f("threshold", cfg.e_default_threshold),
                "trigger": bool(e_fields.get("trigger", False)),
            }

            meta = {
                "type": "patch_runtime",
                "kind": _safe_label(kind, default="op"),
                "patch_id": state.descriptor.patch_id,
                "subject_id": state.descriptor.subject_id,
                "risk_level": state.descriptor.risk_level.value,
                "environment": cfg.environment,
                "trust_zone": cfg.trust_zone,
                "cfg_fp": self._cfg_fp,
                "effective_hash_alg": self._effective_hash_alg,
            }
            if cfg.e_process_id is not None:
                meta["e_process_id"] = cfg.e_process_id

            # bound inputs deterministically before signing (JSON closure)
            budget = _JsonBudget(max_nodes=2048, max_items=512, max_depth=8, max_str=64_000)
            req_obj_s = _json_sanitize(req_obj, budget=budget, depth=0, redact_secrets=True)
            comp_obj_s = _json_sanitize(comp_obj, budget=budget, depth=0, redact_secrets=True)
            e_obj_s = _json_sanitize(e_obj, budget=budget, depth=0, redact_secrets=True)
            meta_s = _json_sanitize(meta, budget=budget, depth=0, redact_secrets=True)

            if not isinstance(req_obj_s, dict) or not isinstance(comp_obj_s, dict) or not isinstance(e_obj_s, dict) or not isinstance(meta_s, dict):
                return None

            receipt = self._attestor.issue(
                req_obj=req_obj_s,
                comp_obj=comp_obj_s,
                e_obj=e_obj_s,
                witness_segments=None,
                witness_tags=None,
                meta=meta_s,
            )
            if not isinstance(receipt, dict):
                return None

            # store strategy
            head = _safe_str_only(receipt.get("receipt"), max_len=16_384, default="") or None
            body = _safe_str_only(receipt.get("receipt_body"), max_len=64_000, default="") or None
            sig = _safe_str_only(receipt.get("receipt_sig"), max_len=8_192, default="") or None
            key = _safe_str_only(receipt.get("verify_key"), max_len=8_192, default="") or None

            if cfg.receipt_store_mode == "head_only":
                body = None
                sig = None
                key = None
            elif cfg.receipt_store_mode == "head_sig":
                body = None

            ref = PatchReceiptRef(receipt_head=head, receipt_body=body, receipt_sig=sig, verify_key=key)

            # track bytes to avoid unbounded memory growth
            approx = sum(len(x or "") for x in (head, body, sig, key))
            with self._lock:
                if cfg.max_total_receipt_bytes > 0 and (self._receipt_bytes_total + approx) > cfg.max_total_receipt_bytes:
                    # refuse storing more receipts
                    return PatchReceiptRef(receipt_head=head, receipt_body=None, receipt_sig=None, verify_key=None)
                self._receipt_bytes_total += approx

            return ref
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Telemetry / audit
    # ------------------------------------------------------------------

    def _emit_telemetry_register(self, state: PatchState, operator: Optional[OperatorId], environment: str) -> None:
        exporter = self._cfg.telemetry
        if not exporter or not self._cfg.telemetry_emit_register_events:
            return
        attrs = {
            "patch_id": state.descriptor.patch_id,
            "patch_kind": state.descriptor.patch_kind.value,
            "risk_level": state.descriptor.risk_level.value,
            "environment": environment,
            "trust_zone": self._cfg.trust_zone,
            "operator_id_hash": self._operator_id_hash(operator) if operator else None,
            "cfg_fp": self._cfg_fp,
        }
        if not self._cfg.minimize_telemetry_metadata:
            attrs["subject_id"] = state.descriptor.subject_id

        exporter.record_metric(name="tcd.patch.register.count", value=1.0, labels=attrs)
        exporter.push_event(name="tcd.patch.register", attrs=attrs)

    def _emit_telemetry_approve(self, state: PatchState, operator: OperatorId, environment: str) -> None:
        exporter = self._cfg.telemetry
        if not exporter or not self._cfg.telemetry_emit_approve_events:
            return
        attrs = {
            "patch_id": state.descriptor.patch_id,
            "patch_kind": state.descriptor.patch_kind.value,
            "risk_level": state.descriptor.risk_level.value,
            "environment": environment,
            "trust_zone": self._cfg.trust_zone,
            "operator_id_hash": self._operator_id_hash(operator),
            "approval_count": self._approval_count_distinct(state),
            "cfg_fp": self._cfg_fp,
        }
        if not self._cfg.minimize_telemetry_metadata:
            attrs["subject_id"] = state.descriptor.subject_id

        exporter.record_metric(name="tcd.patch.approve.count", value=1.0, labels=attrs)
        exporter.push_event(name="tcd.patch.approve", attrs=attrs)

    def _emit_telemetry_apply(self, *, state: PatchState, ok: bool, dry_run: bool, mode: Any, environment: str) -> None:
        exporter = self._cfg.telemetry
        if not exporter or not self._cfg.telemetry_emit_apply_events:
            return
        attrs = {
            "patch_id": state.descriptor.patch_id,
            "patch_kind": state.descriptor.patch_kind.value,
            "risk_level": state.descriptor.risk_level.value,
            "status": state.status.value,
            "dry_run": bool(dry_run),
            "mode": _safe_mode_label(mode),
            "environment": environment,
            "trust_zone": self._cfg.trust_zone,
            "operator_id_hash": state.last_operator_id_hash,
            "ok": bool(ok),
            "cfg_fp": self._cfg_fp,
            "error_code": state.last_error_code,
            "error_type": state.last_error_type,
        }
        if self._cfg.telemetry_include_error_message:
            attrs["error"] = state.last_error
        if not self._cfg.minimize_telemetry_metadata:
            attrs["subject_id"] = state.descriptor.subject_id

        exporter.record_metric(name="tcd.patch.apply.count", value=1.0, labels=attrs)
        exporter.push_event(name="tcd.patch.apply", attrs=attrs)

    def _emit_telemetry_rollback(self, *, state: PatchState, ok: bool, mode: Any, environment: str) -> None:
        exporter = self._cfg.telemetry
        if not exporter or not self._cfg.telemetry_emit_rollback_events:
            return
        attrs = {
            "patch_id": state.descriptor.patch_id,
            "patch_kind": state.descriptor.patch_kind.value,
            "risk_level": state.descriptor.risk_level.value,
            "status": state.status.value,
            "mode": _safe_mode_label(mode),
            "environment": environment,
            "trust_zone": self._cfg.trust_zone,
            "operator_id_hash": state.last_operator_id_hash,
            "ok": bool(ok),
            "cfg_fp": self._cfg_fp,
            "error_code": state.last_error_code,
            "error_type": state.last_error_type,
        }
        if self._cfg.telemetry_include_error_message:
            attrs["error"] = state.last_error
        if not self._cfg.minimize_telemetry_metadata:
            attrs["subject_id"] = state.descriptor.subject_id

        exporter.record_metric(name="tcd.patch.rollback.count", value=1.0, labels=attrs)
        exporter.push_event(name="tcd.patch.rollback", attrs=attrs)

    def _audit_critical_keys(self, event_name: str) -> List[str]:
        # event-specific critical keys to keep on shrink
        if event_name.endswith(".apply") or event_name.endswith(".rollback"):
            return ["cfg_fp", "patch_id", "subject_id", "status", "environment", "trust_zone", "ok", "mode",
                    "error_code", "error_type", "apply_attempts", "rollback_attempts", "risk_level"]
        if event_name.endswith(".approve"):
            return ["cfg_fp", "patch_id", "subject_id", "environment", "trust_zone", "operator_id_hash",
                    "approval_count", "required_approvals", "postmortem", "role"]
        return ["cfg_fp", "patch_id", "subject_id", "environment", "trust_zone", "risk_level", "error_code", "error_type"]

    def _emit_audit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        cfg = self._cfg
        hook = cfg.audit_hook
        hook_bytes = cfg.audit_hook_bytes
        if not hook and not hook_bytes:
            return

        budget = _JsonBudget(max_nodes=1024, max_items=256, max_depth=6, max_str=cfg.audit_payload_max_bytes)
        safe_payload = _json_sanitize(payload, budget=budget, depth=0, redact_secrets=True, redact_sensitive_keys=True)
        if not isinstance(safe_payload, dict):
            safe_payload = {"_tcd_error": "bad_audit_payload"}

        try:
            b = json.dumps(safe_payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("utf-8")
        except Exception:
            safe_payload = {"_tcd_error": "audit_payload_unserializable"}
            b = json.dumps(safe_payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("utf-8")

        if len(b) > cfg.audit_payload_max_bytes:
            keep = self._audit_critical_keys(event_name)
            shrunk = {k: safe_payload.get(k) for k in keep if k in safe_payload}
            shrunk["_tcd_shrunk"] = True
            safe_payload = shrunk
            b = json.dumps(safe_payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("utf-8")

        if hook_bytes:
            try:
                hook_bytes(event_name, b)
            except Exception:
                pass

        if hook:
            try:
                hook(event_name, safe_payload)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Agent metadata
    # ------------------------------------------------------------------

    def _make_agent_metadata(self, *, state: PatchState, reason: str, action_kind: str) -> Dict[str, Any]:
        cfg = self._cfg
        meta = {
            "patch_id": state.descriptor.patch_id,
            "subject_id": state.descriptor.subject_id,
            "reason": reason,
            "risk_level": state.descriptor.risk_level.value,
            "action_kind": _safe_label(action_kind, default="action"),
            "origin": state.descriptor.origin,
            "patch_kind": state.descriptor.patch_kind.value,
            "artifact_digest": state.descriptor.artifact_digest,
            "allowed_envs": list(state.descriptor.allowed_envs) if state.descriptor.allowed_envs else None,
            "allowed_trust_zones": list(state.descriptor.allowed_trust_zones) if state.descriptor.allowed_trust_zones else None,
            "change_ticket_id": state.descriptor.change_ticket_id,
            "environment": cfg.environment,
            "trust_zone": cfg.trust_zone,
            "cfg_fp": self._cfg_fp,
        }
        budget = _JsonBudget(max_nodes=256, max_items=64, max_depth=3, max_str=8000)
        safe = _json_sanitize(meta, budget=budget, depth=0, redact_secrets=True, redact_sensitive_keys=True)
        return safe if isinstance(safe, dict) else {}

    # ------------------------------------------------------------------
    # Errors / snapshots (deep copy)
    # ------------------------------------------------------------------

    def _fail(self, state: PatchState, *, code: str, msg: Optional[str] = None, err_type: Optional[str] = None) -> None:
        state.status = PatchStatus.FAILED
        state.last_error_code = _safe_label(code, default="error")
        state.last_error_type = _safe_label(err_type, default="") if isinstance(err_type, str) else (err_type or None)

        if msg is None:
            # do not emit secrets; message is audit-only
            state.last_error = None
            return

        m = _safe_str_only(msg, max_len=512, default="")
        if _looks_like_secret(m):
            m = "[redacted]"
        state.last_error = m or None

    def _snapshot_receipt(self, r: Optional[PatchReceiptRef]) -> Optional[PatchReceiptRef]:
        if r is None:
            return None
        return PatchReceiptRef(
            receipt_head=r.receipt_head,
            receipt_body=r.receipt_body,
            receipt_sig=r.receipt_sig,
            verify_key=r.verify_key,
        )

    def _snapshot_descriptor(self, d: PatchDescriptor, *, env: str) -> PatchDescriptor:
        # deep copy metadata
        budget = _JsonBudget(max_nodes=1024, max_items=256, max_depth=8, max_str=32_000)
        md = _json_sanitize(d.metadata, budget=budget, depth=0, redact_secrets=True, redact_sensitive_keys=True)
        md2 = md if isinstance(md, dict) else {}
        # optionally strip clear ids if not allowed
        if not self._should_include_clear_ids(env):
            md2.pop("subject_id_clear", None)
            md2.pop("operator_id_clear", None)

        return PatchDescriptor(
            patch_id=d.patch_id,
            subject_id=d.subject_id,
            patch_kind=d.patch_kind,
            description=d.description,
            origin=d.origin,
            created_ts=float(d.created_ts),
            checksum=d.checksum,
            risk_level=d.risk_level,
            artifact_digest=d.artifact_digest,
            artifact_source=d.artifact_source,
            artifact_sbom_id=d.artifact_sbom_id,
            build_pipeline_id=d.build_pipeline_id,
            commit_hash=d.commit_hash,
            allowed_envs=list(d.allowed_envs) if d.allowed_envs else None,
            allowed_trust_zones=list(d.allowed_trust_zones) if d.allowed_trust_zones else None,
            max_scope=dict(d.max_scope) if d.max_scope else None,
            change_ticket_id=d.change_ticket_id,
            required_approvals=int(d.required_approvals),
            metadata=dict(md2),
        )

    def _snapshot_state(self, st: PatchState, *, env: str) -> PatchState:
        d = self._snapshot_descriptor(st.descriptor, env=env)

        budget = _JsonBudget(max_nodes=1024, max_items=256, max_depth=6, max_str=32_000)
        approvals_safe = _json_sanitize(st.approvals, budget=budget, depth=0, redact_secrets=True, redact_sensitive_keys=True)
        approvals2 = approvals_safe if isinstance(approvals_safe, list) else []

        targets2 = None
        if st.apply_targets is not None:
            t = _json_sanitize(st.apply_targets, budget=budget, depth=0, redact_secrets=True, redact_sensitive_keys=True)
            targets2 = t if isinstance(t, dict) else None

        return PatchState(
            descriptor=d,
            status=st.status,
            last_update_ts=float(st.last_update_ts),
            last_error=st.last_error,
            last_error_code=st.last_error_code,
            last_error_type=st.last_error_type,
            applied_ts=st.applied_ts,
            rolled_back_ts=st.rolled_back_ts,
            apply_receipt=self._snapshot_receipt(st.apply_receipt),
            rollback_receipt=self._snapshot_receipt(st.rollback_receipt),
            created_by=st.created_by,
            approvals=[dict(a) for a in approvals2 if isinstance(a, dict)],
            last_operator_id_hash=st.last_operator_id_hash,
            apply_attempts=int(st.apply_attempts),
            rollback_attempts=int(st.rollback_attempts),
            apply_targets=dict(targets2) if isinstance(targets2, dict) else None,
            canary_success=st.canary_success,
            promotion_ts=st.promotion_ts,
        )


__all__ = [
    "PatchStatus",
    "PatchRiskLevel",
    "PatchKind",
    "OperatorId",
    "PatchDescriptor",
    "PatchReceiptRef",
    "PatchState",
    "PatchRuntimeConfig",
    "PatchRuntime",
]