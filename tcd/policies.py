# FILE: tcd/policies.py
from __future__ import annotations

import json
import math
import os
import re
import threading
import time
import unicodedata
from dataclasses import dataclass, fields as dc_fields, is_dataclass, replace
from types import MappingProxyType
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union, Literal

from pydantic import BaseModel, Field, ValidationError, ConfigDict, field_validator, model_validator

from .crypto import Blake3Hash
from .detector import TCDConfig
from .risk_av import AlwaysValidConfig

__all__ = [
    "MatchSpec",
    "DetectorOverrides",
    "AVOverrides",
    "RoutingOverrides",
    "ReceiptOptions",
    "SREOptions",
    "AuditOptions",
    "PolicyRule",
    "BoundPolicy",
    "PolicyStore",
]

# ---------------------------------------------------------------------------
# Matching helpers + canonicalization
# ---------------------------------------------------------------------------

_HASH_CTX_RULE = "tcd:policy"
_HASH_CTX_SET = "tcd:policyset"

_DEFAULT_MAX_POLICY_BYTES = 2_000_000

# Optional: safer regex engine with timeouts (if installed).
try:  # pragma: no cover
    import regex as _regex  # type: ignore
except Exception:  # pragma: no cover
    _regex = None  # type: ignore


# ---------------------------------------------------------------------------
# Text hardening (align with stronger sanitizers used elsewhere)
# ---------------------------------------------------------------------------

_ASCII_CTRL_RE = re.compile(r"[\x00-\x1F\x7F]")


def _has_unsafe_unicode(s: str) -> bool:
    for ch in s:
        if ch in ("\u2028", "\u2029"):
            return True
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            return True
    return False


def _strip_unsafe_text(s: Any, *, max_len: int) -> str:
    """
    L7: sanitize text without calling __str__ on unknown objects.
    Only accepts str; otherwise returns "".
    Removes ASCII control chars + unsafe unicode categories.
    """
    if not isinstance(s, str):
        return ""
    if max_len > 0 and len(s) > max_len:
        s = s[:max_len]

    if s.isascii():
        if _ASCII_CTRL_RE.search(s):
            s = _ASCII_CTRL_RE.sub("", s)
        return s.strip()

    if not _ASCII_CTRL_RE.search(s) and not _has_unsafe_unicode(s):
        # also strip 0x80-0x9F C1 controls if present
        if any(0x80 <= ord(ch) <= 0x9F for ch in s):
            pass
        else:
            return s.strip()

    out: List[str] = []
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


def _finite_float(x: Any) -> Optional[float]:
    if isinstance(x, bool):
        return None
    if not isinstance(x, (int, float)):
        return None
    v = float(x)
    if not math.isfinite(v):
        return None
    return v


def _canon_json(obj: Any) -> str:
    # L7: deterministic + JSON-closed
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _cap_errors(errs: Sequence[str], *, max_items: int = 200, max_len: int = 240) -> Tuple[str, ...]:
    out: List[str] = []
    for e in errs:
        if len(out) >= max_items:
            break
        if not isinstance(e, str):
            continue
        s = _strip_unsafe_text(e, max_len=max_len)
        if not s:
            continue
        out.append(s)
    if len(errs) > max_items:
        out.append("...errors_truncated")
    return tuple(out)


# ---------------------------------------------------------------------------
# Safe identifiers / labels
# ---------------------------------------------------------------------------

# Safe identifiers for labels used in refs/metrics.
_SAFE_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9_.:\-]{0,63}$")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:\-]{0,127}$")
_SAFE_VER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,63}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-@#]{0,255}$")

_COMMIT_RE = re.compile(r"^(?:sha256:)?[0-9a-f]{7,64}$", re.IGNORECASE)
# patch id family (conservative): <prefix>-<hex...>(-<hex...>)?
_PATCH_ID_RE = re.compile(r"^[a-z][a-z0-9_.:\-]{0,63}-[0-9a-f]{8,64}(?:-[0-9a-f]{4,32})?$", re.IGNORECASE)
_TICKET_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{1,15}-?\d{1,12}$")  # e.g. JIRA-123, INC12345, CHG-9


def _safe_label(s: Any, *, default: Optional[str] = None) -> Optional[str]:
    if not isinstance(s, str):
        return default
    x = _strip_unsafe_text(s.lower(), max_len=64)
    if not x:
        return default
    if not _SAFE_LABEL_RE.fullmatch(x):
        return default
    return x


def _safe_id(s: Any, *, default: Optional[str] = None, max_len: int = 256) -> Optional[str]:
    if not isinstance(s, str):
        return default
    x = _strip_unsafe_text(s, max_len=max_len)
    if not x:
        return default
    if not _SAFE_ID_RE.fullmatch(x):
        return default
    return x


# Keys allowed in ctx (MatchSpec fields)
_CTX_KEYS: Tuple[str, ...] = (
    "tenant",
    "user",
    "session",
    "model_id",
    "gpu_id",
    "task",
    "lang",
    "env",
    "trust_zone",
    "route",
    "data_class",
    "workload",
    "jurisdiction",
    "regulation",
    "client_app",
    "access_channel",
)

# Canonicalization: fields that should be casefolded to avoid drift.
_DEFAULT_CASEFOLD_KEYS: Tuple[str, ...] = (
    "env",
    "trust_zone",
    "route",
    "lang",
    "data_class",
    "workload",
    "jurisdiction",
    "regulation",
    "client_app",
    "access_channel",
)

# ---------------------------------------------------------------------------
# Config copying / updating (works for dataclass + pydantic + dict)
# ---------------------------------------------------------------------------

def _copy_config(obj: Any) -> Any:
    """
    L7: copy configs defensively without calling unknown __str__/__repr__.
    Supports:
      - dataclasses: replace()
      - pydantic v2: model_copy(deep=True)
      - dict/list/tuple: shallow structural copy
    Otherwise returns obj (assumed immutable) unless strict mode decides to error elsewhere.
    """
    if obj is None:
        return None
    if is_dataclass(obj):
        try:
            return replace(obj)
        except Exception:
            return obj
    mc = getattr(obj, "model_copy", None)
    if callable(mc):
        try:
            return mc(deep=True)
        except Exception:
            return obj
    if isinstance(obj, dict):
        return dict(obj)
    if isinstance(obj, list):
        return list(obj)
    if isinstance(obj, tuple):
        return tuple(obj)
    cp = getattr(obj, "copy", None)
    if callable(cp):
        try:
            return cp()
        except Exception:
            return obj
    return obj


def _dc_update(base: Any, override: Dict[str, Any]) -> Any:
    """
    Shallow, field-safe update. Works for dataclasses and pydantic v2 models.
    """
    if base is None:
        return None

    if not override:
        return _copy_config(base)

    # pydantic v2
    mu = getattr(base, "model_copy", None)
    if callable(mu) and hasattr(base, "model_fields"):
        try:
            return base.model_copy(update=override, deep=True)
        except Exception:
            return _copy_config(base)

    # dataclass
    if is_dataclass(base):
        try:
            valid = {f.name for f in dc_fields(base)}
            kwargs = {k: v for k, v in override.items() if k in valid}
            return replace(base, **kwargs) if kwargs else _copy_config(base)
        except Exception:
            return _copy_config(base)

    # dict fallback
    if isinstance(base, dict):
        out = dict(base)
        for k, v in override.items():
            out[k] = v
        return out

    # unknown type: best-effort copy
    return _copy_config(base)


# ---------------------------------------------------------------------------
# Regex safety policy (L7 hardened)
# ---------------------------------------------------------------------------

PatEngine = Literal["re", "regex"]


def _is_regex(p: Optional[str]) -> bool:
    return isinstance(p, str) and len(p) >= 2 and p.startswith("/") and p.endswith("/")


def _regex_inner(p: str) -> str:
    return p[1:-1]


# sentinel: never matches
_BAD_RE = object()
_Pat = Union[str, re.Pattern, object, Any]  # Any: regex.Pattern if using `regex` module


@dataclass(frozen=True)
class RegexPolicy:
    """
    L7 regex safety policy.

    Notes:
      - engine is the desired engine; effective_engine depends on availability.
      - allow_regex_on_re_engine controls whether regex is allowed when only stdlib re is available.
      - require_timeout_enforced makes timeout mandatory when using regex engine.
      - static_safety_checks rejects known dangerous constructs (best-effort heuristics).
    """
    allow_regex: bool = True
    engine: PatEngine = "regex"          # desired
    timeout_ms: int = 25                 # used only when effective_engine == "regex"
    max_pattern_len: int = 512
    reject_empty_regex: bool = True

    allow_regex_on_re_engine: bool = False
    require_timeout_enforced: bool = True
    static_safety_checks: bool = True

    def effective_engine(self) -> PatEngine:
        if self.engine == "regex" and _regex is not None:
            return "regex"
        return "re"


def _normalize_regex_policy(rp: RegexPolicy, *, strict: bool) -> Tuple[RegexPolicy, List[str]]:
    errors: List[str] = []
    allow_regex = bool(rp.allow_regex)
    max_pat = int(rp.max_pattern_len) if isinstance(rp.max_pattern_len, int) else 512
    max_pat = max(16, min(max_pat, 4096))

    timeout_ms = int(rp.timeout_ms) if isinstance(rp.timeout_ms, int) else 0
    # clamp timeout in strict mode
    if strict:
        if timeout_ms <= 0:
            # enforce a safe floor
            timeout_ms = 25
        timeout_ms = max(1, min(timeout_ms, 500))
    else:
        timeout_ms = max(0, min(timeout_ms, 2000))

    desired_engine: PatEngine = rp.engine if rp.engine in ("re", "regex") else "regex"
    eff = "regex" if (desired_engine == "regex" and _regex is not None) else "re"

    # If effective is re and regex is allowed, this is still ReDoS surface.
    # L7 baseline: default disallow unless explicitly allowed.
    allow_on_re = bool(rp.allow_regex_on_re_engine)
    if eff == "re" and allow_regex and not allow_on_re:
        allow_regex = False
        errors.append("regex_disabled_on_re_engine: stdlib re has no timeout; set allow_regex_on_re_engine=True to override")

    # Require timeout when using regex engine in strict mode
    req_timeout = bool(rp.require_timeout_enforced)
    if eff == "regex" and allow_regex and req_timeout and timeout_ms <= 0:
        errors.append("regex_timeout_required_but_zero")
        if strict:
            allow_regex = False

    out = RegexPolicy(
        allow_regex=allow_regex,
        engine=desired_engine,
        timeout_ms=timeout_ms,
        max_pattern_len=max_pat,
        reject_empty_regex=bool(rp.reject_empty_regex),
        allow_regex_on_re_engine=allow_on_re,
        require_timeout_enforced=req_timeout,
        static_safety_checks=bool(rp.static_safety_checks),
    )
    return out, errors


_DANGEROUS_RE_HINTS = (
    r"(?<= ",  # placeholder to avoid false positives in tuple; real checks below
)


def _regex_static_check(inner: str) -> Optional[str]:
    """
    Best-effort heuristic checks for dangerous constructs.
    Returns error code string if unsafe, else None.
    """
    s = inner
    # backreferences (catastrophic in many engines)
    if re.search(r"\\[1-9]", s):
        return "regex_backreference_disallowed"
    if re.search(r"\(\?P=", s):
        return "regex_named_backreference_disallowed"
    # lookbehind often expensive/unsupported; treat as unsafe baseline
    if "(?<=" in s or "(?<!" in s:
        return "regex_lookbehind_disallowed"
    # nested quantifiers heuristics: something like (.*)+, (.+)+, (a+)+, (a*)+
    if re.search(r"\((?:[^()\\]|\\.){0,80}(?:\.\*|\.\+|[^()]{0,40}[+*])\)\s*[+*{]", s):
        return "regex_nested_quantifier_suspected"
    # excessive alternation count (very rough)
    if s.count("|") > 50:
        return "regex_too_many_alternations"
    return None


def _compile_pat(p: Optional[str], rp: RegexPolicy, *, key: str, casefold: bool) -> Optional[_Pat]:
    """
    Compile a match token into:
      - None    => wildcard
      - str     => literal
      - Pattern => compiled regex
      - _BAD_RE => invalid/disabled/unsafe
    """
    if p is None:
        return None
    if not isinstance(p, str):
        return _BAD_RE

    raw = _strip_unsafe_text(p, max_len=2048)
    if not raw or raw == "*":
        return None

    if _is_regex(raw):
        if not rp.allow_regex:
            return _BAD_RE
        inner = _regex_inner(raw)
        if rp.reject_empty_regex and inner == "":
            return _BAD_RE
        if len(inner) > rp.max_pattern_len:
            return _BAD_RE

        if rp.static_safety_checks:
            msg = _regex_static_check(inner)
            if msg is not None:
                return _BAD_RE

        eff = rp.effective_engine()
        if eff == "regex" and _regex is not None:
            try:
                return _regex.compile(inner)
            except Exception:
                return _BAD_RE
        # stdlib re (only reachable if allow_regex_on_re_engine=True)
        try:
            return re.compile(inner)
        except Exception:
            return _BAD_RE

    # literal
    lit = raw
    if len(lit) > 512:
        return _BAD_RE
    if casefold:
        lit = lit.lower()
    return lit


def _match_token_compiled(value: Any, pat: Optional[_Pat], rp: RegexPolicy, *, casefold: bool) -> bool:
    if pat is None:
        return True
    if pat is _BAD_RE:
        return False

    v = value if isinstance(value, str) else ""
    v = _strip_unsafe_text(v, max_len=512)
    if casefold:
        v = v.lower()

    if isinstance(pat, str):
        return v == pat

    try:
        if rp.effective_engine() == "regex" and _regex is not None and rp.timeout_ms > 0:
            try:
                return bool(pat.fullmatch(v, timeout=rp.timeout_ms / 1000.0))
            except TypeError:
                return bool(pat.fullmatch(v))
            except Exception:
                return False
        return bool(pat.fullmatch(v))
    except Exception:
        return False


def _specificity_from_match(match: "MatchSpec", rp: RegexPolicy) -> int:
    score = 0
    pats = [
        match.tenant,
        match.user,
        match.session,
        match.model_id,
        match.gpu_id,
        match.task,
        match.lang,
        match.env,
        match.trust_zone,
        match.route,
        match.data_class,
        match.workload,
        match.jurisdiction,
        match.regulation,
        match.client_app,
        match.access_channel,
    ]
    for p in pats:
        if p is None or p == "*":
            continue
        if _is_regex(p):
            inner = _regex_inner(p)
            if rp.reject_empty_regex and inner == "":
                continue
            score += 1
        else:
            score += 2
    return score


# ---------------------------------------------------------------------------
# Schemas (Pydantic v2; extra=forbid)
# ---------------------------------------------------------------------------

class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_default=True,
    )


def _sanitize_pat_str(v: Any) -> str:
    """
    L7: do NOT call str(v) for unknown objects.
    Only accept str. Non-str => wildcard.
    """
    if v is None:
        return "*"
    if not isinstance(v, str):
        return "*"
    s = _strip_unsafe_text(v, max_len=512)
    return s if s else "*"


class MatchSpec(_StrictModel):
    tenant: str = "*"
    user: str = "*"
    session: str = "*"
    model_id: str = "*"
    gpu_id: str = "*"
    task: str = "*"
    lang: str = "*"

    env: str = "*"
    trust_zone: str = "*"
    route: str = "*"

    data_class: str = "*"
    workload: str = "*"

    jurisdiction: str = "*"
    regulation: str = "*"

    client_app: str = "*"
    access_channel: str = "*"

    @field_validator(
        "tenant",
        "user",
        "session",
        "model_id",
        "gpu_id",
        "task",
        "lang",
        "env",
        "trust_zone",
        "route",
        "data_class",
        "workload",
        "jurisdiction",
        "regulation",
        "client_app",
        "access_channel",
        mode="before",
    )
    @classmethod
    def _v_pat(cls, v: Any) -> str:
        return _sanitize_pat_str(v)


class DetectorOverrides(_StrictModel):
    window_size: Optional[int] = Field(default=None, ge=1, le=10_000_000)
    ewma_alpha: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    entropy_floor: Optional[float] = Field(default=None, ge=0.0, le=1e9)
    spread_threshold: Optional[float] = Field(default=None, ge=0.0, le=1e9)
    rel_drop_threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    z_threshold: Optional[float] = Field(default=None, ge=0.0, le=1e6)
    min_calibration_steps: Optional[int] = Field(default=None, ge=0, le=10_000_000)
    hard_fail_on_floor: Optional[bool] = None

    combine_mode: Optional[str] = None
    on_threshold: Optional[float] = Field(default=None, ge=0.0, le=1e9)
    off_threshold: Optional[float] = Field(default=None, ge=0.0, le=1e9)
    cooldown_steps: Optional[int] = Field(default=None, ge=0, le=10_000_000)

    multi_var_enabled: Optional[bool] = None
    multi_var_window: Optional[int] = Field(default=None, ge=1, le=10_000_000)
    multi_var_dim_limit: Optional[int] = Field(default=None, ge=1, le=1_000_000)
    apt_profile: Optional[str] = None

    @field_validator(
        "ewma_alpha",
        "entropy_floor",
        "spread_threshold",
        "rel_drop_threshold",
        "z_threshold",
        "on_threshold",
        "off_threshold",
        mode="before",
    )
    @classmethod
    def _v_finite_float(cls, v: Any) -> Any:
        if v is None:
            return None
        fv = _finite_float(v)
        if fv is None:
            raise ValueError("float must be finite")
        return fv

    @field_validator("combine_mode", "apt_profile", mode="before")
    @classmethod
    def _v_lbl(cls, v: Any) -> Any:
        if v is None:
            return None
        if not isinstance(v, str):
            return None
        return _safe_label(v, default=None)

    @model_validator(mode="after")
    def _cross_checks(self) -> "DetectorOverrides":
        # Example cross-field sanity: off_threshold should not exceed on_threshold if both exist.
        if self.on_threshold is not None and self.off_threshold is not None:
            if self.off_threshold > self.on_threshold:
                raise ValueError("off_threshold must be <= on_threshold")
        return self


class AVOverrides(_StrictModel):
    alpha_base: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    alpha_budget_fraction: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    e_stream: Optional[str] = None

    @field_validator("alpha_base", "alpha_budget_fraction", mode="before")
    @classmethod
    def _v_finite_float(cls, v: Any) -> Any:
        if v is None:
            return None
        fv = _finite_float(v)
        if fv is None:
            raise ValueError("float must be finite")
        return fv

    @field_validator("e_stream", mode="before")
    @classmethod
    def _v_stream(cls, v: Any) -> Any:
        if v is None:
            return None
        if not isinstance(v, str):
            return None
        return _safe_label(v, default=None)


class RoutingOverrides(_StrictModel):
    t_low: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    t_high: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    top_p_low: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    top_p_high: Optional[float] = Field(default=None, ge=0.0, le=1.0)

    fallback_decoder: Optional[str] = None
    action_hint: Optional[str] = None
    route_profile: Optional[str] = None

    @field_validator("t_low", "t_high", "top_p_low", "top_p_high", mode="before")
    @classmethod
    def _v_finite_float(cls, v: Any) -> Any:
        if v is None:
            return None
        fv = _finite_float(v)
        if fv is None:
            raise ValueError("float must be finite")
        return fv

    @field_validator("fallback_decoder", "action_hint", "route_profile", mode="before")
    @classmethod
    def _v_lbl(cls, v: Any) -> Any:
        if v is None:
            return None
        if not isinstance(v, str):
            return None
        return _safe_label(v, default=None)

    @model_validator(mode="after")
    def _range_checks(self) -> "RoutingOverrides":
        if self.t_low is not None and self.t_high is not None and self.t_low > self.t_high:
            raise ValueError("t_low must be <= t_high")
        if self.top_p_low is not None and self.top_p_high is not None and self.top_p_low > self.top_p_high:
            raise ValueError("top_p_low must be <= top_p_high")
        return self


class ReceiptOptions(_StrictModel):
    enable_issue: bool = False
    enable_verify_metrics: bool = False

    attach_policy_refs: bool = True
    attach_match_context: bool = False

    profile: Optional[str] = None
    crypto_profile: Optional[str] = None
    match_context_level: Optional[str] = None

    @field_validator("profile", "crypto_profile", "match_context_level", mode="before")
    @classmethod
    def _v_id(cls, v: Any) -> Any:
        if v is None:
            return None
        if not isinstance(v, str):
            return None
        return _safe_id(v, default=None, max_len=128)


class SREOptions(_StrictModel):
    slo_latency_ms: Optional[float] = Field(default=None, ge=0.0, le=10_000_000.0)
    token_cost_divisor: Optional[float] = Field(default=None, ge=1.0, le=1_000_000.0)
    error_budget_fraction: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    probe_sample_rate: Optional[float] = Field(default=None, ge=0.0, le=1.0)

    @field_validator("slo_latency_ms", "token_cost_divisor", "error_budget_fraction", "probe_sample_rate", mode="before")
    @classmethod
    def _v_finite_float(cls, v: Any) -> Any:
        if v is None:
            return None
        fv = _finite_float(v)
        if fv is None:
            raise ValueError("float must be finite")
        return fv


class AuditOptions(_StrictModel):
    audit_label: Optional[str] = None
    sample_rate: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    log_level: Optional[str] = None
    incident_class: Optional[str] = None
    force_audit_on_violation: Optional[bool] = None
    require_full_trace: Optional[bool] = None

    @field_validator("sample_rate", mode="before")
    @classmethod
    def _v_finite_float(cls, v: Any) -> Any:
        if v is None:
            return None
        fv = _finite_float(v)
        if fv is None:
            raise ValueError("float must be finite")
        return fv

    @field_validator("audit_label", "log_level", "incident_class", mode="before")
    @classmethod
    def _v_lbl(cls, v: Any) -> Any:
        if v is None:
            return None
        if not isinstance(v, str):
            return None
        return _safe_label(v, default=None)


class PolicyRule(_StrictModel):
    name: str = Field(..., min_length=1, max_length=128)
    version: str = Field(default="1", max_length=64)
    priority: int = 0

    match: MatchSpec = Field(default_factory=MatchSpec)

    detector: Optional[DetectorOverrides] = None
    av: Optional[AVOverrides] = None
    routing: Optional[RoutingOverrides] = None
    receipt: Optional[ReceiptOptions] = None
    sre: Optional[SREOptions] = None
    audit: Optional[AuditOptions] = None

    compliance_profile: Optional[str] = None
    risk_label: Optional[str] = None

    origin: Optional[str] = None
    policy_patch_id: Optional[str] = None
    commit_hash: Optional[str] = None
    change_ticket_id: Optional[str] = None

    @field_validator("name", mode="before")
    @classmethod
    def _v_name(cls, v: Any) -> str:
        if not isinstance(v, str):
            raise ValueError("policy name must be a string")
        s = _strip_unsafe_text(v, max_len=128)
        if not _SAFE_NAME_RE.fullmatch(s):
            raise ValueError("policy name must be a safe identifier")
        return s

    @field_validator("version", mode="before")
    @classmethod
    def _v_ver(cls, v: Any) -> str:
        if v is None:
            v = "1"
        if not isinstance(v, str):
            raise ValueError("policy version must be a string")
        s = _strip_unsafe_text(v, max_len=64) or "1"
        if not _SAFE_VER_RE.fullmatch(s):
            raise ValueError("policy version must be a safe identifier")
        return s

    @field_validator("compliance_profile", "risk_label", mode="before")
    @classmethod
    def _v_lbl(cls, v: Any) -> Any:
        if v is None:
            return None
        if not isinstance(v, str):
            return None
        return _safe_label(v, default=None)

    @field_validator("origin", mode="before")
    @classmethod
    def _v_origin(cls, v: Any) -> Any:
        if v is None:
            return None
        if not isinstance(v, str):
            return None
        return _safe_id(v, default=None, max_len=256)

    @field_validator("commit_hash", mode="before")
    @classmethod
    def _v_commit(cls, v: Any) -> Any:
        if v is None:
            return None
        if not isinstance(v, str):
            return None
        s = _strip_unsafe_text(v, max_len=80)
        if not s:
            return None
        if not _COMMIT_RE.fullmatch(s):
            return None
        return s.lower()

    @field_validator("policy_patch_id", mode="before")
    @classmethod
    def _v_patch_id(cls, v: Any) -> Any:
        if v is None:
            return None
        if not isinstance(v, str):
            return None
        s = _strip_unsafe_text(v, max_len=256)
        if not s:
            return None
        if _PATCH_ID_RE.fullmatch(s):
            return s
        # fallback to safe id if it doesn't match patch format but still safe
        return _safe_id(s, default=None, max_len=256)

    @field_validator("change_ticket_id", mode="before")
    @classmethod
    def _v_ticket(cls, v: Any) -> Any:
        if v is None:
            return None
        if not isinstance(v, str):
            return None
        s = _strip_unsafe_text(v, max_len=128)
        if not s:
            return None
        if _TICKET_RE.fullmatch(s):
            return s
        return _safe_id(s, default=None, max_len=128)

    def policy_ref(self) -> str:
        """
        Stable reference token for this policy rule.

        L7: must not raise; on failure returns a safe fallback ref.
        """
        try:
            payload = {
                "name": self.name,
                "version": self.version,
                "priority": int(self.priority),
                "match": self.match.model_dump(),
                "detector": self.detector.model_dump() if self.detector else {},
                "av": self.av.model_dump() if self.av else {},
                "routing": self.routing.model_dump() if self.routing else {},
                "receipt": self.receipt.model_dump() if self.receipt else {},
                "sre": self.sre.model_dump() if self.sre else {},
                "audit": self.audit.model_dump() if self.audit else {},
                "compliance_profile": self.compliance_profile,
                "risk_label": self.risk_label,
                "origin": self.origin,
                "policy_patch_id": self.policy_patch_id,
                "commit_hash": self.commit_hash,
                "change_ticket_id": self.change_ticket_id,
            }
            h = Blake3Hash().hex(_canon_json(payload).encode("utf-8"), ctx=_HASH_CTX_RULE)
            return f"{self.name}@{self.version}#{h[:12]}"
        except Exception:
            return f"{self.name}@{self.version}#badref000000"


# ---------------------------------------------------------------------------
# Bound output
# ---------------------------------------------------------------------------

Decision = Literal["inherit", "allow", "deny", "degrade"]


@dataclass(frozen=True)
class BoundPolicy:
    """
    Immutable, fully-resolved policy view for a single request context.

    L7 hardening:
      - match is MappingProxyType (read-only)
      - detector_cfg / av_cfg are fresh copies per bind()
      - policyset_ref is always populated (never None) for matched policies
      - decision provides strong semantic hint for fail-closed scenarios
    """

    name: str
    version: str
    policy_ref: str
    priority: int

    detector_cfg: TCDConfig
    av_cfg: AlwaysValidConfig

    t_low: Optional[float]
    t_high: Optional[float]
    top_p_low: Optional[float]
    top_p_high: Optional[float]
    fallback_decoder: Optional[str]
    action_hint: Optional[str]
    route_profile: Optional[str]

    enable_receipts: bool
    enable_verify_metrics: bool
    attach_policy_refs: bool
    attach_match_context: bool
    receipt_profile: Optional[str]
    receipt_crypto_profile: Optional[str]
    receipt_match_context_level: Optional[str]

    slo_latency_ms: Optional[float]
    token_cost_divisor: float
    error_budget_fraction: Optional[float]
    probe_sample_rate: Optional[float]

    alpha_budget_fraction: Optional[float]
    e_stream: Optional[str]

    compliance_profile: Optional[str]
    risk_label: Optional[str]
    audit_label: Optional[str]
    audit_sample_rate: Optional[float]
    audit_log_level: Optional[str]
    audit_incident_class: Optional[str]
    audit_force_on_violation: Optional[bool]
    audit_require_full_trace: Optional[bool]

    match: Mapping[str, str]

    policyset_ref: str = "set@1#000000000000"
    origin: Optional[str] = None
    policy_patch_id: Optional[str] = None
    commit_hash: Optional[str] = None
    change_ticket_id: Optional[str] = None

    # Stronger semantic enforcement hint (outer stack should honor)
    decision: Decision = "inherit"
    enforcement: Optional[str] = None


# ---------------------------------------------------------------------------
# Internal compiled rules
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _CompiledRule:
    tenant: Optional[_Pat]
    user: Optional[_Pat]
    session: Optional[_Pat]
    model_id: Optional[_Pat]
    gpu_id: Optional[_Pat]
    task: Optional[_Pat]
    lang: Optional[_Pat]
    env: Optional[_Pat]
    trust_zone: Optional[_Pat]
    route: Optional[_Pat]
    data_class: Optional[_Pat]
    workload: Optional[_Pat]
    jurisdiction: Optional[_Pat]
    regulation: Optional[_Pat]
    client_app: Optional[_Pat]
    access_channel: Optional[_Pat]

    specificity: int
    priority: int
    order: int

    policy_ref: str
    bound_template: BoundPolicy
    detector_cfg_eff: Any
    av_cfg_eff: Any

    # For index / diagnostics
    has_regex: bool


def _matches_compiled(ctx: Mapping[str, str], cr: _CompiledRule, rp: RegexPolicy, casefold_keys: "set[str]") -> bool:
    def cf(k: str) -> bool:
        return k in casefold_keys

    return (
        _match_token_compiled(ctx.get("tenant", ""), cr.tenant, rp, casefold=cf("tenant"))
        and _match_token_compiled(ctx.get("user", ""), cr.user, rp, casefold=cf("user"))
        and _match_token_compiled(ctx.get("session", ""), cr.session, rp, casefold=cf("session"))
        and _match_token_compiled(ctx.get("model_id", ""), cr.model_id, rp, casefold=cf("model_id"))
        and _match_token_compiled(ctx.get("gpu_id", ""), cr.gpu_id, rp, casefold=cf("gpu_id"))
        and _match_token_compiled(ctx.get("task", ""), cr.task, rp, casefold=cf("task"))
        and _match_token_compiled(ctx.get("lang", ""), cr.lang, rp, casefold=cf("lang"))
        and _match_token_compiled(ctx.get("env", ""), cr.env, rp, casefold=cf("env"))
        and _match_token_compiled(ctx.get("trust_zone", ""), cr.trust_zone, rp, casefold=cf("trust_zone"))
        and _match_token_compiled(ctx.get("route", ""), cr.route, rp, casefold=cf("route"))
        and _match_token_compiled(ctx.get("data_class", ""), cr.data_class, rp, casefold=cf("data_class"))
        and _match_token_compiled(ctx.get("workload", ""), cr.workload, rp, casefold=cf("workload"))
        and _match_token_compiled(ctx.get("jurisdiction", ""), cr.jurisdiction, rp, casefold=cf("jurisdiction"))
        and _match_token_compiled(ctx.get("regulation", ""), cr.regulation, rp, casefold=cf("regulation"))
        and _match_token_compiled(ctx.get("client_app", ""), cr.client_app, rp, casefold=cf("client_app"))
        and _match_token_compiled(ctx.get("access_channel", ""), cr.access_channel, rp, casefold=cf("access_channel"))
    )


# ---------------------------------------------------------------------------
# Bundle + indexing
# ---------------------------------------------------------------------------

OnLoadErrorMode = Literal["fail_open", "fail_closed", "raise"]


@dataclass(frozen=True)
class _KeyIndex:
    # compiled-order indices
    any_idx: Tuple[int, ...]
    regex_idx: Tuple[int, ...]
    lit_map: Mapping[str, Tuple[int, ...]]


@dataclass(frozen=True)
class _PolicyBundle:
    rules: Tuple[PolicyRule, ...]
    compiled: Tuple[_CompiledRule, ...]
    set_ref: str
    updated_ts: float

    # includes load/parse/compile/warn diagnostics
    errors: Tuple[str, ...]
    warnings: Tuple[str, ...]
    on_error: OnLoadErrorMode
    fail_closed_on_any_error: bool

    default_policy: BoundPolicy
    error_policy: BoundPolicy

    regex_policy: RegexPolicy
    regex_engine_effective: PatEngine

    casefold_keys: Tuple[str, ...]
    source: Optional[str]
    policyset_meta: Mapping[str, Any]

    # optional prefilter index for performance
    prefilter_keys: Tuple[str, ...]
    prefilter_index: Mapping[str, _KeyIndex]

    # diagnostics extras
    shadowed_rules: Tuple[str, ...]
    potential_conflicts: Tuple[Tuple[str, str, str], ...]
    analysis_truncated: bool


def _merge_sorted(a: Sequence[int], b: Sequence[int]) -> List[int]:
    i = j = 0
    out: List[int] = []
    while i < len(a) and j < len(b):
        if a[i] < b[j]:
            out.append(a[i]); i += 1
        else:
            out.append(b[j]); j += 1
    if i < len(a):
        out.extend(a[i:])
    if j < len(b):
        out.extend(b[j:])
    return out


def _merge3_sorted(a: Sequence[int], b: Sequence[int], c: Sequence[int]) -> List[int]:
    return _merge_sorted(_merge_sorted(a, b), c)


def _intersect_sorted(a: Sequence[int], b: Sequence[int]) -> List[int]:
    i = j = 0
    out: List[int] = []
    while i < len(a) and j < len(b):
        ai = a[i]; bj = b[j]
        if ai == bj:
            out.append(ai); i += 1; j += 1
        elif ai < bj:
            i += 1
        else:
            j += 1
    return out


def _pat_kind(p: Optional[_Pat]) -> str:
    if p is None:
        return "any"
    if isinstance(p, str):
        return "lit"
    return "regex"


def _build_key_index(compiled: Sequence[_CompiledRule], *, key: str) -> _KeyIndex:
    any_idx: List[int] = []
    regex_idx: List[int] = []
    lit_map: Dict[str, List[int]] = {}

    for i, cr in enumerate(compiled):
        pat = getattr(cr, key)
        k = _pat_kind(pat)
        if k == "any":
            any_idx.append(i)
        elif k == "regex":
            regex_idx.append(i)
        else:
            lit = pat  # type: ignore[assignment]
            if isinstance(lit, str):
                lit_map.setdefault(lit, []).append(i)

    lit_map_t: Dict[str, Tuple[int, ...]] = {k: tuple(v) for k, v in lit_map.items()}
    return _KeyIndex(any_idx=tuple(any_idx), regex_idx=tuple(regex_idx), lit_map=lit_map_t)


# ---------------------------------------------------------------------------
# Top-level policy blob parsing (schema_version + meta supported)
# ---------------------------------------------------------------------------

_SUPPORTED_SCHEMA_VERSIONS = {1}


def _sanitize_meta(meta: Any, *, max_items: int = 64, max_str: int = 256) -> Mapping[str, Any]:
    if not isinstance(meta, Mapping):
        return MappingProxyType({})
    out: Dict[str, Any] = {}
    n = 0
    for k, v in meta.items():
        if n >= max_items:
            break
        if not isinstance(k, str):
            continue
        kk = _strip_unsafe_text(k, max_len=64)
        if not kk:
            continue
        if isinstance(v, str):
            out[kk] = _strip_unsafe_text(v, max_len=max_str)
        elif isinstance(v, (int, bool)):
            out[kk] = int(v) if isinstance(v, int) and not isinstance(v, bool) else bool(v)
        elif isinstance(v, float):
            fv = _finite_float(v)
            out[kk] = float(fv) if fv is not None else None
        else:
            # drop complex values (avoid executing custom containers)
            continue
        n += 1
    return MappingProxyType(out)


def _parse_policy_obj(obj: Any, *, strict_schema: bool) -> Tuple[List[PolicyRule], List[str], Mapping[str, Any]]:
    errors: List[str] = []
    meta: Mapping[str, Any] = MappingProxyType({})

    # Envelope form
    if isinstance(obj, Mapping):
        if "schema_version" in obj:
            sv = obj.get("schema_version")
            if not isinstance(sv, int):
                errors.append("schema_version_invalid_type")
                if strict_schema:
                    return [], errors, meta
            elif sv not in _SUPPORTED_SCHEMA_VERSIONS:
                errors.append(f"schema_version_unsupported:{sv}")
                if strict_schema:
                    return [], errors, meta

        if "policyset_meta" in obj:
            meta = _sanitize_meta(obj.get("policyset_meta"))

        # Accepted rule array locations
        if "rules" in obj and isinstance(obj.get("rules"), list):
            arr = obj.get("rules")
        elif "policies" in obj and isinstance(obj.get("policies"), list):
            # optional alias
            arr = obj.get("policies")
        else:
            # Backward compatible: {"rules": [...]} already handled; otherwise treat as empty.
            return [], (errors or ["policy_blob_missing_rules"]), meta

    elif isinstance(obj, list):
        arr = obj
    else:
        return [], ["policy blob is neither a list nor an object"], meta

    out: List[PolicyRule] = []
    for i, item in enumerate(arr):  # type: ignore[name-defined]
        try:
            out.append(PolicyRule.model_validate(item))
        except ValidationError as e:
            # keep bounded, actionable info
            errors.append(f"rule[{i}] validation_error:{e.__class__.__name__}")
    return out, errors, meta


# ---------------------------------------------------------------------------
# Policy store
# ---------------------------------------------------------------------------

class PolicyStore:
    """
    L6–L7+ PolicyStore:

      - load/parse/compile errors are NEVER silently swallowed (recorded in bundle.errors)
      - fail-closed is enforceable and optionally strict (fail_closed_on_any_error)
      - default size limits always apply (even if caller doesn't pass kwargs)
      - signature verifier is called AFTER size guard
      - regex is disabled on stdlib re by default (unless explicitly allowed)
      - effective regex engine is tracked for audit
      - policyset_ref is injected into every BoundPolicy template (never None)
      - optional prefilter index reduces bind CPU for large rule sets
      - optional shadowing/conflict diagnostics for maintainability
    """

    def __init__(
        self,
        rules: List[PolicyRule],
        *,
        base_detector: Optional[TCDConfig] = None,
        base_av: Optional[AlwaysValidConfig] = None,
        default_token_cost_divisor: float = 50.0,
        # Load/compile error semantics
        on_load_error: OnLoadErrorMode = "fail_closed",
        fail_closed_on_any_error: Optional[bool] = None,
        strict_validation: bool = False,
        strict_schema: bool = False,
        # Budgets / DoS controls
        max_rules: int = 10_000,
        max_policy_bytes: int = _DEFAULT_MAX_POLICY_BYTES,
        max_compile_ms: int = 500,
        max_regex_rules: int = 2_000,
        max_total_regex_fields: int = 50_000,
        # Regex policy
        regex_policy: Optional[RegexPolicy] = None,
        # Canonicalization
        casefold_keys: Optional[Sequence[str]] = None,
        # Performance: prefilter index keys (env/trust_zone/route are high ROI)
        prefilter_keys: Optional[Sequence[str]] = ("env", "trust_zone", "route"),
        # Diagnostics depth controls
        shadow_analysis_max_rules: int = 2000,
        conflict_analysis_max_rules: int = 1000,
        # Hooks / counters (optional)
        on_bundle_update: Optional[Callable[[Dict[str, Any]], None]] = None,
        enable_hit_counters: bool = False,
        # load provenance injection (used by loaders)
        initial_errors: Optional[List[str]] = None,
        initial_warnings: Optional[List[str]] = None,
        source: Optional[str] = None,
        policyset_meta: Optional[Mapping[str, Any]] = None,
    ):
        self._lock = threading.RLock()

        self._base_detector = _copy_config(base_detector or TCDConfig())
        self._base_av = _copy_config(base_av or AlwaysValidConfig())
        self._default_token_cost_divisor = float(default_token_cost_divisor)

        self._hasher = Blake3Hash()

        self._strict_validation = bool(strict_validation)
        self._strict_schema = bool(strict_schema)

        self._max_rules = int(max(0, max_rules))
        self._max_policy_bytes = int(max(0, max_policy_bytes or _DEFAULT_MAX_POLICY_BYTES))
        self._max_compile_ms = int(max(1, max_compile_ms))
        self._max_regex_rules = int(max(0, max_regex_rules))
        self._max_total_regex_fields = int(max(0, max_total_regex_fields))

        # casefold keys
        cf = set(_DEFAULT_CASEFOLD_KEYS if casefold_keys is None else [str(k) for k in casefold_keys if isinstance(k, str)])
        self._casefold_keys = tuple(sorted(k for k in cf if k in _CTX_KEYS))

        # regex policy normalization (important!)
        rp_in = regex_policy or RegexPolicy(
            allow_regex=True,
            engine="regex",                  # desire regex if available
            timeout_ms=25,
            max_pattern_len=512,
            reject_empty_regex=True,
            allow_regex_on_re_engine=False,  # critical baseline
            require_timeout_enforced=True,
            static_safety_checks=True,
        )
        rp_norm, rp_errs = _normalize_regex_policy(rp_in, strict=self._strict_validation)

        # strict fail-closed mode
        if fail_closed_on_any_error is None:
            fail_closed_on_any_error = bool(self._strict_validation)

        # optional hit counters (keep out of hot path unless enabled)
        self._hit_lock = threading.Lock()
        self._enable_hit_counters = bool(enable_hit_counters)
        self._hits: Dict[str, int] = {}

        self._on_bundle_update = on_bundle_update

        # build bundle (copy-on-write)
        self._bundle: _PolicyBundle = self._build_bundle(
            rules=rules or [],
            rp=rp_norm,
            on_error=on_load_error,
            fail_closed_on_any_error=bool(fail_closed_on_any_error),
            load_errors=list(initial_errors or []) + rp_errs,
            load_warnings=list(initial_warnings or []),
            source=_strip_unsafe_text(source, max_len=128) if isinstance(source, str) else None,
            policyset_meta=policyset_meta or MappingProxyType({}),
            prefilter_keys=tuple(k for k in (prefilter_keys or ()) if isinstance(k, str) and k in _CTX_KEYS),
            shadow_analysis_max_rules=int(max(0, shadow_analysis_max_rules)),
            conflict_analysis_max_rules=int(max(0, conflict_analysis_max_rules)),
        )

        self._emit_bundle_update()

    # ------------------------------------------------------------------
    # Loaders (fix: never swallow errors; size guard always applies)
    # ------------------------------------------------------------------

    @classmethod
    def from_env(
        cls,
        env_key: str = "TCD_POLICIES_JSON",
        *,
        verifier: Optional[Callable[[bytes], None]] = None,
        max_bytes: int = _DEFAULT_MAX_POLICY_BYTES,
        **kwargs,
    ) -> "PolicyStore":
        """
        Build from env var JSON. If verifier is provided, it is called with the UTF-8 bytes.
        L7: size guard happens before verifier.
        """
        src = f"env:{env_key}"
        txt = os.environ.get(env_key, "")
        if not isinstance(txt, str):
            return cls(rules=[], initial_errors=[f"{src}: env_value_not_string"], source=src, max_policy_bytes=max_bytes, **kwargs)

        b = txt.encode("utf-8", errors="ignore")
        if max_bytes > 0 and len(b) > max_bytes:
            return cls(
                rules=[],
                initial_errors=[f"{src}: policy_blob_too_large:{len(b)}>{max_bytes}"],
                source=src,
                max_policy_bytes=max_bytes,
                **kwargs,
            )

        # optional verifier (after size guard)
        if verifier is not None:
            try:
                verifier(b)
            except Exception:
                return cls(
                    rules=[],
                    initial_errors=[f"{src}: verifier_failed"],
                    source=src,
                    max_policy_bytes=max_bytes,
                    **kwargs,
                )

        txt2 = txt.strip()
        if not txt2:
            # empty is not an error (explicitly no policies)
            return cls(rules=[], initial_warnings=[f"{src}: empty_policy_blob"], source=src, max_policy_bytes=max_bytes, **kwargs)

        try:
            obj = json.loads(txt2)
        except Exception:
            return cls(
                rules=[],
                initial_errors=[f"{src}: json_decode_failed"],
                source=src,
                max_policy_bytes=max_bytes,
                **kwargs,
            )

        rules, perr, meta = _parse_policy_obj(obj, strict_schema=bool(kwargs.get("strict_schema", False)))
        return cls(
            rules=rules,
            initial_errors=[f"{src}: parse_errors:{len(perr)}"] + perr if perr else [],
            source=src,
            policyset_meta=meta,
            max_policy_bytes=max_bytes,
            **kwargs,
        )

    @classmethod
    def from_file(
        cls,
        path: str,
        *,
        verifier: Optional[Callable[[bytes], None]] = None,
        max_bytes: int = _DEFAULT_MAX_POLICY_BYTES,
        **kwargs,
    ) -> "PolicyStore":
        """
        Build from JSON file.
        L7: file size guard best-effort; verifier runs after size guard.
        """
        src = f"file:{_strip_unsafe_text(path, max_len=256) or 'unknown'}"
        try:
            if max_bytes > 0 and os.path.exists(path) and os.path.getsize(path) > max_bytes:
                return cls(
                    rules=[],
                    initial_errors=[f"{src}: policy_file_too_large:{os.path.getsize(path)}>{max_bytes}"],
                    source=src,
                    max_policy_bytes=max_bytes,
                    **kwargs,
                )
            with open(path, "rb") as frb:
                blob = frb.read(max_bytes + 1 if max_bytes > 0 else -1)
        except Exception:
            return cls(rules=[], initial_errors=[f"{src}: file_read_failed"], source=src, max_policy_bytes=max_bytes, **kwargs)

        if max_bytes > 0 and len(blob) > max_bytes:
            return cls(
                rules=[],
                initial_errors=[f"{src}: policy_blob_too_large:{len(blob)}>{max_bytes}"],
                source=src,
                max_policy_bytes=max_bytes,
                **kwargs,
            )

        if verifier is not None:
            try:
                verifier(blob)
            except Exception:
                return cls(
                    rules=[],
                    initial_errors=[f"{src}: verifier_failed"],
                    source=src,
                    max_policy_bytes=max_bytes,
                    **kwargs,
                )

        try:
            obj = json.loads(blob.decode("utf-8", errors="strict"))
        except Exception:
            return cls(rules=[], initial_errors=[f"{src}: json_decode_failed"], source=src, max_policy_bytes=max_bytes, **kwargs)

        rules, perr, meta = _parse_policy_obj(obj, strict_schema=bool(kwargs.get("strict_schema", False)))
        return cls(
            rules=rules,
            initial_errors=[f"{src}: parse_errors:{len(perr)}"] + perr if perr else [],
            source=src,
            policyset_meta=meta,
            max_policy_bytes=max_bytes,
            **kwargs,
        )

    @classmethod
    def from_signed_blob(
        cls,
        blob: bytes,
        *,
        verifier: Optional[Callable[[bytes], None]] = None,
        source: str = "signed_blob",
        max_bytes: int = _DEFAULT_MAX_POLICY_BYTES,
        **kwargs,
    ) -> "PolicyStore":
        """
        Build from signed JSON blob.
        L7: size guard happens BEFORE verifier(blob).
        """
        src = f"{_strip_unsafe_text(source, max_len=64) or 'signed_blob'}"
        if not isinstance(blob, (bytes, bytearray)):
            return cls(rules=[], initial_errors=[f"{src}: blob_not_bytes"], source=src, max_policy_bytes=max_bytes, **kwargs)

        if max_bytes > 0 and len(blob) > max_bytes:
            return cls(
                rules=[],
                initial_errors=[f"{src}: policy_blob_too_large:{len(blob)}>{max_bytes}"],
                source=src,
                max_policy_bytes=max_bytes,
                **kwargs,
            )

        if verifier is not None:
            try:
                verifier(blob)
            except Exception:
                return cls(
                    rules=[],
                    initial_errors=[f"{src}: verifier_failed"],
                    source=src,
                    max_policy_bytes=max_bytes,
                    **kwargs,
                )

        try:
            obj = json.loads(bytes(blob).decode("utf-8", errors="strict"))
        except Exception:
            return cls(rules=[], initial_errors=[f"{src}: json_decode_failed"], source=src, max_policy_bytes=max_bytes, **kwargs)

        rules, perr, meta = _parse_policy_obj(obj, strict_schema=bool(kwargs.get("strict_schema", False)))
        return cls(
            rules=rules,
            initial_errors=[f"{src}: parse_errors:{len(perr)}"] + perr if perr else [],
            source=src,
            policyset_meta=meta,
            max_policy_bytes=max_bytes,
            **kwargs,
        )

    # ------------------------------------------------------------------
    # Public read APIs
    # ------------------------------------------------------------------

    def replace_rules(self, rules: List[PolicyRule], *, source: Optional[str] = None, errors: Optional[List[str]] = None, warnings: Optional[List[str]] = None) -> None:
        """
        Atomic replace (copy-on-write).
        """
        with self._lock:
            self._bundle = self._build_bundle(
                rules=rules or [],
                rp=self._bundle.regex_policy,
                on_error=self._bundle.on_error,
                fail_closed_on_any_error=self._bundle.fail_closed_on_any_error,
                load_errors=list(errors or []),
                load_warnings=list(warnings or []),
                source=_strip_unsafe_text(source, max_len=128) if isinstance(source, str) else self._bundle.source,
                policyset_meta=self._bundle.policyset_meta,
                prefilter_keys=self._bundle.prefilter_keys,
                shadow_analysis_max_rules=2000,
                conflict_analysis_max_rules=1000,
            )
        self._emit_bundle_update()

    def rules(self) -> List[PolicyRule]:
        b = self._bundle
        return [r.model_copy(deep=True) for r in b.rules]

    def policyset_ref(self) -> str:
        return self._bundle.set_ref

    def rules_refs(self) -> List[str]:
        return [cr.policy_ref for cr in self._bundle.compiled]

    def diagnostics(self) -> Dict[str, Any]:
        b = self._bundle
        return {
            "policyset_ref": b.set_ref,
            "updated_ts": b.updated_ts,
            "source": b.source,
            "rule_count": len(b.rules),
            "compiled_rule_count": len(b.compiled),
            "error_count": len(b.errors),
            "warning_count": len(b.warnings),
            "errors": list(b.errors[:50]),
            "warnings": list(b.warnings[:50]),
            "on_load_error": b.on_error,
            "fail_closed_on_any_error": b.fail_closed_on_any_error,
            "regex_engine_effective": b.regex_engine_effective,
            "regex_timeout_ms": b.regex_policy.timeout_ms,
            "regex_max_pattern_len": b.regex_policy.max_pattern_len,
            "regex_allowed": b.regex_policy.allow_regex,
            "casefold_keys": list(b.casefold_keys),
            "prefilter_keys": list(b.prefilter_keys),
            "shadowed_rules_count": len(b.shadowed_rules),
            "shadowed_rules": list(b.shadowed_rules[:50]),
            "potential_conflicts_count": len(b.potential_conflicts),
            "potential_conflicts": list(b.potential_conflicts[:20]),
            "analysis_truncated": b.analysis_truncated,
            "policyset_meta": dict(b.policyset_meta) if isinstance(b.policyset_meta, Mapping) else {},
        }

    def hit_counters_snapshot(self) -> Dict[str, int]:
        if not self._enable_hit_counters:
            return {}
        with self._hit_lock:
            return dict(self._hits)

    # ------------------------------------------------------------------
    # Binding (hot path)
    # ------------------------------------------------------------------

    def bind(self, ctx: Dict[str, Any]) -> BoundPolicy:
        b = self._bundle
        ctx_n = self._normalize_ctx(ctx, casefold_keys=set(b.casefold_keys))

        # Strong fail-closed semantics
        if b.errors:
            if b.on_error == "raise":
                raise RuntimeError("PolicyStore has load/parse/compile errors; refusing to bind")
            if b.on_error == "fail_closed" and b.fail_closed_on_any_error:
                return self._return_error_policy(b)

        candidates = self._candidate_indices(ctx_n, b)

        for idx in candidates:
            cr = b.compiled[idx]
            if _matches_compiled(ctx_n, cr, b.regex_policy, set(b.casefold_keys)):
                bp = replace(cr.bound_template, detector_cfg=_copy_config(cr.detector_cfg_eff), av_cfg=_copy_config(cr.av_cfg_eff))
                self._count_hit(bp.policy_ref, is_default=False, is_error=False)
                return bp

        # no match
        if b.errors and b.on_error == "fail_closed":
            bp = self._return_error_policy(b)
            self._count_hit(bp.policy_ref, is_default=False, is_error=True)
            return bp

        bp = self._return_default_policy(b)
        self._count_hit(bp.policy_ref, is_default=True, is_error=False)
        return bp

    def bind_many(self, ctxs: Sequence[Dict[str, Any]]) -> List[BoundPolicy]:
        b = self._bundle
        casefold_keys = set(b.casefold_keys)

        # strict fail-closed (batch)
        if b.errors and b.on_error == "raise":
            raise RuntimeError("PolicyStore has load/parse/compile errors; refusing to bind_many")
        if b.errors and b.on_error == "fail_closed" and b.fail_closed_on_any_error:
            ep = self._return_error_policy(b)
            return [ep for _ in ctxs]

        out: List[BoundPolicy] = []
        for ctx in ctxs:
            ctx_n = self._normalize_ctx(ctx, casefold_keys=casefold_keys)
            candidates = self._candidate_indices(ctx_n, b)
            chosen: Optional[_CompiledRule] = None
            for idx in candidates:
                cr = b.compiled[idx]
                if _matches_compiled(ctx_n, cr, b.regex_policy, casefold_keys):
                    chosen = cr
                    break
            if chosen is None:
                if b.errors and b.on_error == "fail_closed":
                    out.append(self._return_error_policy(b))
                else:
                    out.append(self._return_default_policy(b))
            else:
                out.append(replace(chosen.bound_template, detector_cfg=_copy_config(chosen.detector_cfg_eff), av_cfg=_copy_config(chosen.av_cfg_eff)))
        return out

    def bind_explain(self, ctx: Dict[str, Any], *, top_k: int = 10) -> Dict[str, Any]:
        """
        L7: actionable explain without leaking ctx values.
        Includes mismatch fields for top candidates scanned (bounded).
        """
        b = self._bundle
        casefold_keys = set(b.casefold_keys)
        ctx_n = self._normalize_ctx(ctx, casefold_keys=casefold_keys)

        out: Dict[str, Any] = {
            "policyset_ref": b.set_ref,
            "source": b.source,
            "updated_ts": b.updated_ts,
            "errors": list(b.errors[:20]),
            "warnings": list(b.warnings[:20]),
            "matched": False,
            "matched_policy_ref": None,
            "candidate_count": len(b.compiled),
            "regex_engine_effective": b.regex_engine_effective,
        }

        if b.errors and b.on_error == "raise":
            out["would_raise"] = True
            return out

        if b.errors and b.on_error == "fail_closed" and b.fail_closed_on_any_error:
            out["matched"] = True
            out["matched_policy_ref"] = b.error_policy.policy_ref
            out["forced_fail_closed"] = True
            return out

        candidates = self._candidate_indices(ctx_n, b)
        trace: List[Dict[str, Any]] = []
        scanned = 0

        def cf(k: str) -> bool:
            return k in casefold_keys

        for idx in candidates:
            if scanned >= max(1, int(top_k)):
                break
            cr = b.compiled[idx]
            mism: List[str] = []
            # per-field mismatch list (no ctx values)
            if not _match_token_compiled(ctx_n.get("tenant", ""), cr.tenant, b.regex_policy, casefold=cf("tenant")):
                mism.append("tenant")
            if not _match_token_compiled(ctx_n.get("user", ""), cr.user, b.regex_policy, casefold=cf("user")):
                mism.append("user")
            if not _match_token_compiled(ctx_n.get("session", ""), cr.session, b.regex_policy, casefold=cf("session")):
                mism.append("session")
            if not _match_token_compiled(ctx_n.get("model_id", ""), cr.model_id, b.regex_policy, casefold=cf("model_id")):
                mism.append("model_id")
            if not _match_token_compiled(ctx_n.get("gpu_id", ""), cr.gpu_id, b.regex_policy, casefold=cf("gpu_id")):
                mism.append("gpu_id")
            if not _match_token_compiled(ctx_n.get("task", ""), cr.task, b.regex_policy, casefold=cf("task")):
                mism.append("task")
            if not _match_token_compiled(ctx_n.get("lang", ""), cr.lang, b.regex_policy, casefold=cf("lang")):
                mism.append("lang")
            if not _match_token_compiled(ctx_n.get("env", ""), cr.env, b.regex_policy, casefold=cf("env")):
                mism.append("env")
            if not _match_token_compiled(ctx_n.get("trust_zone", ""), cr.trust_zone, b.regex_policy, casefold=cf("trust_zone")):
                mism.append("trust_zone")
            if not _match_token_compiled(ctx_n.get("route", ""), cr.route, b.regex_policy, casefold=cf("route")):
                mism.append("route")
            if not _match_token_compiled(ctx_n.get("data_class", ""), cr.data_class, b.regex_policy, casefold=cf("data_class")):
                mism.append("data_class")
            if not _match_token_compiled(ctx_n.get("workload", ""), cr.workload, b.regex_policy, casefold=cf("workload")):
                mism.append("workload")
            if not _match_token_compiled(ctx_n.get("jurisdiction", ""), cr.jurisdiction, b.regex_policy, casefold=cf("jurisdiction")):
                mism.append("jurisdiction")
            if not _match_token_compiled(ctx_n.get("regulation", ""), cr.regulation, b.regex_policy, casefold=cf("regulation")):
                mism.append("regulation")
            if not _match_token_compiled(ctx_n.get("client_app", ""), cr.client_app, b.regex_policy, casefold=cf("client_app")):
                mism.append("client_app")
            if not _match_token_compiled(ctx_n.get("access_channel", ""), cr.access_channel, b.regex_policy, casefold=cf("access_channel")):
                mism.append("access_channel")

            trace.append(
                {
                    "policy_ref": cr.policy_ref,
                    "priority": cr.priority,
                    "specificity": cr.specificity,
                    "mismatched_fields": mism,
                    "match_ok": len(mism) == 0,
                }
            )
            scanned += 1
            if len(mism) == 0:
                out["matched"] = True
                out["matched_policy_ref"] = cr.policy_ref
                break

        out["trace"] = trace
        if not out["matched"]:
            out["fallback"] = "error_policy" if (b.errors and b.on_error == "fail_closed") else "default_policy"
        return out

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _emit_bundle_update(self) -> None:
        hook = self._on_bundle_update
        if hook is None:
            return
        b = self._bundle
        payload = {
            "policyset_ref": b.set_ref,
            "updated_ts": b.updated_ts,
            "source": b.source,
            "rule_count": len(b.rules),
            "compiled_rule_count": len(b.compiled),
            "error_count": len(b.errors),
            "warning_count": len(b.warnings),
            "on_load_error": b.on_error,
            "fail_closed_on_any_error": b.fail_closed_on_any_error,
            "regex_engine_effective": b.regex_engine_effective,
            "regex_allowed": b.regex_policy.allow_regex,
        }
        try:
            hook(payload)
        except Exception:
            pass

    def _count_hit(self, policy_ref: str, *, is_default: bool, is_error: bool) -> None:
        if not self._enable_hit_counters:
            return
        if not isinstance(policy_ref, str) or not policy_ref:
            return
        with self._hit_lock:
            self._hits[policy_ref] = int(self._hits.get(policy_ref, 0)) + 1
            if is_default:
                self._hits["_default"] = int(self._hits.get("_default", 0)) + 1
            if is_error:
                self._hits["_error"] = int(self._hits.get("_error", 0)) + 1

    def _return_default_policy(self, b: _PolicyBundle) -> BoundPolicy:
        return replace(b.default_policy, detector_cfg=_copy_config(b.default_policy.detector_cfg), av_cfg=_copy_config(b.default_policy.av_cfg))

    def _return_error_policy(self, b: _PolicyBundle) -> BoundPolicy:
        return replace(b.error_policy, detector_cfg=_copy_config(b.error_policy.detector_cfg), av_cfg=_copy_config(b.error_policy.av_cfg))

    def _normalize_ctx(self, ctx: Mapping[str, Any], *, casefold_keys: "set[str]") -> Dict[str, str]:
        out: Dict[str, str] = {}
        if not isinstance(ctx, Mapping):
            return {k: "" for k in _CTX_KEYS}
        for k in _CTX_KEYS:
            v = ctx.get(k, "")
            if isinstance(v, str):
                s = _strip_unsafe_text(v, max_len=512)
                if k in casefold_keys:
                    s = s.lower()
                out[k] = s
            else:
                out[k] = ""
        return out

    def _candidate_indices(self, ctx_n: Mapping[str, str], b: _PolicyBundle) -> Sequence[int]:
        # If no index configured, scan all
        if not b.prefilter_keys or not b.prefilter_index:
            return range(len(b.compiled))

        cand: Optional[List[int]] = None
        for key in b.prefilter_keys:
            idx = b.prefilter_index.get(key)
            if idx is None:
                continue
            v = ctx_n.get(key, "")
            lit = idx.lit_map.get(v, ())
            merged = _merge3_sorted(lit, idx.any_idx, idx.regex_idx)
            cand = merged if cand is None else _intersect_sorted(cand, merged)
            if cand is not None and not cand:
                return ()
        return cand if cand is not None else range(len(b.compiled))

    def _build_bundle(
        self,
        *,
        rules: List[PolicyRule],
        rp: RegexPolicy,
        on_error: OnLoadErrorMode,
        fail_closed_on_any_error: bool,
        load_errors: List[str],
        load_warnings: List[str],
        source: Optional[str],
        policyset_meta: Mapping[str, Any],
        prefilter_keys: Tuple[str, ...],
        shadow_analysis_max_rules: int,
        conflict_analysis_max_rules: int,
    ) -> _PolicyBundle:
        errors: List[str] = list(load_errors or [])
        warnings: List[str] = list(load_warnings or [])

        # Deep-copy rules (callers cannot mutate store state)
        safe_rules: List[PolicyRule] = []
        for i, r in enumerate(rules or []):
            try:
                if isinstance(r, PolicyRule):
                    safe_rules.append(r.model_copy(deep=True))
                elif isinstance(r, dict):
                    safe_rules.append(PolicyRule.model_validate(r))
                else:
                    errors.append(f"rule[{i}] unsupported_type:{type(r).__name__}")
            except ValidationError:
                errors.append(f"rule[{i}] validation_error")

        if self._max_rules > 0 and len(safe_rules) > self._max_rules:
            warnings.append(f"too_many_rules:{len(safe_rules)}>{self._max_rules};truncated")
            safe_rules = safe_rules[: self._max_rules]

        # Compute set_ref early so every rule template gets it (fixes audit gap)
        try:
            canon = {"schema_version": 1, "rules": [r.model_dump() for r in safe_rules]}
            digest = self._hasher.hex(_canon_json(canon).encode("utf-8"), ctx=_HASH_CTX_SET)
            set_ref = f"set@1#{digest[:12]}"
        except Exception:
            # This should not happen now that NaN/Inf are rejected, but fail closed deterministically.
            set_ref = "set@1#ffffffffffff"
            errors.append("policyset_ref_compute_failed")

        # Budgets for regex compilation / memory
        regex_rule_count = 0
        regex_field_count = 0

        compiled: List[_CompiledRule] = []
        start = time.monotonic()
        max_ms = float(self._max_compile_ms)

        casefold_keys = set(self._casefold_keys)

        def cf(k: str) -> bool:
            return k in casefold_keys

        for idx, rule in enumerate(safe_rules):
            if (time.monotonic() - start) * 1000.0 > max_ms:
                errors.append(f"compile_timeout>{self._max_compile_ms}ms")
                break

            cr, err, used_regex_fields = self._compile_rule(rule, idx, rp, set_ref=set_ref, casefold_keys=casefold_keys)
            if err:
                errors.append(err)
                if self._strict_validation:
                    compiled = []
                    break
                continue
            if cr is None:
                continue

            if cr.has_regex:
                regex_rule_count += 1
                if self._max_regex_rules > 0 and regex_rule_count > self._max_regex_rules:
                    errors.append(f"max_regex_rules_exceeded:{regex_rule_count}>{self._max_regex_rules}")
                    if self._strict_validation:
                        compiled = []
                    break
                regex_field_count += used_regex_fields
                if self._max_total_regex_fields > 0 and regex_field_count > self._max_total_regex_fields:
                    errors.append(f"max_total_regex_fields_exceeded:{regex_field_count}>{self._max_total_regex_fields}")
                    if self._strict_validation:
                        compiled = []
                    break

            compiled.append(cr)

        # Deterministic sort: specificity desc, priority desc, order asc
        compiled.sort(key=lambda x: (-int(x.specificity), -int(x.priority), int(x.order)))

        # Build prefilter index
        pre_idx: Dict[str, _KeyIndex] = {}
        for k in prefilter_keys:
            pre_idx[k] = _build_key_index(compiled, key=k)

        # Shadowing/conflict analysis (bounded)
        shadowed: List[str] = []
        conflicts: List[Tuple[str, str, str]] = []
        analysis_truncated = False

        # Only attempt analysis on top N rules to avoid O(N^2) blowups
        N_shadow = min(len(compiled), max(0, shadow_analysis_max_rules))
        N_conf = min(len(compiled), max(0, conflict_analysis_max_rules))

        # Literal-only tokens representation for fast cover/overlap checks
        def is_literal_only(cr: _CompiledRule) -> bool:
            for k in ("tenant","user","session","model_id","gpu_id","task","lang","env","trust_zone","route","data_class","workload","jurisdiction","regulation","client_app","access_channel"):
                p = getattr(cr, k)
                if p is None:
                    continue
                if isinstance(p, str):
                    continue
                return False
            return True

        def token_tuple(cr: _CompiledRule) -> Tuple[str, ...]:
            toks: List[str] = []
            for k in ("tenant","user","session","model_id","gpu_id","task","lang","env","trust_zone","route","data_class","workload","jurisdiction","regulation","client_app","access_channel"):
                p = getattr(cr, k)
                toks.append("*" if p is None else (p if isinstance(p, str) else "~regex"))
            return tuple(toks)

        literal_rules: List[Tuple[int, str, Tuple[str, ...]]] = []
        for i in range(min(N_shadow, len(compiled))):
            cr = compiled[i]
            if is_literal_only(cr):
                literal_rules.append((i, cr.policy_ref, token_tuple(cr)))

        # Shadowing: earlier rule covers later rule (literal-only)
        # cover(A,B): for each field, A is "*" or equals B
        for j in range(len(literal_rules)):
            idx_j, ref_j, tok_j = literal_rules[j]
            # search earlier rules only
            for i in range(j):
                idx_i, ref_i, tok_i = literal_rules[i]
                if idx_i >= idx_j:
                    continue
                covers = True
                for a, b2 in zip(tok_i, tok_j):
                    if a == "*" or a == b2:
                        continue
                    covers = False
                    break
                if covers:
                    shadowed.append(ref_j)
                    break
            if len(shadowed) >= 500:
                analysis_truncated = True
                break

        # Conflicts (overlaps): literal-only pair overlap but neither covers the other (bounded)
        # overlap(A,B): for each field, equal or one is "*"
        # We only check the top N_conf literal-only rules
        literal_rules_conf: List[Tuple[int, str, Tuple[str, ...]]] = []
        for i in range(min(N_conf, len(compiled))):
            cr = compiled[i]
            if is_literal_only(cr):
                literal_rules_conf.append((i, cr.policy_ref, token_tuple(cr)))

        M = len(literal_rules_conf)
        max_pairs = 500
        for a in range(M):
            if len(conflicts) >= max_pairs:
                analysis_truncated = True
                break
            _, ref_a, tok_a = literal_rules_conf[a]
            for b2 in range(a + 1, min(M, a + 200)):  # local window to bound
                _, ref_b, tok_b = literal_rules_conf[b2]
                overlap = True
                for x, y in zip(tok_a, tok_b):
                    if x == y or x == "*" or y == "*":
                        continue
                    overlap = False
                    break
                if not overlap:
                    continue
                # neither covers the other
                cover_a_b = all((x == "*" or x == y) for x, y in zip(tok_a, tok_b))
                cover_b_a = all((y == "*" or y == x) for x, y in zip(tok_a, tok_b))
                if not cover_a_b and not cover_b_a:
                    conflicts.append((ref_a, ref_b, "literal_overlap_ambiguous"))
                    if len(conflicts) >= max_pairs:
                        analysis_truncated = True
                        break

        # Build default & error policies
        default_policy = self._default_bound_policy(set_ref=set_ref)
        error_policy = self._error_bound_policy(set_ref=set_ref)

        eff_engine = rp.effective_engine()

        return _PolicyBundle(
            rules=tuple(safe_rules),
            compiled=tuple(compiled),
            set_ref=set_ref,
            updated_ts=time.time(),
            errors=_cap_errors(errors),
            warnings=_cap_errors(warnings),
            on_error=on_error,
            fail_closed_on_any_error=bool(fail_closed_on_any_error),
            default_policy=default_policy,
            error_policy=error_policy,
            regex_policy=rp,
            regex_engine_effective=eff_engine,
            casefold_keys=tuple(self._casefold_keys),
            source=source,
            policyset_meta=_sanitize_meta(policyset_meta),
            prefilter_keys=tuple(prefilter_keys),
            prefilter_index=MappingProxyType(pre_idx),
            shadowed_rules=tuple(shadowed),
            potential_conflicts=tuple(conflicts),
            analysis_truncated=bool(analysis_truncated),
        )

    def _compile_rule(
        self,
        rule: PolicyRule,
        idx: int,
        rp: RegexPolicy,
        *,
        set_ref: str,
        casefold_keys: "set[str]",
    ) -> Tuple[Optional[_CompiledRule], Optional[str], int]:
        """
        Returns (compiled_rule, error_str, regex_fields_used).
        """
        m = rule.match
        regex_fields_used = 0

        def cp(key: str, val: str) -> Optional[_Pat]:
            nonlocal regex_fields_used
            pat = _compile_pat(val, rp, key=key, casefold=(key in casefold_keys))
            if pat is _BAD_RE:
                return _BAD_RE  # type: ignore[return-value]
            if _is_regex(val):
                regex_fields_used += 1
            return pat

        pats = {
            "tenant": cp("tenant", m.tenant),
            "user": cp("user", m.user),
            "session": cp("session", m.session),
            "model_id": cp("model_id", m.model_id),
            "gpu_id": cp("gpu_id", m.gpu_id),
            "task": cp("task", m.task),
            "lang": cp("lang", m.lang),
            "env": cp("env", m.env),
            "trust_zone": cp("trust_zone", m.trust_zone),
            "route": cp("route", m.route),
            "data_class": cp("data_class", m.data_class),
            "workload": cp("workload", m.workload),
            "jurisdiction": cp("jurisdiction", m.jurisdiction),
            "regulation": cp("regulation", m.regulation),
            "client_app": cp("client_app", m.client_app),
            "access_channel": cp("access_channel", m.access_channel),
        }

        bad_fields = [k for k, v in pats.items() if v is _BAD_RE]
        if bad_fields:
            return None, f"rule[{idx}] {rule.name}@{rule.version}: invalid_or_unsafe_pattern:{bad_fields}", regex_fields_used

        spec = _specificity_from_match(m, rp)
        prio = int(rule.priority)

        det_override = rule.detector.model_dump(exclude_none=True) if rule.detector else {}
        av_override = rule.av.model_dump(exclude_none=True) if rule.av else {}
        det_eff = _dc_update(self._base_detector, det_override)
        av_eff = _dc_update(self._base_av, av_override)

        r = rule.routing.model_dump(exclude_none=True) if rule.routing else {}
        t_low = r.get("t_low")
        t_high = r.get("t_high")
        top_p_low = r.get("top_p_low")
        top_p_high = r.get("top_p_high")
        fallback_decoder = r.get("fallback_decoder")
        action_hint = r.get("action_hint")
        route_profile = r.get("route_profile")

        enable_receipts = bool(rule.receipt.enable_issue) if rule.receipt else False
        enable_verify_metrics = bool(rule.receipt.enable_verify_metrics) if rule.receipt else False
        attach_policy_refs = bool(rule.receipt.attach_policy_refs) if rule.receipt else True
        attach_match_context = bool(rule.receipt.attach_match_context) if rule.receipt else False
        receipt_profile = rule.receipt.profile if rule.receipt else None
        receipt_crypto_profile = rule.receipt.crypto_profile if rule.receipt else None
        receipt_match_context_level = rule.receipt.match_context_level if rule.receipt else None

        slo_latency_ms = rule.sre.slo_latency_ms if rule.sre else None
        token_cost_divisor = float(
            (rule.sre.token_cost_divisor if (rule.sre and rule.sre.token_cost_divisor is not None) else None)
            or self._default_token_cost_divisor
        )
        error_budget_fraction = rule.sre.error_budget_fraction if rule.sre else None
        probe_sample_rate = rule.sre.probe_sample_rate if rule.sre else None

        alpha_budget_fraction = rule.av.alpha_budget_fraction if rule.av else None
        e_stream = rule.av.e_stream if rule.av else None

        compliance_profile = rule.compliance_profile
        risk_label = rule.risk_label
        audit_label = rule.audit.audit_label if rule.audit else None
        audit_sample_rate = rule.audit.sample_rate if rule.audit else None
        audit_log_level = rule.audit.log_level if rule.audit else None
        audit_incident_class = rule.audit.incident_class if rule.audit else None
        audit_force_on_violation = rule.audit.force_audit_on_violation if rule.audit else None
        audit_require_full_trace = rule.audit.require_full_trace if rule.audit else None

        high_risk = bool(risk_label and risk_label.lower() in {"high", "critical"})
        high_compliance = bool(compliance_profile and compliance_profile.lower() in {"high", "strict"})
        if high_risk or high_compliance:
            enable_receipts = True
            if audit_sample_rate is None:
                audit_sample_rate = 1.0
            if audit_force_on_violation is None:
                audit_force_on_violation = True

        match_dict = rule.match.model_dump()
        # ensure match template canonicalization mirrors ctx canonicalization for literal patterns
        mt: Dict[str, str] = {}
        for k in _CTX_KEYS:
            v = match_dict.get(k, "*")
            if not isinstance(v, str):
                v = "*"
            v2 = _strip_unsafe_text(v, max_len=512) or "*"
            if (k in casefold_keys) and (not _is_regex(v2)) and v2 != "*":
                v2 = v2.lower()
            mt[k] = v2
        match_ro = MappingProxyType(mt)

        pref = rule.policy_ref()

        has_regex = any(_is_regex(getattr(m, k)) for k in _CTX_KEYS if hasattr(m, k))

        template = BoundPolicy(
            name=rule.name,
            version=rule.version,
            policy_ref=pref,
            priority=prio,
            detector_cfg=det_eff,
            av_cfg=av_eff,
            t_low=t_low,
            t_high=t_high,
            top_p_low=top_p_low,
            top_p_high=top_p_high,
            fallback_decoder=fallback_decoder,
            action_hint=action_hint,
            route_profile=route_profile,
            enable_receipts=enable_receipts,
            enable_verify_metrics=enable_verify_metrics,
            attach_policy_refs=attach_policy_refs,
            attach_match_context=attach_match_context,
            receipt_profile=receipt_profile,
            receipt_crypto_profile=receipt_crypto_profile,
            receipt_match_context_level=receipt_match_context_level,
            slo_latency_ms=slo_latency_ms,
            token_cost_divisor=token_cost_divisor,
            error_budget_fraction=error_budget_fraction,
            probe_sample_rate=probe_sample_rate,
            alpha_budget_fraction=alpha_budget_fraction,
            e_stream=e_stream,
            compliance_profile=compliance_profile,
            risk_label=risk_label,
            audit_label=audit_label,
            audit_sample_rate=audit_sample_rate,
            audit_log_level=audit_log_level,
            audit_incident_class=audit_incident_class,
            audit_force_on_violation=audit_force_on_violation,
            audit_require_full_trace=audit_require_full_trace,
            match=match_ro,
            policyset_ref=set_ref,  # FIX: always injected
            origin=rule.origin,
            policy_patch_id=rule.policy_patch_id,
            commit_hash=rule.commit_hash,
            change_ticket_id=rule.change_ticket_id,
            decision="inherit",
            enforcement=None,
        )

        return (
            _CompiledRule(
                tenant=pats["tenant"],
                user=pats["user"],
                session=pats["session"],
                model_id=pats["model_id"],
                gpu_id=pats["gpu_id"],
                task=pats["task"],
                lang=pats["lang"],
                env=pats["env"],
                trust_zone=pats["trust_zone"],
                route=pats["route"],
                data_class=pats["data_class"],
                workload=pats["workload"],
                jurisdiction=pats["jurisdiction"],
                regulation=pats["regulation"],
                client_app=pats["client_app"],
                access_channel=pats["access_channel"],
                specificity=spec,
                priority=prio,
                order=idx,
                policy_ref=pref,
                bound_template=template,
                detector_cfg_eff=det_eff,
                av_cfg_eff=av_eff,
                has_regex=bool(has_regex),
            ),
            None,
            int(regex_fields_used),
        )

    def _default_bound_policy(self, *, set_ref: str) -> BoundPolicy:
        det = _copy_config(self._base_detector)
        av = _copy_config(self._base_av)
        match_ro = MappingProxyType({k: "*" for k in _CTX_KEYS})
        return BoundPolicy(
            name="default",
            version="0",
            policy_ref="default@0#000000000000",
            priority=0,
            detector_cfg=det,
            av_cfg=av,
            t_low=None,
            t_high=None,
            top_p_low=None,
            top_p_high=None,
            fallback_decoder=None,
            action_hint=None,
            route_profile=None,
            enable_receipts=False,
            enable_verify_metrics=False,
            attach_policy_refs=True,
            attach_match_context=False,
            receipt_profile=None,
            receipt_crypto_profile=None,
            receipt_match_context_level=None,
            slo_latency_ms=None,
            token_cost_divisor=float(self._default_token_cost_divisor),
            error_budget_fraction=None,
            probe_sample_rate=None,
            alpha_budget_fraction=None,
            e_stream=None,
            compliance_profile=None,
            risk_label=None,
            audit_label=None,
            audit_sample_rate=None,
            audit_log_level=None,
            audit_incident_class=None,
            audit_force_on_violation=None,
            audit_require_full_trace=None,
            match=match_ro,
            policyset_ref=set_ref,
            decision="inherit",
            enforcement=None,
        )

    def _error_bound_policy(self, *, set_ref: str) -> BoundPolicy:
        det = _copy_config(self._base_detector)
        av = _copy_config(self._base_av)
        match_ro = MappingProxyType({k: "*" for k in _CTX_KEYS})
        return BoundPolicy(
            name="policy_error",
            version="1",
            policy_ref="policy_error@1#ffffffffffff",
            priority=10**9,
            detector_cfg=det,
            av_cfg=av,
            t_low=None,
            t_high=None,
            top_p_low=None,
            top_p_high=None,
            fallback_decoder=None,
            action_hint="block",
            route_profile="restricted",
            enable_receipts=True,
            enable_verify_metrics=True,
            attach_policy_refs=True,
            attach_match_context=False,
            receipt_profile="reg_strict",
            receipt_crypto_profile=None,
            receipt_match_context_level="coarse",
            slo_latency_ms=None,
            token_cost_divisor=float(self._default_token_cost_divisor),
            error_budget_fraction=0.0,
            probe_sample_rate=1.0,
            alpha_budget_fraction=None,
            e_stream=None,
            compliance_profile="strict",
            risk_label="critical",
            audit_label="restricted",
            audit_sample_rate=1.0,
            audit_log_level="error",
            audit_incident_class="compliance",
            audit_force_on_violation=True,
            audit_require_full_trace=True,
            match=match_ro,
            policyset_ref=set_ref,
            # Strong semantic: deny
            decision="deny",
            enforcement="block",
        )