from __future__ import annotations

import difflib
import json
import re
import textwrap
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Mapping, Optional, Tuple

# Optional hashing primitive for patch_ref (kept opaque here).
try:
    from .crypto import Blake3Hash  # type: ignore
except Exception:  # pragma: no cover
    Blake3Hash = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Guard rails / limits
# ---------------------------------------------------------------------------

# Hard limits to keep this engine firmly in the "small, local edits" regime.
_MAX_SEGMENT_LINES = 64
_MAX_CHANGED_LINES = 32
_MAX_FILE_BYTES = 1_000_000
_MAX_REWRITE_TOKEN_CHARS = 256
_MAX_METADATA_DEPTH = 4
_MAX_METADATA_ITEMS = 64
_MAX_METADATA_STRING_CHARS = 512

# Sensitive areas which should not be rewritten automatically.
# Paths are interpreted relative to the repository root.
_SENSITIVE_PATH_PREFIXES: Tuple[str, ...] = (
    # Crypto / verification / receipts.
    "tcd/crypto",
    "tcd/verify",
    "tcd/receipts",
    "tcd/attest",

    # Runtime transport and edge-control surfaces.
    "tcd/service_http",
    "tcd/service_grpc",
    "tcd/api_v1",
    "tcd/middleware",
    "tcd/middleware_request",
    "tcd/middleware_security",
    "tcd/auth",

    # Policy / routing / security control plane.
    "tcd/policies",
    "tcd/security_router",
    "tcd/routing",
    "tcd/risk_av",
    "tcd/ratelimit",

    # Evidence / persistence / audit surfaces.
    "tcd/schemas",
    "tcd/signals",
    "tcd/storage",
    "tcd/ledger",
    "tcd/audit",
    "tcd/auditor",
    "tcd/trust_graph",

    # Detector / decision core and patch governance.
    "tcd/detector",
    "tcd/decision_engine",
    "tcd/multivariate",
    "tcd/agent",
    "tcd/patch_runtime",
)



_CTRL_RE = re.compile(r"[\x00-\x1F\x7F]")

_SENSITIVE_METADATA_KEY_TOKENS = frozenset(
    {
        "prompt",
        "completion",
        "input",
        "output",
        "message",
        "messages",
        "content",
        "body",
        "payload",
        "headers",
        "header",
        "cookie",
        "authorization",
        "auth",
        "token",
        "secret",
        "password",
        "passwd",
        "pwd",
        "apikey",
        "api_key",
        "private",
        "privatekey",
        "llm_suggestion",
    }
)


def _safe_scalar_text(v: Any, *, max_chars: int = _MAX_METADATA_STRING_CHARS) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        s = v
    elif isinstance(v, bool):
        return "true" if v else "false"
    elif isinstance(v, int):
        s = str(v)
    elif isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")):
            return ""
        s = f"{v:.12g}"
    elif isinstance(v, (bytes, bytearray, memoryview)):
        return "<bytes>"
    else:
        return f"[type:{type(v).__name__}]"
    return _CTRL_RE.sub("", s[:max_chars]).strip()


def _metadata_get(meta: Any, key: str, default: Any = "") -> Any:
    if isinstance(meta, Mapping):
        return meta.get(key, default)
    return default


def _metadata_key_is_sensitive(key: str) -> bool:
    key_l = key.lower()
    parts = [p for p in re.split(r"[^a-z0-9]+", key_l) if p]
    fused = "".join(parts)
    toks = tuple(parts) + ((fused,) if fused else tuple())
    return any(t in _SENSITIVE_METADATA_KEY_TOKENS for t in toks) or any(
        t in key_l for t in _SENSITIVE_METADATA_KEY_TOKENS
    )


def _sanitize_metadata_value(v: Any, *, depth: int = 0) -> Any:
    if depth >= _MAX_METADATA_DEPTH:
        return "[truncated]"

    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, int):
        return int(v) if v.bit_length() <= 256 else "[int:oversize]"
    if isinstance(v, float):
        return float(v) if (v == v and v not in (float("inf"), float("-inf"))) else None
    if isinstance(v, str):
        return _safe_scalar_text(v, max_chars=_MAX_METADATA_STRING_CHARS)
    if isinstance(v, (bytes, bytearray, memoryview)):
        return f"[bytes:{len(v)}]"

    if isinstance(v, Mapping):
        out: Dict[str, Any] = {}
        for idx, (k, val) in enumerate(v.items()):
            if idx >= _MAX_METADATA_ITEMS:
                out["_truncated"] = True
                break
            if not isinstance(k, str):
                continue
            kk = _safe_scalar_text(k, max_chars=128)
            if not kk:
                continue
            if _metadata_key_is_sensitive(kk):
                out[kk] = "[redacted]"
                continue
            out[kk] = _sanitize_metadata_value(val, depth=depth + 1)
        return out

    if isinstance(v, (list, tuple, set, frozenset)):
        seq = list(v)[:_MAX_METADATA_ITEMS]
        out = [_sanitize_metadata_value(x, depth=depth + 1) for x in seq]
        if len(v) > _MAX_METADATA_ITEMS:
            out.append("[truncated]")
        return out

    return f"[type:{type(v).__name__}]"


def _sanitize_metadata(meta: Any) -> Dict[str, Any]:
    if not isinstance(meta, Mapping):
        return {}
    out = _sanitize_metadata_value(meta, depth=0)
    return out if isinstance(out, dict) else {}


def _rewrite_token(v: Any, *, max_chars: int = _MAX_REWRITE_TOKEN_CHARS) -> str:
    if not isinstance(v, str):
        return ""
    if "\x00" in v or "\r" in v or "\n" in v:
        return ""
    if len(v) > max_chars:
        return ""
    return _CTRL_RE.sub("", v).strip()


def _normalize_repo_rel_path(file_path: str) -> Optional[str]:
    if not isinstance(file_path, str):
        return None
    raw = file_path.replace("\\", "/").strip()
    if not raw or raw.startswith("/") or "\x00" in raw:
        return None
    p = PurePosixPath(raw)
    parts: List[str] = []
    for part in p.parts:
        if part in ("", "."):
            continue
        if part == "..":
            return None
        parts.append(part)
    if not parts:
        return None
    return "/".join(parts)


# ---------------------------------------------------------------------------
# Patch data structures
# ---------------------------------------------------------------------------


class PatchRisk(str, Enum):
    """
    Risk level of an automatically generated patch.

    LOW
        Small, local, configuration-style change. Eligible for auto-apply
        only under strict outer control (and static-rule origin).
    MEDIUM
        Behaviour / observability affecting change. Must go through review.
    HIGH
        Diagnostic only, or large / structural edit. Auto-apply must be
        disabled; intended for human inspection and patch tooling.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class PatchOrigin(str, Enum):
    """
    Origin of a patch proposal, for supply-chain and security auditing.

    STATIC_RULE
        Deterministic local rule, no opaque external suggestion involved.
    LLM_ASSISTED
        Any use of model-suggested edits (even if also rule-based).
    HUMAN_REVIEW
        Manually edited / merged proposal produced by a reviewer.
    EXTERNAL_TOOL
        Patch derived from a separate static analysis / scanning tool.
    """

    STATIC_RULE = "static_rule"
    LLM_ASSISTED = "llm_assisted"
    HUMAN_REVIEW = "human_review"
    EXTERNAL_TOOL = "external_tool"


@dataclass
class PatchHunk:
    """
    A minimal diff hunk inside a single file.
    """

    file_path: str
    old_start: int
    old_end: int
    new_start: int
    new_end: int
    old_lines: List[str]
    new_lines: List[str]

    def as_unified_diff(self) -> str:
        """
        Render this hunk as a unified diff string, suitable for PRs or logging.
        """
        diff = difflib.unified_diff(
            self.old_lines,
            self.new_lines,
            fromfile=f"a/{self.file_path}",
            tofile=f"b/{self.file_path}",
            fromfiledate="",
            tofiledate="",
            lineterm="",
        )
        return "\n".join(diff)


@dataclass
class PatchProposal:
    """
    A cohesive patch proposal.

    This is the unit consumed by higher-level agents or humans for review
    and application. It is intentionally immutable once created; any change
    should be expressed as a new patch with its own identifier.
    """

    patch_id: str
    title: str
    description: str
    risk: PatchRisk
    origin: PatchOrigin
    created_at: float
    hunks: List[PatchHunk]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "patch_id": self.patch_id,
            "title": self.title,
            "description": self.description,
            "risk": self.risk.value,
            "origin": self.origin.value,
            "created_at": self.created_at,
            "hunks": [
                {
                    "file_path": h.file_path,
                    "old_start": h.old_start,
                    "old_end": h.old_end,
                    "new_start": h.new_start,
                    "new_end": h.new_end,
                    "old_lines": h.old_lines,
                    "new_lines": h.new_lines,
                    "unified_diff": h.as_unified_diff(),
                }
                for h in self.hunks
            ],
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Bug signal – input to the rewrite engine
# ---------------------------------------------------------------------------


@dataclass
class BugSignal:
    """
    Description of a low-risk issue that might be fixable via a small patch.

    kind:
        A short category string such as:
        - "config_key_mismatch"
        - "log_level_too_verbose"
        - "retry_policy_inconsistent"
        - "typo"

    message:
        Human-readable summary suitable for receipts or logs.

    file_path:
        Path to the file relative to the repository root.

    line:
        1-based line number where the issue was detected (best-effort).

    context_lines:
        Number of lines of context around the target line to consider.

    metadata:
        Additional structured details. Typical keys include:
        - "expected_key", "actual_key"
        - "logger_name", "target_level"
        - "from_text", "to_text"
        - "llm_suggestion" – optional suggestion from an external model
        - "policy_ref", "policyset_ref"
        - "subject_hash" – hashed subject / tenant identifier
        - "e_snapshot" – anytime-valid state snapshot driving this signal

        Raw prompts, completions or secrets must not be placed here.
    """

    kind: str
    message: str
    file_path: str
    line: int
    context_lines: int = 8
    metadata: Dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.metadata is None:
            self.metadata = {}


# ---------------------------------------------------------------------------
# Rewrite engine
# ---------------------------------------------------------------------------


class RewriteEngine:
    """
    Semi-automatic rewrite engine for TCD.

    Design principles:
      - Only handles local, low-risk changes in non-sensitive areas.
      - Never writes to disk or runs git operations.
      - Always returns structured PatchProposal objects for review.
      - Produces security metadata (origin, risk, auto-apply flag, patch_ref)
        so that a higher-level security / control plane can make decisions.

    This engine is deliberately content-agnostic at the control level:
    it does not know about policies, receipts, or e-process semantics;
    it just propagates structured metadata that upstream components
    supply in BugSignal.metadata.
    """

    def __init__(self, repo_root: Path | str | None = None) -> None:
        # Compatibility with service_http.create_http_runtime(), which calls
        # RewriteEngine() without arguments. Default to the repository root
        # inferred from this package file: <repo>/tcd/rewrite_engine.py.
        self.repo_root = (
            Path(repo_root).resolve()
            if repo_root is not None
            else Path(__file__).resolve().parents[1]
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def propose_patch(self, signal: BugSignal) -> Optional[PatchProposal]:
        """
        Attempt to generate a patch proposal for the given bug signal.

        Returns:
            PatchProposal on success, or None if no safe patch could be formed.

        Safety notes:
          - Sensitive paths are never patched automatically.
          - Large or heavily modified segments are escalated to HIGH risk.
          - Only STATIC_RULE + LOW risk patches can be marked as
            auto_apply_allowed in their security metadata.
        """
        rel_path, abs_path = self._resolve_repo_file(signal.file_path)
        if rel_path is None or abs_path is None:
            return None

        # Guard: do not propose patches in sensitive core areas.
        if self._is_sensitive_path(rel_path):
            return None

        if not abs_path.is_file():
            return None

        lines = self._safe_read_lines(abs_path)
        if not lines:
            return None

        start_idx, end_idx = self._context_window(signal.line, signal.context_lines, len(lines))
        old_segment = lines[start_idx:end_idx]

        new_segment, base_risk = self._rewrite_segment(
            signal=signal,
            original_lines=old_segment,
        )

        # No rewrite rule fired.
        if new_segment is None or new_segment == old_segment:
            return None

        # Enforce segment size / change limits by escalating risk if needed.
        changed_lines = self._estimate_changed_lines(old_segment, new_segment)
        risk = self._adjust_risk_for_size(base_risk, new_segment, changed_lines)

        # Determine origin and apply origin-based risk gating.
        origin = self._infer_origin(signal)
        risk = self._adjust_risk_for_origin(risk, origin)

        hunk = PatchHunk(
            file_path=rel_path,
            old_start=start_idx + 1,
            old_end=end_idx,
            new_start=start_idx + 1,
            new_end=start_idx + len(new_segment),
            old_lines=old_segment,
            new_lines=new_segment,
        )

        title = self._title_for_signal(signal)
        description = self._description_for_signal(signal, risk, origin)
        safe_signal_metadata = _sanitize_metadata(signal.metadata)

        # Base metadata from the signal and engine.
        metadata: Dict[str, Any] = {
            "signal": {
                "kind": signal.kind,
                "message": signal.message,
                "file_path": rel_path,
                "line": signal.line,
                "context_lines": signal.context_lines,
                "metadata": safe_signal_metadata,
            },
            "engine": {
                "name": "tcd.rewrite_engine",
                "version": "0.2.0",
            },
        }

        # Security / supply-chain block for higher-level control planes.
        security_meta: Dict[str, Any] = {
            "origin": origin.value,
            "risk": risk.value,
            # auto_apply_allowed is conservative and may be further constrained
            # by external policy / control-plane logic.
            "auto_apply_allowed": bool(
                origin == PatchOrigin.STATIC_RULE and risk == PatchRisk.LOW
            ),
            # Pass-through hints used by control planes for auditing and routing.
            "policy_ref": safe_signal_metadata.get("policy_ref"),
            "policyset_ref": safe_signal_metadata.get("policyset_ref"),
            "subject_hash": safe_signal_metadata.get("subject_hash"),
            "e_snapshot": safe_signal_metadata.get("e_snapshot"),
        }
        metadata["security"] = security_meta

        proposal = PatchProposal(
            patch_id=self._new_patch_id(),
            title=title,
            description=description,
            risk=risk,
            origin=origin,
            created_at=time.time(),
            hunks=[hunk],
            metadata=metadata,
        )

        # Attach a stable patch_ref derived from the proposal content.
        self._attach_patch_ref(proposal)

        return proposal

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------


    def _resolve_repo_file(self, file_path: str) -> Tuple[Optional[str], Optional[Path]]:
        rel = _normalize_repo_rel_path(file_path)
        if rel is None:
            return None, None

        abs_path = (self.repo_root / rel).resolve()
        try:
            abs_path.relative_to(self.repo_root)
        except ValueError:
            return None, None

        return rel, abs_path

    def _safe_read_lines(self, path: Path) -> List[str]:
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                return []
            text = path.read_text(encoding="utf-8")
        except Exception:
            return []
        # Keep original newlines to preserve formatting in diffs.
        return text.splitlines(keepends=True)

    @staticmethod
    def _context_window(line: int, context: int, n_lines: int) -> Tuple[int, int]:
        try:
            line_i = int(line)
        except Exception:
            line_i = 1
        try:
            ctx = int(context)
        except Exception:
            ctx = 0
        ctx = max(0, min(ctx, _MAX_SEGMENT_LINES // 2))
        line_idx = max(0, line_i - 1)
        start = max(0, line_idx - ctx)
        end = min(n_lines, line_idx + ctx + 1)
        return start, end

    @staticmethod
    def _is_sensitive_path(file_path: str) -> bool:
        """
        Return True if the given path should never be patched automatically.

        This is a coarse guard rail against accidental modification of
        security-critical primitives or control-plane logic. The caller
        can still surface signals for these files, but the engine will
        abstain from generating edits.
        """
        norm = _normalize_repo_rel_path(file_path)
        if norm is None:
            return True
        for prefix in _SENSITIVE_PATH_PREFIXES:
            pref = prefix.rstrip("/")
            if norm == pref or norm.startswith(pref + "/") or norm.startswith(pref + "."):
                return True
        return False

    @staticmethod
    def _estimate_changed_lines(old: List[str], new: List[str]) -> int:
        """
        Rough estimate of how many lines differ between old/new segments.

        This is intentionally simple and bounded, as segments are small.
        """
        changed = 0
        max_len = max(len(old), len(new))
        for i in range(max_len):
            o = old[i] if i < len(old) else None
            n = new[i] if i < len(new) else None
            if o != n:
                changed += 1
        return changed

    @staticmethod
    def _adjust_risk_for_size(
        base_risk: PatchRisk,
        new_segment: List[str],
        changed_lines: int,
    ) -> PatchRisk:
        """
        Escalate risk if the patch touches too many lines.

        This keeps large / structural edits out of the auto-apply zone
        while still allowing them to be proposed for human review.
        """
        if len(new_segment) > _MAX_SEGMENT_LINES or changed_lines > _MAX_CHANGED_LINES:
            return PatchRisk.HIGH
        return base_risk

    @staticmethod
    def _infer_origin(signal: BugSignal) -> PatchOrigin:
        """
        Infer patch origin from BugSignal.metadata.

        Conventions:
          - if metadata["origin"] is present and valid, use it;
          - else if "llm_suggestion" is present, treat as LLM_ASSISTED;
          - else if "external_tool" or "tool_name" is present, treat as EXTERNAL_TOOL;
          - otherwise assume STATIC_RULE.
        """
        meta = signal.metadata if isinstance(signal.metadata, Mapping) else {}

        explicit = str(meta.get("origin", "")).strip().lower()
        for o in PatchOrigin:
            if o.value == explicit:
                return o

        if "llm_suggestion" in meta:
            return PatchOrigin.LLM_ASSISTED
        if "external_tool" in meta or "tool_name" in meta:
            return PatchOrigin.EXTERNAL_TOOL
        return PatchOrigin.STATIC_RULE

    @staticmethod
    def _adjust_risk_for_origin(risk: PatchRisk, origin: PatchOrigin) -> PatchRisk:
        """
        Enforce origin-based risk floor.

        For example, any LLM_ASSISTED patch is at least MEDIUM risk, even
        if the syntactic edit is small.
        """
        if origin == PatchOrigin.LLM_ASSISTED and risk == PatchRisk.LOW:
            return PatchRisk.MEDIUM
        return risk

    def _attach_patch_ref(self, proposal: PatchProposal) -> None:
        """
        Compute and attach a stable patch_ref under metadata["security"]["patch_ref"].

        The ref is derived from the proposal content (excluding any existing
        patch_ref) and can be used as a supply-chain identifier and as a
        signing target for attestation / receipts.
        """
        if Blake3Hash is None:
            return
        try:
            payload = proposal.to_dict()
            # Remove volatile fields so identical semantic patches get the same ref.
            payload.pop("patch_id", None)
            payload.pop("created_at", None)
            # Remove any pre-existing patch_ref to avoid self-dependence.
            sec = payload.get("metadata", {}).get("security", {})
            if isinstance(sec, dict):
                sec.pop("patch_ref", None)

            data = json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")

            hasher = Blake3Hash()
            ref = hasher.hex(data, ctx="tcd:patch")[:32]

            proposal.metadata.setdefault("security", {})["patch_ref"] = ref
        except Exception:
            # Patch identification must not block patch proposal.
            return

    # ------------------------------------------------------------------
    # Rewrite rules
    # ------------------------------------------------------------------

    def _rewrite_segment(
        self,
        signal: BugSignal,
        original_lines: List[str],
    ) -> Tuple[Optional[List[str]], PatchRisk]:
        """
        Dispatch to a rule based on signal.kind.
        """
        kind = signal.kind.lower().strip()

        if kind == "config_key_mismatch":
            return self._fix_config_key_mismatch(signal, original_lines)

        if kind == "log_level_too_verbose":
            return self._fix_log_level(signal, original_lines)

        if kind == "typo":
            return self._fix_typo(signal, original_lines)

        # Unknown kind: no patch; treat as diagnostic-only.
        return None, PatchRisk.HIGH

    # ------------------------------------------------------------------
    # Specific fix rules
    # ------------------------------------------------------------------

    def _fix_config_key_mismatch(
        self,
        signal: BugSignal,
        original_lines: List[str],
    ) -> Tuple[Optional[List[str]], PatchRisk]:
        expected = _rewrite_token(_metadata_get(signal.metadata, "expected_key"))
        actual = _rewrite_token(_metadata_get(signal.metadata, "actual_key"))

        if not expected or not actual or expected == actual:
            return None, PatchRisk.HIGH

        pattern = re.compile(
            rf"(?<![A-Za-z0-9_.:-]){re.escape(actual)}(?![A-Za-z0-9_.:-])"
        )

        new_lines: List[str] = []
        replaced = False

        for line in original_lines:
            new_line, n = pattern.subn(lambda _m: expected, line)
            if n:
                replaced = True
            new_lines.append(new_line)

        if not replaced:
            return None, PatchRisk.MEDIUM

        # Small config-key rename is usually low risk.
        return new_lines, PatchRisk.LOW

    def _fix_log_level(
        self,
        signal: BugSignal,
        original_lines: List[str],
    ) -> Tuple[Optional[List[str]], PatchRisk]:
        """
        Example: turn logging.debug(...) into logging.info(...) or logging.warning(...).

        Safety rule:
          - only rewrite one explicit source level;
          - default source level is debug;
          - never downgrade severity, for example error -> info.
        """
        target_level = _rewrite_token(_metadata_get(signal.metadata, "target_level", "info")).lower()
        source_level = _rewrite_token(_metadata_get(signal.metadata, "from_level", "debug")).lower()

        severity_order = {"debug": 0, "info": 1, "warning": 2, "error": 3}
        if target_level not in severity_order:
            target_level = "info"
        if source_level not in severity_order:
            source_level = "debug"

        if source_level == target_level:
            return None, PatchRisk.MEDIUM

        # "too_verbose" may only move toward less verbosity / higher severity.
        if severity_order[target_level] < severity_order[source_level]:
            return None, PatchRisk.HIGH

        pattern = re.compile(rf"(?<![A-Za-z0-9_.])logging\.{re.escape(source_level)}\(")
        replacement = f"logging.{target_level}("

        new_lines: List[str] = []
        replaced = False

        for line in original_lines:
            new_line, n = pattern.subn(replacement, line)
            if n:
                replaced = True
            new_lines.append(new_line)

        if not replaced:
            return None, PatchRisk.MEDIUM

        # Changing log level is usually medium risk: it affects observability.
        return new_lines, PatchRisk.MEDIUM

    def _fix_typo(
        self,
        signal: BugSignal,
        original_lines: List[str],
    ) -> Tuple[Optional[List[str]], PatchRisk]:
        """
        Simple string replacement based on metadata["from_text"] -> metadata["to_text"].
        """
        src = _rewrite_token(_metadata_get(signal.metadata, "from_text"))
        dst = _rewrite_token(_metadata_get(signal.metadata, "to_text"))

        if not src or not dst or src == dst:
            return None, PatchRisk.HIGH

        new_lines: List[str] = []
        replaced = False

        for line in original_lines:
            if src in line:
                new_lines.append(line.replace(src, dst))
                replaced = True
            else:
                new_lines.append(line)

        if not replaced:
            return None, PatchRisk.MEDIUM

        # Small typo fixes are low risk by default.
        return new_lines, PatchRisk.LOW

    # ------------------------------------------------------------------
    # Presentation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _title_for_signal(signal: BugSignal) -> str:
        base = signal.kind.replace("_", " ").strip().title()
        return f"Auto-suggested fix: {base}"

    @staticmethod
    def _description_for_signal(
        signal: BugSignal,
        risk: PatchRisk,
        origin: PatchOrigin,
    ) -> str:
        meta_preview = json.dumps(_sanitize_metadata(signal.metadata), ensure_ascii=False, sort_keys=True)
        body = textwrap.dedent(
            f"""
            Automatically generated patch suggestion for bug signal:

              kind: {signal.kind}
              file: {signal.file_path}
              line: {signal.line}
              message: {signal.message}
              risk: {risk.value}
              origin: {origin.value}

            Metadata:
              {meta_preview}
            """
        ).strip()
        return body

    @staticmethod
    def _new_patch_id() -> str:
        return f"patch_{uuid.uuid4().hex}"