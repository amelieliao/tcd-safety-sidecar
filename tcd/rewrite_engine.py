from __future__ import annotations

import difflib
import json
import textwrap
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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

# Sensitive areas which should not be rewritten automatically.
# Paths are interpreted relative to the repository root.
_SENSITIVE_PATH_PREFIXES: Tuple[str, ...] = (
    "tcd/crypto",
    "tcd/verify",
    "tcd/receipts",
    "tcd/ratelimit",
    "tcd/security_router",
)


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

    def __init__(self, repo_root: Path | str) -> None:
        self.repo_root = Path(repo_root).resolve()

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
        # Guard: do not propose patches in sensitive core areas.
        if self._is_sensitive_path(signal.file_path):
            return None

        abs_path = (self.repo_root / signal.file_path).resolve()
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
            file_path=signal.file_path,
            old_start=start_idx + 1,
            old_end=end_idx,
            new_start=start_idx + 1,
            new_end=start_idx + 1 + len(new_segment),
            old_lines=old_segment,
            new_lines=new_segment,
        )

        title = self._title_for_signal(signal)
        description = self._description_for_signal(signal, risk, origin)

        # Base metadata from the signal and engine.
        metadata: Dict[str, Any] = {
            "signal": {
                "kind": signal.kind,
                "message": signal.message,
                "file_path": signal.file_path,
                "line": signal.line,
                "context_lines": signal.context_lines,
                "metadata": signal.metadata,
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
            "policy_ref": signal.metadata.get("policy_ref"),
            "policyset_ref": signal.metadata.get("policyset_ref"),
            "subject_hash": signal.metadata.get("subject_hash"),
            "e_snapshot": signal.metadata.get("e_snapshot"),
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

    def _safe_read_lines(self, path: Path) -> List[str]:
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            return []
        # Keep original newlines to preserve formatting in diffs.
        return text.splitlines(keepends=True)

    @staticmethod
    def _context_window(line: int, context: int, n_lines: int) -> Tuple[int, int]:
        line_idx = max(0, line - 1)
        start = max(0, line_idx - context)
        end = min(n_lines, line_idx + context + 1)
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
        norm = Path(file_path).as_posix()
        return any(norm.startswith(prefix) for prefix in _SENSITIVE_PATH_PREFIXES)

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
        meta = signal.metadata or {}

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
        expected = str(signal.metadata.get("expected_key", "")).strip()
        actual = str(signal.metadata.get("actual_key", "")).strip()

        if not expected or not actual or expected == actual:
            return None, PatchRisk.HIGH

        new_lines: List[str] = []
        replaced = False

        for line in original_lines:
            if actual in line:
                new_lines.append(line.replace(actual, expected))
                replaced = True
            else:
                new_lines.append(line)

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
        """
        target_level = str(signal.metadata.get("target_level", "info")).lower()
        if target_level not in {"debug", "info", "warning", "error"}:
            target_level = "info"

        old_levels = ["debug", "info", "warning", "error"]
        new_lines: List[str] = []
        replaced = False

        for line in original_lines:
            new_line = line
            for lvl in old_levels:
                needle = f"logging.{lvl}("
                if needle in new_line and lvl != target_level:
                    new_line = new_line.replace(needle, f"logging.{target_level}(")
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
        src = str(signal.metadata.get("from_text", "")).strip()
        dst = str(signal.metadata.get("to_text", "")).strip()

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
        meta_preview = json.dumps(signal.metadata, ensure_ascii=False, sort_keys=True)
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