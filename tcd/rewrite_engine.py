# tcd/rewrite_engine.py
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


# ---------------------------------------------------------------------------
# Patch data structures
# ---------------------------------------------------------------------------


class PatchRisk(str, Enum):
    """
    Risk level of an automatically generated patch.

    LOW    – can be auto-applied by an agent in a canary or low-traffic env.
    MEDIUM – should go through human review; agent should not auto-apply.
    HIGH   – diagnostic only; auto-apply must be disabled.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


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
    A cohesive patch proposal. It may contain multiple hunks and is the unit
    consumed by higher-level agents or humans for review and application.
    """

    patch_id: str
    title: str
    description: str
    risk: PatchRisk
    created_at: float
    hunks: List[PatchHunk]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "patch_id": self.patch_id,
            "title": self.title,
            "description": self.description,
            "risk": self.risk.value,
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

    It is intentionally conservative:

    * Only handles local, low-risk changes.
    * Never writes to disk or runs git operations.
    * Always returns structured PatchProposal objects for review.
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
        """
        abs_path = (self.repo_root / signal.file_path).resolve()
        if not abs_path.is_file():
            return None

        lines = self._safe_read_lines(abs_path)
        if not lines:
            return None

        start_idx, end_idx = self._context_window(signal.line, signal.context_lines, len(lines))
        old_segment = lines[start_idx:end_idx]

        new_segment, risk = self._rewrite_segment(
            signal=signal,
            original_lines=old_segment,
        )

        if new_segment is None or new_segment == old_segment:
            return None

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
        description = self._description_for_signal(signal, risk)

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
                "version": "0.1.0",
            },
        }

        return PatchProposal(
            patch_id=self._new_patch_id(),
            title=title,
            description=description,
            risk=risk,
            created_at=time.time(),
            hunks=[hunk],
            metadata=metadata,
        )

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

        # Unknown kind: only surface metadata; no patch.
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
        Simple string replacement based on metadata["from_text"] -> ["to_text"].
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

        return new_lines, PatchRisk.LOW

    # ------------------------------------------------------------------
    # Presentation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _title_for_signal(signal: BugSignal) -> str:
        base = signal.kind.replace("_", " ").strip().title()
        return f"Auto-suggested fix: {base}"

    @staticmethod
    def _description_for_signal(signal: BugSignal, risk: PatchRisk) -> str:
        meta_preview = json.dumps(signal.metadata, ensure_ascii=False, sort_keys=True)
        body = textwrap.dedent(
            f"""
            Automatically generated patch suggestion for bug signal:

              kind: {signal.kind}
              file: {signal.file_path}
              line: {signal.line}
              message: {signal.message}
              risk: {risk.value}

            Metadata:
              {meta_preview}
            """
        ).strip()
        return body

    @staticmethod
    def _new_patch_id() -> str:
        return f"patch_{uuid.uuid4().hex}"