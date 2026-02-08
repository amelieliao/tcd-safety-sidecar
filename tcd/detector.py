# FILE: tcd/detector.py
from __future__ import annotations

"""
Low-latency, pluggable safety detector with monotone calibration and conformal fallback.

This module is designed for production routing and receipts. Key guarantees:

L6/L7 hardening guarantees
- Deterministic behavior for a fixed (config_digest, calibrator_state_digest, request)
- End-to-end time budget enforced across: truncate, model.score, calibration, evidence sanitize, hash
- Never throws from Detector.detect(); fail-closed on error/timeout (decision="block")
- Evidence is content-agnostic: never includes raw text; forbidden keys stripped at any depth
- Evidence sanitization is bounded (max nodes/depth/keys/items) and DoS-resistant (scan caps)
- No module-level mutable policy (no cross-instance or cross-thread policy bleed)
- Stable digests:
    - config_hash: static config only
    - policy_digest: static semantics (incl. iso knots hash, evidence policy, forbiddens)
    - state_digest: dynamic calibrator state (conformal window summary), changes as state updates
    - evidence_hash: keyed HMAC when configured; domain-separated by (engine_version, config_hash)
    - decision_id: derived from (engine_version, config_hash, state_digest, evidence_hash, decision, error_code)

Environment knobs (safe-parsed, bounded)
- TCD_DETECTOR_TIME_BUDGET_MS            default: 3.0  clamp [0.5, 50.0]
- TCD_DETECTOR_MAX_TOKENS                default: 2048 clamp [64, 8192]
- TCD_DETECTOR_MAX_BYTES                 default: 100_000 clamp [1024, 2_000_000]

Routing thresholds (risk-space, where risk = 1 - p_value; higher = riskier)
- TCD_DETECTOR_THRESH_LOW                default: 0.20 clamp [0,1]
- TCD_DETECTOR_THRESH_HIGH               default: 0.80 clamp [0,1]
Decision:
    if risk >= thresh_high => block
    elif risk >= thresh_low => throttle
    else => allow

Legacy compatibility:
    decision_legacy uses "cool" instead of "throttle".

Calibration config
- TCD_DETECTOR_CALIB_MODE                default: "isotonic" ("isotonic"|"conformal"|"identity")
- TCD_DETECTOR_CALIB_KNOTS               JSON [[score,p], ...] for isotonic mode (bounded)
- TCD_DETECTOR_CONFORMAL_WINDOW          default: 1024 clamp [32,16384]
- TCD_DETECTOR_CONFORMAL_ALPHA           default: 0.05 clamp [0,1] informational
- TCD_DETECTOR_CONFORMAL_BOOTSTRAP       default: "identity" ("identity"|"mid")

Conformal update guard knobs (poisoning resistance)
- TCD_DETECTOR_CONFORMAL_REF_MAX         default: 0.50 clamp [0,1] (winsorize cap)
- TCD_DETECTOR_CONFORMAL_MIN_P_UPDATE    default: 0.80 clamp [0,1] (minimum p to accept auto-updates)
- TCD_DETECTOR_CONFORMAL_ALLOWED_SOURCES default: "golden_safe,canary" (comma separated)

Evidence / PII / hashing knobs
- TCD_DETECTOR_SANITIZE_EVIDENCE         default: "1"
- TCD_DETECTOR_STRIP_PII                 default: "1"
- TCD_DETECTOR_HASH_PII_TAGS             default: "1"
- TCD_DETECTOR_PII_MODE                  default: "light" ("light"|"strict")
- TCD_DETECTOR_ALLOW_RAW_TENANT          default: "0" (dev-only; production should stay 0)
- TCD_DETECTOR_MAX_EVIDENCE_KEYS         default: 64 clamp [16,256]
- TCD_DETECTOR_MAX_EVIDENCE_STRING       default: 512 clamp [128,2048]

PII hashing keys (optional but recommended)
- TCD_DETECTOR_PII_HMAC_KEY_HEX          optional hex key for HMAC-SHA256
- TCD_DETECTOR_PII_HMAC_KEY_ID           optional key id (e.g., "k2026q1") recorded in receipts

Evidence hashing keys (optional; helps unlinkability across envs/tenants)
- TCD_DETECTOR_EVIDENCE_HMAC_KEY_HEX     optional hex key for HMAC-SHA256
- TCD_DETECTOR_EVIDENCE_HMAC_KEY_ID      optional key id recorded in receipts

Notes
- We map raw scores (higher = riskier) to p-values in [0,1] with a monotone calibrator.
- Small p => "unlikely under safe behavior" => more risky.
- Routing is performed in calibrated risk space: risk = 1 - p_value.
"""