# FILE: tcd/multivariate.py
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Union


# -----------------------------
# Config
# -----------------------------


@dataclass
class MultiVarConfig:
    """
    Configuration for the multivariate security / risk detector.

    This object is designed to be:
      - JSON-serializable
      - hashable via a canonical fingerprint
      - stable across versions (new fields must have safe defaults)

    It can be attached to receipts by hashing `to_dict()` with a stable
    digest function and recording that fingerprint alongside decisions.
    """

    # Base switches
    enabled: bool = False
    # Sliding window length (number of recent observations) for any
    # historical statistics the detector may maintain.
    window: int = 10
    # High-level profile hint, used to tweak defaults and thresholds.
    # Typical values: "DEV", "PROD", "HIGH_SEC".
    profile: str = "DEV"

    # Global risk thresholds (0.0 ~ 1.0).
    threshold_global: float = 0.8
    threshold_apt: float = 0.7
    threshold_insider: float = 0.7
    threshold_supply_chain: float = 0.7
    # If a PQ / crypto check fails hard, this represents the risk level
    # used when projecting that failure into the overall score.
    threshold_pq_fail: float = 1.0

    # Dimension weights for combining individual feature contributions.
    # Keys are feature names from MultiVarInput.to_features().
    weights: Dict[str, float] = field(
        default_factory=lambda: {
            "tokens_delta": 0.05,
            "rate_limit_fill": 0.10,
            "rate_limit_recent": 0.10,
            "gpu_hot_low_throughput": 0.15,
            "gpu_util_norm": 0.05,
            "gpu_mem_ratio": 0.05,
            "gpu_temp_norm": 0.05,
            "crypto_fallback": 0.15,
            "model_hash_mismatch": 0.20,
            "binary_hash_mismatch": 0.20,
            "recent_denials_ratio": 0.10,
            "ip_diversity": 0.10,
        }
    )

    # PQ / crypto-related expectations.
    require_pq_in_high_profile: bool = False
    # When non-empty and profile is considered high-security, the
    # signature algorithm is expected to be one of these values.
    allowed_sign_algos_high: List[str] = field(default_factory=list)
    # If true, non-PQ or fallback algorithms in productive deployments
    # are recorded as warnings in the risk output.
    flag_non_pq_in_prod: bool = True

    # Supply-chain / model integrity expectations.
    enforce_model_hash_allowlist: bool = False
    enforce_binary_hash_allowlist: bool = False
    block_on_model_mismatch: bool = False
    allowed_model_hashes: List[str] = field(default_factory=list)
    allowed_tokenizer_hashes: List[str] = field(default_factory=list)
    allowed_binary_hashes: List[str] = field(default_factory=list)

    # Wealth / e-process style state.
    wealth_init: float = 0.0
    wealth_upper_bound: float = 10.0
    wealth_lower_bound: float = -10.0
    # How much to increase/decrease wealth per request by default.
    wealth_step_positive: float = 0.1
    wealth_step_negative: float = 0.05

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to a plain dict for hashing / persistence.

        Field order is canonicalized at serialization time; callers should
        not rely on dict order here.
        """
        return {
            "enabled": self.enabled,
            "window": self.window,
            "profile": self.profile,
            "threshold_global": self.threshold_global,
            "threshold_apt": self.threshold_apt,
            "threshold_insider": self.threshold_insider,
            "threshold_supply_chain": self.threshold_supply_chain,
            "threshold_pq_fail": self.threshold_pq_fail,
            "weights": dict(self.weights),
            "require_pq_in_high_profile": self.require_pq_in_high_profile,
            "allowed_sign_algos_high": list(self.allowed_sign_algos_high),
            "flag_non_pq_in_prod": self.flag_non_pq_in_prod,
            "enforce_model_hash_allowlist": self.enforce_model_hash_allowlist,
            "enforce_binary_hash_allowlist": self.enforce_binary_hash_allowlist,
            "block_on_model_mismatch": self.block_on_model_mismatch,
            "allowed_model_hashes": list(self.allowed_model_hashes),
            "allowed_tokenizer_hashes": list(self.allowed_tokenizer_hashes),
            "allowed_binary_hashes": list(self.allowed_binary_hashes),
            "wealth_init": self.wealth_init,
            "wealth_upper_bound": self.wealth_upper_bound,
            "wealth_lower_bound": self.wealth_lower_bound,
            "wealth_step_positive": self.wealth_step_positive,
            "wealth_step_negative": self.wealth_step_negative,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "MultiVarConfig":
        """
        Reconstruct a configuration from a dict, applying defaults for
        any fields that are not present.
        """
        base = cls()
        for k, v in data.items():
            if hasattr(base, k):
                setattr(base, k, v)
        return base

    def fingerprint(self) -> str:
        """
        Compute a stable fingerprint of this configuration.

        The fingerprint can be embedded into receipts and logs so that
        decisions can be tied back to the exact configuration in effect.
        """
        payload = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            from blake3 import blake3  # type: ignore

            return blake3(payload).hexdigest()
        except Exception:
            # Conservative fallback if blake3 is not available.
            import hashlib

            return hashlib.sha256(payload).hexdigest()


# -----------------------------
# Input container
# -----------------------------


@dataclass
class MultiVarInput:
    """
    Structured input for the multivariate detector.

    All fields are optional; the detector is expected to behave gracefully
    when information is missing. Non-numeric fields are translated into
    numeric indicators when building the feature vector.
    """

    timestamp: float = field(default_factory=time.time)
    request_id: Optional[str] = None

    # HTTP / routing
    http_method: Optional[str] = None
    path: Optional[str] = None
    norm_path: Optional[str] = None
    client_ip: Optional[str] = None
    tenant: Optional[str] = None
    user: Optional[str] = None
    session: Optional[str] = None

    # Rate limiting / tokens
    tokens_delta: Optional[float] = None
    rate_limit_remaining_before: Optional[float] = None
    rate_limit_capacity: Optional[float] = None
    rate_limit_recently_limited: bool = False

    # Origin / edge context
    origin: Optional[str] = None
    origin_ok: Optional[bool] = None
    threat_level: Optional[int] = None

    # GPU / runtime health samples
    gpu_util: Optional[float] = None
    gpu_mem_used_mib: Optional[float] = None
    gpu_mem_total_mib: Optional[float] = None
    gpu_temp_c: Optional[float] = None
    gpu_power_w: Optional[float] = None
    gpu_health_level: Optional[str] = None

    # Crypto / PQ context
    crypto_profile: Optional[str] = None
    hash_algo: Optional[str] = None
    mac_algo: Optional[str] = None
    sign_algo: Optional[str] = None
    key_id: Optional[str] = None
    key_status: Optional[str] = None
    crypto_fallback_used: bool = False

    # Model / binary integrity
    model_hash: Optional[str] = None
    tokenizer_hash: Optional[str] = None
    binary_hash: Optional[str] = None

    # Inference runtime characteristics
    sampler_cfg: Optional[Dict[str, Any]] = None
    latency_ms: Optional[float] = None
    throughput_tok_s: Optional[float] = None
    context_len: Optional[int] = None
    rng_seed: Optional[int] = None

    # Historical / aggregated behaviour, passed in by caller.
    # For example:
    #   - recent_denials_ratio
    #   - recent_ip_count_for_user
    #   - recent_rate_limited_count
    #   - recent_paths_accessed
    historical: Dict[str, Any] = field(default_factory=dict)

    # For forward compatibility: arbitrary extra data that should be
    # preserved into feature snapshots but is not directly interpreted
    # by the detector.
    extra: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "MultiVarInput":
        """
        Best-effort construction from a generic mapping, ignoring unknown keys.
        """
        init_kwargs: Dict[str, Any] = {}
        field_names = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        for k, v in data.items():
            if k in field_names:
                init_kwargs[k] = v
        return cls(**init_kwargs)

    @classmethod
    def from_legacy(cls, data: Any) -> "MultiVarInput":
        """
        Legacy compatibility constructor.

        If `data` is already a MultiVarInput instance, it is returned as-is.
        If it is a mapping, this behaves like from_mapping().
        Otherwise, a mostly-empty instance is returned.
        """
        if isinstance(data, MultiVarInput):
            return data
        if isinstance(data, Mapping):
            return cls.from_mapping(data)
        # Fallback: nothing to extract.
        return cls()

    def to_features(self) -> Dict[str, float]:
        """
        Build a numeric feature vector from the available fields.

        All feature values are in [0, +inf) unless explicitly clamped into
        [0, 1]. Callers can further normalize or project this vector if
        needed.
        """
        features: Dict[str, float] = {}

        # Tokens / rate limiting
        if self.tokens_delta is not None:
            try:
                features["tokens_delta"] = max(0.0, float(self.tokens_delta))
            except Exception:
                features["tokens_delta"] = 0.0

        if (
            self.rate_limit_remaining_before is not None
            and self.rate_limit_capacity is not None
            and self.rate_limit_capacity > 0
        ):
            try:
                fill = 1.0 - float(self.rate_limit_remaining_before) / float(self.rate_limit_capacity)
                features["rate_limit_fill"] = max(0.0, min(1.0, fill))
            except Exception:
                features["rate_limit_fill"] = 0.0

        if self.rate_limit_recently_limited:
            features["rate_limit_recent"] = 1.0

        # Threat level, normalized.
        if self.threat_level is not None:
            try:
                # Map example range 0..5 → 0..1, clamp.
                features["threat_level_norm"] = max(0.0, min(1.0, float(self.threat_level) / 5.0))
            except Exception:
                features["threat_level_norm"] = 0.0

        # GPU metrics
        if self.gpu_util is not None:
            try:
                features["gpu_util_norm"] = max(0.0, min(1.0, float(self.gpu_util) / 100.0))
            except Exception:
                features["gpu_util_norm"] = 0.0

        if self.gpu_mem_used_mib is not None and self.gpu_mem_total_mib:
            try:
                ratio = float(self.gpu_mem_used_mib) / float(self.gpu_mem_total_mib)
                features["gpu_mem_ratio"] = max(0.0, min(1.0, ratio))
            except Exception:
                features["gpu_mem_ratio"] = 0.0

        if self.gpu_temp_c is not None:
            try:
                # Rough normalization assuming interesting range up to ~100C.
                features["gpu_temp_norm"] = max(0.0, min(1.0, float(self.gpu_temp_c) / 100.0))
            except Exception:
                features["gpu_temp_norm"] = 0.0

        # Crypto / PQ indicators
        if self.crypto_fallback_used:
            features["crypto_fallback"] = 1.0

        # Latency / throughput
        if self.latency_ms is not None:
            try:
                # Normalize with a soft ceiling, e.g. 2000 ms ~ 1.0.
                norm = float(self.latency_ms) / 2000.0
                features["latency_norm"] = max(0.0, min(1.0, norm))
            except Exception:
                features["latency_norm"] = 0.0

        if self.throughput_tok_s is not None and self.throughput_tok_s >= 0:
            try:
                # Very rough: low throughput under active load can be suspicious.
                # Here we simply record it; interpretation is in rules/weights.
                features["throughput_tok_s"] = float(self.throughput_tok_s)
            except Exception:
                features["throughput_tok_s"] = 0.0

        # Historical / behavioural features
        hist = self.historical
        if isinstance(hist, Mapping):
            if "recent_denials_ratio" in hist:
                try:
                    v = float(hist["recent_denials_ratio"])
                    features["recent_denials_ratio"] = max(0.0, min(1.0, v))
                except Exception:
                    features["recent_denials_ratio"] = 0.0

            if "recent_rate_limited_count" in hist:
                try:
                    v = float(hist["recent_rate_limited_count"])
                    features["recent_rate_limited_count"] = max(0.0, v)
                except Exception:
                    features["recent_rate_limited_count"] = 0.0

            if "recent_ip_count_for_user" in hist:
                try:
                    v = float(hist["recent_ip_count_for_user"])
                    # Map 0..10+ → 0..1 with a soft ceiling at 10.
                    features["ip_diversity"] = max(0.0, min(1.0, v / 10.0))
                except Exception:
                    features["ip_diversity"] = 0.0

        # A crude composite indicator: GPU hot with low throughput.
        try:
            util = float(self.gpu_util) if self.gpu_util is not None else 0.0
            temp_norm = features.get("gpu_temp_norm", 0.0)
            thr = float(self.throughput_tok_s) if self.throughput_tok_s is not None else 0.0
            if util > 0.5 and temp_norm > 0.7 and thr < 1.0:
                features["gpu_hot_low_throughput"] = 1.0
        except Exception:
            pass

        return features


# -----------------------------
# Detector
# -----------------------------


class MultiVarDetector:
    """
    Multivariate security / risk detector.

    Responsibilities:
      - Combine multiple signals (HTTP, edge, runtime, crypto, history)
        into a single structured risk verdict.
      - Maintain a small wealth-like state to capture long-term patterns.
      - Remain local, deterministic and auditable: rules and weights are
        data-driven and can be recorded as part of receipts.

    The detector does *not* perform cryptography or network operations.
    """

    def __init__(self, config: Optional[MultiVarConfig] = None):
        self.config = config or MultiVarConfig()
        self._wealth = float(self.config.wealth_init)
        self._wealth_lock = threading.Lock()

    # ---- internal helpers ----

    def _update_wealth(self, risk_score: float, rules_triggered: List[str]) -> Dict[str, float]:
        """
        Update internal wealth state given the current risk and rule set.

        Returns a dict with wealth_before, wealth_after, and thresholds.
        """
        with self._wealth_lock:
            before = self._wealth
            delta = 0.0

            # If risk is above 0.5, treat as a positive contribution to wealth;
            # otherwise slowly decrease towards baseline.
            if risk_score > 0.5:
                delta += self.config.wealth_step_positive * (risk_score - 0.5) * 2.0
            else:
                delta -= self.config.wealth_step_negative * (0.5 - risk_score) * 2.0

            # Each high-impact rule can nudge wealth further.
            if any(
                name
                in {
                    "model_hash_not_allowed",
                    "binary_hash_not_allowed",
                    "sign_algo_not_in_high_profile",
                    "crypto_policy_violation",
                }
                for name in rules_triggered
            ):
                delta += 0.2

            self._wealth += delta
            # Clamp to configured bounds.
            self._wealth = max(self.config.wealth_lower_bound, min(self.config.wealth_upper_bound, self._wealth))
            after = self._wealth

        return {
            "wealth_before": before,
            "wealth_after": after,
            "wealth_upper": self.config.wealth_upper_bound,
            "wealth_lower": self.config.wealth_lower_bound,
        }

    def _rule_eval(
        self,
        cfg: MultiVarConfig,
        inp: MultiVarInput,
        features: Mapping[str, float],
    ) -> Dict[str, Any]:
        """
        Evaluate rule-based components: supply-chain, crypto, and behavioural signals.
        """
        profile = (inp.crypto_profile or cfg.profile or "DEV").upper()
        rules_triggered: List[str] = []
        apt_score = 0.0
        insider_score = 0.0
        supply_chain_score = 0.0
        pq_risk_level = "ok"

        # Supply-chain: model integrity.
        if cfg.enforce_model_hash_allowlist and inp.model_hash:
            if inp.model_hash not in cfg.allowed_model_hashes:
                supply_chain_score = max(supply_chain_score, 1.0)
                rules_triggered.append("model_hash_not_allowed")
                # Tag feature to weight into global risk.
                if "model_hash_mismatch" not in features:
                    # type: ignore[assignment]
                    features = dict(features)
                    features["model_hash_mismatch"] = 1.0

        if cfg.enforce_model_hash_allowlist and inp.tokenizer_hash:
            if inp.tokenizer_hash not in cfg.allowed_tokenizer_hashes:
                supply_chain_score = max(supply_chain_score, 0.8)
                rules_triggered.append("tokenizer_hash_not_allowed")

        if cfg.enforce_binary_hash_allowlist and inp.binary_hash:
            if inp.binary_hash not in cfg.allowed_binary_hashes:
                supply_chain_score = max(supply_chain_score, 1.0)
                rules_triggered.append("binary_hash_not_allowed")
                if "binary_hash_mismatch" not in features:
                    # type: ignore[assignment]
                    features = dict(features)
                    features["binary_hash_mismatch"] = 1.0

        # Crypto / PQ rules.
        high_profile = profile == "HIGH_SEC"
        allowed_high = set(cfg.allowed_sign_algos_high or [])

        if cfg.require_pq_in_high_profile and high_profile and allowed_high:
            if not inp.sign_algo:
                pq_risk_level = "fail"
                rules_triggered.append("sign_algo_missing_in_high_profile")
            elif inp.sign_algo not in allowed_high:
                pq_risk_level = "fail"
                rules_triggered.append("sign_algo_not_in_high_profile")

        # Fallback or non-preferred algorithms.
        if inp.crypto_fallback_used:
            rules_triggered.append("crypto_fallback_used")
            apt_score = max(apt_score, 0.6)

        # Optionally flag non-PQ or legacy algorithms in productive profiles.
        if cfg.flag_non_pq_in_prod and profile in {"PROD", "HIGH_SEC"}:
            # We do not attempt to classify algorithms here; callers should
            # provide higher-level labels in sign_algo if needed.
            if inp.sign_algo and "pq" not in inp.sign_algo.lower():
                # This is a soft warning unless profile and config require stricter handling.
                pq_risk_level = "warn" if pq_risk_level != "fail" else pq_risk_level
                rules_triggered.append("crypto_policy_warning")

        # Behavioural / historical signals for APT / insider-like patterns.
        hist = inp.historical or {}
        try:
            rl_count = float(hist.get("recent_rate_limited_count", 0.0))
            denials_ratio = float(hist.get("recent_denials_ratio", 0.0))
            ip_count = float(hist.get("recent_ip_count_for_user", 0.0))
        except Exception:
            rl_count = denials_ratio = ip_count = 0.0

        if rl_count > 0:
            apt_score = max(apt_score, min(1.0, 0.1 * rl_count))
            rules_triggered.append("rate_limit_pattern")

        if denials_ratio > 0.3:
            apt_score = max(apt_score, min(1.0, denials_ratio))
            rules_triggered.append("denial_pattern")

        if ip_count > 3:
            insider_score = max(insider_score, min(1.0, (ip_count - 3.0) / 5.0))
            rules_triggered.append("ip_diversity_pattern")

        # Edge threat level from outer middleware.
        if inp.threat_level is not None and inp.threat_level > 0:
            # Higher threat levels can elevate APT risk.
            apt_score = max(apt_score, min(1.0, float(inp.threat_level) / 5.0))

        return {
            "apt_score": float(max(0.0, min(1.0, apt_score))),
            "insider_score": float(max(0.0, min(1.0, insider_score))),
            "supply_chain_score": float(max(0.0, min(1.0, supply_chain_score))),
            "pq_risk_level": pq_risk_level,
            "rules_triggered": rules_triggered,
            "features": dict(features),
        }

    def _combine_scores(
        self,
        cfg: MultiVarConfig,
        base_features: Mapping[str, float],
        rule_out: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Combine feature-based and rule-based scores into a single risk value.
        """
        features = rule_out["features"]
        apt_score = float(rule_out["apt_score"])
        insider_score = float(rule_out["insider_score"])
        supply_chain_score = float(rule_out["supply_chain_score"])
        pq_risk_level = str(rule_out["pq_risk_level"])
        rules_triggered: List[str] = list(rule_out["rules_triggered"])

        # Linear combination of features with configured weights.
        linear_score = 0.0
        for name, w in cfg.weights.items():
            try:
                v = float(features.get(name, 0.0))
            except Exception:
                v = 0.0
            linear_score += w * v

        # Normalize linear_score into [0, 1] with a soft bounding.
        # This is a simple rescaling; callers may choose to tune it further.
        linear_score = max(0.0, min(1.0, linear_score))

        # Combine with rule-based scores. Supply-chain / PQ failures are
        # treated as high impact.
        combined = linear_score
        combined = max(combined, apt_score)
        combined = max(combined, insider_score)
        combined = max(combined, supply_chain_score)

        if pq_risk_level == "fail":
            combined = max(combined, cfg.threshold_pq_fail)
        elif pq_risk_level == "warn":
            combined = min(1.0, combined + 0.1)

        risk_score = max(0.0, min(1.0, combined))

        # Determine action.
        action = "allow"
        verdict_bool = True

        if pq_risk_level == "fail":
            action = "block"
            verdict_bool = False
        elif cfg.block_on_model_mismatch and supply_chain_score >= cfg.threshold_supply_chain:
            action = "block"
            verdict_bool = False
        elif risk_score >= cfg.threshold_global:
            action = "block"
            verdict_bool = False
        elif risk_score >= 0.5:
            # Elevated but not above global threshold.
            action = "degrade"
        elif rules_triggered:
            # Non-empty rule set with low aggregate risk can be treated as an alert.
            action = "alert"

        return {
            "verdict": verdict_bool,
            "action": action,
            "risk_score": risk_score,
            "apt_score": apt_score,
            "insider_score": insider_score,
            "supply_chain_score": supply_chain_score,
            "pq_risk_level": pq_risk_level,
            "rules_triggered": rules_triggered,
            "features": features,
        }

    # ---- public API ----

    def detect(self, data: Any) -> Dict[str, Any]:
        """
        Main entry point.

        Arguments
        ---------
        data:
            - MultiVarInput instance; or
            - mapping/dict compatible with MultiVarInput.from_mapping; or
            - any object (legacy), in which case only a minimal default
              result is produced.

        Returns
        -------
        A stable dict with at least:
          - verdict: bool        # True means "allowed"
          - action: str          # "allow" | "degrade" | "block" | "alert"
          - score: float         # alias of risk_score
          - risk_score: float
          - rules_triggered: list[str]
          - config_fingerprint: str
          - wealth_before / wealth_after / wealth_thresholds: numbers
          - profile: str
          - timestamp: float
          - request_id: Optional[str]

        Additional keys (feature_snapshot, etc.) may be present and are
        safe to forward into receipts.
        """
        cfg = self.config

        # If disabled, return a minimal "allow" verdict, preserving the
        # original shape of {"verdict": False/True, "score": 0.0} as much
        # as possible while adding a richer structure.
        if not cfg.enabled:
            # Legacy-compatible default: verdict=True, score=0.0.
            base: Dict[str, Any] = {
                "verdict": True,
                "action": "allow",
                "score": 0.0,
                "risk_score": 0.0,
                "apt_score": 0.0,
                "insider_score": 0.0,
                "supply_chain_score": 0.0,
                "pq_risk_level": "ok",
                "rules_triggered": [],
                "feature_snapshot": {},
                "config_fingerprint": cfg.fingerprint(),
                "profile": cfg.profile,
                "timestamp": time.time(),
                "request_id": None,
                "wealth_before": self._wealth,
                "wealth_after": self._wealth,
                "wealth_thresholds": {
                    "upper": cfg.wealth_upper_bound,
                    "lower": cfg.wealth_lower_bound,
                },
            }
            return base

        inp = MultiVarInput.from_legacy(data)
        features = inp.to_features()
        rule_out = self._rule_eval(cfg, inp, features)
        combined = self._combine_scores(cfg, features, rule_out)

        wealth_info = self._update_wealth(combined["risk_score"], combined["rules_triggered"])
        cfg_fp = cfg.fingerprint()

        result: Dict[str, Any] = {
            "verdict": combined["verdict"],
            "action": combined["action"],
            # Keep "score" for legacy call sites: it is the same as risk_score.
            "score": combined["risk_score"],
            "risk_score": combined["risk_score"],
            "apt_score": combined["apt_score"],
            "insider_score": combined["insider_score"],
            "supply_chain_score": combined["supply_chain_score"],
            "pq_risk_level": combined["pq_risk_level"],
            "rules_triggered": combined["rules_triggered"],
            # Snapshot is intentionally JSON-safe and may be truncated at
            # higher layers if needed.
            "feature_snapshot": {
                "tenant": inp.tenant,
                "user": inp.user,
                "session": inp.session,
                "client_ip": None,  # do not expose raw IP here by default
                "path": inp.path,
                "norm_path": inp.norm_path,
                "crypto_profile": inp.crypto_profile or cfg.profile,
                "sign_algo": inp.sign_algo,
                "model_hash": inp.model_hash,
                "tokenizer_hash": inp.tokenizer_hash,
                "binary_hash": inp.binary_hash,
                "gpu_health_level": inp.gpu_health_level,
                "historical": dict(inp.historical),
                "extra": dict(inp.extra),
            },
            "features": combined["features"],
            "config_fingerprint": cfg_fp,
            "profile": cfg.profile,
            "timestamp": inp.timestamp,
            "request_id": inp.request_id,
            "wealth_before": wealth_info["wealth_before"],
            "wealth_after": wealth_info["wealth_after"],
            "wealth_thresholds": {
                "upper": wealth_info["wealth_upper"],
                "lower": wealth_info["wealth_lower"],
            },
        }
        return result