# FILE: tcd/ratelimit.py
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

try:
    # Optional: integrate with the OTEL-like exporter if available.
    from .otel_exporter TCDOtelExporter
except Exception:  # pragma: no cover
    TCDOtelExporter = None  # type: ignore[misc]

try:
    # Optional: structured hash for key anonymization in audit events.
    from .crypto import Blake3Hash
except Exception:  # pragma: no cover
    Blake3Hash = None  # type: ignore[misc]


__all__ = [
    "RateLimitZoneConfig",
    "RateLimitConfig",
    "RateDecision",
    "RateLimiter",
]


# ---------------------------------------------------------------------------
# Config and state
# ---------------------------------------------------------------------------


@dataclass
class RateLimitZoneConfig:
    """
    Per-zone configuration for token-bucket style limiting.

    A "zone" is a logical grouping such as:
      - "internet": traffic from public networks;
      - "partner": traffic from partner APIs;
      - "internal": traffic from internal networks or VPN;
      - "high_security": traffic bound to high-risk / sensitive policies;
      - "admin": control-plane / admin endpoints.

    capacity:
        Maximum number of tokens in the bucket for this zone. A larger
        capacity allows for more bursty traffic.

    refill_per_s:
        Number of tokens added per second while the bucket is not full.
        This effectively controls sustained rate.

    temp_block_after_denies:
        If > 0, once a key accumulates this many consecutive denials in the
        given zone, it will be temporarily blocked for `temp_block_ttl`
        seconds. This is a coarse defence against sustained abuse.

    temp_block_ttl:
        Duration (seconds) of a temporary block once triggered.

    max_entries:
        Soft cap on the number of active keys tracked in this zone.
        When exceeded, older entries may be evicted lazily. This prevents
        unbounded memory growth when many keys appear.
    """

    capacity: float = 10.0
    refill_per_s: float = 10.0
    temp_block_after_denies: int = 0
    temp_block_ttl: float = 0.0
    max_entries: int = 65_536


@dataclass
class RateLimitConfig:
    """
    Top-level configuration for the rate limiter.

    This layer is HTTP-agnostic and can be used by:
      - request middleware (IP / tenant / user / route based limiting);
      - background workers;
      - control-plane operations.

    It is designed to cooperate with:
      - PolicyStore / BoundPolicy (to choose zones and costs);
      - trust / subject models (to build keys);
      - telemetry and audit exporters.

    zones:
        Mapping from zone name (str) to RateLimitZoneConfig. A zone name
        should align with upstream semantics such as trust_zone, route_profile,
        or policy risk class.

    default_zone:
        Zone to use when no explicit zone is passed to `consume_decision`.

    enable_audit:
        If true, denies and temporary blocks will be reported to the
        audit_hook when present.

    enable_metrics:
        If true, metric events will be emitted via exporter or metrics_hook.

    exporter:
        Optional TCDOtelExporter instance for metrics events. If not present,
        you may still use metrics_hook.

    metrics_hook:
        Optional callable accepting (name: str, value: float, labels: Dict[str, Any]).
        This allows integration with other metric systems or adding richer
        labels (tenant hash, risk label, regulation, etc.) externally.

    audit_hook:
        Optional callable accepting (event: Dict[str, Any]) for structured
        audit logging when interesting events occur (e.g. denies, temp blocks).
        The event never contains raw keys; only hashed identifiers.

    global_max_entries:
        Soft cap on total number of keys across all zones. Once exceeded,
        older keys may be evicted lazily when new keys appear.

    monotonic_fn:
        Optional function returning a monotonically increasing float, used
        for time accounting. Defaults to time.monotonic. This is mainly for
        testing or specialized environments that need a custom time source.
    """

    zones: Dict[str, RateLimitZoneConfig] = field(default_factory=dict)
    default_zone: str = "default"

    enable_audit: bool = True
    enable_metrics: bool = True

    exporter: Optional["TCDOtelExporter"] = None
    metrics_hook: Optional[Callable[[str, float, Dict[str, Any]], None]] = None
    audit_hook: Optional[Callable[[Dict[str, Any]], None]] = None

    global_max_entries: int = 200_000
    monotonic_fn: Optional[Callable[[], float]] = None

    def get_zone(self, zone: Optional[str]) -> Tuple[str, RateLimitZoneConfig]:
        """
        Resolve the zone name and its config, falling back to default if needed.

        If the requested zone is unknown, a default zone is lazily created
        using a basic configuration. Callers are encouraged to pre-populate
        `zones` with domain-specific semantics that align with policies.
        """
        name = zone or self.default_zone
        if name not in self.zones:
            # Lazy default; callers can pre-populate zones with richer config.
            self.zones[name] = RateLimitZoneConfig()
        return name, self.zones[name]


@dataclass
class RateDecision:
    """
    Result of a rate-limit check.

    allowed:
        Whether the operation should be allowed (tokens were available and
        no temporary block is active).

    zone:
        The logical zone this key was evaluated in.

    remaining_tokens:
        Number of tokens remaining after this decision (clamped to >= 0).
        This is for internal SRE / control-plane use and is not intended to
        be exposed directly to external clients.

    blocked_until:
        If not None, this key is temporarily blocked until this monotonic
        time. A non-None value implies a temporary block is active.

    reason:
        Short reason label:
          - "ok": tokens were available;
          - "exhausted": no tokens left and no temp block yet;
          - "temp_block": temporary block is active.
    """

    allowed: bool
    zone: str
    remaining_tokens: float
    blocked_until: Optional[float]
    reason: str


@dataclass
class _BucketState:
    """
    Internal per-key token-bucket state.
    """

    tokens: float
    ts: float  # last update monotonic time
    denies: int = 0
    temp_block_until: float = 0.0


# ---------------------------------------------------------------------------
# RateLimiter core
# ---------------------------------------------------------------------------


class RateLimiter:
    """
    Token-bucket based rate limiter with zone-aware configuration,
    temporary blocking and audit / metrics hooks.

    This primitive is independent of HTTP; it can be used by middleware,
    background workers or control-plane code. The typical usage pattern:

        cfg = RateLimitConfig(
            zones={
                "internet": RateLimitZoneConfig(capacity=20, refill_per_s=10),
                "internal": RateLimitZoneConfig(capacity=200, refill_per_s=100),
                "user_model": RateLimitZoneConfig(capacity=50, refill_per_s=25),
            },
            default_zone="internet",
            exporter=otel_exporter,
            audit_hook=audit_fn,
        )
        limiter = RateLimiter(config=cfg)

        # Example of layered limiting in upstream middleware:
        # 1) by IP / network
        d_ip = limiter.consume_decision(key=client_ip, zone="internet")
        # 2) by tenant
        d_tenant = limiter.consume_decision(key=(tenant_id,), zone="tenant")
        # 3) by (tenant, user, model)
        d_user = limiter.consume_decision(
            key=(tenant_id, user_id, model_id),
            zone="user_model",
            cost=cost_from_tokens,
        )

        allowed = d_ip.allowed and d_tenant.allowed and d_user.allowed

    The basic `consume` method is a compatibility wrapper that returns
    only a boolean decision.
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self._config = config or RateLimitConfig()
        self._buckets: Dict[Tuple[str, Any], _BucketState] = {}
        self._lock = threading.Lock()
        self._mono: Callable[[], float] = (
            self._config.monotonic_fn or time.monotonic
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def consume(self, key: Any, cost: float = 1.0, zone: Optional[str] = None) -> bool:
        """
        Consume tokens for a key in a given zone and return a simple boolean
        decision.

        This is a thin wrapper around `consume_decision` for legacy-style
        usage where only allow/deny is needed.
        """
        decision = self.consume_decision(key=key, cost=cost, zone=zone)
        return decision.allowed

    def consume_decision(
        self,
        key: Any,
        cost: float = 1.0,
        zone: Optional[str] = None,
        *,
        now: Optional[float] = None,
    ) -> RateDecision:
        """
        Consume `cost` tokens for `key` in the given `zone` and return a
        full RateDecision.

        The `now` parameter is for deterministic tests or external time
        sources; if omitted, the configured monotonic function is used.
        """
        mono_now = self._mono() if now is None else float(now)
        zone_name, zone_cfg = self._config.get_zone(zone)

        with self._lock:
            bucket_key = (zone_name, key)
            state = self._buckets.get(bucket_key)

            # Initialize state if this is a new key.
            if state is None:
                state = _BucketState(tokens=zone_cfg.capacity, ts=mono_now)
                self._buckets[bucket_key] = state

            # Handle temporary block first.
            if state.temp_block_until > mono_now:
                decision = RateDecision(
                    allowed=False,
                    zone=zone_name,
                    remaining_tokens=max(0.0, state.tokens),
                    blocked_until=state.temp_block_until,
                    reason="temp_block",
                )
                self._emit_after_decision(bucket_key, state, zone_cfg, decision)
                return decision

            # Normal token-bucket refill.
            elapsed = max(0.0, mono_now - state.ts)
            state.tokens = min(
                zone_cfg.capacity, state.tokens + elapsed * zone_cfg.refill_per_s
            )
            state.ts = mono_now

            if state.tokens >= cost:
                # Allow and deduct tokens.
                state.tokens -= cost
                state.denies = 0
                state.temp_block_until = 0.0
                decision = RateDecision(
                    allowed=True,
                    zone=zone_name,
                    remaining_tokens=max(0.0, state.tokens),
                    blocked_until=None,
                    reason="ok",
                )
            else:
                # Deny, increment consecutive denies.
                state.denies += 1
                # Possibly enter temporary block state if threshold exceeded.
                if (
                    zone_cfg.temp_block_after_denies > 0
                    and state.denies >= zone_cfg.temp_block_after_denies
                ):
                    state.temp_block_until = mono_now + max(
                        0.0, zone_cfg.temp_block_ttl
                    )
                    decision = RateDecision(
                        allowed=False,
                        zone=zone_name,
                        remaining_tokens=max(0.0, state.tokens),
                        blocked_until=state.temp_block_until,
                        reason="temp_block",
                    )
                else:
                    decision = RateDecision(
                        allowed=False,
                        zone=zone_name,
                        remaining_tokens=max(0.0, state.tokens),
                        blocked_until=None,
                        reason="exhausted",
                    )

            # Possibly evict stale entries if the global soft cap is exceeded.
            self._maybe_evict_global()

            # Emit metrics / audit after the decision is made.
            self._emit_after_decision(bucket_key, state, zone_cfg, decision)
            return decision

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        """
        Return a shallow snapshot of the internal state for diagnostics.

        This is intended for metrics / debug endpoints, not for hot-path use.
        Values are approximate and read under a single lock.
        """
        with self._lock:
            total_entries = len(self._buckets)
            zones: Dict[str, int] = {}
            temp_blocks: Dict[str, int] = {}
            now = self._mono()
            for (zone_name, _key), state in self._buckets.items():
                zones[zone_name] = zones.get(zone_name, 0) + 1
                if state.temp_block_until > now:
                    temp_blocks[zone_name] = temp_blocks.get(zone_name, 0) + 1
            return {
                "total_entries": total_entries,
                "zones": zones,
                "temp_blocks": temp_blocks,
            }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _maybe_evict_global(self) -> None:
        """
        Soft eviction when the number of tracked keys exceeds global_max_entries.

        This uses a simple strategy: if over the limit, drop some oldest
        entries based on their last timestamp. It is intentionally conservative
        and only runs while holding the internal lock.
        """
        limit = int(self._config.global_max_entries)
        size = len(self._buckets)
        if size <= limit or limit <= 0:
            return

        # Evict up to 5% of entries when over the cap, preferring older ones.
        to_evict = max(1, int(0.05 * size))
        items = list(self._buckets.items())
        items.sort(key=lambda kv: kv[1].ts)  # oldest first
        for (zone_key, _), _state in items[:to_evict]:
            self._buckets.pop(zone_key, None)

    def _emit_after_decision(
        self,
        bucket_key: Tuple[str, Any],
        state: _BucketState,
        zone_cfg: RateLimitZoneConfig,
        decision: RateDecision,
    ) -> None:
        """
        Emit metrics and audit events after a decision has been made.

        Metrics are lightweight and label-limited. Audit events never contain
        raw keys; they use a hashed identifier when hashing support is
        available.
        """
        zone_name, key = bucket_key

        # Metrics
        if self._config.enable_metrics:
            labels: Dict[str, Any] = {
                "zone": zone_name,
                "allowed": "1" if decision.allowed else "0",
                "reason": decision.reason,
            }
            # Exporter, if present.
            if (
                getattr(self._config, "exporter", None) is not None
                and TCDOtelExporter is not None
                and isinstance(self._config.exporter, TCDOtelExporter)
            ):
                try:
                    self._config.exporter.record_metric(
                        name="tcd.rate_limit",
                        value=1.0,
                        labels=labels,
                    )
                except Exception:
                    pass
            # Metrics hook, if present.
            if self._config.metrics_hook is not None:
                try:
                    self._config.metrics_hook(
                        "tcd.rate_limit",
                        1.0,
                        labels,
                    )
                except Exception:
                    pass

        # Audit
        if (
            self._config.enable_audit
            and self._config.audit_hook is not None
            and (not decision.allowed or decision.reason != "ok")
        ):
            try:
                key_hash: Optional[str] = None
                if Blake3Hash is not None:
                    try:
                        hasher = Blake3Hash()
                        raw = str(key).encode("utf-8", errors="ignore")
                        key_hash = hasher.hex(raw, ctx="tcd:ratelimit:key")[:32]
                    except Exception:
                        key_hash = None

                event: Dict[str, Any] = {
                    "type": "tcd.rate_limit",
                    "ts_mono": state.ts,
                    "zone": zone_name,
                    "key_hash": key_hash,
                    "allowed": decision.allowed,
                    "reason": decision.reason,
                    "remaining_tokens": decision.remaining_tokens,
                    "blocked_until": decision.blocked_until,
                    "temp_block_active": state.temp_block_until > state.ts,
                    "consecutive_denies": state.denies,
                    "capacity": zone_cfg.capacity,
                    "refill_per_s": zone_cfg.refill_per_s,
                }
                self._config.audit_hook(event)
            except Exception:
                # Never let audit failures interfere with limiting decisions.
                pass