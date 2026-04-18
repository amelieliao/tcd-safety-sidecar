```text
TCD

Trusted Control Plane for Governed, Quantified, and Verifiable AI Inference

TCD is an infrastructure-native control plane for AI inference. It sits beside model-serving runtimes, intercepts each inference request before execution, binds it to identity and policy context, evaluates runtime risk and statistical budget state, produces a structured decision, and emits verifiable evidence that can be stored, replayed, audited, and independently verified. In practical terms: TCD turns an LLM call from an opaque application-side operation into a governed systems event.  ￼  ￼  ￼

⸻

Why TCD exists

Most production AI stacks still treat inference as a black-box API call. The application decides what to send, the model returns output, and whatever “safety” or “governance” exists is often split across SDK hooks, logs, ad hoc middleware, and post hoc review. That leaves five recurring gaps:

* no unified runtime identity for requests, sessions, chains, and subjects,
* no single place where policy, risk, and statistical budget meet,
* no evidence object that outlives the request,
* no governed control plane for mutations and runtime actions,
* no durable boundary between “decision made” and “decision can be proven.”  ￼  ￼  ￼  ￼

TCD is built to close those gaps. It is not a prompt filter, not a logging wrapper, and not a thin gateway plugin. It is a control plane that governs inference-time behavior and the evidence produced by that behavior.  ￼  ￼  ￼

⸻

What TCD does

At a high level, TCD provides six capabilities.

1. Ingress governance
    Request, session, request-chain, trusted-upstream, XFF, edge security, and edge rate-limit semantics are established before model execution begins.  ￼  ￼
2. Runtime risk interpretation
    Detector outputs, calibrated p-values, multivariate signals, SLO pressure, and policy state are turned into explicit actions and reason codes rather than ad hoc branching.  ￼  ￼  ￼
3. Always-valid statistical control
    Cross-request evidence processes are maintained per stream, with explicit guarantee scope, controller mode, and degradation semantics.  ￼
4. Route and security orchestration
    Strategy routing and security routing produce route contracts, enforcement modes, and required actions that can be enforced, audited, and reasoned about independently from the model implementation.  ￼  ￼
5. Receipt and evidence generation
    Decisions, controller state, route identity, artifacts, and attestation metadata are normalized into structured evidence objects suitable for receipts, verification, storage, and audit.   ￼  ￼
6. Durable governance and audit
    Storage, ledger, local audit, and chain auditing provide idempotent persistence, anti-fork receipt chains, replay-safe event handling, and continuous verification.   ￼  ￼  ￼

⸻

Architecture

TCD is easiest to understand as three cooperating planes.

1. Inference Data Plane

This is the path that sees live inference traffic. It handles request identity, trusted transport context, authentication, edge security, edge rate limiting, and the transport adapters for HTTP and gRPC. Its job is not to make the final governance decision; its job is to turn an incoming request into a well-formed, budgeted, identity-bearing inference event.  ￼  ￼  ￼  ￼  ￼

2. Decision & Policy Plane

This is where detection, calibration, multivariate aggregation, policy binding, always-valid evidence processes, route planning, and security orchestration meet. It produces the runtime decision surface: action, reason, enforcement mode, route contract, statistical state, and decision identity.  ￼  ￼  ￼  ￼  ￼  ￼

3. Governance & Evidence Plane

This is where TCD becomes more than “runtime middleware.” The governance and evidence plane includes the admin API, action agent, patch runtime, attestation, crypto envelope, schemas, signals, storage, ledger, audit log, chain auditor, and trust graph. It governs control-plane changes and it gives every important inference or mutation path a durable, verifiable afterlife.  ￼  ￼  ￼  ￼  ￼   ￼  ￼

⸻

Request lifecycle

A typical inference request through TCD looks like this:

client
  -> HTTP/gRPC surface
  -> request / auth / security middleware
  -> detector + calibration + multivariate
  -> decision_engine + risk_av
  -> routing + security_router
  -> schemas + signals
  -> attest + crypto
  -> storage + ledger + audit
  -> response headers / receipt refs / telemetry

More concretely:

1. The HTTP or gRPC surface accepts a request and enforces hard limits on body size, headers, metadata, JSON depth, and endpoint budgets. It attaches request and event identifiers plus config/bundle fingerprints to the response path.  ￼  ￼
2. Middleware establishes request context, session semantics, trusted-upstream handling, chain propagation, and edge fairness/DoS controls. Authentication normalizes principal identity and replay-resistant auth state.  ￼  ￼  ￼
3. Detector, calibration, and multivariate analysis produce risk signals and bounded, content-agnostic evidence fragments.  ￼  ￼  ￼
4. DecisionEngine interprets those signals under explicit policy and data-quality semantics, while AlwaysValidRiskController updates cross-request statistical state for the relevant stream.  ￼  ￼
5. StrategyRouter and SecurityRouter convert the decision surface into a route contract and required action, including fail-closed or degraded behavior where needed.  ￼  ￼
6. schemas.py and signals.py unify route, controller, receipt, and security fragments into evidence-oriented views.   ￼
7. attest.py, crypto.py, storage.py, ledger.py, audit.py, and auditor.py issue, bind, persist, and re-verify the resulting evidence.  ￼  ￼   ￼  ￼  ￼

⸻

The evidence model

TCD does not treat “a receipt” as a single flat object. The repository separates evidence into layers:

* Decision identity from decision_engine.py
    policy_digest, config_hash, decision_id, reason_code, and canonicalized snapshots anchor the decision itself.  ￼
* Statistical evidence state from risk_av.py (and the earlier receipt_v2.py path)
    e_state, guarantee scope, controller mode, stream identity status, and backend degradation state anchor the cross-request statistical story.  ￼
* Unified evidence views from schemas.py and signals.py
    TCD aligns public, audit, receipt, and verification views and prevents silent cross-object inconsistencies.   ￼
* Attestation and crypto envelope from attest.py and crypto.py
    Canonical body, head, integrity hash, message versioning, policy digest binding, and key/registry governance anchor authenticity and integrity.  ￼  ￼
* Durable persistence and replay semantics from storage.py, ledger.py, audit.py, and auditor.py
    These modules provide explicit conflict, anti-fork chains, idempotent event handling, local trust anchors, and ongoing verification.   ￼  ￼  ￼

⸻

Operational model

TCD’s operational semantics are explicit by design.

* Policies and config are process-local atomic swaps unless an external coordinator is introduced. Multi-instance propagation is best-effort.  ￼
* Runtime controllers such as RateLimiter and AlwaysValidRiskController are strong local control primitives, but they should be described as local or local-best-effort unless backed by stronger shared state.  ￼  ￼
* Receipt and evidence storage use idempotent boundary semantics with explicit conflict rather than silent overwrite. Ordering is storage-view unless a stronger backend contract is supplied.  ￼
* Ledger semantics are durable and anti-fork within store constraints, but they are not a global consensus system. The ledger is best described as strong local durability plus replay- and idempotency-safe event handling.  ￼

That explicitness matters. TCD is opinionated about governance, but it does not hide system boundaries behind vague “enterprise-grade” language.

⸻

Repository map

The repository naturally groups into a few subsystems. Every file below is part of the runtime/control/evidence story.

Transport, ingress, and request governance

* service_http.py — hardened HTTP inference surface with request envelopes, response headers, diagnose/verify endpoints, and receipt issuance hooks.
* service_grpc.py — gRPC transport shim with bounded metadata/payload handling, authz, verify isolation, and evidence prepare/commit flow.
* api_v1.py — /v1/diagnose API surface with end-to-end deadlines, concurrency gates, outbox-aware evidence flow, and structured request-end logging.
* middleware.py — request context, session/chain semantics, edge rate limiting, metrics middleware, plus pure ASGI variants.
* middleware_request.py — higher-level request governance: bounded body read, auth-first flow, policy bind, subject-aware limits, idempotency, and classification derivation.
* middleware_security.py — edge security middleware for IP controls, CORS/origin policy, browser security headers, and structured security events.
* auth.py — pluggable authentication and identity normalization for HMAC, JWT/JWKS, bearer, and mTLS/XFCC.  ￼  ￼  ￼  ￼  ￼  ￼  ￼

Detection, calibration, and decisioning

* detector.py — bounded, pluggable detector with monotone calibration and conformal fallback.
* calibration.py — predictable calibration core that turns scores into conservative p-values using previous-block-only state.
* multivariate.py — multivariate risk detector with immutable policy bundle semantics and bounded snapshots.
* decision_engine.py — explicit risk interpreter with data-quality policy, threshold normalization, and receipt-oriented decision identities.
* risk_av.py — always-valid statistical controller platform with guarantee scopes, controller modes, and stream-level evidence state.
* receipt_v2.py — compatibility-oriented, receipt-first statistical state builder used by existing service surfaces.  ￼  ￼  ￼  ￼  ￼

Policy, rate, route, and security orchestration

* policies.py — policy compilation and binding with rich match context, canonical rule/set hashing, and bounded overrides.
* ratelimit.py — compiled-bundle rate limiting with typed keys, fixed-point accounting, dual clocks, and event identity.
* routing.py — strategy router that turns signals into route contracts, required actions, and route-plan identity.
* security_router.py — content-agnostic orchestration layer that combines policy, rate, signals, route contracts, attest/ledger requirements, and outbox fallbacks.
* rewrite_engine.py — semi-automatic rewrite proposal engine that generates bounded patch proposals, never mutates the repository directly, and annotates origin/risk for higher-level control planes.  ￼  ￼  ￼  ￼  ￼

Governance execution and control-plane actions

* agent.py — TrustAgent execution shell with gates, bounded executors, circuit breakers, prepare/commit semantics, outbox support, and side-effect uncertainty handling.
* patch_runtime.py — governed runtime patch pipeline with artifact digests, approvals, canary constraints, and receipt/telemetry metadata controls.
* admin_http.py — admin-only HTTP surface for policies, verification, receipt ingest/access, health, readiness, runtime status, and explicit consistency semantics.  ￼  ￼  ￼

Evidence, verification, and persistence

* schemas.py — unified public, audit, receipt, and verification views, including DiagnoseIn/DiagnoseOut.
* signals.py — governed signal/evidence bus used to move route, security, receipt, ledger, and lifecycle signals without leaking raw content.
* attest.py — structured attestation generator with deterministic canonicalization and verifier-friendly records.
* crypto.py — cryptographic control-plane substrate with message versions, digest binding, key registry governance, and envelope signing/verification.
* verify.py — receipt and chain verification surface with strict schema and budget enforcement.
* storage.py — governed persistence boundary for receipts and wealth state, with explicit conflict, anti-fork semantics, and compatibility shims.
* ledger.py — durable wealth and receipt-chain substrate with idempotent events and anti-fork constraints.
* audit.py — local append-only audit trust anchor.
* auditor.py — one-shot and periodic chain auditor with anomaly accounting and verification isolation.   ￼  ￼  ￼  ￼   ￼  ￼  ￼

Observability, configuration, and foundations

* exporter.py — governed Prometheus exporter with schema-driven metric surface, label governance, privacy modes, and cardinality hard-stops.
* otel_exporter.py — governed OTEL-style exporter with deep sanitization, async delivery, and bundle-aware fingerprinting.
* telemetry_gpu.py — content-agnostic GPU telemetry boundary that emits bounded hardware/runtime evidence.
* logging.py — structured logging surface with governance-aware redaction, rate limiting, and stable envelope semantics.
* config.py — settings compiler/governor with effective vs provenance hashing, signature verification, reload semantics, and break-glass.
* kv.py — canonical key/value hashing and deterministic-ID substrate used across receipts, chains, events, and evidence envelopes.
* utils.py — shared sanitization and bounded JSON/meta helpers for content-agnostic output paths.
* trust_graph.py — relationship layer for subjects, evidence, edges, trust state, and audit/telemetry projections.  ￼  ￼  ￼  ￼  ￼  ￼  ￼  ￼

⸻

Design principles

TCD follows a few explicit design rules that show up across the repository.

Content-agnostic by default

Evidence, storage, signals, telemetry, and most runtime outputs are designed to avoid carrying raw prompts, completions, request bodies, response bodies, cookies, or authorization material. The system prefers structured identifiers, bounded metadata, artifact references, and digests.  ￼   ￼  ￼

Deterministic and reproducible

Canonical JSON, stable digests, message versions, bounded normalization, and stable event/decision/route identifiers are treated as system primitives, not convenience features.  ￼  ￼  ￼

Explicit conflict over silent overwrite

Storage, admin ingest, and ledger layers consistently prefer explicit conflict semantics and idempotent dedupe over hidden replacement or last-write-wins behavior.  ￼   ￼

Governance over convenience

Strict modes, scope enforcement, approvals, change tickets, break-glass, outbox fallback, and prepare/commit semantics appear repeatedly because TCD optimizes for governance and verifiability, not just API ergonomics.  ￼  ￼  ￼  ￼

Boundedness everywhere

Untrusted input is always expected. Body size, JSON depth, cardinality, evidence node counts, string lengths, queue sizes, stream counts, chain windows, and patch segment sizes are bounded throughout the repo.  ￼  ￼  ￼  ￼  ￼  ￼

⸻

What TCD is not

TCD is not:

* a model provider,
* a prompt archive,
* a generic event bus,
* a generic SIEM replacement,
* a consensus system for globally ordered receipts,
* a one-file “AI firewall.”

signals.py explicitly says it is not a generic event bus; service_grpc.py explicitly says it is a transport/control-plane adapter, not a policy engine; storage.py explicitly says it is not a casual helper layer; and the white paper positions the system as a control plane around inference events, not an SDK-bound application feature.  ￼  ￼   ￼

⸻

Current status and honest boundaries

The current repository already proves a lot, but it is important to describe it accurately.

* TCD already has strong runtime control, structured evidence generation, and durable local persistence boundaries.  ￼   ￼
* Runtime controllers such as RateLimiter and AlwaysValidRiskController should still be described as local or local-best-effort primitives unless backed by stronger shared state.  ￼  ￼
* The repository already defines a governed cryptographic control plane, but you should not casually market it as a fully production-complete PQ stack without specifying the exact backend and key-management environment in use.  ￼

That honesty is part of the design philosophy. TCD is explicit about system boundaries because governance without accurate semantics is theater.

⸻

In one sentence

TCD turns inference from an opaque application call into a governed systems event with identity, policy binding, statistical budget state, route contracts, verifiable evidence, and durable auditability.  ￼  ￼
```