# TCD

> **Trusted Control Plane for Governed, Quantified, and Verifiable AI Inference**

TCD is an infrastructure-native control plane for AI inference.

It sits beside model-serving runtimes, intercepts inference requests before execution, binds each request to identity and policy context, evaluates runtime risk and statistical budget state, produces an explicit decision, and emits verifiable evidence that can be stored, replayed, audited, and independently verified.

In practical terms, **TCD turns an LLM call from an opaque application-side operation into a governed systems event**.

---

## What TCD is

TCD is a **runtime control plane** for inference systems.

It is designed for teams that need to:

- govern inference behavior before model execution
- bind requests to stable runtime identity
- combine policy, routing, risk, and statistical budget state in one decision surface
- issue receipts and evidence that survive the request
- operate a control plane that is itself governed and auditable

TCD is not implemented as a thin SDK hook. It is built as an infrastructure-native sidecar/gateway/control-plane layer that can sit next to model-serving runtimes.

---

## What TCD is not

TCD is **not**:

- a model provider
- a prompt archive
- a generic event bus
- a generic SIEM replacement
- a globally consistent consensus system for receipts
- a one-file AI firewall
- a pure logging wrapper
- a thin gateway plugin with post-hoc safety checks

If all you need is a lightweight content filter or a single middleware that blocks obviously bad prompts, TCD is probably more system than you need.

---

## Why teams use TCD

Most production AI stacks still treat inference as a black-box API call.

The application decides what to send, the model returns output, and whatever “safety” or “governance” exists is often split across SDK hooks, logs, ad hoc middleware, and post hoc review.

That leaves recurring gaps:

- no unified runtime identity for requests, sessions, chains, and subjects
- no single place where policy, risk, and statistical budget meet
- no evidence object that outlives the request
- no governed control plane for mutations and runtime actions
- no durable boundary between “decision made” and “decision can be proven”

TCD is built to close those gaps.

---

## When to use TCD

TCD is a good fit when you need one or more of the following:

- **Multi-tenant or multi-team inference infrastructure**
- **Regulated or audit-heavy environments**
- **Inference-time routing and enforcement**, not just offline review
- **Per-stream statistical controls** rather than single-request thresholding
- **Receipts, verification, replay, and evidence storage**
- **Governed runtime mutations** such as reloads, policy updates, or patch actions
- **A separate control plane** instead of embedding governance logic inside every application

Examples:

- internal AI platforms serving multiple products or teams
- high-value customer workflows
- government or large financial environments
- AI systems where route, action, and evidence must be explainable after the fact

---

## When not to use TCD

TCD is probably the wrong tool if:

- you only need a lightweight prompt filter
- you do not need a separate control plane
- you do not care about receipts, verification, or replay
- you want globally strong distributed guarantees without providing shared state or an external coordinator
- you are looking for a hosted model platform rather than an inference governance layer

---

## Deployment modes

TCD can be used in more than one way.

| Mode | What it looks like | Best for |
|---|---|---|
| **Sidecar mode** | One TCD instance sits next to one model-serving runtime or workload | Single service ownership, local strong control semantics |
| **Shared gateway mode** | One TCD cluster fronts multiple model runtimes | Platform teams, shared routing and governance |
| **Control-plane-first mode** | You keep your existing serving path and introduce TCD for admin, verify, storage, and policy/governance first | Incremental adoption |
| **Verify / audit mode** | Use TCD primarily for verify, receipt ingest, storage, ledger, and audit workflows | Audit-first deployments or staged rollout |
| **Hybrid mode** | Use HTTP/gRPC inference surfaces in some paths and receipt/verify/storage/admin in others | Large, mixed estates |

---

## 5-minute quickstart

This section is intentionally practical: the goal is to tell a reader how to evaluate TCD quickly.

### 1. Choose a deployment mode

Start with one:

- sidecar
- shared gateway
- control-plane-first
- verify / audit only

If you are unsure, start with **sidecar mode** for one protected inference path.

### 2. Bring up an inference-facing surface

TCD exposes both:

- an HTTP inference surface
- a gRPC inference surface

Use whichever matches your serving stack.

### 3. Send a request through TCD

A minimal HTTP-style example:

```bash
curl -i \
  -X POST http://localhost:8080/diagnose \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: demo-1' \
  -d '{
    "input_kind": "request",
    "input_json": {
      "tenant": "demo",
      "route": "/chat",
      "model_id": "model-a"
    }
  }'
```

### 4. Inspect the runtime contract

A successful TCD response is not just a payload. It can also attach stable runtime identifiers, for example:

- `X-Request-Id`
- `X-TCD-Event-Id`
- `X-TCD-Http-Version`
- `X-TCD-Config-Fingerprint`
- `X-TCD-Bundle-Version`
- `X-TCD-Decision-Id`
- `X-TCD-Route-Plan-Id`

These are important because they let operators and downstream systems correlate the live request with policy/config identity, decision identity, and route-plan identity.

### 5. Turn on the evidence path

For a meaningful deployment, wire in:

- attestation
- verification
- governed storage
- ledger and/or local audit
- admin control-plane endpoints
- telemetry and metrics

If you want to adopt TCD incrementally, start with:

1. ingress + decision
2. route/security orchestration
3. receipt/verify/storage
4. admin mutation governance
5. ledger/auditor/trust graph

---

## Runtime model

A typical inference path through TCD looks like this:

```text
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
```

At a high level:

1. the transport surface accepts and bounds the request
2. middleware establishes request/session/chain/trust context
3. detector, calibration, and multivariate layers produce risk signals
4. decision and always-valid control produce action and statistical state
5. routing and security orchestration produce a route contract and required action
6. schemas and signals normalize the evidence surface
7. attest, crypto, storage, ledger, and audit make that evidence durable and verifiable

---

## Evidence model

TCD does not treat “a receipt” as one flat object.

The evidence model is layered:

### Decision identity

From `decision_engine.py`:

- `policy_digest`
- `config_hash`
- `decision_id`
- `reason_code`
- canonicalized snapshot fields

These anchor the decision itself.

### Statistical evidence state

From `risk_av.py` and the compatibility path in `receipt_v2.py`:

- `e_state`
- guarantee scope
- controller mode
- stream identity status
- backend degradation state

These anchor the cross-request statistical story.

### Unified evidence views

From `schemas.py` and `signals.py`:

- public view
- audit view
- receipt view
- verification view

These prevent silent cross-object inconsistency and align evidence identity, artifact refs, route contracts, and receipt fragments.

### Attestation and crypto envelope

From `attest.py` and `crypto.py`:

- canonical body
- head
- integrity hash
- message versioning
- policy digest binding
- key and registry governance

These anchor authenticity and integrity.

### Durable persistence and replay semantics

From `storage.py`, `ledger.py`, `audit.py`, and `auditor.py`:

- explicit conflict
- anti-fork chain semantics
- idempotent event handling
- local trust anchors
- continuous verification

These give evidence a durable afterlife.

---

## Integration surfaces

From an operator perspective, TCD is not a single endpoint. It is a set of cooperating surfaces.

### Inference-facing

- HTTP surface
- gRPC surface
- ingress/request/auth/security middleware
- detector, calibration, multivariate, decision, route, security orchestration

### Evidence-facing

- schemas
- signals
- attestation
- crypto
- verification
- storage
- ledger
- audit
- auditor

### Control-plane-facing

- admin HTTP surface
- policy and config reloads
- verify / receipt ingest
- health / readiness / runtime introspection
- action agent
- patch runtime

---

## Guarantees vs non-guarantees

This section is intentionally explicit.

### Strong local guarantees available now

TCD already provides strong local or single-process / single-node semantics for:

- request/session/chain identity establishment
- bounded ingress behavior
- explicit decision identities
- explicit route and security contracts
- verify-first ingest
- explicit storage conflict instead of silent overwrite
- anti-fork receipt-chain constraints within store boundaries
- local audit anchoring
- continuous chain auditing

### What is local-best-effort unless you add stronger infrastructure

Without external coordination or shared state, do not describe the following as globally strong guarantees:

- multi-instance config/policy propagation
- globally ordered receipt streams
- globally shared statistical budget state
- globally synchronized route decisions
- distributed consensus semantics for ledger ordering

### Control-plane semantics to state explicitly

TCD already makes several operational semantics explicit:

- **Policies/config:** process-local atomic swap
- **Multi-instance propagation:** best-effort unless externally coordinated
- **Receipt store:** idempotent writes at the boundary; overwrite yields explicit conflict
- **Receipt ordering:** storage-view unless the backend guarantees more
- **Ledger:** at-least-once with deterministic event IDs for dedupe
- **Readiness:** separate from liveness; readiness can depend on strict-mode hard dependencies and breaker state

### Crypto boundary honesty

TCD already defines a governed cryptographic control plane, but you should not market it as a fully production-complete PQ stack unless you specify the exact backend, key-management environment, and deployment profile in use.

---

## Design principles

TCD follows a few strict design rules across the repository.

### Content-agnostic by default

Evidence, storage, signals, telemetry, and most runtime outputs are designed to avoid carrying raw prompts, completions, request bodies, response bodies, cookies, or authorization material.

TCD prefers:

- structured identifiers
- bounded metadata
- artifact references
- digests

### Deterministic and reproducible

Canonical JSON, stable digests, message versions, bounded normalization, and stable event/decision/route identifiers are treated as system primitives, not convenience features.

### Explicit conflict over silent overwrite

Storage, admin ingest, and ledger layers prefer:

- explicit conflict
- idempotent dedupe
- anti-fork semantics

over hidden replacement or last-write-wins behavior.

### Governance over convenience

Strict modes, scope enforcement, approvals, change tickets, break-glass, outbox fallback, and prepare/commit semantics appear repeatedly because TCD optimizes for governance and verifiability, not just API ergonomics.

### Boundedness everywhere

Untrusted input is always expected. Body size, JSON depth, cardinality, evidence node counts, string lengths, queue sizes, stream counts, chain windows, and patch segment sizes are bounded throughout the system.

---

## Repository guide

This is the short root-level map. It highlights the modules most readers actually need first.

### Transport and ingress

- `service_http.py` — HTTP inference surface
- `service_grpc.py` — gRPC inference surface
- `middleware.py` — request/session/chain context + edge rate limit + metrics
- `middleware_request.py` — higher-level request governance
- `middleware_security.py` — edge security controls
- `auth.py` — authentication and identity normalization

### Decision and policy

- `detector.py` — bounded detector runtime
- `calibration.py` — score-to-p calibration core
- `multivariate.py` — multivariate risk detector
- `decision_engine.py` — explicit decision interpreter
- `risk_av.py` — always-valid statistical controller
- `routing.py` — strategy router
- `security_router.py` — policy/risk/route/evidence orchestration
- `policies.py` — policy compilation and binding
- `ratelimit.py` — compiled-bundle runtime rate limiting

### Evidence and persistence

- `schemas.py` — unified public/audit/receipt/verification views
- `signals.py` — governed signal/evidence bus
- `attest.py` — structured attestation generator
- `crypto.py` — crypto control-plane substrate
- `verify.py` — receipt and chain verification
- `storage.py` — governed persistence boundary
- `ledger.py` — durable wealth + receipt-chain substrate
- `audit.py` — local append-only audit trust anchor
- `auditor.py` — chain auditor

### Governance execution

- `admin_http.py` — admin-only HTTP control plane
- `agent.py` — TrustAgent execution shell
- `patch_runtime.py` — governed runtime patch pipeline
- `rewrite_engine.py` — bounded rewrite proposal engine
- `trust_graph.py` — relationship and trust-state layer

### Observability and foundations

- `exporter.py` — governed Prometheus exporter
- `otel_exporter.py` — governed OTEL exporter
- `telemetry_gpu.py` — governed GPU telemetry boundary
- `logging.py` — structured logging surface
- `config.py` — settings compiler / governor
- `kv.py` — canonical key/value hashing and deterministic IDs
- `utils.py` — shared sanitization and bounded JSON/meta helpers

---

## Current maturity

A useful way to read the repository is by maturity layer.

### Available now

- strong ingress governance
- auth normalization
- bounded detector/calibration/decision flow
- always-valid controller with structured state
- strategy routing and security orchestration
- unified evidence views
- attestation and verification paths
- governed storage + durable ledger + local audit + chain auditor
- admin control plane with explicit DoD semantics

### Strong local semantics

- request and decision identity
- per-process or per-node controller state
- local durable audit and ledger paths
- explicit storage conflicts
- anti-fork chain checks within store boundaries

### Requires external coordination or shared state for stronger distributed guarantees

- globally synchronized config/policy rollout
- globally shared budget/controller state
- globally ordered receipt semantics
- stronger distributed lock/coordinator semantics
- hardware-backed or externally governed signing environments

### Compatibility / transitional paths

- `receipt_v2.py` remains relevant as a compatibility-oriented statistical receipt builder
- richer evidence and persistence paths increasingly center on `risk_av.py`, `schemas.py`, `signals.py`, and `storage.py`

---

## In one sentence

> **TCD turns inference from an opaque application call into a governed systems event with identity, policy binding, statistical budget state, route contracts, verifiable evidence, and durable auditability.**