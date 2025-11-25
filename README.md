# tcd-safety-sidecar

Anytime-valid, verifiable safety sidecar for LLM inference.  
Online detection + always-valid (alpha-investing) control, optional verifiable receipts, rate limiting, and SRE-grade observability.  
Primary interfaces: HTTP service plane (`/diagnose`, `/verify`, `/state/*`) and admin/control plane for ledgers, audit, and policy management.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
  - [Service plane (HTTP / gRPC)](#service-plane-http--grpc)
  - [Admin & control plane](#admin--control-plane)
- [Quick start](#quick-start)
  - [Install](#install)
  - [Run the HTTP sidecar](#run-the-http-sidecar)
  - [Health checks](#health-checks)
- [HTTP API](#http-api)
- [Verifiable receipts](#verifiable-receipts)
  - [Receipt issuance](#receipt-issuance)
  - [Receipt verification](#receipt-verification)
- [Rate limiting & always-valid control](#rate-limiting--always-valid-control)
- [Observability](#observability)
- [Security & policies](#security--policies)
- [Repository layout](#repository-layout)
- [Development](#development)

---

## Features

**Service plane**

- **HTTP service (FastAPI)**  
  - `/diagnose` – online detector + routing decision + optional receipt  
  - `/v1/diagnose` – compatibility alias  
  - `/verify` – single-receipt or chain verification  
  - `/healthz`, `/readyz`, `/version` – health, readiness, and config info  
  - `/state/get`, `/state/load` – detector snapshot export/import

- **Always-valid controller (`risk_av`)**  
  - Per-subject (tenant, user, session) alpha-investing controller  
  - Tracks `e_value`, `alpha_alloc`, `alpha_wealth`, and `alpha_spent`  
  - Can enforce hard “alpha budget” limits and feed into routing / Trust OS

- **Routing on degrade (`routing`)**  
  - Given detector verdict + scores, returns decoder strategy  
  - Controls temperature, top-p, decoder tags for “allow / degrade / block”

- **Multivariate drift & anomaly detector (`multivariate`)**  
  - Optional feature-space detector (e.g., LW covariance + scores)  
  - Output is folded into the main decision components / receipts

- **Rate limiting (`rate_limit`)**  
  - Token bucket per (tenant, user, session)  
  - Token cost derived from `tokens_delta` with configurable divisors  
  - Subject-level micro-policies possible (per tenant / model overrides)

- **Verifiable receipts (`attest`, `receipt_v2`, `verify`)**  
  - Deterministic `(head, body, sig)` triplet for each decision  
  - Witness segments for trace / spectrum / features (quantized)  
  - Chain verification for long-running sessions or pipelines

- **Observability (`exporter`, `otel_exporter`, `telemetry`)**  
  - Prometheus metrics for detectors, alpha budget, routing actions, SLOs  
  - OpenTelemetry spans/metrics for scores, receipts, and failures  
  - GPU telemetry sampler (optional) for runtime hardware context

- **gRPC shim (`service_grpc`)**  
  - Optional gRPC surface mirroring the HTTP semantics  
  - Designed to be plugged into model servers or orchestration systems

---

**Admin / control plane**

- **Admin HTTP API (`admin_http`, `api_v1`)**  
  - Control-plane surface for:
    - Receipt ledgers and stores
    - PQ-friendly logs (for zk / PQ pipelines)
    - Policy reloads and calibration assets
    - Audit and replay control

- **Ledgers & storage (`ledger`, `storage`, `receipt_store`, `kv`)**  
  - Pluggable backends (in-memory, SQLite, or external stores)  
  - RollingHasher abstraction for keyed digests and KV-style hashing

- **Audit & replay (`audit`, `auditor`)**  
  - Chain and ledger consistency checks  
  - Synthetic or recorded traffic replay into `/diagnose`  
  - Latency and correctness statistics for offline analysis

- **Calibration (`calibration`)**  
  - Structures and helpers for thresholds / scaling / tuning  
  - Designed to run on offline logs, then export configs back to runtime

- **Trust OS extension (`decision_engine`, `trust_graph`, `rewrite_engine`, `patch_runtime`, `policies`)**  
  - DecisionEngine: maps scores + verdicts to high-level actions  
  - TrustGraph: models dependencies between models, tools, or tenants  
  - RewriteEngine: optional policy-driven request/response rewriting  
  - PatchRuntime: hooks for safe, limited runtime patching  
  - Policies: central place for policy bundles and enforcement helpers

- **Security surface (`middleware_security`, `security_router`, `crypto`)**  
  - Security-oriented middleware (auth, replay protection, request guards)  
  - Security router helpers (e.g., per-scope allowlist)  
  - Crypto helpers for receipt signing and key management

- **Logging & middleware (`logging`, `middleware`, `middleware_request`)**  
  - Structured logging with request IDs and decision metadata  
  - Request context middleware for tenant/user/session binding  
  - Per-IP guards and HTTP metrics middleware

---

## Architecture

At a high level the system is a **sidecar safety and verification plane** that sits next to an LLM runtime (or any streaming model server). It has two clearly separated surfaces:

- **Service plane (public):**
  - `service_http.py` – FastAPI HTTP surface (`/diagnose`, `/verify`, `/healthz`, `/version`, `/state/*`)
  - `service_grpc.py` – optional gRPC shim mirroring the HTTP contract  
  - Exposed to tenants / applications (per-tenant, per-user, per-session controls)

- **Admin / control plane (internal):**
  - `admin_http.py` + `api_v1.py` – operator API for configs, receipts, ledgers, audits
  - `audit.py` / `auditor.py` – replay, audit windows, chain checks, budget reports
  - `calibration.py` – score / threshold calibration & drift monitoring
  - `ledger.py`, `receipt_store.py`, `storage.py` – durable stores (SQL / KV / file)

Everything else is shared infrastructure: detectors, always-valid controller, routing, receipts, telemetry, and security middleware.

---

### Module map

**Core runtime**

- `detector.py` – trace / entropy / spectrum based online detector
- `multivariate.py` – multivariate feature monitor (covariance / anomaly scoring)
- `risk_av.py` – always-valid controller (alpha-investing e-process budget)
- `routing.py` – strategy router that turns decisions into “temperature / top-p / decoder / tags”
- `signals.py` – pluggable model-side signal provider (e.g. token stats, latency)

**Trust & decision OS**

- `decision_engine.py` – higher-level decision labels & policies
- `rewrite_engine.py` – hooks to rewrite routes / attach additional tags
- `trust_graph.py` – placeholder for graph-based trust relationships
- `patch_runtime.py` – patch / hot-reload hooks for controlled runtime tweaks
- `policies.py` – policy helpers used by both service and admin plane

**Receipts, crypto & verification**

- `attest.py` – deterministic receipt issuer (head/body/sig + witness segments)
- `receipt_v2.py` – v2 receipt body schema and metadata builder
- `verify.py` – local verification of single receipts and chains
- `kv.py` – rolling hasher (witness compression) and lightweight KV helpers
- `crypto.py` – signing / verification primitives and key helpers

**Admin, audit & observability**

- `audit.py` / `auditor.py` – replay, chain audit, integrity and coverage checks
- `exporter.py` – Prometheus exporter for detector / AV / request metrics
- `otel_exporter.py` – optional OpenTelemetry exporter (metrics/spans)
- `telemetry.py` – generic telemetry helpers (tags, spans, error reporting)
- `logging.py` – structured logging: request IDs, decision logs, audit trails

**HTTP / gRPC surfaces & security**

- `service_http.py` – *tenant-facing* FastAPI app (`/diagnose`, `/verify`, `/state/*`)
- `admin_http.py` – *operator-facing* FastAPI app for control & audits
- `service_grpc.py` – gRPC mirror of `/diagnose` and `/verify` semantics
- `security_router.py` – high-level routing helpers with security hooks
- `middleware_security.py` – auth / authz / JWT / replay protection (admin)
- `middleware.py` – shared middleware (metrics, error shaping, etc.)
- `middleware_request.py` – request context (IDs, subject keys, headers)

**Config, schemas & utilities**

- `config.py` – reloadable settings (env / file) for both planes
- `schemas.py` – shared Pydantic schemas for configs and APIs
- `rate_limit.py` – token-bucket per subject (tenant/user/session)
- `storage.py` – storage backends for ledgers and receipts
- `utility.py` – small helpers (JSON, type guards, numeric safety)
- `signals.py` – default model signal provider (CPU/GPU/etc.)
- `telemetry_gpu.py` – GPU sampler helper

---

## Data & control flow

### Online decision path (`/diagnose`)

1. **Caller → service plane**

   Client sends a `DiagnoseRequest` to `/diagnose` with:
   - `trace_vector` / `entropy` / `spectrum` – online model signals  
   - optional `features` – multivariate feature vector  
   - `tokens_delta` – tokens generated/consumed in this step  
   - subject metadata: `tenant`, `user`, `session`, `model_id`, `gpu_id`, `task`, `lang`  
   - `context` – lightweight config (temperature, top-p, decoder, latency, etc.)

2. **HTTP layer**

   In `service_http.py`:
   - Request gets a **request ID** and **subject key** (tenant/user/session).  
   - Rate-limit via `RateLimiter` with subject-aware policies.  
   - GPU stats are optionally sampled and merged into `context`.  
   - Inputs are sanitized (`sanitize_floats`) and clipped to size limits.

3. **Detector**

   `TraceCollapseDetector` receives:
   - `trace_vector`, `entropy`, `spectrum`, `step_id`  
   and returns a `verdict_pack`:
   - `score` – risk score in `[0,1]`  
   - `verdict` – boolean “fail” flag  
   - `components` – structured breakdown  
   - `step` – internal step counter, metadata, etc.

4. **Multivariate monitor (optional)**

   If `features` is non-empty:
   - `MultiVarDetector` computes feature-level anomaly signals.  
   - The result is merged into the component map.

5. **Always-valid controller**

   `AlwaysValidRiskController` is invoked with the HTTP `Request` context:
   - Maintains per-subject **e-process budget** (`alpha_wealth`).  
   - Returns `e_value`, `alpha_alloc`, `alpha_wealth`, `alpha_spent`, `threshold`, `trigger`.  
   - `trigger` is true when the budget decides to flag this step.

6. **Routing**

   `StrategyRouter.decide(...)` combines:
   - Model base temperature / top-p  
   - Detector score  
   - Decision flags (`verdict`, `trigger`)  

   and returns a **route**:
   - effective `temperature`, `top_p`  
   - `decoder` choice  
   - `tags` to attach (e.g. `["degrade", "safe_mode"]`)

7. **Trust OS (optional)**

   If `DecisionEngine` / `TrustGraph` / `RewriteEngine` are enabled:
   - A `DecisionContext` is created with score + verdict.  
   - `DecisionEngine` returns a higher-level action label: `"allow"`, `"degrade"`, `"block"`, etc.  
   - `RewriteEngine` may tweak route fields or tags.  
   - These labels feed logging, receipts and admin dashboards.

8. **Receipt (optional)**

   If `TCD_RECEIPTS_ENABLE=1`:
   - Witness segments are quantized (`_quantize_to_u32`) from trace / spectrum / features.  
   - Rolling KV digest is computed via `RollingHasher`.  
   - `build_v2_body(...)` builds the v2 receipt body (model, sampler, context, e-process snapshot).  
   - `Attestor.issue(...)` signs and returns:
     - `receipt` (head)  
     - `receipt_body`  
     - `receipt_sig`  
     - `verify_key`  

   - Response includes these fields in `RiskResponse`.

9. **Metrics & logs**

   - Prometheus exporter updates:
     - verdict counts  
     - e-process metrics  
     - per-subject budget usage  
     - SLOs (latency, failures, verify failures)  

   - OpenTelemetry exporter (if enabled) emits metrics/spans with model + subject tags.  
   - Structured logger records the decision with route and action.

10. **Caller response**

    Caller receives a typed `RiskResponse`:
    - `verdict` (boolean)  
    - `score`, `threshold`  
    - `budget_remaining`, `alpha_alloc`, `alpha_spent`, `e_value`  
    - `components` (per-detector details)  
    - `action` (e.g. `"allow"`, `"degrade"`, `"block"`)  
    - optional receipt fields (if receipts enabled)

---

### Receipt verification path (`/verify`)

`/verify` supports two modes:

1. **Chain verify mode**

   - Caller passes `heads` and `bodies` arrays.  
   - Service enforces:
     - per-request window limit  
     - basic input validation and length bounds  

   - `verify_chain(...)` checks linear consistency of head→body mapping and signatures.  
   - Returns `{"ok": true}` on success.

2. **Single receipt mode**

   - Caller passes:
     - `receipt_head_hex`  
     - `receipt_body_json`  
     - optionally `verify_key_hex`, `receipt_sig_hex`  
     - optional `req_obj`, `comp_obj`, `e_obj`, `witness_segments`  

   - Service applies size limits (body, witnesses) and validity checks.  
   - `verify_receipt(...)` re-derives witness hashes and checks:
     - head/body consistency  
     - signature under `verify_key`  
     - optional concordance with request / component / e-process objects  

   - Returns `{"ok": true}` if everything matches.

Admin plane offers higher-level APIs for verifying chains across time windows, cross-checking with ledgers, and running full audits.

---

## HTTP API (service plane)

### `POST /diagnose`

- Input: `DiagnoseRequest`  
- Output: `RiskResponse`  

Main online decision endpoint used by model servers or middlewares.

Typical use:

1. Model server collects per-request signals at each generation step.  
2. It POSTs them to `/diagnose`.  
3. It applies the returned route (`temperature`, `top_p`, tags) before generating the next portion.  
4. It logs/stores the returned receipt if `receipts` are enabled.

---

### `POST /v1/diagnose`

Stable alias for `/diagnose` to keep old clients compatible.

---

### `POST /verify`

- Input: `VerifyRequest`  
- Output: `VerifyResponse` (`ok: bool`)

Verifies either:

- a single receipt, or  
- a head/body chain.

Used by external verifiers, auditors, or on-prem customers who want independent checks.

---

### `GET /healthz`

Liveness + feature flags:

- `ok`  
- `config_hash`  
- `otel`, `prom`, `receipts`, `trust_os` flags  

---

### `GET /readyz`

Readiness:

- `ready`  
- `prom_http` (whether the Prometheus HTTP exporter is active)  

---

### `GET /version`

Version + core config snapshot:

- `version` (semantic version of the sidecar)  
- `config_version`  
- `alpha` (default alpha budget)  
- `slo_latency_ms`  

---

### `GET /state/get`

Returns detector state for a given `(model_id, gpu_id, task, lang)` key:

```json
{
  "detector": { "...": "..." }
}
```

Used to snapshot or migrate online detector state.

---

### POST /state/load

Loads a previously captured state into the detector keyed by `(model_id, gpu_id, task, lang)`.

---

## gRPC interface (optional)

If you want a gRPC surface instead of HTTP, `service_grpc.py` exposes:

- Diagnose — mirrors `POST /diagnose`
- Verify — mirrors `POST /verify`

The protobuf file is designed to be as close as possible to the HTTP schemas, enabling:

- Running HTTP and gRPC side-by-side
- Choosing whichever protocol fits your environment
- Reusing receipts, keys, and ledger entries across both

---

## Admin / control plane

The admin surface is not meant for end-user tenants.  
It is an operator API with strong security and stricter rate limits.

Core areas:

- **Config & policies**
  - Manage alpha budgets, thresholds, routing presets  
  - Configure per-tenant / per-model overrides  

- **Receipts & ledger**
  - Search receipts by subject, time range, model, or decision  
  - Inspect receipt bodies and chain relationships  
  - Trigger chain checks and repair tasks  

- **Audits**
  - Run auditor jobs over historical data  
  - Export reports for compliance / governance  

- **Calibration**
  - Evaluate detector score distributions  
  - Adjust thresholds / policies based on benchmarks  

Admin endpoints reuse the same underlying components as the service plane, but with:

- Authentication & authorization via `middleware_security`
- Replay protection  
- Stricter rate limits  
- More detailed operator logging  

---

## Observability

### Prometheus

`exporter.py` exposes:

- Detector metrics (scores, verdict counts)
- Always-valid controller metrics (e-values, alpha wealth, spends)
- HTTP / gRPC metrics (latency, status codes, SLO violations)
- Verify failures and replay / audit stats

Prometheus scraping available at:

```
/metrics
```

A dedicated embedded Prometheus server is available if needed.

---

### OpenTelemetry

`otel_exporter.py` pushes metrics + spans:

- Tagged by model_id, gpu_id, tenant, user, session  
- Marks receipts as present/absent with approximate size  
- Marks decisions with action labels and verdict flags  

Works with any OTEL backend.

---

## Logging

`logging.py` provides:

- request IDs and session IDs in every log line  
- structured logging fields for subject, model, GPU, action  
- clear separation between service and admin logs  

---

## Configuration

`config.py` defines a reloadable settings object.

Configuration sources:

- Environment variables  
- Config file (local dev or on-prem)

Key settings:

- HTTP / gRPC bind ports  
- Global SLO thresholds  
- Alpha budgets & detector defaults  
- GPU telemetry toggles  
- Receipt/OTEL toggles  
- Rate-limit capacities  

Reloadable via:

```
make_reloadable_settings()
```

---

## Running locally

### Prerequisites

- Python 3.10+  
- poetry or pip  
- Optional: uvicorn, prometheus_client, fastapi, numpy  

### Dev run (HTTP service plane)

```bash
pip install -r requirements.txt

export TCD_RECEIPTS_ENABLE=1   # optional

uvicorn tcd.service_http:create_app \
  --factory \
  --host 127.0.0.1 \
  --port 8000 \
  --reload
```

Test endpoints:

- http://127.0.0.1:8000/healthz  
- http://127.0.0.1:8000/version  
- POST http://127.0.0.1:8000/diagnose  

---

## Admin plane

```bash
uvicorn tcd.admin_http:create_app \
  --factory \
  --host 127.0.0.1 \
  --port 8001 \
  --reload
```

Admin security is governed by config.

---

## Docker & deployment (high-level)

A minimal Dockerfile:

1. Copy project into image  
2. Install requirements  
3. Start uvicorn with service/admin plane  

Example service entrypoint:

```bash
uvicorn tcd.service_http:create_app \
  --factory \
  --host 0.0.0.0 \
  --port 8000
```

### Deployment patterns:

- **Sidecar** — one container per model server  
- **Shared gateway** — front multiple model servers  
- **On-prem** — internal DNS + mTLS + API gateway  

### Kubernetes (Helm chart)

- Deploy service plane  
- Deploy admin plane (restricted namespace)  
- Prometheus + OTEL integration  
- Config + secrets  

---

## Development workflow

Core logic lives in `tcd/`.

- Keep HTTP/gRPC surfaces thin  
- Keep detector, AV, receipts, audit logic testable  
- Tests under `tests/` cover:
  - detector behavior  
  - AV controller invariants  
  - receipt issuance & verification  
  - audit flows & chain checks  

Run tests:

```
pytest
```

Feature PR expectations:

- extend schemas in `schemas.py`  
- update defaults in `config.py`  
- add metrics in `exporter.py` / `otel_exporter.py`  
- keep service & admin plane cohesive but separated  

---

This section provides a complete picture of how the system is structured and how components interact.  
The system can attach to any model runtime—from a single-GPU server to a multi-tenant cluster—while preserving:

- verifiable receipts  
- always-valid e-process budgets  
- full SRE-grade observability  




