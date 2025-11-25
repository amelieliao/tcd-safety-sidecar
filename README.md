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

### Service plane (HTTP / gRPC)

The service plane is the **public sidecar surface**. It is designed to sit next to an LLM or toolchain and make online decisions:

1. Inference metadata (trace, entropy, spectrum, features, context) are sent to `/diagnose`.
2. The detector + multivariate stats produce a score and verdict.
3. The always-valid controller updates alpha budgets per subject.
4. Routing logic chooses a decoder strategy (`allow`, `degrade`, or stronger).
5. Optionally, an Attestor issues