# tcd-safety-sidecar

Anytime-valid, verifiable safety sidecar for LLM inference.  
Online detection + always-valid (alpha-investing) control, optional verifiable receipts, rate limiting, and SRE-grade observability.  
Primary interfaces: HTTP service plane (`/diagnose`, `/verify`, `/state/*`) and admin/control plane for ledgers, audit, and policy management.

---

## Table of Contents

- [What is TCD?](#what-is-tcd)
- [Why this matters](#why-this-matters)
- [Quickstart (1-minute demo)](#quickstart-1-minute-demo)
- [Minimal examples](#minimal-examples)
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

## What is TCD?

TCD is an **infra-native safety & audit sidecar** for LLM inference.

Instead of being another guardrail model or red-teaming toolkit, TCD runs **next to your model server** and turns every request into a **scored decision + verifiable receipt**. It behaves like a safety control plane for inference: online checks, per-subject budgets, routing decisions, and cryptographic receipts that can be re-checked later in a different trust domain (another cluster, another team, or a regulator).

At a high level, TCD is designed to answer three questions that most AI stacks can’t answer cleanly today:

1. **“What actually happened on this request?”**  
   – Which model, which sampler, which policies, which signals, which route.

2. **“Did we enforce the safety / rate limits we think we enforced?”**  
   – Per-tenant / per-user budgets, e-process–based controls, and explicit decisions.

3. **“Can we prove this to someone who doesn’t trust our logs?”**  
   – Deterministic receipts with signatures and hash chains, verifiable offline.

### In one sentence

> **TCD is a small sidecar that scores every inference step, enforces always-valid safety budgets, and emits receipts you can later verify independently.**

### Concretely, TCD gives you

- A **service plane** (`/diagnose`, `/verify`, `/state/*`) that model servers or gateways call at inference time.
- An **always-valid controller** that treats safety like a budgeted statistical process, not a one-off heuristic.
- A **routing layer** that can “allow / degrade / block” by adjusting sampler settings or decoder tags.
- **Verifiable receipts** that bind inputs, outputs, policies, and scores into a hash chain you can audit later.
- **SRE-grade observability** (Prometheus, OTEL) so safety sits next to latency and errors on real dashboards.
- An **admin/control plane** for ledgers, audits, calibration, and policy management.

TCD is meant to be **deployed as infrastructure**: a small, testable component you can run as a sidecar or shared service in front of one model server or a whole fleet, without changing product-level SDKs or user-facing flows.

---

## Why this matters

Most AI stacks today are built to **serve tokens**, not to **prove what happened**.

Tracing and safety are usually bolted on as:
- ad-hoc logs,
- heuristic guardrails inside the application,
- or one-shot red-teaming reports.

That’s fine for prototypes, but it breaks down as soon as you have:
- multiple models and tools in a single request,
- real users and real money on the line,
- regulators or enterprise customers asking, *“Show me exactly what happened here.”*

TCD assumes that **inference is a governed, auditable surface**, not just “something behind an API”. It focuses on three gaps that existing infra does not handle well.

### 1. Logs are not enough for safety or audit

Conventional logs answer “what we think we logged”, not “what provably happened”:

- Logs can be **partial, mutable, or misconfigured** (sampling, dropped events, format changes).
- They rarely encode the **full decision context**: model ID, sampler settings, policies, per-subject state, and internal scores are often scattered across services.
- There is usually **no cryptographic binding** between request, response, and decision – nothing that can be safely re-checked in another trust domain.

TCD flips this around:

- Every decision can emit a **deterministic receipt** tying together:
  - inputs (prompts, key signals, subject metadata),
  - outputs (model decisions, routes),
  - and **policy + e-process state** at the time.
- Receipts are signed and hash-chained, so they can be **verified offline**, against an independently compiled verifier, without trusting the model server, app logs, or even the original cluster.

For enterprises, this turns “we think we did X” into **cryptographic evidence** that X happened under a specific configuration.

### 2. “One-off guardrails” don’t scale to many requests and many users

Most guardrail systems treat each request in isolation:

- A bad request is either blocked or allowed based on a **single threshold**.
- There is little notion of **per-subject history**: a user can “probe” the system thousands of times, and the system reacts the same way each time.
- Safety limits are typically heuristics rather than **budgeted, statistically controlled** processes.

TCD’s controller is built around **always-valid e-process / alpha-investing** ideas:

- Every subject (tenant, user, session) carries a **safety budget** over time.
- Each risky step **spends from that budget**; conservative steps can “earn back” budget.
- Decisions are **anytime-valid**: you can stop at any time and your false-positive/false-negative guarantees still hold, even under adaptivity and probing.

This makes it possible to talk about safety in the same way SRE teams talk about SLIs/SLOs:

- “Did we stay within our allocated risk budget for this tenant?”  
- “Which subjects are approaching exhaustion?”  
- “Which models/routes are consuming the most budget?”

### 3. Regulation and large customers are moving toward verifiable inference

Regulators, internal risk teams, and large customers are converging on a few clear expectations:

- **Provenance & traceability** – not just “we log everything”, but **provable lineage** for important decisions.
- **Explainable enforcement** – the ability to explain *why* a request was degraded/blocked and **reproduce that decision** from preserved state.
- **Independent verification** – the ability for a separate system (or third party) to **check receipts** without full access to production infra.

TCD is engineered to meet that bar:

- The **service plane** makes safety decisions in real time, but it is thin and testable.
- The **admin/control plane** exposes ledgers, audits, and calibration as first-class APIs.
- Receipts are built to be **externally verifiable primitives**, not proprietary logs:
  - a downstream “proof-of-inference” pipeline, customer audit service, or zk/IR circuit can consume them directly.

### 4. A new primitive: the inference receipt

The core thesis is simple:

> In modern AI infra, the **unit of truth** should not be “a log line” or “a response”, but an **inference receipt**: a compact, signed object that binds together what the model saw, how it behaved, how much risk it consumed, and which policies were in force.

Once you have that primitive, a lot of otherwise hard problems become straightforward:

- **Post-hoc policy changes** – re-score old traffic against new policies without losing auditability.
- **Cross-vendor portability** – compare behavior across different model providers using a single receipt schema.
- **Incident and failure analysis** – replay exact decision state during incidents, not just approximate logs.
- **Future-proofing for zk / PoI** – receipts can be wired into proof systems without changing product-side code.

TCD is built to make this primitive **cheap enough and infra-native enough** that it can sit in front of real, high-volume workloads – not just as a research demo.

---

## Quickstart (1-minute demo)

This is the smallest end-to-end slice: run the sidecar, send one request, get back a **verdict + routing + verifiable receipt**.

> Goal: show that TCD can sit next to any model server as an independent safety / receipt plane.

---

### **1. Run the HTTP sidecar locally**

```bash
git clone https://github.com/amelieliao/tcd-safety-sidecar.git
cd tcd-safety-sidecar

pip install -r requirements.txt

# Enable receipts and start the tenant-facing HTTP plane
export TCD_RECEIPTS_ENABLE=1

uvicorn tcd.service_http:create_app \
  --factory \
  --host 127.0.0.1 \
  --port 8000
```

You now have:

- `POST /diagnose` – online decision + optional receipt  
- `POST /verify` – receipt / chain verification  
- `GET /healthz`, `GET /readyz`, `GET /version` – liveness + config

---

### **2. Send a single diagnose request**

Run this in a separate shell (Python 3.10+):

```bash
python demo_diagnose.py
```

#### **demo_diagnose.py**

```python
import json
import uuid
import requests

BASE = "http://127.0.0.1:8000"

req = {
    "request_id": f"demo-{uuid.uuid4()}",
    "tenant": "demo-tenant",
    "user": "user-1234",
    "session": "sess-1",
    "model_id": "demo-llm",
    "task": "chat",
    "lang": "en",
    "tokens_delta": 128,
    "entropy": 2.7,
    "trace_vector": [0.12, 0.08, 0.04, 0.01],
    "spectrum": [0.6, 0.25, 0.15],
    "features": [0.01, -0.03, 0.12],
    "context": {
        "temperature": 0.7,
        "top_p": 0.9,
        "decoder": "default"
    },
}

resp = requests.post(f"{BASE}/diagnose", json=req, timeout=3)
resp.raise_for_status()

risk = resp.json()
print("== RiskResponse ==")
print(json.dumps(risk, indent=2))

if risk.get("receipt_head_hex") and risk.get("receipt_body_json"):
    print("\n== Minimal verify request ==")
    verify_payload = {
        "mode": "single",
        "receipt_head_hex": risk["receipt_head_hex"],
        "receipt_body_json": risk["receipt_body_json"],
        "receipt_sig_hex": risk.get("receipt_sig_hex"),
        "verify_key_hex": risk.get("verify_key_hex"),
    }

    v = requests.post(f"{BASE}/verify", json=verify_payload, timeout=3)
    v.raise_for_status()
    print(json.dumps(v.json(), indent=2))
else:
    print("\nReceipts are not enabled or not returned in this response.")
```

---

### **This will print:**

A `RiskResponse` containing:

- `verdict`, `score`, `threshold`
- `action` (`"allow"` | `"degrade"` | `"block"`)
- `budget_remaining`, `e_value`, `alpha_spent` (always-valid controller)
- optional receipt fields (`receipt_head_hex`, `receipt_body_json`, `receipt_sig_hex`, `verify_key_hex`)
- a `{"ok": true}` result from `/verify` if receipts are enabled and consistent

---

### **3. What you have proven in 1 minute**

With this flow you have:

- a **standalone safety plane** running as its own process, not embedded in the model server  
- **online decisions** driven by trace / entropy / feature signals + an always-valid controller  
- a **verifiable receipt** for the decision  
- an independent **/verify** path usable for audits, CI, or proof systems  

From here you can:

- mirror real model traffic into `/diagnose`  
- persist receipts via the admin/ledger plane  
- integrate verification into observability, trust, or proof-of-inference infrastructure  

---

## Minimal examples

The goal of these snippets is to show how little surface area you need to:

1. **Call `/diagnose`** with real signals  
2. **Use the returned decision in your model server**  
3. **Verify receipts independently**  

All examples assume the HTTP plane is running at `http://127.0.0.1:8000` with receipts enabled.

---

### 1. Minimal `curl` request to `/diagnose`

This is the smallest practical JSON body that still exercises:

- subject scoping (`tenant`, `user`, `session`)  
- trace / entropy / feature inputs  
- the always-valid controller (via `tokens_delta`)  

```bash
curl -sS -X POST "http://127.0.0.1:8000/diagnose" \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "demo-curl-1",
    "tenant": "tenant-demo",
    "user": "user-1",
    "session": "sess-1",
    "model_id": "demo-llm",
    "task": "chat",
    "lang": "en",
    "tokens_delta": 64,
    "entropy": 2.4,
    "trace_vector": [0.14, 0.09, 0.03],
    "spectrum": [0.6, 0.25, 0.15],
    "features": [0.01, -0.02, 0.07],
    "context": {
      "temperature": 0.7,
      "top_p": 0.9,
      "decoder": "default"
    }
  }'
```

Typical response (truncated):

```json
{
  "verdict": false,
  "score": 0.18,
  "threshold": 0.65,
  "action": "allow",
  "budget_remaining": 0.91,
  "e_value": 0.73,
  "alpha_spent": 0.02,
  "receipt_head_hex": "…",
  "receipt_body_json": "{…}",
  "receipt_sig_hex": "…",
  "verify_key_hex": "…"
}
```

You can already:

- gate the request with `verdict` / `action`  
- log or persist the receipt fields for later verification  

---

### 2. Minimal Python integration inside a model server

This example shows how a model server can:

- send signals to `/diagnose`  
- adjust its decoding based on the returned route  
- attach receipt metadata to its own logs or traces  

```python
import os
import json
import uuid
import requests

TCD_BASE = os.getenv("TCD_BASE_URL", "http://127.0.0.1:8000")

def tcd_decide(subject, signals, context):
    req = {
        "request_id": f"req-{uuid.uuid4()}",
        "tenant": subject["tenant"],
        "user": subject["user"],
        "session": subject["session"],
        "model_id": context["model_id"],
        "task": context.get("task", "chat"),
        "lang": context.get("lang", "en"),
        "tokens_delta": signals["tokens_delta"],
        "entropy": signals["entropy"],
        "trace_vector": signals["trace_vector"],
        "spectrum": signals["spectrum"],
        "features": signals.get("features", []),
        "context": {
            "temperature": context["temperature"],
            "top_p": context["top_p"],
            "decoder": context.get("decoder", "default"),
        },
    }

    resp = requests.post(f"{TCD_BASE}/diagnose", json=req, timeout=2.0)
    resp.raise_for_status()
    risk = resp.json()

    # core decision surface for the caller
    route = {
        "temperature": context["temperature"],
        "top_p": context["top_p"],
        "decoder": context.get("decoder", "default"),
        "action": risk["action"],
    }

    # optional: degrade if TCD asks for it
    if risk["action"] == "degrade":
        route["temperature"] = min(route["temperature"], 0.4)
        route["top_p"] = min(route["top_p"], 0.8)

    return route, risk
```

Usage inside your generation loop:

```python
subject = {"tenant": "tenant-demo", "user": "user-123", "session": "sess-42"}
context = {"model_id": "demo-llm", "task": "chat", "lang": "en",
           "temperature": 0.8, "top_p": 0.95}

signals = {
    "tokens_delta": 128,
    "entropy": 2.3,
    "trace_vector": [0.11, 0.09, 0.05, 0.02],
    "spectrum": [0.58, 0.27, 0.15],
    "features": [0.02, -0.01, 0.04],
}

route, risk = tcd_decide(subject, signals, context)

print("Route from TCD:", route)
print("Risk snapshot:", json.dumps({
    "verdict": risk["verdict"],
    "score": risk["score"],
    "action": risk["action"],
    "budget_remaining": risk["budget_remaining"],
}, indent=2))
```

This is enough to prove that:

- the **safety plane runs out-of-process**; you just call `/diagnose`  
- **routing is explicit and reversible** (`route` is a plain dict)  
- you can wire risk and receipt fields into your own logging / tracing system  

---

### 3. Minimal receipt verification client

This example assumes you have already stored the four receipt fields from a previous `RiskResponse`.

```python
import json
import requests

TCD_BASE = "http://127.0.0.1:8000"

def verify_receipt(head_hex, body_json, sig_hex, verify_key_hex):
    payload = {
        "mode": "single",
        "receipt_head_hex": head_hex,
        "receipt_body_json": body_json,
        "receipt_sig_hex": sig_hex,
        "verify_key_hex": verify_key_hex,
    }

    resp = requests.post(f"{TCD_BASE}/verify", json=payload, timeout=2.0)
    resp.raise_for_status()
    result = resp.json()
    print("Verify result:", json.dumps(result, indent=2))
    return result["ok"]
```

You can call it with values taken from storage or logs:

```python
ok = verify_receipt(
    head_hex=stored_head,
    body_json=stored_body,
    sig_hex=stored_sig,
    verify_key_hex=stored_key,
)

if not ok:
    # escalate to your audit / incident pipeline
    raise RuntimeError("TCD receipt verification failed")
```

This proves that:

- verification can be done by a **separate process or trust domain**  
- TCD exposes a **narrow, auditable surface** (`/verify`) that fits into CI, audits, or proof-of-inference flows  
- you can enforce invariants such as “no receipt, no deploy” or “no receipt, no compliance attestation” without modifying model code  

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




