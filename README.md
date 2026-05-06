# TCD

> **Trusted Control Plane for Governed, Quantified, and Verifiable AI Inference**

TCD is an infrastructure-native control plane for AI inference.

It sits beside model-serving runtimes, intercepts inference requests before or around execution, binds each request to identity and policy context, evaluates runtime risk and statistical budget state, produces an explicit decision, and emits verifiable evidence that can be stored, replayed, audited, and independently verified.

In practical terms, **TCD turns an LLM call from an opaque application-side operation into a governed systems event**.

---

## Current maturity

The current `service_http` / receipt governance subsystem has moved beyond a runnable PoC.

Based on the latest full receipt governance closure test, the subsystem is best described as:

> **Receipt Governance Subsystem: core governance loop is implemented, end-to-end integration tested, and suitable for staging or internal trial evaluation. It is not yet a production compliance certification or a claim of global distributed consensus.**

This means the current repository has demonstrated a working, test-backed receipt governance loop across:

| Area | Current state |
|---|---|
| Functionality | Receipt generation, signing, public view, verification view, persistence, restart recovery, and chain verification are connected. |
| Governance closure | Both local fallback and SecurityRouter / PolicyStore paths have been exercised. |
| Durable evidence | SQLite-backed evidence store and receipt reference store survive process restart. |
| Integrity verification | Signed receipt body, commit receipt, ledger ref, commit ref, and consistency checks are validated. |
| Security binding | Build/image supply-chain binding, PQ-required path, PQ-signature path, and negative verification paths are covered. |
| Operational testability | Uvicorn startup, cleanup, restart, logs, summaries, and pass/fail gates are scripted. |
| Failure awareness | Wrong build/image and wrong chain head negative tests fail as expected. |

The current maturity level is therefore:

```bash
Receipt Governance Subsystem: Engineering Alpha / Pre-Beta
Recommended use: staging, internal trial, integration hardening, CI regression
Not yet: production compliance certification, global consensus claim, or security audit replacement
```

---

## Latest full receipt governance validation

The latest full governance closure test completed with:

```bash
ALL_FULL_RECEIPT_GOVERNANCE_TESTS_PASSED
FULL_RECEIPT_GOVERNANCE_EXIT_CODE=0
```

The test covered two major runtime profiles.

### Local profile

The local profile validated:

- local fallback path
- local HMAC attestation
- durable SQLite evidence store
- durable SQLite receipt reference store
- schema-view receipt projection
- signed receipt body
- durable commit state
- ledger ref / commit ref consistency
- attestation ref
- PQ required
- PQ signature
- restart-after-issue receipt reference lookup
- restart-after-issue storage-window chain verification
- wrong build/image negative verification
- wrong chain head negative verification

The local profile intentionally did not require SecurityRouter, PolicyStore, audit ref, prepare ref, or outbox ref.

### Security profile

The security profile validated:

- SecurityRouter path
- PolicyStore path
- local HMAC attestation
- durable SQLite evidence store
- durable SQLite receipt reference store
- schema-view receipt projection
- policy ref binding
- policyset ref binding
- signed receipt body
- durable commit state
- ledger ref / commit ref consistency
- attestation ref
- audit ref
- prepare ref
- outbox ref
- outbox queued state
- PQ required
- PQ signature
- restart-after-issue receipt reference lookup
- restart-after-issue storage-window chain verification
- wrong build/image negative verification
- wrong chain head negative verification

Important nuance:

```bash
policy_ref and policyset_ref are validated in the security profile.
policy_digest is not currently mandatory in the full governance summary.
If policy_digest becomes a required release gate, add an explicit assertion for it.
```

---

## What TCD is

TCD is a **runtime control plane** for inference systems.

It is designed for teams that need to:

- govern inference behavior before or around model execution
- bind requests to stable runtime identity
- combine policy, routing, risk, and statistical budget state in one decision surface
- issue receipts and evidence that survive the request
- verify receipts and receipt chains after the request has finished
- operate a control plane that is itself governed, observable, and auditable
- fail explicitly under storage, ledger, receipt, and outbox faults rather than silently overwriting evidence

TCD is not implemented as a thin SDK hook. It is built as an infrastructure-native sidecar, gateway, or control-plane layer that can sit next to model-serving runtimes.

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
- a production compliance certificate by itself

If all you need is a lightweight content filter or a single middleware that blocks obviously bad prompts, TCD is probably more system than you need.

TCD can provide strong local and shared-storage guarantees under configured deployment profiles, but it does not claim global distributed consensus unless you provide the required external coordination or shared-state infrastructure.

---

## Why teams use TCD

Most production AI stacks still treat inference as a black-box API call.

The application decides what to send, the model returns output, and whatever safety or governance exists is often split across SDK hooks, logs, ad hoc middleware, and post hoc review.

That leaves recurring gaps:

- no unified runtime identity for requests, sessions, chains, and subjects
- no single place where policy, risk, route, and statistical budget meet
- no evidence object that outlives the request
- no durable boundary between "decision made" and "decision can be proven"
- no governed control plane for mutations and runtime actions
- no explicit behavior for crash windows, duplicate retries, ledger outage, or storage faults
- no independent receipt verification path after the request has finished

TCD is built to close those gaps.

---

## When to use TCD

TCD is a good fit when you need one or more of the following:

- multi-tenant or multi-team inference infrastructure
- regulated or audit-heavy environments
- inference-time routing and enforcement, not just offline review
- per-stream statistical controls rather than single-request thresholding
- receipts, verification, replay, and evidence storage
- governed runtime mutations such as reloads, policy updates, or patch actions
- crash-aware action semantics around prepare, commit, replay, and idempotency
- outbox-backed degradation when a ledger or downstream evidence sink is temporarily unavailable
- a separate control plane instead of embedding governance logic inside every application

Examples:

- internal AI platforms serving multiple products or teams
- high-value customer workflows
- government or large financial environments
- AI systems where route, action, and evidence must be explainable after the fact
- inference systems where auditability must survive restarts, retries, and storage faults

---

## When not to use TCD

TCD is probably the wrong tool if:

- you only need a lightweight prompt filter
- you do not need a separate control plane
- you do not care about receipts, verification, replay, or durable audit trails
- you want globally strong distributed guarantees without providing shared state or an external coordinator
- you are looking for a hosted model platform rather than an inference governance layer
- you are unwilling to operate storage, ledger, verification, key management, and observability surfaces as part of the inference platform

---

## Deployment modes

TCD can be used in more than one way.

| Mode | What it looks like | Best for |
|---|---|---|
| Sidecar mode | One TCD instance sits next to one model-serving runtime or workload. | Single service ownership and local strong control semantics. |
| Shared gateway mode | One TCD cluster fronts multiple model runtimes. | Platform teams, shared routing, and centralized governance. |
| Control-plane-first mode | Existing serving path remains; TCD is introduced first for admin, verify, storage, and policy governance. | Incremental adoption. |
| Verify / audit mode | TCD is used primarily for verify, receipt ingest, storage, ledger, and audit workflows. | Audit-first deployments or staged rollout. |
| Shared-persistence mode | Multiple TCD processes or nodes write to a shared durable receipt store. | Multi-worker or staged multi-node durability validation. |
| Hybrid mode | HTTP/gRPC inference surfaces are used in some paths and receipt/verify/storage/admin in others. | Large mixed estates. |

---

## Quickstart

### 1. Clone and enter the repository

```bash
cd ~/tcd-safety-sidecar
source venv/bin/activate
```

### 2. Always clean old uvicorn and curl processes first

Before every local server or full governance test run, check and clean port `8080`.

```bash
lsof -nP -iTCP:8080 -sTCP:LISTEN || true
for p in $(lsof -tiTCP:8080 -sTCP:LISTEN 2>/dev/null); do kill "$p" 2>/dev/null || true; done
pkill -f "uvicorn.*tcd\.service_http:create_app" 2>/dev/null || true
pkill -f "curl .*127\.0\.0\.1:8080" 2>/dev/null || true
pkill -f "curl .*localhost:8080" 2>/dev/null || true
lsof -nP -iTCP:8080 -sTCP:LISTEN || true
```

### 3. Start the HTTP service

For a basic local run:

```bash
cd ~/tcd-safety-sidecar
source venv/bin/activate

PYTHONWARNINGS="ignore::DeprecationWarning,ignore::UserWarning" \
python -m uvicorn tcd.service_http:create_app \
  --factory \
  --host 127.0.0.1 \
  --port 8080
```

### 4. Check health

```bash
curl -sS http://127.0.0.1:8080/healthz
curl -sS http://127.0.0.1:8080/readyz
curl -sS http://127.0.0.1:8080/version
```

### 5. Send a diagnose request

```bash
curl -i \
  -X POST http://127.0.0.1:8080/diagnose \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: demo-3" \
  -d '{
    "tenant": "demo",
    "user": "user1",
    "session": "sess1",
    "model_id": "model-a",
    "gpu_id": "gpu0",
    "task": "chat",
    "lang": "en",
    "trace_vector": [0.1, 0.2, 0.3],
    "spectrum": [0.4, 0.5],
    "features": [0.6, 0.7],
    "entropy": 0.42,
    "step_id": 1,
    "context": {},
    "tokens_delta": 50,
    "drift_score": 0.0,
    "trust_zone": "internet",
    "route_profile": "inference",
    "risk_label": "normal",
    "base_temp": 0.7,
    "base_top_p": 0.9
  }'
```

A successful response may include stable runtime identifiers such as:

- `X-Request-Id`
- `X-TCD-Event-Id`
- `X-TCD-Http-Version`
- `X-TCD-Config-Fingerprint`
- `X-TCD-Service-Config-Fingerprint`
- `X-TCD-Config-Fingerprint-Kind`
- `X-TCD-Route-Config-Fingerprint`
- `X-TCD-Receipt-Cfg-Fp`
- `X-TCD-Bundle-Version`
- `X-TCD-Decision-Id`
- `X-TCD-Route-Plan-Id`

These identifiers let operators correlate the live request with policy/config identity, decision identity, route-plan identity, receipt identity, and durable evidence state.

---

## Receipt governance quickstart

The receipt governance path becomes meaningful when these are enabled together:

- local HMAC attestation
- durable receipt reference lookup
- durable evidence store
- schema-view receipt projection
- verification bundle exposure for test mode
- build/image supply-chain binding
- PQ-required and PQ-signature path
- optional SecurityRouter / PolicyStore path
- durable commit receipt validation

### Local fallback + HMAC + SQLite evidence profile

```bash
cd ~/tcd-safety-sidecar
source venv/bin/activate

export TCD_ATTEST_HMAC_KEY="local-test-hmac-key-that-is-long-enough"
export TCD_ATTEST_HMAC_KEY_ID="tcd-attestor:hmac:local"

export TCD_BUILD_ID="build-local-demo"
export TCD_IMAGE_DIGEST="sha256:local-demo-image"

export TCD_HTTP_RECEIPTS_ENABLE_DEFAULT=1
export TCD_HTTP_RECEIPT_SELF_CHECK=1
export TCD_HTTP_EXPOSE_VERIFICATION_BUNDLE_PUBLIC=1
export TCD_HTTP_EXPOSE_LEGACY_RECEIPT_ALIASES=1
export TCD_HTTP_EXPOSE_VERIFY_KEY_PUBLIC=0
export TCD_HTTP_RECEIPT_USE_SCHEMA_VIEW=1

export TCD_HTTP_RECEIPT_REF_STORE_DSN="sqlite:////tmp/tcd_receipt_ref_store.sqlite3"
export TCD_HTTP_EVIDENCE_STORE_DSN="sqlite:////tmp/tcd_evidence_store.sqlite3"
export TCD_HTTP_REQUIRE_DURABLE_EVIDENCE=1
export TCD_HTTP_REQUIRE_COMMIT_RECEIPT_AFTER_DURABLE=1

PYTHONWARNINGS="ignore::DeprecationWarning,ignore::UserWarning" \
python -m uvicorn tcd.service_http:create_app \
  --factory \
  --host 127.0.0.1 \
  --port 8080
```

### SecurityRouter + PolicyStore + full governance profile

```bash
cd ~/tcd-safety-sidecar
source venv/bin/activate

export TCD_ATTEST_HMAC_KEY="security-test-hmac-key-that-is-long-enough"
export TCD_ATTEST_HMAC_KEY_ID="tcd-attestor:hmac:security"

export TCD_BUILD_ID="build-security-demo"
export TCD_IMAGE_DIGEST="sha256:security-demo-image"

export TCD_POLICY_STORE_ENABLE=1
export TCD_HTTP_SECURITY_ROUTER_ENABLE=1
export TCD_SECURITY_ROUTER_ENABLE=1
export TCD_SECURITY_ROUTER_ATTESTOR_ENABLE=1
export TCD_SECURITY_ROUTER_DURABLE_RECEIPTS=1
export TCD_SECURITY_ROUTER_REQUIRE_LEDGER_WHEN_REQUIRED=1
export TCD_SECURITY_ROUTER_REQUIRE_TERMINAL_GOVERNANCE_FOR_RECEIPT=1
export TCD_SECURITY_ROUTER_REQUIRE_STORAGE_READY_FOR_RECEIPT=1
export TCD_SECURITY_ROUTER_LOCAL_LEDGER_ENABLE=1
export TCD_SECURITY_ROUTER_LOCAL_AUDIT_ENABLE=1
export TCD_SECURITY_ROUTER_OUTBOX_ENABLE=1

export TCD_HTTP_RECEIPTS_ENABLE_DEFAULT=1
export TCD_HTTP_RECEIPT_SELF_CHECK=1
export TCD_HTTP_EXPOSE_VERIFICATION_BUNDLE_PUBLIC=1
export TCD_HTTP_EXPOSE_LEGACY_RECEIPT_ALIASES=1
export TCD_HTTP_EXPOSE_VERIFY_KEY_PUBLIC=0
export TCD_HTTP_RECEIPT_USE_SCHEMA_VIEW=1

export TCD_HTTP_RECEIPT_REF_STORE_DSN="sqlite:////tmp/tcd_security_receipt_ref_store.sqlite3"
export TCD_HTTP_EVIDENCE_STORE_DSN="sqlite:////tmp/tcd_security_evidence_store.sqlite3"
export TCD_HTTP_REQUIRE_DURABLE_EVIDENCE=1
export TCD_HTTP_REQUIRE_COMMIT_RECEIPT_AFTER_DURABLE=1

PYTHONWARNINGS="ignore::DeprecationWarning,ignore::UserWarning" \
python -m uvicorn tcd.service_http:create_app \
  --factory \
  --host 127.0.0.1 \
  --port 8080
```

---

## Full receipt governance regression gate

The full receipt governance gate should pass both local and security modes.

A passing run prints:

```bash
local: FULL_RECEIPT_GOVERNANCE_SUITE_PASSED
security: FULL_RECEIPT_GOVERNANCE_SUITE_PASSED
ALL_FULL_RECEIPT_GOVERNANCE_TESTS_PASSED
FULL_RECEIPT_GOVERNANCE_EXIT_CODE=0
```

Recommended test coverage for this gate:

| Test area | Required assertion |
|---|---|
| Local fallback | Local mode completes without SecurityRouter or PolicyStore. |
| SecurityRouter | Security mode reports `security_router=true`. |
| PolicyStore | Security mode reports `policy_store=true`. |
| HMAC attestation | Receipt has signature material and PQ signature path passes. |
| Durable evidence store | Evidence backend is SQLite and durable commit is present. |
| Durable receipt ref store | Receipt ref lookup backend is SQLite and survives restart. |
| Schema-view path | `schema_view_enabled=true`. |
| Signed receipt body | Receipt verification passes with the signed body. |
| Durable commit state | `receipt_surface_kind=durable_committed`, `ledger_stage=committed`, and `receipt_delivery_state=committed`. |
| Ledger / commit refs | `ledger_ref` and `commit_ref` are present and consistent. |
| Attestation ref | Attestation ref is present. |
| Audit / prepare / outbox refs | Present in security mode. |
| PQ path | `pq_ok=true` and `pq_signature_ok=true`. |
| Restart receipt lookup | Receipt ref verifies after uvicorn restart. |
| Restart storage-window chain verification | Chain window verifies after uvicorn restart. |
| Wrong build/image negative verification | Wrong build/image fails verification. |
| Wrong chain head negative verification | Wrong chain head fails verification. |

The current full governance validation passed these assertions with exit code `0`.

---

## Runtime model

A typical inference path through TCD looks like this:

```bash
client
# -> HTTP/gRPC surface
# -> request / auth / security middleware
# -> detector + calibration + multivariate
# -> decision_engine + risk_av
# -> routing + security_router
# -> schemas + signals
# -> attest + crypto
# -> storage + ledger + audit
# -> response headers / receipt refs / telemetry
```

At a high level:

1. The transport surface accepts and bounds the request.
2. Middleware establishes request/session/chain/trust context.
3. Detector, calibration, and multivariate layers produce risk signals.
4. Decision and always-valid control produce action and statistical state.
5. Routing and security orchestration produce a route contract and required action.
6. Schemas and signals normalize the evidence surface.
7. Attest, crypto, storage, ledger, outbox, and audit make evidence durable, replayable, and verifiable under the configured deployment profile.

---

## Evidence model

TCD does not treat a receipt as one flat object.

The evidence model is layered.

### Decision identity

Anchors the decision itself:

- policy reference
- policyset reference
- optional policy digest
- config hash
- decision ID
- route plan ID
- reason code
- canonicalized snapshot fields

### Statistical evidence state

Anchors the cross-request statistical story:

- e-state
- alpha allocation
- alpha spent
- alpha wealth
- guarantee scope
- controller mode
- stream identity status
- backend degradation state

### Unified evidence views

Normalizes and separates evidence views:

- public view
- audit view
- receipt view
- verification view

This prevents silent cross-object inconsistency and aligns evidence identity, artifact refs, route contracts, and receipt fragments.

### Attestation and crypto envelope

Anchors authenticity and integrity:

- canonical body
- receipt head
- integrity hash
- message versioning
- policy binding
- config fingerprint binding
- build/image binding
- signature key ID
- signature verification path

### Durable persistence and replay semantics

Gives evidence a durable afterlife:

- explicit conflict
- anti-fork chain semantics
- idempotent event handling
- local trust anchors
- continuous verification
- durable receipt lookup
- chain verification windows
- restart-safe receipt reference lookup

### Outbox and failure semantics

Gives degraded evidence delivery a governed path:

- duplicate dedupe key + same digest is idempotent
- duplicate dedupe key + different digest is conflict
- ledger outage can queue evidence into outbox
- queued items can later be flushed and verified
- silent overwrite is rejected

---

## Validated behavior

The following behaviors have passed the current manual, regression, fault-injection, concurrency, soak, and full receipt governance closure tests recorded for this repository.

These are test-backed engineering claims, not formal mathematical proofs. They are intentionally scoped to the tested runtime profiles, storage backends, and deployment shapes.

| Area | Validation result | What it means |
|---|---|---|
| Durable committed receipt surface | Durable-required requests returned committed durable receipt surfaces with committed ledger state. | TCD can issue durable committed receipts under the tested durable profile. |
| Local fallback receipt path | Local mode passed without SecurityRouter or PolicyStore. | TCD can still produce verifiable local HMAC receipts and durable evidence under the local profile. |
| SecurityRouter receipt path | Security mode passed with SecurityRouter enabled. | Policy/risk/route/evidence orchestration can participate in the final receipt path. |
| PolicyStore binding path | Security mode passed with PolicyStore enabled and policy refs present. | Policy refs and policyset refs participate in governance identity. |
| HMAC attestation | Local HMAC attestation and verification passed. | The configured local HMAC signing path is functional. |
| Schema-view projection | Schema-view path passed. | Receipt public and verification projections work through the schema view path. |
| Signed receipt body | Receipt verification passed against the signed receipt body. | Receipt body integrity is preserved through issue, surface, storage, and verify. |
| Durable SQLite evidence | SQLite evidence store passed commit and restart validation. | Evidence can survive the process lifetime under the tested SQLite profile. |
| Durable receipt ref lookup | SQLite receipt ref store passed restart validation. | Receipt references can be resolved after process restart. |
| Durable commit consistency | Decision receipt and commit receipt were both present, with ledger and commit refs aligned. | The durable commit receipt path is consistent in the tested profile. |
| Audit/prepare/outbox refs | Security mode produced audit, prepare, and outbox refs. | Security governance artifacts are surfaced in the security profile. |
| PQ path | PQ required and PQ signature checks passed. | PQ-related receipt claims and signature requirements are wired into the current verification path. |
| Negative build/image verification | Wrong build/image validation failed. | Supply-chain binding is checked by the verification path. |
| Negative chain head verification | Wrong chain head validation failed. | Chain verification catches expected head mismatch. |
| Process restart persistence | Receipt reference lookup and storage-window chain verification passed after uvicorn restart. | The durable lookup and chain paths are not merely in-memory. |
| Crash after prepare, before commit | A process killed after prepare did not create a false committed state. | Prepare/commit governance avoids pretending that an uncommitted action committed. |
| Crash after commit, before response | A process killed after commit but before response replayed idempotently. | Response-loss crash windows are replay-safe for committed actions under the tested idempotency path. |
| Outbox failure/retry | Ledger unavailable forced queueing into outbox, and later flush committed the item. | Ledger outage can degrade into explicit queued outbox state and later recover. |
| Outbox conflict handling | Same dedupe key + same digest was idempotent; same key + different digest conflicted. | Outbox dedupe avoids silent overwrite. |
| Storage fault injection | Permission denied, disk full simulation, invalid SQLite path, WAL lock, corrupted row, and oversized receipt body were handled or detected. | Storage fails explicitly and can detect integrity corruption under common SQLite fault scenarios. |
| Multi-process shared storage | Two uvicorn workers wrote concurrent durable block requests to shared SQLite storage without chain ambiguity. | Shared-storage multi-worker writes preserve an unambiguous chain under tested load. |
| Multi-node shared persistence | Node A issued a receipt, Node B verified and tailed it, and A/B concurrent commits preserved a single chain. | Shared persistence supports cross-node read/verify and concurrent server-assigned appends under the tested SQLite profile. |
| Capacity boundary | A 5,000-request / 100-concurrent-client staging run completed with zero diagnose failures and sampled receipt verification success. | The tested local staging profile handled 100-way concurrent request pressure. |
| Soak window | A 30-minute mixed-load soak completed without observed failures. | The HTTP/control-plane surface did not show receipt deadlock or verify failure in that soak window. |

---

## Validation scope

The current validation set supports these scoped claims:

- durable receipt issuance works under the tested durable profile
- receipt references survive process restart when backed by durable lookup storage
- committed actions can be replayed idempotently after response-loss crashes
- prepare-only crashes do not create false commits
- outbox queue/flush can bridge ledger unavailability
- storage faults are explicit and corruption is detectable
- shared SQLite persistence can support concurrent multi-process and tested multi-node writers without chain ambiguity
- local single-process staging capacity testing has passed at 5,000 requests and 100 concurrent clients
- full receipt governance closure passes in local and security profiles

The current validation set does **not** imply:

- global multi-region consensus
- globally ordered receipt streams without a shared backend or coordinator
- globally shared statistical budget state across unrelated deployments
- production-complete hardware-rooted signing in every environment
- production-complete PQ-signature deployment in every environment
- production latency SLOs for all hardware, networks, backends, or deployment profiles
- indefinite soak stability beyond the tested windows
- third-party security audit approval
- regulatory certification

Longer soak windows, restart-interval tests, mixed receipt soak tests, key rotation tests, and larger multi-node capacity tests should be tracked as separate validation artifacts when completed.

---

## Integration surfaces

TCD is not a single endpoint. It is a set of cooperating surfaces.

### Inference-facing

- HTTP surface
- gRPC surface
- ingress/request/auth/security middleware
- detector
- calibration
- multivariate risk detector
- decision engine
- route engine
- security orchestration

### Evidence-facing

- schemas
- signals
- attestation
- crypto
- verification
- storage
- ledger
- outbox
- audit
- auditor

### Control-plane-facing

- admin HTTP surface
- policy reloads
- config reloads
- verify / receipt ingest
- health / readiness / runtime introspection
- action agent
- patch runtime
- crash/replay/idempotency governance

---

## HTTP surface

Common endpoints:

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness and basic runtime state. |
| `GET /readyz` | Readiness. |
| `GET /version` | Version/config summary. |
| `GET /dod` | Definition-of-done / contract summary. |
| `GET /runtime/public` | Public runtime view. |
| `GET /runtime/diagnostics` | Runtime diagnostics. |
| `POST /diagnose` | Main inference governance decision surface. |
| `POST /v1/diagnose` | Versioned alias. |
| `POST /verify` | Receipt and chain verification surface. |
| `POST /v1/verify` | Versioned alias. |
| `GET /metrics` | Prometheus metrics. |

---

## Important environment variables

### Attestation and signing

```bash
export TCD_ATTEST_HMAC_KEY="local-test-hmac-key-that-is-long-enough"
export TCD_ATTEST_HMAC_KEY_ID="tcd-attestor:hmac:local"
```

Accepted signing-key env aliases include:

```bash
TCD_ATTEST_HMAC_KEY
TCD_RECEIPT_HMAC_KEY
TCD_ATTEST_SIGNING_KEY
TCD_RECEIPT_SIGNING_KEY
```

Accepted key-ID env aliases include:

```bash
TCD_ATTEST_HMAC_KEY_ID
TCD_RECEIPT_HMAC_KEY_ID
```

### Receipt surfaces

```bash
export TCD_HTTP_RECEIPTS_ENABLE_DEFAULT=1
export TCD_HTTP_RECEIPT_SELF_CHECK=1
export TCD_HTTP_RECEIPT_USE_SCHEMA_VIEW=1
export TCD_HTTP_EXPOSE_VERIFICATION_BUNDLE_PUBLIC=1
export TCD_HTTP_EXPOSE_LEGACY_RECEIPT_ALIASES=1
export TCD_HTTP_EXPOSE_VERIFY_KEY_PUBLIC=0
```

### Durable receipt reference lookup

```bash
export TCD_HTTP_RECEIPT_REF_STORE_DSN="sqlite:////tmp/tcd_receipt_ref_store.sqlite3"
```

Alternative:

```bash
export TCD_HTTP_RECEIPT_REF_STORE_PATH="/tmp/tcd_receipt_ref_store.sqlite3"
```

### Durable evidence store

```bash
export TCD_HTTP_EVIDENCE_STORE_DSN="sqlite:////tmp/tcd_evidence_store.sqlite3"
export TCD_HTTP_REQUIRE_DURABLE_EVIDENCE=1
export TCD_HTTP_REQUIRE_COMMIT_RECEIPT_AFTER_DURABLE=1
```

Alternative:

```bash
export TCD_HTTP_EVIDENCE_STORE_PATH="/tmp/tcd_evidence_store.sqlite3"
```

### SecurityRouter and PolicyStore

```bash
export TCD_POLICY_STORE_ENABLE=1
export TCD_HTTP_SECURITY_ROUTER_ENABLE=1
export TCD_SECURITY_ROUTER_ENABLE=1
export TCD_SECURITY_ROUTER_ATTESTOR_ENABLE=1
export TCD_SECURITY_ROUTER_DURABLE_RECEIPTS=1
export TCD_SECURITY_ROUTER_REQUIRE_LEDGER_WHEN_REQUIRED=1
export TCD_SECURITY_ROUTER_REQUIRE_TERMINAL_GOVERNANCE_FOR_RECEIPT=1
export TCD_SECURITY_ROUTER_REQUIRE_STORAGE_READY_FOR_RECEIPT=1
export TCD_SECURITY_ROUTER_LOCAL_LEDGER_ENABLE=1
export TCD_SECURITY_ROUTER_LOCAL_AUDIT_ENABLE=1
export TCD_SECURITY_ROUTER_OUTBOX_ENABLE=1
```

Policy input can be provided by:

```bash
TCD_POLICIES_FILE
TCD_POLICY_FILE
TCD_POLICIES_PATH
TCD_SECURITY_POLICIES_FILE
TCD_POLICIES_JSON
TCD_POLICY_JSON
TCD_SECURITY_POLICIES_JSON
```

If SecurityRouter or PolicyStore is requested and no external policy is provided, `service_http` can build a safe default compatibility policy store.

### Supply-chain binding

```bash
export TCD_BUILD_ID="build-demo"
export TCD_IMAGE_DIGEST="sha256:demo-image"
```

These values can also be supplied per request as `build_id` and `image_digest`.

### Authentication

```bash
export TCD_HTTP_REQUIRE_TOKEN=1
export TCD_HTTP_SERVICE_TOKEN="dev-service-token"
```

Client request:

```bash
curl -sS \
  -H "X-TCD-Service-Token: dev-service-token" \
  http://127.0.0.1:8080/runtime/public
```

---

## Guarantees vs non-guarantees

This section is intentionally explicit.

### Strong local guarantees available now

TCD provides strong local or single-process / single-node semantics for:

- request/session/chain identity establishment
- bounded ingress behavior
- explicit decision identities
- explicit route and security contracts
- verify-first ingest
- explicit storage conflict instead of silent overwrite
- anti-fork receipt-chain constraints within store boundaries
- local audit anchoring
- continuous chain auditing
- prepare/commit action governance
- idempotent replay for committed actions
- outbox conflict detection and retry/flush behavior
- durable receipt reference lookup when backed by configured SQLite storage
- signed receipt verification under configured HMAC attestation

### Shared-persistence guarantees validated under tested profiles

With a shared SQLite receipt store and server-assigned chain positioning, the validation suite has demonstrated:

- cross-node read/verify after one node writes
- tail/page access from a second node
- concurrent A/B commits into one chain
- no duplicate receipt heads under tested load
- no duplicate chain sequence under tested load
- no fork, cycle, or missing predecessor under tested load
- one genesis and one leaf in the tested chain

This is stronger than local-only behavior, but it is still shared-storage consistency, not global distributed consensus.

### Capacity-boundary behavior validated under tested staging profile

With local single-process staging settings and 100 concurrent clients, the validation suite has demonstrated:

- 5,000 / 5,000 allow-only requests returned HTTP 200
- allow-only failure count was zero
- 5,000 / 5,000 mixed workload requests returned HTTP 200
- mixed workload curl error count was zero
- mixed workload diagnose failure count was zero
- sampled receipt verification passed for receipt-bearing decisions in the mixed workload

This is a staging capacity-boundary validation, not a universal performance guarantee for every production deployment.

### What remains local-best-effort unless stronger infrastructure is added

Without external coordination or shared state, do not describe the following as globally strong guarantees:

- multi-instance config/policy propagation
- globally ordered receipt streams
- globally shared statistical budget state
- globally synchronized route decisions
- distributed consensus semantics for ledger ordering
- multi-region receipt ordering
- hardware-backed signing guarantees across all deployment environments

### Control-plane semantics to state explicitly

TCD makes several operational semantics explicit:

- policies/config are process-local atomic swaps unless externally coordinated
- multi-instance propagation is best-effort unless backed by coordination
- receipt store writes are idempotent at the boundary
- overwrite attempts should become explicit conflicts
- receipt ordering is storage-view unless the backend guarantees more
- ledger behavior is at-least-once with deterministic event IDs for dedupe
- outbox states are explicit: queued, flushed, committed, ignored, or conflict
- crash before commit must not appear as committed
- crash after commit before response should replay idempotently under the same key
- readiness is separate from liveness

### Crypto boundary honesty

TCD defines a governed cryptographic control plane and validates receipt integrity checks, but it should not be marketed as a fully production-complete PQ or hardware-rooted stack unless the exact backend, key-management environment, hardware-root profile, and deployment policy are specified.

---

## Design principles

### Content-agnostic by default

Evidence, storage, signals, telemetry, and most runtime outputs are designed to avoid carrying raw prompts, completions, request bodies, response bodies, cookies, or authorization material.

TCD prefers:

- structured identifiers
- bounded metadata
- artifact references
- digests

### Deterministic and reproducible

Canonical JSON, stable digests, message versions, bounded normalization, stable event IDs, decision IDs, route IDs, receipt heads, and chain heads are treated as system primitives, not convenience features.

### Explicit conflict over silent overwrite

Storage, admin ingest, ledger, and outbox layers prefer:

- explicit conflict
- idempotent dedupe
- anti-fork semantics
- stable original payload preservation

over hidden replacement or last-write-wins behavior.

### Governance over convenience

Strict modes, scope enforcement, approvals, change tickets, break-glass, outbox fallback, and prepare/commit semantics appear repeatedly because TCD optimizes for governance and verifiability, not just API ergonomics.

### Boundedness everywhere

Untrusted input is always expected. Body size, JSON depth, cardinality, evidence node counts, string lengths, queue sizes, stream counts, chain windows, outbox payload size, receipt body size, and patch segment sizes are bounded throughout the system.

### Crash windows are first-class

TCD treats crash windows as part of the control-plane contract:

- prepare happened, commit did not happen
- commit happened, response did not return
- ledger unavailable, outbox queued
- duplicate write, same digest
- duplicate write, different digest
- restart, lookup, and verify

These are not afterthoughts. They are part of the system semantics.

---

## Repository guide

### Transport and ingress

| File | Purpose |
|---|---|
| `service_http.py` | HTTP inference and receipt governance surface. |
| `service_grpc.py` | gRPC inference surface and outbox support. |
| `middleware.py` | Request/session/chain context, edge rate limit, metrics. |
| `middleware_request.py` | Higher-level request governance. |
| `middleware_security.py` | Edge security controls. |
| `auth.py` | Authentication and identity normalization. |

### Decision and policy

| File | Purpose |
|---|---|
| `detector.py` | Bounded detector runtime. |
| `calibration.py` | Score-to-p calibration core. |
| `multivariate.py` | Multivariate risk detector. |
| `decision_engine.py` | Explicit decision interpreter. |
| `risk_av.py` | Always-valid statistical controller. |
| `routing.py` | Strategy router. |
| `security_router.py` | Policy/risk/route/evidence orchestration. |
| `policies.py` | Policy compilation and binding. |
| `ratelimit.py` | Compiled-bundle runtime rate limiting. |

### Evidence and persistence

| File | Purpose |
|---|---|
| `schemas.py` | Unified public/audit/receipt/verification views. |
| `signals.py` | Governed signal/evidence bus. |
| `attest.py` | Structured attestation generator. |
| `crypto.py` | Crypto control-plane substrate. |
| `verify.py` | Receipt and chain verification. |
| `storage.py` | Governed persistence boundary. |
| `ledger.py` | Durable write and receipt-chain substrate. |
| `audit.py` | Local append-only audit trust anchor. |
| `auditor.py` | Chain auditor. |
| `receipt_v2.py` | Compatibility-oriented receipt body builder. |

### Governance execution

| File | Purpose |
|---|---|
| `admin_http.py` | Admin-only HTTP control plane. |
| `agent.py` | TrustAgent execution shell. |
| `patch_runtime.py` | Governed runtime patch pipeline. |
| `rewrite_engine.py` | Bounded rewrite proposal engine. |
| `trust_graph.py` | Relationship and trust-state layer. |

### Observability and foundations

| File | Purpose |
|---|---|
| `exporter.py` | Governed Prometheus exporter. |
| `otel_exporter.py` | Governed OTEL exporter. |
| `telemetry_gpu.py` | Governed GPU telemetry boundary. |
| `logging.py` | Structured logging surface. |
| `config.py` | Settings compiler / governor. |
| `kv.py` | Canonical key/value hashing and deterministic IDs. |
| `utils.py` | Shared sanitization and bounded JSON/meta helpers. |

---

## Recommended validation artifacts

When publishing claims, keep the test command, environment, runtime version, storage backend, concurrency level, total request count, sample verification count, latency summary, and pass/fail output with the release artifact.

Recommended validation artifacts include:

- full receipt governance closure test
- durable receipt readiness test
- negative receipt verification regression
- restart persistence test
- kill-after-prepare-before-commit test
- kill-after-commit-before-response test
- outbox failure/retry test
- outbox conflict test
- storage fault injection test
- multi-process shared-storage write test
- multi-node shared-persistence test
- capacity-boundary concurrency test
- soak test
- key rotation test
- malformed receipt fuzz test
- oversized JSON and Unicode boundary test
- SQLite corruption and WAL recovery test
- CI matrix across supported Python and dependency versions

---

## Release gate checklist

A release candidate should not be called production-ready unless the following are explicitly addressed.

### Functional release gate

```bash
python -m py_compile tcd/service_http.py
```

Expected:

```bash
PY_COMPILE_OK
```

### Full receipt governance gate

Expected:

```bash
ALL_FULL_RECEIPT_GOVERNANCE_TESTS_PASSED
FULL_RECEIPT_GOVERNANCE_EXIT_CODE=0
```

### Runtime cleanup gate

Before every local server or integration run:

```bash
lsof -nP -iTCP:8080 -sTCP:LISTEN || true
for p in $(lsof -tiTCP:8080 -sTCP:LISTEN 2>/dev/null); do kill "$p" 2>/dev/null || true; done
pkill -f "uvicorn.*tcd\.service_http:create_app" 2>/dev/null || true
pkill -f "curl .*127\.0\.0\.1:8080" 2>/dev/null || true
pkill -f "curl .*localhost:8080" 2>/dev/null || true
lsof -nP -iTCP:8080 -sTCP:LISTEN || true
```

### Evidence gate

Verify that the release candidate exercises:

- local fallback
- SecurityRouter
- PolicyStore
- local HMAC attestation
- durable SQLite evidence store
- durable SQLite receipt reference store
- schema-view receipt projection
- signed receipt body verification
- durable commit consistency
- ledger ref / commit ref consistency
- attestation ref
- audit / prepare / outbox refs in security mode
- PQ required / PQ signature
- restart receipt reference lookup
- restart storage-window chain verification
- wrong build/image negative verification
- wrong chain head negative verification

### Production hardening gate

Before describing a deployment as production-grade, add or document:

- high-concurrency soak beyond the current tested window
- key rotation and multi-kid verification
- key compromise recovery policy
- SQLite or backend corruption recovery playbook
- disk-full and permission fault runbooks
- outbox consumer, flush, retry, and dedupe operational proof
- TLS and authentication deployment profile
- secrets management profile
- backup and restore profile
- structured audit export profile
- dependency update and CVE response process
- multi-node or multi-region consistency model
- threat model
- third-party security review, if required by the deployment environment

---

## Available now

The current repository includes:

- strong ingress governance
- authentication normalization
- bounded detector/calibration/decision flow
- always-valid controller with structured state
- strategy routing and security orchestration
- unified evidence views
- attestation and verification paths
- durable receipt surfaces under configured profiles
- governed storage
- durable ledger
- local audit
- chain auditor
- explicit outbox queue/flush/conflict behavior
- admin control plane with explicit DoD semantics
- crash-aware prepare/commit/idempotency behavior
- staging capacity-boundary validation
- full receipt governance closure validation for local and security profiles

---

## Current limitations

The current system should still be treated as an engineering Alpha / Pre-Beta candidate because these areas need more hardening before broad production claims:

- long-running soak beyond current windows
- high-concurrency receipt-heavy workloads
- storage backend migration and schema versioning
- key rotation and multi-key verification
- stronger external KMS or hardware-rooted signing profile
- true PQ signing backend, if required
- multi-region ordering and consensus semantics
- policy propagation across multiple independent nodes
- global statistical budget state
- outbox consumer production runbook
- formal threat model
- external security audit
- compatibility matrix across dependency versions
- CI automation for the full governance closure suite

---

## In one sentence

> **TCD turns inference from an opaque application call into a governed systems event with identity, policy binding, statistical budget state, route contracts, verifiable evidence, durable receipt semantics, replay-aware control-plane actions, auditable persistence, and tested staging governance boundaries.**
