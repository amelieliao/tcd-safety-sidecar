#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${TCD_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
cd "$ROOT"

PY="${PY:-}"
if [ -z "$PY" ]; then
  if [ -x "$ROOT/venv/bin/python" ]; then
    PY="$ROOT/venv/bin/python"
  else
    PY="$(command -v python3 || command -v python)"
  fi
fi

PORT="${TCD_TEST_PORT:-8080}"
HOST="${TCD_TEST_HOST:-127.0.0.1}"
BASE_URL="http://${HOST}:${PORT}"
BASE_WORK="${TCD_TEST_WORKDIR:-/tmp/tcd_receipt_full_$(date +%Y%m%d_%H%M%S)_$$}"

mkdir -p "$BASE_WORK"
export PYTHONPATH="$ROOT:${PYTHONPATH:-}"
UVICORN_PID=""

log() { echo "$*"; }

cleanup_port() {
  if command -v lsof >/dev/null 2>&1; then
    for p in $(lsof -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null || true); do
      kill "$p" 2>/dev/null || true
    done
  fi
  pkill -f "uvicorn.*tcd\.service_http:create_app" 2>/dev/null || true
  sleep 0.3
}

stop_server() {
  if [ -n "${UVICORN_PID:-}" ]; then
    kill "$UVICORN_PID" 2>/dev/null || true
    wait "$UVICORN_PID" 2>/dev/null || true
    UVICORN_PID=""
  fi
  cleanup_port
}

dump_debug() {
  echo "=============================="
  echo "DEBUG_WORKDIR=$BASE_WORK"
  echo "=============================="
  find "$BASE_WORK" -maxdepth 3 -type f \( -name "*.log" -o -name "*.json" \) -print | sort || true
  for f in $(find "$BASE_WORK" -maxdepth 3 -type f -name "uvicorn*.log" -print 2>/dev/null | sort); do
    echo "----- $f -----"
    tail -200 "$f" || true
  done
}

trap 'ec=$?; if [ "$ec" -ne 0 ]; then dump_debug; fi; stop_server; exit "$ec"' EXIT

python_compile_check() {
  log "PY_COMPILE_SERVICE_HTTP_ADMIN_GRPC"
  "$PY" - <<'PY'
import pathlib, py_compile, importlib
files = [
    pathlib.Path("tcd/service_http.py"),
    pathlib.Path("tcd/service_grpc.py"),
    pathlib.Path("tcd/admin_http.py"),
]
for p in files:
    if not p.exists():
        raise SystemExit(f"missing source file: {p}")
    py_compile.compile(str(p), doraise=True)

for mod in ("tcd.service_http", "tcd.service_grpc", "tcd.admin_http"):
    importlib.import_module(mod)

print("PY_COMPILE_OK")
PY
}

reset_governance_env() {
  unset TCD_HTTP_SECURITY_ROUTER_ENABLE || true
  unset TCD_SECURITY_ROUTER_ENABLE || true
  unset TCD_SECURITY_ROUTER_REQUIRED || true
  unset TCD_HTTP_REQUIRE_SECURITY_ROUTER || true
  unset TCD_POLICY_STORE_ENABLE || true
  unset TCD_POLICIES_FILE || true
  unset TCD_POLICY_FILE || true
  unset TCD_POLICIES_JSON || true
  unset TCD_POLICY_JSON || true
  unset TCD_SECURITY_POLICIES_JSON || true
  unset TCD_SECURITY_ROUTER_LEDGER_DB || true
  unset TCD_SECURITY_ROUTER_AUDIT_PATH || true
  unset TCD_SECURITY_ROUTER_OUTBOX_AUDIT_PATH || true
  unset TCD_SECURITY_ROUTER_OUTBOX_DB || true
  unset TCD_LEDGER_DB || true
}

setup_mode_env() {
  local mode="$1"
  local work="$2"

  reset_governance_env

  local hmac_hex
  hmac_hex="$("$PY" - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"

  local image_hex
  image_hex="$("$PY" - "$mode" <<'PY'
import hashlib, sys
print(hashlib.sha256(("tcd-ci-image-" + sys.argv[1]).encode()).hexdigest())
PY
)"

  export TCD_HASH_ALG=sha256
  export TCD_BUILD_ID="ci-build-${mode}"
  export TCD_IMAGE_DIGEST="sha256:${image_hex}"

  export TCD_ATTEST_HMAC_KEY="hex:${hmac_hex}"
  export TCD_RECEIPT_HMAC_KEY="hex:${hmac_hex}"
  export TCD_ATTEST_HMAC_KEY_ID="ci-hmac-${mode}"
  export TCD_RECEIPT_HMAC_KEY_ID="ci-hmac-${mode}"

  export TCD_HTTP_ENABLE_DOCS=0
  export TCD_HTTP_STRICT_MODE=0
  export TCD_HTTP_REQUIRE_TOKEN=0
  export TCD_HTTP_ALLOW_NO_AUTH_LOCAL=1
  export TCD_HTTP_ENABLE_AUTHENTICATOR=1
  export TCD_HTTP_LOCAL_AUTHENTICATOR_FALLBACK_ENABLE=1

  export TCD_HTTP_RECEIPTS_ENABLE_DEFAULT=1
  export TCD_HTTP_REQUIRE_RECEIPTS_ON_FAIL=1
  export TCD_HTTP_REQUIRE_RECEIPTS_WHEN_PQ=1
  export TCD_HTTP_REQUIRE_ATTESTOR_WHEN_RECEIPT_REQUIRED=1
  export TCD_HTTP_REQUIRE_FINAL_RECEIPT_SURFACE_STRICT=1

  export TCD_HTTP_EXPOSE_VERIFICATION_BUNDLE_PUBLIC=1
  export TCD_HTTP_EXPOSE_VERIFY_KEY_PUBLIC=1
  export TCD_HTTP_EXPOSE_LEGACY_RECEIPT_ALIASES=0

  export TCD_HTTP_RECEIPT_SELF_CHECK=1
  export TCD_HTTP_RECEIPT_ISSUE_TIMEOUT_MS=5000
  export TCD_HTTP_RECEIPT_SELF_CHECK_TIMEOUT_MS=5000
  export TCD_HTTP_RECEIPT_VERIFY_TIMEOUT_MS=5000
  export TCD_HTTP_RECEIPT_SURFACE_TIMEOUT_MS=5000
  export TCD_HTTP_RECEIPT_USE_SCHEMA_VIEW=1

  export TCD_VERIFY_RECEIPT_BODY_MAXBYTES=1048576
  export TCD_HTTP_MAX_BODY_BYTES=1048576
  export TCD_HTTP_MAX_JSON_COMPONENT_BYTES=524288

  export TCD_HTTP_RECEIPT_REF_STORE_PATH="$work/receipt_refs.sqlite3"
  export TCD_HTTP_EVIDENCE_STORE_PATH="$work/evidence.sqlite3"
  export TCD_HTTP_REQUIRE_DURABLE_EVIDENCE=1
  export TCD_HTTP_REQUIRE_COMMIT_RECEIPT_AFTER_DURABLE=1
  export TCD_HTTP_EVIDENCE_CHAIN_NAMESPACE="service_http"
  export TCD_HTTP_EVIDENCE_CHAIN_ID="receipts_${mode}"

  if [ "$mode" = "security" ]; then
    export TCD_POLICY_STORE_ENABLE=1
    export TCD_HTTP_SECURITY_ROUTER_ENABLE=1
    export TCD_SECURITY_ROUTER_ENABLE=1
    export TCD_SECURITY_ROUTER_ATTESTOR_ENABLE=1
    export TCD_SECURITY_ROUTER_DURABLE_RECEIPTS=1
    export TCD_SECURITY_ROUTER_REQUIRE_LEDGER_WHEN_REQUIRED=1
    export TCD_SECURITY_ROUTER_REQUIRE_STORAGE_READY_FOR_RECEIPT=1
    export TCD_SECURITY_ROUTER_REQUIRE_TERMINAL_GOVERNANCE_FOR_RECEIPT=1
    export TCD_SECURITY_ROUTER_LOCAL_LEDGER_ENABLE=1
    export TCD_SECURITY_ROUTER_LOCAL_AUDIT_ENABLE=1
    export TCD_SECURITY_ROUTER_OUTBOX_ENABLE=1
    export TCD_SECURITY_ROUTER_LEDGER_DB="$work/security_router_ledger.sqlite3"
    export TCD_LEDGER_DB="$work/ledger.sqlite3"
    export TCD_SECURITY_ROUTER_AUDIT_PATH="$work/security_router_audit.log"
    export TCD_SECURITY_ROUTER_OUTBOX_AUDIT_PATH="$work/security_router_outbox.log"
    export TCD_SECURITY_ROUTER_OUTBOX_DB="$work/security_router_outbox.sqlite3"
  fi
}

start_server() {
  local work="$1"
  local log_file="$2"

  cleanup_port

  (
    cd "$ROOT"
    "$PY" -m uvicorn tcd.service_http:create_app \
      --factory \
      --host "$HOST" \
      --port "$PORT"
  ) >"$log_file" 2>&1 &

  UVICORN_PID="$!"
  echo "$UVICORN_PID" > "$work/uvicorn.pid"

  for _ in $(seq 1 120); do
    if curl -fsS "$BASE_URL/healthz" > "$work/healthz.json" 2>/dev/null; then
      curl -fsS "$BASE_URL/runtime/public" > "$work/runtime_public.json" 2>/dev/null || true
      log "UVICORN_READY pid=$UVICORN_PID"
      return 0
    fi
    sleep 0.25
  done

  echo "uvicorn did not become ready"
  tail -200 "$log_file" || true
  return 1
}

http_post_json() {
  local path="$1"
  local in_json="$2"
  local out_json="$3"
  local code

  code="$(curl -sS \
    -o "$out_json" \
    -w "%{http_code}" \
    --max-time 30 \
    -X POST "$BASE_URL$path" \
    -H "Content-Type: application/json" \
    -H "X-Request-Id: ci-${RANDOM}-${RANDOM}" \
    --data-binary @"$in_json" || true)"

  if [ "$code" != "200" ]; then
    echo "HTTP $path returned $code"
    cat "$out_json" || true
    return 1
  fi
}

validate_verify_result() {
  local file="$1"
  local expected="$2"
  local label="$3"

  "$PY" - "$file" "$expected" "$label" <<'PY'
import json, sys
path, expected_raw, label = sys.argv[1], sys.argv[2], sys.argv[3]
obj = json.load(open(path, "r", encoding="utf-8"))
expected = expected_raw.lower() == "true"
actual = bool(obj.get("ok"))
if actual != expected:
    raise SystemExit(f"{label}: expected ok={expected}, got {actual}, body={json.dumps(obj, sort_keys=True)[:4000]}")
print(f"{label}: ok={actual}")
PY
}

write_diagnose_request() {
  local mode="$1"
  local work="$2"

  cat > "$work/diagnose.json" <<JSON
{
  "tenant": "ci-${mode}",
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
  "context": {
    "detector_text": "benign receipt governance CI check",
    "env": "ci",
    "data_class": "test"
  },
  "tokens_delta": 50,
  "drift_score": 0.0,
  "trust_zone": "partner",
  "route_profile": "inference",
  "risk_label": "normal",
  "pq_required": true,
  "build_id": "${TCD_BUILD_ID}",
  "image_digest": "${TCD_IMAGE_DIGEST}",
  "base_temp": 0.7,
  "base_top_p": 0.9
}
JSON

  log "WROTE_DIAGNOSE_REQUEST"
}

write_verify_requests_and_summary() {
  local mode="$1"
  local work="$2"

  "$PY" - "$work" "$mode" <<'PY'
import json, os, sys

work, mode = sys.argv[1], sys.argv[2]

def load(name):
    with open(os.path.join(work, name), "r", encoding="utf-8") as f:
        return json.load(f)

resp = load("diagnose_response.json")
health = load("healthz.json")
runtime = load("runtime_public.json") if os.path.exists(os.path.join(work, "runtime_public.json")) else {}

components = resp.get("components") if isinstance(resp.get("components"), dict) else {}
artifacts = resp.get("artifacts") if isinstance(resp.get("artifacts"), dict) else components.get("artifacts", {})
evidence = resp.get("evidence_identity") if isinstance(resp.get("evidence_identity"), dict) else components.get("evidence_identity", {})
receipt_public = resp.get("receipt_public") if isinstance(resp.get("receipt_public"), dict) else components.get("receipt", {})
receipt_verification = resp.get("receipt_verification") if isinstance(resp.get("receipt_verification"), dict) else components.get("receipt_verification", {})

def first(*vals):
    for v in vals:
        if v not in (None, "", {}, []):
            return v
    return None

def must(cond, msg):
    if not cond:
        raise SystemExit(msg)

receipt_ref = first(resp.get("receipt_ref"), artifacts.get("receipt_ref"), evidence.get("receipt_ref"), receipt_public.get("receipt_ref"), receipt_verification.get("receipt_ref"))
ledger_ref = first(resp.get("ledger_ref"), artifacts.get("ledger_ref"), evidence.get("ledger_ref"), receipt_public.get("ledger_ref"), receipt_verification.get("ledger_ref"))
commit_ref = first(resp.get("commit_ref"), artifacts.get("commit_ref"), evidence.get("commit_ref"), receipt_public.get("commit_ref"), receipt_verification.get("commit_ref"))
attestation_ref = first(resp.get("attestation_ref"), artifacts.get("attestation_ref"), evidence.get("attestation_ref"), receipt_public.get("attestation_ref"), receipt_verification.get("attestation_ref"))
audit_ref = first(resp.get("audit_ref"), artifacts.get("audit_ref"), evidence.get("audit_ref"), receipt_public.get("audit_ref"), receipt_verification.get("audit_ref"))
prepare_ref = first(resp.get("prepare_ref"), artifacts.get("prepare_ref"), evidence.get("prepare_ref"), receipt_public.get("prepare_ref"), receipt_verification.get("prepare_ref"))
outbox_ref = first(resp.get("outbox_ref"), artifacts.get("outbox_ref"), evidence.get("outbox_ref"), receipt_public.get("outbox_ref"), receipt_verification.get("outbox_ref"))
outbox_status = first(resp.get("outbox_status"), artifacts.get("outbox_status"), evidence.get("outbox_status"), receipt_public.get("outbox_status"), receipt_verification.get("outbox_status"))
policy_ref = first(resp.get("policy_ref"), evidence.get("policy_ref"), receipt_public.get("policy_ref"), receipt_verification.get("policy_ref"))
policyset_ref = first(resp.get("policyset_ref"), evidence.get("policyset_ref"), receipt_public.get("policyset_ref"), receipt_verification.get("policyset_ref"))
policy_digest = first(receipt_public.get("policy_digest"), receipt_verification.get("policy_digest"), evidence.get("policy_digest"))
receipt_cfg_fp = first(resp.get("receipt_cfg_fp"), receipt_public.get("cfg_fp"), receipt_verification.get("cfg_fp"), resp.get("route_config_fingerprint"), resp.get("config_fingerprint"))
service_cfg_fp = resp.get("service_config_fingerprint")
decision_receipt_ref = artifacts.get("decision_receipt_ref")
commit_receipt_ref = first(artifacts.get("commit_receipt_ref"), receipt_ref)

must(receipt_ref, "receipt_ref missing")
must(ledger_ref, "ledger_ref missing")
must(commit_ref, "commit_ref missing")
must(ledger_ref == commit_ref, f"ledger_ref/commit_ref mismatch: {ledger_ref} != {commit_ref}")
must(attestation_ref, "attestation_ref missing")
must(receipt_cfg_fp, "receipt_cfg_fp missing")
must(service_cfg_fp, "service_config_fingerprint missing")
must(isinstance(receipt_verification, dict) and receipt_verification.get("head") and receipt_verification.get("body"), "receipt_verification material missing")

must(health.get("evidence_store_backend") == "sqlite", f"evidence store is not sqlite: {health.get('evidence_store_backend')}")
must(health.get("receipt_ref_store_backend") == "sqlite", f"receipt ref store is not sqlite: {health.get('receipt_ref_store_backend')}")
must(bool(runtime.get("receipt_use_schema_view", True)) is True, "schema-view disabled")

pq_required = first(resp.get("pq_required"), receipt_public.get("pq_required"), receipt_verification.get("pq_required"), artifacts.get("pq_required"), evidence.get("pq_required"))
pq_ok = first(resp.get("pq_ok"), receipt_public.get("pq_ok"), receipt_verification.get("pq_ok"), artifacts.get("pq_ok"), evidence.get("pq_ok"))
pq_sig_ok = first(resp.get("pq_signature_ok"), receipt_public.get("pq_signature_ok"), receipt_verification.get("pq_signature_ok"), artifacts.get("pq_signature_ok"), evidence.get("pq_signature_ok"))

must(pq_required is True, f"pq_required not true: {pq_required!r}")
must(pq_ok is True, f"pq_ok not true: {pq_ok!r}")
must(pq_sig_ok is True, f"pq_signature_ok not true: {pq_sig_ok!r}")

if mode == "local":
    must(health.get("security_router") is False, "local mode unexpectedly has security_router")
    must(health.get("policy_store") is False, "local mode unexpectedly has policy_store")

if mode == "security":
    must(health.get("security_router") is True, "security mode missing security_router")
    must(health.get("policy_store") is True, "security mode missing policy_store")
    must(policy_ref, "security mode policy_ref missing")
    must(policyset_ref, "security mode policyset_ref missing")
    must(audit_ref, "security mode audit_ref missing")
    must(prepare_ref, "security mode prepare_ref missing")
    must(outbox_ref, "security mode outbox_ref missing")
    must(outbox_status == "queued", f"security mode outbox_status not queued: {outbox_status!r}")

base_verify = {
    "receipt_verification": receipt_verification,
    "receipt_ref": receipt_ref,
    "pq_required": True,
    "require_signature": True,
    "expected_build_id": os.environ["TCD_BUILD_ID"],
    "expected_image_digest": os.environ["TCD_IMAGE_DIGEST"],
    "expected_service_config_fingerprint": service_cfg_fp,
    "expected_receipt_cfg_fp": receipt_cfg_fp
}
if policy_ref:
    base_verify["expected_policy_ref"] = policy_ref
if policyset_ref:
    base_verify["expected_policyset_ref"] = policyset_ref
if policy_digest:
    base_verify["expected_policy_digest"] = policy_digest

by_ref = dict(base_verify)
by_ref.pop("receipt_verification", None)

bad_build = dict(base_verify)
bad_build["expected_build_id"] = "WRONG-BUILD-ID"

bad_image = dict(base_verify)
bad_image["expected_image_digest"] = "sha256:" + ("0" * 64)

storage_good = {
    "verify_storage_window": True,
    "storage_window_limit": 100,
    "expected_latest_chain_head": commit_ref,
    "expected_ledger_ref": ledger_ref,
    "expected_commit_ref": commit_ref,
    "expected_service_config_fingerprint": service_cfg_fp
}

storage_bad = dict(storage_good)
storage_bad["expected_latest_chain_head"] = "wrong-chain-head"
storage_bad["expected_ledger_ref"] = "wrong-ledger-ref"
storage_bad["expected_commit_ref"] = "wrong-commit-ref"

for name, payload in {
    "verify_receipt.json": base_verify,
    "verify_receipt_by_ref.json": by_ref,
    "verify_bad_build.json": bad_build,
    "verify_bad_image.json": bad_image,
    "verify_storage_good.json": storage_good,
    "verify_storage_bad.json": storage_bad,
}.items():
    with open(os.path.join(work, name), "w", encoding="utf-8") as f:
        json.dump(payload, f, sort_keys=True, indent=2)

summary = {
    "mode": mode,
    "receipt_ref": receipt_ref,
    "decision_receipt_ref": decision_receipt_ref,
    "commit_receipt_ref": commit_receipt_ref,
    "ledger_ref": ledger_ref,
    "commit_ref": commit_ref,
    "attestation_ref_present": bool(attestation_ref),
    "audit_ref_present": bool(audit_ref),
    "prepare_ref_present": bool(prepare_ref),
    "outbox_ref_present": bool(outbox_ref),
    "outbox_status": outbox_status or "none",
    "policy_ref": policy_ref,
    "policyset_ref": policyset_ref,
    "policy_digest_present": bool(policy_digest),
    "receipt_cfg_fp": receipt_cfg_fp,
    "service_config_fingerprint": service_cfg_fp,
    "schema_view_enabled": bool(runtime.get("receipt_use_schema_view", True)),
    "security_router": bool(health.get("security_router")),
    "policy_store": bool(health.get("policy_store")),
    "evidence_store_backend": health.get("evidence_store_backend"),
    "receipt_ref_store_backend": health.get("receipt_ref_store_backend"),
    "pq_ok": bool(pq_ok),
    "pq_signature_ok": bool(pq_sig_ok)
}

with open(os.path.join(work, "summary.json"), "w", encoding="utf-8") as f:
    json.dump(summary, f, sort_keys=True, indent=2)

print("WROTE_VERIFY_REQUESTS")
PY
}

run_suite() {
  local mode="$1"
  local work="$BASE_WORK/$mode"
  mkdir -p "$work"

  log "=============================="
  log "RUN_SUITE mode=$mode work=$work"
  log "=============================="

  setup_mode_env "$mode" "$work"

  log "CHECK_PORT_${PORT}_BEFORE_CLEAN"
  cleanup_port
  log "CHECK_PORT_${PORT}_AFTER_CLEAN"

  start_server "$work" "$work/uvicorn.log"

  write_diagnose_request "$mode" "$work"
  http_post_json "/diagnose" "$work/diagnose.json" "$work/diagnose_response.json"

  curl -fsS "$BASE_URL/healthz" > "$work/healthz.json"
  curl -fsS "$BASE_URL/runtime/public" > "$work/runtime_public.json"

  write_verify_requests_and_summary "$mode" "$work"

  http_post_json "/verify" "$work/verify_receipt.json" "$work/verify_receipt_response.json"
  validate_verify_result "$work/verify_receipt_response.json" true "${mode}: receipt verification"

  http_post_json "/verify" "$work/verify_bad_build.json" "$work/verify_bad_build_response.json"
  validate_verify_result "$work/verify_bad_build_response.json" false "${mode}: bad build negative"

  http_post_json "/verify" "$work/verify_bad_image.json" "$work/verify_bad_image_response.json"
  validate_verify_result "$work/verify_bad_image_response.json" false "${mode}: bad image negative"

  http_post_json "/verify" "$work/verify_storage_good.json" "$work/verify_storage_good_response.json"
  validate_verify_result "$work/verify_storage_good_response.json" true "${mode}: storage window verification"

  http_post_json "/verify" "$work/verify_storage_bad.json" "$work/verify_storage_bad_response.json"
  validate_verify_result "$work/verify_storage_bad_response.json" false "${mode}: bad chain head negative"

  log "RESTART_SERVER_FOR_DURABLE_RECEIPT_REF_AND_CHAIN mode=$mode"
  stop_server
  start_server "$work" "$work/uvicorn_restart.log"

  http_post_json "/verify" "$work/verify_receipt_by_ref.json" "$work/verify_receipt_by_ref_after_restart_response.json"
  validate_verify_result "$work/verify_receipt_by_ref_after_restart_response.json" true "${mode}: restart receipt_ref lookup"

  http_post_json "/verify" "$work/verify_storage_good.json" "$work/verify_storage_good_after_restart_response.json"
  validate_verify_result "$work/verify_storage_good_after_restart_response.json" true "${mode}: restart storage window verification"

  stop_server

  log "${mode}: FULL_RECEIPT_GOVERNANCE_SUITE_PASSED"
  cat "$work/summary.json"
}

log "ROOT=$ROOT"
log "PY=$PY"
"$PY" --version
log "BASE_WORK=$BASE_WORK"

python_compile_check

run_suite local
run_suite security

log "=============================="
log "ALL_FULL_RECEIPT_GOVERNANCE_TESTS_PASSED"
log "WORKDIR=$BASE_WORK"
log "=============================="

log "LOCAL_SUMMARY"
cat "$BASE_WORK/local/summary.json"
echo
log "SECURITY_SUMMARY"
cat "$BASE_WORK/security/summary.json"
echo

log "FINAL_WORKDIR=$BASE_WORK"
