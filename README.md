# TCD

> **Trusted Control Plane for Governed, Quantified, and Verifiable AI Inference**

TCD is an infrastructure-native control plane for AI inference.

It sits beside model-serving runtimes, intercepts inference requests before or around execution, binds each request to identity and policy context, evaluates runtime risk and statistical budget state, produces an explicit decision, and emits verifiable evidence that can be stored, replayed, audited, and independently verified.

In practical terms, **TCD turns an LLM call from an opaque application-side operation into a governed systems event**.

---

## Current maturity

The current `service_http` / receipt governance / KMS-backed receipt subsystem has moved beyond a runnable PoC.

Based on the latest full receipt governance closure tests, shared durable evidence-chain consistency tests, and completed KMS/HSM validation track, the subsystem is best described as:

> **Receipt Governance + KMS/HSM Subsystem: engineering beta candidate for staging, internal trial, and controlled production-pilot evaluation under the tested profiles. KMS-backed receipt signing, verification, allowlist policy, fail-closed behavior, rotation, revocation, and hardware-root provenance have completed the current K1-K7 validation track. This is still not a production compliance certification, third-party security audit, real-provider HSM certification, or global distributed-consensus claim.**

This means the current repository has demonstrated a working, test-backed governance loop across:

| Area | Current state |
|---|---|
| Functionality | Receipt generation, signing, public view, verification view, persistence, restart recovery, chain verification, and KMS/HSM-backed signing paths are connected. |
| Governance closure | Both local fallback and SecurityRouter / PolicyStore paths have been exercised. |
| KMS/HSM signing maturity | K1-K7 passed: signer abstraction, KMS issuance, key allowlist enforcement, fail-closed signing faults, key rotation, revocation, and hardware-root KMS/HSM profile. |
| Hardware-root provenance | K7 passed with hardware signature verification, key provenance verification, attestation-chain verification, non-exportable key proof, storage-window verification, restart lookup, rotation/revocation, and audit correlation. |
| Durable evidence | SQLite-backed evidence store and receipt reference store survive process restart. |
| Integrity verification | Signed receipt body, commit receipt, ledger ref, commit ref, receipt_ref lookup, and consistency checks are validated. |
| Security binding | Build/image supply-chain binding, PQ-required path, PQ-signature path, KMS key allowlist, key scope, revocation policy, and negative verification paths are covered. |
| Shared persistence | Multi-worker, multi-process, and staged multi-node shared SQLite receipt-chain tests passed without fork or missing predecessor. |
| Failure recovery | Restart, periodic restart, `kill -9` recovery, KMS timeout, KMS unavailable, malformed KMS response, corrupted signature, and response-loss replay paths were tested. |
| Operational testability | Uvicorn startup, cleanup, restart, logs, summaries, artifacts, KMS fake backends, durable DBs, and pass/fail gates are scripted. |
| Failure awareness | Wrong build/image, wrong chain head, disallowed key, wrong key binding, post-revocation old-key receipt, hardware attestation mismatch, hardware timeout, and audit-correlation regressions fail as expected. |

The current maturity level is therefore:

```bash
Receipt Governance + KMS/HSM Subsystem: Engineering Beta Candidate
Recommended use: staging, internal trial, controlled pilot, integration hardening, CI regression, and engineering review
Validated now: KMS K1-K7, full receipt governance, shared durable evidence-chain M2-M8
Not yet: production compliance certification, third-party security audit, real-provider HSM certification, global consensus claim, or multi-region ordering guarantee
```

Important maturity boundary:

```bash
KMS completed validation track: K1-K7
K7 scope: K7.1-K7.10 hardware-root KMS/HSM profile
Current final KMS gate: K7 hardware-root profile
```

---

## Latest KMS / HSM validation

The KMS validation track has passed from K1 through K7.

Overall engineering conclusion:

```bash
KMS_SIGNER_ADAPTER_COMPATIBILITY=PASS
KMS_SIGN_LOCAL_VERIFY=PASS
KMS_VERIFY_ALLOWLIST=PASS
KMS_TIMEOUT_FAIL_CLOSED=PASS
KMS_KEY_ROTATION=PASS
KMS_KEY_REVOCATION=PASS
KMS_HARDWARE_ROOT_PROFILE=PASS
KMS_CURRENT_COMPLETED_TRACK=K1_THROUGH_K7
KMS_FINAL_CURRENT_GATE=K7_HARDWARE_ROOT_PROFILE
```

### KMS validation summary

| Gate | Focus | Result | Key evidence |
|---|---|---:|---|
| K1 | Signer backend abstraction + local HMAC backward compatibility | PASS | Local HMAC issue/verify preserved, signer interface present, verify contract reused, receipt_ref lookup and storage_window still work, negative verification regressions fail as expected. |
| K2 | KMS sign + local verify | PASS | Fake KMS path signs receipts, KMS key identity enters receipt and durable DB metadata, local `/verify` validates KMS signature, tampered KMS receipts fail, no silent local HMAC fallback, restart lookup passes, mixed HMAC + KMS signer history remains linear. |
| K3 | KMS verify-key allowlist enforcement | PASS | Valid signature is not sufficient; signing key must be governed and allowlisted. Unknown keys, disallowed keys, wrong key binding, algorithm confusion, scope misuse, key-id normalization attacks, receipt_ref bypass, and storage_window bypass are rejected. |
| K4 | KMS timeout/error/malformed/corrupted-signature fail-closed behavior | PASS | KMS timeout, unavailable, explicit errors, malformed responses, and corrupted signatures fail closed. No fake committed receipt, no late commit after timeout, no duplicate committed receipt, and response-loss replay returns the original committed receipt. |
| K5 | KMS key rotation | PASS | Old-key receipts remain verifiable, new receipts use new key, old/new allowlist works during rotation window, storage_window remains valid, restart preserves rotation state, multi-node staggered rollout does not fork chain, idempotent replay does not re-sign old committed requests. |
| K6 | KMS key revocation | PASS | Old key is `revoked_for_signing` while historical verification remains allowed. Revoked key cannot create new trusted receipts, post-revocation old-key receipts fail even with cryptographically valid signatures, timestamp tamper cannot bypass revocation, receipt_ref/storage_window/restart policy behavior is consistent. |
| K7 | Hardware-root KMS/HSM profile | PASS | Hardware signature, hardware-root policy, key provenance, attestation chain, non-exportable key proof, restart lookup, storage window, negative material rejection, fail-closed hardware signer behavior, hardware rotation/revocation, and audit correlation all pass. |

### K1: signer adapter compatibility

K1 validates that introducing the signer backend abstraction does not regress the existing local HMAC receipt system.

Key validated properties:

```bash
K1_SIGNER_ADAPTER_RC=0
passed=true
failed_gates=[]
signer_interface_present=true
local_hmac_function_still_present=true
verify_contract_reused=true
signature_verified=true
integrity_ok=true
verify_input_source=receipt_ref_lookup
storage_window_ok=true
negative_tests_fail_as_expected=true
```

Engineering interpretation:

> K1 preserves the migration boundary. The system can introduce KMS-style signer abstraction without changing local HMAC canonicalization, signature semantics, receipt_ref lookup, durable evidence behavior, or existing verification contract.

### K2: KMS sign + local verify

K2 validates that the fake KMS signing path can issue receipts carrying KMS key identity and that the existing local verify contract validates the signed material.

Key validated properties:

```bash
K2_KMS_SIGN_LOCAL_VERIFY_RC=0
passed=true
failed_gates=[]
kms_sign_success=true
kms_key_id_in_receipt=true
kms_signature_verified=true
kms_receipt_ref_lookup_ok=true
kms_restart_verify_ok=true
tampered_kms_receipts_fail=true
no_unexpected_local_hmac_fallback=true
storage_window_ok=true
forks=0
missing_prev=0
tip_count=1
```

Engineering interpretation:

> K2 proves the KMS path is not merely accepted by shape. Receipt verification checks the signed material, key identity is persisted, tampered KMS receipts fail, restart lookup works, and KMS + local HMAC signer histories can coexist in one durable chain.

### K3: KMS allowlist enforcement

K3 validates governed key identity enforcement.

Key validated properties:

```bash
K3_KMS_ALLOWLIST_RC=0
passed=true
failed_gates=[]
negative_cases_100_percent_failed=true
allowed_key_passes=true
unknown_key_fails=true
disallowed_key_fails=true
wrong_key_id_binding_fails=true
algorithm_confusion_rejected=true
key_scope_enforced=true
key_id_normalization_safe=true
receipt_ref_lookup_enforces_allowlist=true
storage_window_enforces_allowlist=true
```

Engineering interpretation:

> K3 closes the policy gap between cryptographic validity and governed verification. A valid signature must also come from an explicitly allowlisted key, with the expected algorithm, scheme, tenant, chain namespace, and chain ID.

### K4: KMS timeout / fail-closed receipt semantics

K4 validates production-critical fail-closed behavior when KMS signing cannot be trusted.

Key validated properties:

```bash
K4_KMS_TIMEOUT_FAIL_CLOSED_RC=0
passed=true
failed_gates=[]
kms_timeout_fails_closed=true
kms_unavailable_fails_closed=true
kms_error_fails_closed=true
kms_malformed_response_fails_closed=true
kms_bad_signature_detected=true
no_fake_committed_receipt=true
no_late_commit_after_timeout=true
idempotent_retry_after_failed_signing_ok=true
idempotent_replay_after_commit_response_loss_ok=true
optional_receipt_path_behavior_ok=true
critical_logs_zero_except_expected_kms_faults=true
```

Engineering interpretation:

> K4 protects the receipt-required path under degradation and adversarial KMS behavior. No trusted receipt is produced without trustworthy signing, no committed evidence is written for failed signing, timeout-late signatures cannot create late commits, and idempotency remains stable across failed-signing and response-loss crash windows.

### K5: KMS key rotation

K5 validates controlled old-to-new KMS key rotation.

Key validated properties:

```bash
K5_KMS_KEY_ROTATION_RC=0
passed=true
failed_gates=[]
old_key_receipts_verify_ok=true
new_key_receipts_verify_ok=true
new_receipts_use_new_key=true
old_receipts_remain_verifiable=true
storage_window_across_rotation_ok=true
restart_after_rotation_ok=true
idempotency_across_rotation_ok=true
no_unexpected_fallback=true
no_chain_fork=true
```

Additional stability evidence:

```bash
old_batch=500_receipts
new_batch=500_receipts
primary_rotation_volume=1000_receipts
restart_old_receipt_verify_ok=true
restart_new_receipt_verify_ok=true
restart_storage_window_ok=true
multi_node_staggered_rotation_ok=true
latest_chain_head_equal_all_nodes=true
same_receipt_ref_returned_for_idempotent_old_request=true
same_signature_returned_for_idempotent_old_request=true
no_new_signature_for_same_committed_request=true
```

Production note:

```bash
Recommended production setting:
TCD_KMS_ROTATION_PREFLIGHT_REQUIRED=1

Purpose:
Fail readiness on unsafe rotation configuration such as removing the old verify key too early.
```

Engineering interpretation:

> K5 demonstrates safe KMS receipt-key rotation under a controlled dual-track rotation window. Old receipts remain verifiable, new receipts use the new key, multi-node rollout does not fork the chain, restart preserves key state, and idempotent replay does not mint a new signature for an already committed old-key request.

### K6: KMS key revocation

K6 validates separation of historical verification from active signing authority.

Key validated properties:

```bash
K6_KMS_KEY_REVOCATION_RC=0
passed=true
failed_gates=[]
old_historical_receipts_verify_ok=true
revoked_key_new_signing_fails=true
post_revocation_old_key_receipts_fail=true
timestamp_tamper_cannot_bypass_revocation=true
receipt_ref_lookup_historical_policy_ok=true
storage_window_revocation_policy_ok=true
restart_revocation_policy_ok=true
```

Policy validated:

```bash
old_key_status=revoked_for_signing
historical_verify_allowed=true
active_signing_key=kms:test:receipt-key-v2
```

Engineering interpretation:

> K6 confirms that revocation removes signing authority without breaking historical auditability. Pre-revocation old-key receipts remain explicitly verifiable as historical, post-revocation old-key receipts fail even if cryptographically valid, timestamp tampering does not bypass policy, and direct verify, receipt_ref lookup, storage_window, and restart behavior remain aligned.

### K7: hardware-root KMS/HSM profile

K7 validates hardware-root KMS/HSM receipt signing and provenance.

Final result:

```bash
K7_HARDWARE_ROOT_PROFILE_RC=0
passed=true
failed_gates=[]
hardware_signature_verified=true
hardware_root_verified=true
key_provenance_verified=true
attestation_chain_verified=true
software_key_rejected_when_hardware_required=true
hardware_negative_cases_fail=true
hardware_timeout_fails_closed=true
hardware_storage_window_ok=true
hardware_restart_verify_ok=true
hardware_rotation_revocation_ok=true
audit_correlation_complete=true
```

Detailed properties validated:

```bash
K7.1_hardware_root_positive_receipt_ok=true
K7.1_signature_verified=true
K7.1_hardware_root_verified=true
K7.1_key_provenance_verified=true
K7.1_attestation_chain_verified=true
K7.1_key_non_exportable=true
K7.2_software_key_rejected_when_hardware_required=true
K7.3_attestation_chain_validation_ok=true
K7.3_negative_attestation_cases_fail=true
K7.4_non_exportable_key_proof_ok=true
K7.5_restart_hardware_receipt_ref_lookup_ok=true
K7.6_hardware_storage_window_ok=true
K7.6_no_forks_missing_prev_tip_one=true
K7.7_hardware_negative_cases_fail=true
K7.8_hardware_timeout_fails_closed=true
K7.8_no_fake_committed_receipt=true
K7.8_no_late_commit_after_hardware_timeout=true
K7.9_old_hardware_key_historical_verify_ok=true
K7.9_new_hardware_key_used_for_new_receipts=true
K7.9_revoked_hardware_key_cannot_new_sign=true
K7.9_hardware_provenance_valid_for_both_keys=true
K7.10_hardware_signing_audit_correlation_complete=true
```

Hardware-root evidence surface:

```bash
signing_backend=hsm
hardware_profile=K7_HSM
hardware_root_required=true
hardware_root_verified=true
key_non_exportable=true
key_non_exportable_proof=provider_asserted
key_origin=hardware_generated
key_provenance_verified=true
attestation_chain_verified=true
attestation_chain_signature_ok=true
trust_anchor_known=true
attestation_doc_not_expired=true
attestation_identity_matches_policy=true
key_id_bound_to_attestation=true
hardware_policy_ref=hwpol:k7:hsm:v1
```

Audit-correlation fields validated:

```bash
receipt.event_id
receipt.receipt_ref
receipt.sig_key_id
hardware_signing_request_id
kms_or_hsm_audit_request_id
chain_seq
chain_head_hex
```

Engineering interpretation:

> K7 closes the current KMS/HSM track. A valid signature alone is not enough: receipts must also bind to hardware provenance, attestation chain, key identity, hardware policy, non-exportability, storage-window consistency, restart lookup, rotation/revocation policy, and audit correlation. The verifier accepts valid hardware-root receipts and rejects downgraded, expired, mismatched, tampered, software-generated, or wrong-policy material.

### KMS / HSM validation conclusion

The KMS/HSM track now supports the following scoped engineering claim:

> Under the tested fake-KMS and hardware-root profile, TCD can issue, persist, verify, rotate, revoke, and audit KMS/HSM-backed receipts with fail-closed behavior and hardware-root provenance enforcement. The K1-K7 validation track passed with no failed gates.

This is still a scoped engineering validation. It does not by itself claim:

- real cloud-provider production KMS certification
- real HSM vendor certification
- third-party security audit approval
- multi-region globally ordered signing semantics
- regulatory compliance certification
- indefinite production soak stability

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

## Latest shared durable evidence-chain consistency validation

TCD also completed a staged shared-persistence validation suite covering Phase A through Phase C, from single-machine multi-worker deployment to three-node recovery scenarios.

The suite validated that multiple TCD workers, processes, and nodes can write to a shared durable SQLite evidence store without corrupting the receipt chain, forking the chain, losing receipt references, or reverting to stale chain heads after restart or crash recovery.

### Summary

| Phase | Test | Focus | Result |
|---|---|---|---|
| Phase A | M2 | Single machine, 2 workers, shared SQLite store | PASS |
| Phase A | M3 | Single machine, 4 workers, shared SQLite store | PASS |
| Phase A | M3b | Single machine, 8 workers, high-pressure shared SQLite store | PASS |
| Phase B | M4 | Two uvicorn processes, different ports, shared store, A writes and B verifies | PASS |
| Phase B | M5 | Two uvicorn nodes concurrently writing the same receipt chain | PASS |
| Phase C | M6 | Three nodes concurrently writing with periodic node restarts | PASS |
| Phase C | M7 | Three nodes, Node A `kill -9`, B/C continue writing, A recovers | PASS |
| Phase C | M8 | Recovery verification: latest/window/tail/page/receipt_ref after M7 | PASS |

Overall result:

```bash
M2_WORKERS2_SHARED_SQLITE_RC=0
M3_WORKERS4_SHARED_SQLITE_RC=0
M3B_WORKERS8_SHARED_SQLITE_RC=0
M4_MULTI_UVICORN_SHARED_STORE_RC=0
M5_MULTI_UVICORN_CONCURRENT_SAME_CHAIN_RC=0
M6_THREE_UVICORN_PERIODIC_RESTART_SHARED_CHAIN_RC=0
M7_A_KILL_RESTART_BC_CONTINUE_SHARED_STORE_RC=0
M8_RECOVERY_VERIFY_TAIL_PAGE_WINDOW_RC=0
```

### Phase A: single-machine multi-worker shared store

Phase A validates whether multiple uvicorn workers inside one local service can safely write to the same durable `evidence.sqlite` and `receipt_refs.sqlite`.

#### M2: 2 workers, shared SQLite store

M2 validated the minimum multi-worker shared-store profile.

Key results:

| Metric | Result |
|---|---|
| Cases | cold-start and preinit |
| Cold-start requests | 4000 / 4000 HTTP 200 |
| Preinit requests | 4000 / 4000 HTTP 200 |
| Cold-start durable receipts | 4000 |
| Preinit durable receipts | 4001 |
| Restart receipt_ref lookup | 4000 / 4000 and 4001 / 4001 |
| Storage window verification | Full window verified before and after restart |
| Critical storage errors | 0 |

M2 passed both cold-start and preinit paths:

```bash
deployment_gate_passed=true
m2_cold_start_passed=true
m2_preinit_passed=true
```

M2 conclusion:

> A single machine with 2 uvicorn workers can share one SQLite-backed durable receipt store without receipt-chain fork, receipt-ref loss, or restart verification failure.

#### M3: 4 workers, shared SQLite store

M3 increased the worker count to 4 to validate higher writer pressure.

Key results:

| Metric | Result |
|---|---|
| Requests | 5000 / 5000 HTTP 200 |
| Durable receipts | 5001 including preinit receipt |
| Storage window checked | 5001 |
| Restart checked | 5001 |
| Restart receipt_ref lookup | 5001 / 5001 |
| Storage window max latency | approximately 4.05s |
| Critical storage errors | 0 |

M3 passed all functional, restart, observability, and performance gates:

```bash
passed=true
failed_preinit_gates=[]
failed_pre_restart_gates=[]
failed_restart_gates=[]
failed_observability_gates=[]
```

M3 conclusion:

> A single machine with 4 workers can concurrently append to the shared durable receipt chain and verify the full chain after restart without SQLite lock failure or evidence commit failure.

#### M3b: 8 workers, high-pressure shared SQLite store

M3b extended Phase A to 8 workers, above the expected early MVP worker count, to test whether shared SQLite behavior remains stable under higher local writer pressure.

Key results:

| Metric | Result |
|---|---|
| Requests | 6000 / 6000 HTTP 200 |
| Durable receipts | 6001 including preinit receipt |
| Storage window checked | 6001 |
| Restart checked | 6001 |
| Restart receipt_ref lookup | 6001 / 6001 |
| Storage window max latency | approximately 4.68s |
| Performance gates | Passed |
| Critical storage errors | 0 |

M3b conclusion:

> A single machine with 8 uvicorn workers did not produce fork, database locked failures, commit failures, receipt timeouts, or restart verification failures under the tested load.

### Phase B: multiple uvicorn processes, different ports, shared store

Phase B validates cross-process shared persistence. Each uvicorn process runs independently and shares the same durable receipt stores.

#### M4: two uvicorn processes, A writes and B verifies

M4 validated cross-process visibility and verification.

Key results:

| Metric | Result |
|---|---|
| Node A writes | 3200 / 3200 HTTP 200 |
| Node A receipt refs | 3200 / 3200 |
| Node B receipt_ref verification | 4784 / 4784 |
| Node B final all verify | 3200 / 3200 |
| Final storage window checked | 3200 on A and B |
| Final A/B latest chain head | Equal |
| Critical storage errors | 0 |

M4 passed all gates:

```bash
passed=true
failed_gates=[]
```

M4 conclusion:

> One uvicorn process can write durable receipts while another independent uvicorn process reads and verifies those receipts from the same store, including after restart.

#### M5: two uvicorn nodes concurrently writing the same chain

M5 validated two independent uvicorn nodes concurrently appending to the same `service_http/receipts` chain.

Key results:

| Metric | Result |
|---|---|
| Node A writes | 3000 / 3000 HTTP 200 |
| Node B writes | 3000 / 3000 HTTP 200 |
| Total writes | 6000 / 6000 HTTP 200 |
| Receipt refs | 6000 / 6000 |
| Storage window checked | 6000 on both nodes |
| Latest chain head | Equal before and after restart |
| Network errors | 0 |
| Critical storage errors | 0 |

M5 passed all gates:

```bash
passed=true
failed_gates=[]
a_b_latest_chain_head_equal=true
restart_a_b_latest_chain_head_equal=true
checked_count_equals_total_receipt_writes=true
traffic_covers_block_pq_supply_on_both_nodes=true
```

M5 observation:

```bash
evidence_store_file_lock_timeout=3
```

This did not cause failure. It did not produce commit failure, chain-head mismatch, fork, missing predecessor, or storage-window failure.

M5 conclusion:

> Two independent uvicorn nodes can concurrently write the same shared durable receipt chain while preserving a single latest chain head and complete full-window verification.

### Phase C: three-node concurrency and recovery

Phase C validates scenarios closer to staging: three nodes, shared durable stores, node restarts, crash recovery, and recovery-time global-chain verification.

#### M6: three nodes with concurrent writes and periodic restarts

M6 validated three concurrent writers while periodically restarting nodes.

Key results:

| Metric | Result |
|---|---|
| Node A writes | 2000 / 2000 HTTP 200 |
| Node B writes | 2000 / 2000 HTTP 200 |
| Node C writes | 2000 / 2000 HTTP 200 |
| Total writes | 6000 / 6000 HTTP 200 |
| Receipt refs | 6000 / 6000 |
| A/B/C storage window checked | 6000 each |
| A/B/C latest chain head | Equal |
| Chain sequence | contiguous, 0 through 5999 |
| Restart during other-node 5xx | 0 |
| Critical storage errors | 0 |

M6 passed all core gates:

```bash
passed=true
failed_gates=[]
three_node_http_200_equals_total=true
storage_window_ok_all=true
a_b_c_latest_chain_head_equal=true
checked_count_equals_total_receipt_writes=true
chain_seq_monotonic_if_available=true
```

M6 observations:

```bash
network_error=9
evidence_store_file_lock_timeout=495
```

These occurred around restart or file-lock waiting windows and did not cause chain corruption, storage failure, fork, missing predecessor, or commit failure.

M6 conclusion:

> Three uvicorn nodes can write a shared durable receipt chain through periodic restarts while preserving a single chain head, contiguous chain sequence, and full storage-window verification on every node.

#### M7: Node A `kill -9`, B/C continue writing, A recovers

M7 validated a stronger failure case: Node A is killed with inflight requests while B/C continue writing to the shared store.

Key results:

| Metric | Result |
|---|---|
| Node A acknowledged writes | 800 / 800 HTTP 200 |
| Node B acknowledged writes | 1200 / 1200 HTTP 200 |
| Node C acknowledged writes | 1200 / 1200 HTTP 200 |
| Total acknowledged writes | 3200 / 3200 HTTP 200 |
| Durable receipts in SQLite | 3207 |
| B/C continued during A down | true |
| A restart health | true |
| A/B/C storage window checked | 3207 each |
| A/B/C latest chain head | Equal after A restart |
| Chain sequence | contiguous, 0 through 3206 |
| Critical storage errors | 0 |

M7 passed all gates:

```bash
passed=true
failed_gates=[]
a_kill9_sent=true
a_restart_health_ok=true
b_during_a_down_http_200_continues=true
c_during_a_down_http_200_continues=true
a_b_c_latest_chain_head_equal_after_restart=true
storage_window_ok_all=true
no_fork_all_storage_windows=true
receipt_ref_lookup_ok_all_nodes=true
```

M7 important observation:

```bash
write_total_http_200=3200
evidence.receipts_v2=3207
A network_errors=64
```

This is expected under `kill -9` with inflight requests. Some durable commits can complete before the HTTP response is returned, then the client observes `RemoteDisconnected` and retries. The important result is that the chain remains valid:

```bash
chain_seq_contiguous=true
storage_window_ok_all=true
forks=0
missing_prev=0
tip_count=1
```

M7 conclusion:

> A crashed node does not roll back or overwrite the global chain. After Node A is killed and restarted, it reads the chain head advanced by B/C, proving recovery from shared durable state rather than stale local cache.

#### M8: recovery verification after M7

M8 validated that after M7 recovery, Node A can verify global state, old receipt references, selected receipt references, newest receipt references, bounded tail windows, and SQL page windows.

Key results:

| Metric | Result |
|---|---|
| M7 summary loaded | true |
| M7 passed | true |
| Shared evidence store exists | true |
| Shared receipt_ref store exists | true |
| A/B/C health | true |
| B/C continued M8 writes | 2 / 2 HTTP 200 |
| Final durable receipts | 3211 |
| A/B/C latest chain head | Equal |
| Full storage window checked | 3211 on A/B/C |
| Tail window checked | 128 on A/B/C |
| SQL chain sequence | contiguous, 0 through 3210 |
| Critical storage errors | 0 |

M8 passed all gates:

```bash
passed=true
failed_gates=[]
M8_RECOVERY_VERIFY_TAIL_PAGE_WINDOW_RC=0
```

M8 receipt_ref verification passed for:

- old M7 receipt_ref
- selected M7 receipt_ref
- newest M8 receipt_ref

All used durable lookup:

```bash
verify_input_source=receipt_ref_lookup
signature_verified=true
integrity_ok=true
```

M8 also confirmed signing-key continuity with M7:

```bash
must_match_m7=true
shared_hmac_key_id=tcd-attestor:hmac:m7-local
```

Tail-window note:

The raw service response for bounded tail-window verification may return `ok=false` when only a limited tail window is selected from a longer chain. M8 treats this as acceptable only when the bounded-window gates pass:

```bash
status=200
checked=128
latest_matches_expected=true
forks=0
missing_prev=0
tip_count=1
reasons include window_limit_exceeded
unacceptable_reasons=[]
```

M8 conclusion:

> After crash recovery, Node A can read and verify the global chain head advanced by B/C, verify old and new receipt references, validate bounded tail windows, and confirm contiguous SQL page windows. This proves the recovered node is reading shared global state rather than stale local state.

### Shared-chain validation conclusion

The M2-M8 validation suite supports the following engineering claim:

> Under the tested shared SQLite deployment profiles, TCD preserves a single durable receipt chain across multi-worker, multi-process, and staged multi-node writes. Restart and crash-recovery scenarios did not produce fork, missing predecessor, latest-head mismatch, receipt-ref loss, or evidence commit failure.

This is a shared-persistence consistency result, not a claim of global distributed consensus.

### Shared-chain production observations to monitor

The following counters should remain part of staging and production observability:

- `evidence_store_file_lock_timeout`
- `database is locked`
- `sqlite_busy`
- `sqlite3.OperationalError`
- `evidence_store_commit_failed`
- `latest_chain_head_mismatch`
- `fork`
- `missing_prev`
- `receipt_timeout`
- `receipt_issue_timeout`
- storage-window verification latency
- receipt_ref lookup latency
- RSS growth under worker scaling
- durable receipts vs acknowledged HTTP responses during crash windows

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
- fail explicitly under storage, ledger, receipt, KMS/HSM, and outbox faults rather than silently overwriting evidence

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
- a substitute for real-provider KMS/HSM certification, secrets management, or third-party security review

If all you need is a lightweight content filter or a single middleware that blocks obviously bad prompts, TCD is probably more system than you need.

TCD can provide strong local and shared-storage guarantees under configured deployment profiles, and the current KMS K1-K7 track has passed under the tested fake-KMS and hardware-root profiles. It does not claim global distributed consensus or real-provider hardware certification unless you provide the required external coordination, backend infrastructure, key-management controls, and audit evidence.

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
- no explicit behavior for crash windows, duplicate retries, ledger outage, KMS/HSM faults, or storage faults
- no independent receipt verification path after the request has finished
- no explicit key lifecycle model for allowlist, rotation, revocation, and hardware-root provenance

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
- KMS/HSM-backed receipt signing with governed key identity and explicit fail-closed behavior
- hardware-root receipt provenance under a tested hardware profile
- a separate control plane instead of embedding governance logic inside every application

Examples:

- internal AI platforms serving multiple products or teams
- high-value customer workflows
- government or large financial environments
- AI systems where route, action, and evidence must be explainable after the fact
- inference systems where auditability must survive restarts, retries, storage faults, and key lifecycle events

---

## When not to use TCD

TCD is probably the wrong tool if:

- you only need a lightweight prompt filter
- you do not need a separate control plane
- you do not care about receipts, verification, replay, or durable audit trails
- you want globally strong distributed guarantees without providing shared state or an external coordinator
- you are looking for a hosted model platform rather than an inference governance layer
- you are unwilling to operate storage, ledger, verification, key management, and observability surfaces as part of the inference platform
- you need production-certified hardware KMS/HSM guarantees but cannot provide real-provider key policy, attestation, runbooks, audit retention, and deployment controls

---

## Deployment modes

TCD can be used in more than one way.

| Mode | What it looks like | Best for |
|---|---|---|
| Sidecar mode | One TCD instance sits next to one model-serving runtime or workload. | Single service ownership and local strong control semantics. |
| Shared gateway mode | One TCD cluster fronts multiple model runtimes. | Platform teams, shared routing, and centralized governance. |
| Control-plane-first mode | Existing serving path remains; TCD is introduced first for admin, verify, storage, and policy governance. | Incremental adoption. |
| Verify / audit mode | TCD is used primarily for verify, receipt ingest, storage, ledger, and audit workflows. | Audit-first deployments or staged rollout. |
| Shared-persistence mode | Multiple TCD processes or nodes write to a shared durable receipt store. | Multi-worker, multi-process, or staged multi-node durability validation. |
| KMS/HSM-backed receipt mode | Receipt signing uses KMS/HSM-style signer identity, allowlist policy, rotation/revocation controls, and optional hardware-root provenance. | Audit-heavy environments, controlled production pilots, and key-governed receipt integrity. |
| Hybrid mode | HTTP/gRPC inference surfaces are used in some paths and receipt/verify/storage/admin in others. | Large mixed estates. |

---

## Quickstart

### 1. Clone and enter the repository

```bash
cd ~/tcd-safety-sidecar
source venv/bin/activate
```

If your virtual environment is named `.venv`, use:

```bash
cd ~/tcd-safety-sidecar
source .venv/bin/activate
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

For multi-node local tests, also clean ports `8081` and `8082`:

```bash
for port in 8080 8081 8082; do
  lsof -nP -iTCP:${port} -sTCP:LISTEN || true
  for p in $(lsof -tiTCP:${port} -sTCP:LISTEN 2>/dev/null); do kill "$p" 2>/dev/null || true; done
done

pkill -f "uvicorn.*tcd\.service_http:create_app" 2>/dev/null || true
pkill -f "curl .*127\.0\.0\.1:808[0-2]" 2>/dev/null || true
pkill -f "curl .*localhost:808[0-2]" 2>/dev/null || true
```

For KMS/HSM tests that use ports `8080` through `8084`:

```bash
for port in 8080 8081 8082 8083 8084; do
  lsof -nP -iTCP:${port} -sTCP:LISTEN || true
  for p in $(lsof -tiTCP:${port} -sTCP:LISTEN 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
done

pkill -f "uvicorn.*tcd\.service_http:create_app" 2>/dev/null || true
pkill -f "curl .*127\.0\.0\.1:808[0-4]" 2>/dev/null || true
pkill -f "curl .*localhost:808[0-4]" 2>/dev/null || true
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
- optional KMS/HSM signer backend
- optional KMS allowlist, rotation, revocation, and hardware-root policy

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

### KMS / HSM-backed receipt profile

For fake-KMS or provider-KMS style tests, configure signer backend, active key, verify allowlist, self-check, durable stores, and strict receipt exposure.

```bash
cd ~/tcd-safety-sidecar
source venv/bin/activate

export TCD_RECEIPT_SIGNER_BACKEND="aws_kms"
export TCD_KMS_KEY_ID="kms:test:receipt-key-v1"
export TCD_ACTIVE_SIGNING_KEY="kms:test:receipt-key-v1"

export TCD_KMS_VERIFY_KEY_ALLOWLIST="kms:test:receipt-key-v1"
export TCD_KMS_ENFORCE_VERIFY_KEY_ALLOWLIST=1
export TCD_KMS_VERIFY_SCOPE_ENFORCEMENT=1

export TCD_HTTP_RECEIPTS_ENABLE_DEFAULT=1
export TCD_HTTP_RECEIPT_SELF_CHECK=1
export TCD_HTTP_EXPOSE_VERIFICATION_BUNDLE_PUBLIC=1
export TCD_HTTP_EXPOSE_LEGACY_RECEIPT_ALIASES=1
export TCD_HTTP_EXPOSE_VERIFY_KEY_PUBLIC=1
export TCD_HTTP_RECEIPT_USE_SCHEMA_VIEW=1

export TCD_HTTP_RECEIPT_REF_STORE_DSN="sqlite:////tmp/tcd_kms_receipt_ref_store.sqlite3"
export TCD_HTTP_EVIDENCE_STORE_DSN="sqlite:////tmp/tcd_kms_evidence_store.sqlite3"
export TCD_HTTP_REQUIRE_DURABLE_EVIDENCE=1
export TCD_HTTP_REQUIRE_COMMIT_RECEIPT_AFTER_DURABLE=1

PYTHONWARNINGS="ignore::DeprecationWarning,ignore::UserWarning" \
python -m uvicorn tcd.service_http:create_app \
  --factory \
  --host 127.0.0.1 \
  --port 8080
```

For hardware-root profile tests, the runtime should additionally enforce hardware root and supply a hardware-root policy:

```bash
export TCD_RECEIPT_REQUIRE_HARDWARE_ROOT=1
export TCD_HARDWARE_ROOT_PROFILE="K7_HSM"
export TCD_HARDWARE_ROOT_POLICY_JSON='{"hardware_policy_ref":"hwpol:k7:hsm:v1","keys":[],"trust_anchors":[]}'
```

Real production provider deployments should replace test/fake KMS variables with the appropriate AWS KMS, GCP KMS, Azure Key Vault, CloudHSM, Nitro, TPM, or HSM-backed configuration and preserve the same verification, allowlist, rotation, revocation, and audit-correlation requirements.

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

## Shared durable evidence-chain regression gate

The shared durable evidence-chain gate validates multi-worker, multi-process, and multi-node shared persistence.

A passing validation should include:

```bash
M2_WORKERS2_SHARED_SQLITE_RC=0
M3_WORKERS4_SHARED_SQLITE_RC=0
M3B_WORKERS8_SHARED_SQLITE_RC=0
M4_MULTI_UVICORN_SHARED_STORE_RC=0
M5_MULTI_UVICORN_CONCURRENT_SAME_CHAIN_RC=0
M6_THREE_UVICORN_PERIODIC_RESTART_SHARED_CHAIN_RC=0
M7_A_KILL_RESTART_BC_CONTINUE_SHARED_STORE_RC=0
M8_RECOVERY_VERIFY_TAIL_PAGE_WINDOW_RC=0
```

Minimum assertions for this gate:

| Test area | Required assertion |
|---|---|
| Multi-worker shared SQLite | M2, M3, and M3b pass without fork, database lock failure, or commit failure. |
| Cross-process shared visibility | M4 proves one process can write and another process can verify receipt_ref and storage_window. |
| Concurrent same-chain writes | M5 proves two processes can concurrently append to one chain with one latest head. |
| Three-node restart recovery | M6 proves periodic node restart does not break shared chain verification. |
| Kill/restart recovery | M7 proves `kill -9` on one node does not roll back global chain state. |
| Recovery verification | M8 proves the recovered node can verify latest head, historical receipt refs, newest receipt refs, tail window, and SQL page window. |
| Full-window verification | `storage_window` checks all durable receipts expected by each test. |
| Chain topology | `forks=0`, `missing_prev=0`, and `tip_count=1` where reported. |
| SQL chain sequence | `chain_seq` is unique and contiguous where available. |
| Critical errors | `database is locked`, `sqlite_busy`, `evidence_store_commit_failed`, `latest_chain_head_mismatch`, `fork`, and `missing_prev` remain zero or non-failing. |

This gate supports shared-storage consistency under tested profiles. It does not replace a consensus protocol or a multi-region ordering backend.

---

## KMS / HSM regression gate

The KMS / HSM regression gate validates signer abstraction, KMS-backed issuance, governed verification, fail-closed behavior, rotation, revocation, and hardware-root provenance.

A passing current KMS validation package should include:

```bash
K1_SIGNER_ADAPTER_COMPATIBILITY=PASS
K2_KMS_SIGN_LOCAL_VERIFY_RC=0
K3_KMS_ALLOWLIST_RC=0
K4_KMS_TIMEOUT_FAIL_CLOSED_RC=0
K5_KMS_KEY_ROTATION_RC=0
K6_KMS_KEY_REVOCATION_RC=0
K7_HARDWARE_ROOT_PROFILE_RC=0
```

Minimum assertions for this gate:

| Test area | Required assertion |
|---|---|
| K1 signer adapter | Local HMAC path remains compatible; signer interface exists; verify contract is reused; legacy receipts verify. |
| K2 KMS sign/local verify | KMS signer issues receipts; KMS key identity appears in receipt and durable DB; KMS signature verifies; tampered KMS receipts fail; no local HMAC fallback. |
| K3 allowlist | Unknown/disallowed keys, wrong binding, algorithm confusion, wrong scope, normalization attacks, receipt_ref bypass, and storage_window bypass fail. |
| K4 fail-closed | Timeout, unavailable KMS, explicit errors, malformed response, and corrupted signature fail closed; no fake committed receipt; no late commit; idempotency is stable. |
| K5 rotation | Old receipts verify, new receipts use new key, storage window remains valid, restart preserves rotation, multi-node rollout does not fork, idempotent replay does not re-sign. |
| K6 revocation | Revoked key cannot sign new receipts; historical old receipts remain explicitly verifiable; post-revocation old-key receipts fail; timestamp tampering fails; restart preserves policy. |
| K7 hardware-root | Hardware signature, key provenance, attestation chain, non-exportability, negative material rejection, fail-closed hardware signer behavior, rotation/revocation, and audit correlation pass. |

This gate supports the following scoped engineering statement:

```bash
KMS_K1_TO_K7_COMPLETED=true
KMS_HARDWARE_ROOT_PROFILE_CLOSED=true
KMS_READY_FOR_STAGING_AND_CONTROLLED_PILOT=true
KMS_NOT_YET_REAL_PROVIDER_CERTIFICATION=true
```

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
# -> attest + crypto + KMS/HSM signer
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
7. Attest, crypto, KMS/HSM signer, storage, ledger, outbox, and audit make evidence durable, replayable, and verifiable under the configured deployment profile.

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
- KMS/HSM signer identity
- key allowlist and scope enforcement
- key rotation and revocation policy
- optional hardware-root attestation and non-exportability proof

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

The following behaviors have passed the current manual, regression, fault-injection, concurrency, soak, full receipt governance closure, shared durable evidence-chain, and KMS/HSM tests recorded for this repository.

These are test-backed engineering claims, not formal mathematical proofs. They are intentionally scoped to the tested runtime profiles, storage backends, signing backends, and deployment shapes.

| Area | Validation result | What it means |
|---|---|---|
| Durable committed receipt surface | Durable-required requests returned committed durable receipt surfaces with committed ledger state. | TCD can issue durable committed receipts under the tested durable profile. |
| Local fallback receipt path | Local mode passed without SecurityRouter or PolicyStore. | TCD can still produce verifiable local HMAC receipts and durable evidence under the local profile. |
| SecurityRouter receipt path | Security mode passed with SecurityRouter enabled. | Policy/risk/route/evidence orchestration can participate in the final receipt path. |
| PolicyStore binding path | Security mode passed with PolicyStore enabled and policy refs present. | Policy refs and policyset refs participate in governance identity. |
| HMAC attestation | Local HMAC attestation and verification passed. | The configured local HMAC signing path is functional. |
| KMS signer adapter | K1 passed. | Signer abstraction was introduced without breaking local HMAC semantics or the existing verification contract. |
| KMS sign + local verify | K2 passed. | KMS-style signer identity can issue receipts that are locally verified against signed receipt material. |
| KMS key allowlist | K3 passed. | Verification enforces governed key identity, algorithm, scheme, tenant, and chain scope. |
| KMS fail-closed faults | K4 passed. | KMS timeout, unavailable, explicit error, malformed response, and corrupted signature do not create fake committed receipts or late commits. |
| KMS key rotation | K5 passed. | Old receipts remain verifiable, new receipts use new key, storage remains linear, restart preserves state, and idempotent replay does not re-sign. |
| KMS key revocation | K6 passed. | Revoked keys cannot sign new receipts, historical receipts remain explicitly verifiable, post-revocation old-key receipts fail, and policy survives restart. |
| Hardware-root KMS/HSM | K7 passed. | Hardware-root signing, attestation, non-exportability, negative rejection, fail-closed hardware signer behavior, rotation/revocation, and audit correlation are validated. |
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
| Multi-worker shared storage | M2, M3, and M3b passed with 2, 4, and 8 workers sharing one SQLite evidence store. | Multiple local workers can write one durable receipt chain without fork under tested load. |
| Multi-process shared visibility | M4 passed with two uvicorn processes sharing one durable store. | One process can write receipts and another process can verify receipt refs and full storage windows. |
| Concurrent same-chain writes | M5 passed with two uvicorn nodes concurrently writing the same receipt chain. | Shared persistence supports concurrent server-assigned appends under the tested SQLite profile. |
| Three-node restart recovery | M6 passed with three nodes writing concurrently while nodes restarted periodically. | Node restarts did not break shared-store chain consistency under tested load. |
| Kill/restart recovery | M7 passed with Node A killed by `kill -9`, while B/C continued writing and A later recovered. | A crashed node did not roll back, fork, or overwrite the global chain head. |
| Recovery-time verification | M8 passed after M7 by verifying latest head, old receipt refs, newest receipt refs, tail window, and SQL page window. | A recovered node can read and verify the global shared-store state advanced by other nodes. |
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
- shared SQLite persistence can support concurrent multi-worker, multi-process, and tested multi-node writers without chain ambiguity
- restarted nodes can recover and verify the latest shared chain head
- a killed node does not overwrite the global chain head after recovery under the tested shared-store profile
- local single-process staging capacity testing has passed at 5,000 requests and 100 concurrent clients
- full receipt governance closure passes in local and security profiles
- KMS K1-K7 passed under the tested fake-KMS and hardware-root profiles
- KMS/HSM-style receipt signing can be governed by key identity, allowlist, rotation, revocation, fail-closed behavior, and hardware-root provenance

The current validation set does **not** imply:

- global multi-region consensus
- globally ordered receipt streams without a shared backend or coordinator
- globally shared statistical budget state across unrelated deployments
- production certification for every real cloud KMS or HSM provider
- real-provider attestation certification outside the tested hardware-root profile
- production-complete PQ-signature deployment in every environment
- production latency SLOs for all hardware, networks, backends, or deployment profiles
- indefinite soak stability beyond the tested windows
- third-party security audit approval
- regulatory certification

Longer soak windows, restart-interval tests, mixed receipt soak tests, real-provider KMS/HSM rollout tests, backend migration tests, key compromise recovery tests, and larger multi-node capacity tests should be tracked as separate validation artifacts when completed.

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
- KMS/HSM signer backend
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
- key rotation and revocation readiness checks

---

## HTTP surface

Common endpoints:

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness and basic runtime state. |
| `GET /readyz` | Readiness, including signer/key/hardware-root preflight where configured. |
| `GET /version` | Version/config summary. |
| `GET /dod` | Definition-of-done / contract summary. |
| `GET /runtime/public` | Public runtime view, including signer backend and key policy status where enabled. |
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

When running shared-store recovery tests across multiple phases, use a fixed signing key and key ID across the phases that need to verify historical receipts.

### KMS / HSM signer backend

Common backend selector:

```bash
export TCD_RECEIPT_SIGNER_BACKEND="aws_kms"
```

Accepted backend aliases include local/HMAC and cloud KMS-style names depending on environment support:

```bash
hmac
aws_kms
gcp_kms
azure_keyvault
```

Common key identity variables:

```bash
export TCD_ACTIVE_SIGNING_KEY="kms:test:receipt-key-v1"
export TCD_KMS_KEY_ID="kms:test:receipt-key-v1"
export TCD_KMS_SIG_KEY_ID="kms:test:receipt-key-v1"
export TCD_KMS_VERIFY_KEY_ALLOWLIST="kms:test:receipt-key-v1"
```

AWS-style variables:

```bash
TCD_AWS_KMS_KEY_ID
TCD_AWS_KMS_SIG_KEY_ID
TCD_AWS_KMS_REGION
TCD_AWS_KMS_SIGNING_ALGORITHM
TCD_AWS_KMS_MESSAGE_TYPE
```

GCP-style variables:

```bash
TCD_GCP_KMS_KEY_NAME
TCD_GCP_KMS_KEY_VERSION
TCD_GCP_KMS_SIG_ALG
TCD_GCP_KMS_SIG_KEY_ID
```

Azure-style variables:

```bash
TCD_AZURE_KEY_VAULT_KEY_ID
TCD_AZURE_KEY_VAULT_SIG_KEY_ID
TCD_AZURE_KEY_VAULT_SIGN_ALGORITHM
```

### KMS verification allowlist and scope

```bash
export TCD_KMS_ENFORCE_VERIFY_KEY_ALLOWLIST=1
export TCD_KMS_VERIFY_SCOPE_ENFORCEMENT=1
export TCD_KMS_VERIFY_KEY_ALLOWLIST="kms:test:receipt-key-v1"
```

Structured allowlist policy variables:

```bash
TCD_KMS_VERIFY_KEY_ALLOWLIST_POLICY_JSON
TCD_RECEIPT_VERIFY_KEY_ALLOWLIST_POLICY_JSON
TCD_KMS_VERIFY_KEY_ALLOWLIST_FILE
TCD_RECEIPT_VERIFY_KEY_ALLOWLIST_FILE
```

### KMS timeout and fail-closed controls

```bash
export TCD_KMS_SIGN_TIMEOUT_MS=1000
export TCD_RECEIPT_KMS_SIGN_TIMEOUT_MS=1000
export TCD_HTTP_RECEIPT_ISSUE_TIMEOUT_MS=1000
export TCD_HTTP_RECEIPT_SELF_CHECK_TIMEOUT_MS=500
```

Provider-specific timeout variables may be set for AWS, GCP, or Azure KMS paths where supported.

### KMS rotation and revocation

```bash
export TCD_KMS_ROTATION_PREFLIGHT_REQUIRED=1
export TCD_KMS_ROTATION_WINDOW_ACTIVE=1
export TCD_KMS_OLD_AND_NEW_SIGNING_ALLOWED_DURING_WINDOW=1
export TCD_KMS_PREVIOUS_SIGNING_KEY_ID="kms:test:receipt-key-v1"
export TCD_KMS_NEW_SIGNING_KEY_ID="kms:test:receipt-key-v2"
```

Recommended production posture:

```bash
# During rotation:
allowed_verify_keys=[old,new]

# After cutover:
active_signing_key=new

# For old key after revocation:
status=revoked_for_signing
historical_verify=true
```

### Hardware-root KMS/HSM profile

```bash
export TCD_RECEIPT_REQUIRE_HARDWARE_ROOT=1
export TCD_HARDWARE_ROOT_PROFILE="K7_HSM"
export TCD_HARDWARE_ROOT_POLICY_JSON='{"hardware_policy_ref":"hwpol:k7:hsm:v1","keys":[],"trust_anchors":[]}'
```

Expected hardware-root report fields:

```bash
hardware_root_required=true
hardware_root_verified=true
key_provenance_verified=true
attestation_chain_verified=true
attestation_chain_signature_ok=true
trust_anchor_known=true
attestation_doc_not_expired=true
attestation_identity_matches_policy=true
key_id_bound_to_attestation=true
key_non_exportable=true
key_non_exportable_proof=provider_asserted
key_origin=hardware_generated
signing_backend=hsm
hardware_profile=K7_HSM
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

### Shared SQLite concurrency settings used by shared-store tests

The shared-store tests used explicit SQLite timeout and retry settings to make contention visible and recoverable rather than silently failing:

```bash
export TCD_HTTP_EVIDENCE_STORE_CHAIN_LOCK_ENABLE=1
export TCD_HTTP_EVIDENCE_STORE_CHAIN_LOCK_TIMEOUT_S=300
export TCD_HTTP_EVIDENCE_STORE_INIT_LOCK_TIMEOUT_S=300
export TCD_HTTP_EVIDENCE_STORE_RETRY_ATTEMPTS=64
export TCD_HTTP_EVIDENCE_STORE_RETRY_BASE_S=0.01
export TCD_HTTP_EVIDENCE_STORE_RETRY_MAX_S=1

export TCD_HTTP_RECEIPT_REF_STORE_RETRY_ATTEMPTS=64
export TCD_HTTP_RECEIPT_REF_STORE_INIT_LOCK_TIMEOUT_S=300

export TCD_STORAGE_SQLITE_TIMEOUT_S=300
export TCD_STORAGE_SQLITE_BUSY_TIMEOUT_MS=300000
export TCD_STORAGE_SQLITE_SYNCHRONOUS=FULL
export TCD_STORAGE_SQLITE_WAL_AUTOCHECKPOINT=10000
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
- KMS/HSM signer identity enforcement under configured backends
- key allowlist and scope enforcement under configured policies
- fail-closed behavior when KMS/HSM signing cannot be trusted
- key rotation and revocation semantics under tested policies
- hardware-root provenance enforcement under the tested K7 profile

### Shared-persistence guarantees validated under tested profiles

With a shared SQLite receipt store and server-assigned chain positioning, the validation suite has demonstrated:

- multi-worker writes to one receipt chain
- cross-process read/verify after one process writes
- concurrent A/B commits into one chain
- three-node concurrent shared-store writes
- node restart without chain-head divergence
- node crash recovery without old-head overwrite
- old receipt_ref lookup after process restart or node recovery
- bounded tail-window verification against expected latest chain head
- SQL page-window continuity checks
- no duplicate chain sequence under tested load
- no fork, cycle, or missing predecessor under tested load
- one genesis and one leaf in the tested chain

This is stronger than local-only behavior, but it is still shared-storage consistency, not global distributed consensus.

### KMS/HSM guarantees validated under tested profiles

With the tested fake-KMS and hardware-root KMS/HSM profiles, the validation suite has demonstrated:

- signer backend abstraction without local HMAC regression
- KMS-style receipt issuance and local verification
- KMS key identity persistence in receipt and durable metadata
- KMS allowlist enforcement across direct verify, receipt_ref lookup, and storage_window
- KMS timeout, unavailable, explicit error, malformed response, and corrupted-signature fail-closed behavior
- KMS key rotation with old/new receipt compatibility
- KMS key revocation with historical verification and signing authority removal
- hardware-root signing provenance
- attestation-chain validation
- non-exportable key proof surface
- hardware-root restart lookup and storage-window verification
- hardware-root negative-material rejection
- hardware-root rotation/revocation
- hardware signing audit correlation

This is a test-backed engineering validation of the control-plane semantics. It is not a real-provider certification unless run against the target provider/HSM with production policy, audit retention, secrets management, and operational runbooks.

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
- real-provider hardware-backed signing guarantees across all deployment environments
- production key compromise recovery without external KMS/HSM governance and runbooks

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
- key rotation should preserve old verify keys during the rotation window
- key revocation removes signing authority but may preserve historical verification if policy allows it
- hardware-root signing must bind signature, key provenance, attestation chain, hardware policy, and audit correlation

### Crypto boundary honesty

TCD defines a governed cryptographic control plane and validates receipt integrity checks, KMS-style signer identity, key allowlist behavior, key lifecycle semantics, and hardware-root provenance under the tested profile.

Do not market it as a fully production-certified PQ or hardware-rooted stack unless the exact backend, key-management environment, hardware-root profile, provider attestation, audit retention, deployment policy, and operational controls are specified.

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

Canonical JSON, stable digests, message versions, bounded normalization, stable event IDs, decision IDs, route IDs, receipt heads, chain heads, signer key IDs, key-policy fingerprints, and hardware-policy digests are treated as system primitives, not convenience features.

### Explicit conflict over silent overwrite

Storage, admin ingest, ledger, outbox, and key-governance layers prefer:

- explicit conflict
- idempotent dedupe
- anti-fork semantics
- stable original payload preservation
- explicit verify-key denial
- explicit revocation denial
- explicit hardware-root policy denial

over hidden replacement or last-write-wins behavior.

### Governance over convenience

Strict modes, scope enforcement, approvals, change tickets, break-glass, KMS allowlists, hardware-root requirements, outbox fallback, and prepare/commit semantics appear repeatedly because TCD optimizes for governance and verifiability, not just API ergonomics.

### Boundedness everywhere

Untrusted input is always expected. Body size, JSON depth, cardinality, evidence node counts, string lengths, queue sizes, stream counts, chain windows, outbox payload size, receipt body size, KMS response size, key policy size, and patch segment sizes are bounded throughout the system.

### Crash windows are first-class

TCD treats crash windows as part of the control-plane contract:

- prepare happened, commit did not happen
- commit happened, response did not return
- ledger unavailable, outbox queued
- duplicate write, same digest
- duplicate write, different digest
- restart, lookup, and verify
- node crash, recovery, and shared-chain latest-head verification
- KMS signing failed before commit
- KMS signing succeeded but response was lost
- key rotated after committed request
- key revoked after historical receipt issuance

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

### KMS / HSM governance

| Area | Purpose |
|---|---|
| Signer backend selection | Routes receipt signing through local HMAC, KMS, or HSM-style backend. |
| Key identity binding | Carries `sig_key_id`, `verify_key_id`, `sig_alg`, and `sig_scheme` through receipts and durable metadata. |
| Verify allowlist | Enforces governed signing key identity, algorithm, scheme, tenant, chain namespace, and chain ID. |
| Rotation preflight | Detects unsafe old/new key rollout configuration when enabled. |
| Revocation policy | Separates signing authority from historical verification. |
| Hardware-root policy | Validates hardware profile, trust anchor, attestation chain, key binding, non-exportability, and audit correlation. |

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

When publishing claims, keep the test command, environment, runtime version, storage backend, signing backend, key policy, hardware policy, concurrency level, total request count, sample verification count, latency summary, pass/fail output, and artifact inventory with the release artifact.

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
- K1 signer adapter compatibility test
- K2 KMS sign + local verify test
- K3 KMS allowlist enforcement test
- K4 KMS timeout / fail-closed test
- K5 KMS key rotation test
- K6 KMS key revocation test
- K7 hardware-root KMS/HSM profile test
- KMS fake backend logs and configs
- KMS key policy files
- hardware-root policy files
- hardware-root evidence DBs and receipt-ref DBs
- M2 single-machine 2-worker shared SQLite test
- M3 single-machine 4-worker shared SQLite test
- M3b single-machine 8-worker shared SQLite test
- M4 multi-uvicorn shared-store visibility test
- M5 multi-uvicorn concurrent same-chain write test
- M6 three-node periodic restart shared-chain test
- M7 node kill/restart with other nodes continuing writes test
- M8 recovery verify tail/page/window/receipt_ref test
- capacity-boundary concurrency test
- soak test
- malformed receipt fuzz test
- oversized JSON and Unicode boundary test
- SQLite corruption and WAL recovery test
- CI matrix across supported Python and dependency versions

---

## Release gate checklist

A release candidate should not be called production-ready unless the following are explicitly addressed.

### Functional release gate

```bash
python -m py_compile tcd/service_http.py tcd/storage.py tcd/attest.py tcd/verify.py tcd/receipt_v2.py tcd/crypto.py
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

### Shared durable evidence-chain gate

Expected for the current shared-store consistency suite:

```bash
M2_WORKERS2_SHARED_SQLITE_RC=0
M3_WORKERS4_SHARED_SQLITE_RC=0
M3B_WORKERS8_SHARED_SQLITE_RC=0
M4_MULTI_UVICORN_SHARED_STORE_RC=0
M5_MULTI_UVICORN_CONCURRENT_SAME_CHAIN_RC=0
M6_THREE_UVICORN_PERIODIC_RESTART_SHARED_CHAIN_RC=0
M7_A_KILL_RESTART_BC_CONTINUE_SHARED_STORE_RC=0
M8_RECOVERY_VERIFY_TAIL_PAGE_WINDOW_RC=0
```

### KMS / HSM gate

Expected for the current completed KMS track:

```bash
K1_SIGNER_ADAPTER_COMPATIBILITY=PASS
K2_KMS_SIGN_LOCAL_VERIFY_RC=0
K3_KMS_ALLOWLIST_RC=0
K4_KMS_TIMEOUT_FAIL_CLOSED_RC=0
K5_KMS_KEY_ROTATION_RC=0
K6_KMS_KEY_REVOCATION_RC=0
K7_HARDWARE_ROOT_PROFILE_RC=0
KMS_K1_TO_K7_COMPLETED=true
```

Current final KMS/HSM acceptance line:

```bash
K7_HARDWARE_ROOT_PROFILE_RC=0
passed=true
failed_gates=[]
hardware_signature_verified=true
hardware_root_verified=true
key_provenance_verified=true
attestation_chain_verified=true
software_key_rejected_when_hardware_required=true
hardware_negative_cases_fail=true
hardware_timeout_fails_closed=true
hardware_storage_window_ok=true
hardware_restart_verify_ok=true
hardware_rotation_revocation_ok=true
audit_correlation_complete=true
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

For multi-node tests:

```bash
for port in 8080 8081 8082; do
  lsof -nP -iTCP:${port} -sTCP:LISTEN || true
  for p in $(lsof -tiTCP:${port} -sTCP:LISTEN 2>/dev/null); do kill "$p" 2>/dev/null || true; done
done
pkill -f "uvicorn.*tcd\.service_http:create_app" 2>/dev/null || true
```

For KMS/HSM multi-service tests:

```bash
for port in 8080 8081 8082 8083 8084; do
  lsof -nP -iTCP:${port} -sTCP:LISTEN || true
  for p in $(lsof -tiTCP:${port} -sTCP:LISTEN 2>/dev/null); do kill -9 "$p" 2>/dev/null || true; done
done
pkill -f "uvicorn.*tcd\.service_http:create_app" 2>/dev/null || true
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

### KMS evidence gate

Verify that the release candidate exercises or references validated artifacts for:

- signer interface static audit
- local HMAC backward compatibility
- KMS issue + local verify
- KMS key identity persistence
- KMS signature tamper failure
- no unexpected local HMAC fallback
- KMS allowlist policy
- unknown/disallowed key rejection
- wrong key-id binding rejection
- algorithm confusion rejection
- tenant/chain scope enforcement
- receipt_ref allowlist enforcement
- storage_window allowlist enforcement
- KMS timeout fail-closed
- KMS unavailable fail-closed
- KMS explicit error fail-closed
- malformed KMS response fail-closed
- corrupted KMS signature detection
- no fake committed receipt
- no late commit after timeout
- idempotent retry after failed signing
- idempotent replay after committed response loss
- key rotation old/new verification
- rotation storage_window verification
- rotation restart verification
- rotation multi-node staggered rollout
- rotation idempotency preservation
- key revocation historical verification
- revoked key new signing failure
- post-revocation old-key receipt failure
- timestamp tamper rejection
- revocation receipt_ref/storage_window/restart consistency
- hardware-root positive receipt
- hardware-root attestation chain validation
- hardware-root non-exportability proof
- hardware-root negative material rejection
- hardware-root timeout fail-closed
- hardware-root rotation/revocation
- hardware signing audit correlation

### Shared-store consistency gate

Verify that the release candidate exercises or references validated artifacts for:

- multi-worker shared SQLite writes
- multi-process shared-store read/verify
- two-node concurrent same-chain writes
- three-node shared-chain writes
- periodic node restart
- `kill -9` crash recovery
- recovered-node latest-head verification
- old receipt_ref lookup after recovery
- newest receipt_ref lookup after recovery
- bounded tail-window verification
- SQL page-window continuity verification
- absence of fork, missing predecessor, latest-head mismatch, and evidence commit failure

### Production hardening gate

Before describing a deployment as production-grade, add or document:

- high-concurrency soak beyond the current tested window
- real cloud KMS or real HSM provider integration evidence
- provider-specific attestation and trust-anchor documentation
- key rotation runbook
- key revocation runbook
- key compromise recovery policy
- multi-kid verification and historical-key retention policy
- KMS/HSM timeout and retry runbook
- KMS/HSM audit retention policy
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
- production SLOs for receipt issue, receipt verify, KMS sign, KMS verify, storage-window verify, and recovery windows

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
- KMS signer backend abstraction
- KMS-style receipt signing and local verification
- KMS allowlist enforcement
- KMS fail-closed timeout/error semantics
- KMS key rotation
- KMS key revocation
- hardware-root KMS/HSM profile validation
- hardware attestation-chain verification
- non-exportable key proof surface
- hardware signing audit correlation
- shared SQLite multi-worker validation
- shared SQLite multi-process validation
- staged three-node shared-chain validation
- node restart and kill/recovery validation
- staging capacity-boundary validation
- full receipt governance closure validation for local and security profiles

---

## Current limitations

The current system should still be treated as an Engineering Beta Candidate, not a fully certified production compliance platform, because these areas need more hardening before broad production claims:

- long-running soak beyond current windows
- high-concurrency receipt-heavy workloads beyond the current shared-store tests
- storage backend migration and schema versioning
- real-provider KMS/HSM rollout evidence
- provider-specific hardware attestation and audit retention
- key compromise recovery policy
- production-grade rotation and revocation runbooks
- true PQ signing backend, if required
- multi-region ordering and consensus semantics
- policy propagation across multiple independent nodes
- global statistical budget state
- outbox consumer production runbook
- formal threat model
- external security audit
- compatibility matrix across dependency versions
- CI automation for the full governance closure suite
- CI automation for the shared durable evidence-chain M2-M8 suite
- CI automation for KMS K1-K7 regression suite

---

## In one sentence

> **TCD turns inference from an opaque application call into a governed systems event with identity, policy binding, statistical budget state, route contracts, verifiable evidence, durable receipt semantics, replay-aware control-plane actions, KMS/HSM-governed signing, hardware-root provenance under the tested profile, auditable persistence, and tested staging governance boundaries.**