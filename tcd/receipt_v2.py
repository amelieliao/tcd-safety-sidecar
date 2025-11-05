# FILE: tcd/receipt_v2.py
def build_v2_body(
    *,
    model_hash: str,
    tokenizer_hash: str,
    sampler_cfg: dict,
    context_len: int,
    kv_digest: str,
    rng_seed,
    latency_ms,
    throughput_tok_s,
    batch_index: int,
    batch_size: int,
    e_snapshot: dict,
):
    return {
        "model_hash": model_hash,
        "tokenizer_hash": tokenizer_hash,
        "sampler_cfg": dict(sampler_cfg or {}),
        "context_len": int(context_len),
        "kv_digest": kv_digest,
        "rng_seed": rng_seed,
        "latency_ms": latency_ms,
        "throughput_tok_s": throughput_tok_s,
        "batch_index": int(batch_index),
        "batch_size": int(batch_size),
        "e_snapshot": dict(e_snapshot or {}),
        "version": "v2",
    }
