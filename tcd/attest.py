# FILE: tcd/attest.py
import json
import secrets
import hashlib

class Attestor:
    def __init__(self, hash_alg: str = "blake3"):
        self.hash_alg = hash_alg

    def issue(self, *, req_obj, comp_obj, e_obj, witness_segments, witness_tags, meta):
        head_src = {"req": req_obj, "comp": comp_obj, "e": e_obj, "meta": meta}
        head = hashlib.sha256(json.dumps(head_src, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        body = json.dumps(
            {"meta": meta, "req": req_obj, "comp": comp_obj, "e": e_obj, "witness_tags": list(witness_tags or [])},
            sort_keys=True,
            separators=(",", ":"),
        )
        sig = hashlib.sha256((head + body).encode()).hexdigest()
        vk = secrets.token_hex(32)
        return {"receipt": head, "receipt_body": body, "receipt_sig": sig, "verify_key": vk}