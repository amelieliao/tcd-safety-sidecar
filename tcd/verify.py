# FILE: tcd/verify.py
import json

def verify_receipt(
    *,
    receipt_head_hex: str,
    receipt_body_json: str,
    verify_key_hex: str = None,
    receipt_sig_hex: str = None,
    req_obj=None,
    comp_obj=None,
    e_obj=None,
    witness_segments=None,
    strict: bool = True,
) -> bool:
    try:
        json.loads(receipt_body_json)
    except Exception:
        return False
    if not isinstance(receipt_head_hex, str) or len(receipt_head_hex) == 0:
        return False
    if receipt_sig_hex is not None and not isinstance(receipt_sig_hex, str):
        return False
    return True

def verify_chain(heads, bodies) -> bool:
    if not isinstance(heads, list) or not isinstance(bodies, list):
        return False
    if len(heads) != len(bodies):
        return False
    return len(heads) > 0