# tcd/api_v1.py
from typing import Any, Dict
from fastapi import APIRouter, Request
from .schemas import DiagnoseIn, DiagnoseOut
from .risk_av import AlwaysValidRiskController, AlwaysValidConfig

router = APIRouter(prefix="/v1", tags=["v1"])

# single controller instance is fine for demo
_av = AlwaysValidRiskController(AlwaysValidConfig())

def _normalize(raw: Dict[str, Any]) -> DiagnoseOut:
    return DiagnoseOut(
        verdict=bool(raw.get("allowed", False)),
        score=float(raw.get("score", 0.0)),
        threshold=float(raw.get("threshold", 0.0)),
        budget_remaining=float(raw.get("budget_remaining", 0.0)),
        components=raw.get("components", {}) or {},
        cause=str(raw.get("cause", "")),
        action=str(raw.get("action", "none")),
        step=int(raw.get("step", 0)),
        e_value=float(raw.get("e_value", 1.0)),
        alpha_alloc=float(raw.get("alpha_alloc", 0.0)),
        alpha_spent=float(raw.get("alpha_spent", 0.0)),
        receipt=raw.get("receipt"),
        receipt_body=raw.get("receipt_body"),
        receipt_sig=raw.get("receipt_sig"),
        verify_key=raw.get("verify_key"),
    )

@router.post("/diagnose", response_model=DiagnoseOut)
async def diagnose(payload: DiagnoseIn, request: Request) -> DiagnoseOut:
    # your current AlwaysValidRiskController has step(self, request)
    raw = _av.step(request)
    # make sure minimum keys exist & type-stable
    return _normalize(raw)
