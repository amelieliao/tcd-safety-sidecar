# tcd/schemas.py
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

class DiagnoseIn(BaseModel):
    input: str = Field(..., description="text or payload to check")

class DiagnoseOut(BaseModel):
    verdict: bool
    score: float
    threshold: float
    budget_remaining: float
    components: Dict[str, Any] = {}
    cause: str = ""
    action: str = "none"
    step: int = 0
    e_value: float = 1.0
    alpha_alloc: float = 0.0
    alpha_spent: float = 0.0
    receipt: Optional[Dict[str, Any]] = None
    receipt_body: Optional[str] = None
    receipt_sig: Optional[str] = None
    verify_key: Optional[str] = None