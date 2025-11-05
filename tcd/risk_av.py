# FILE: tcd/risk_av.py
from dataclasses import dataclass
from typing import Any, Dict, Optional

print(">>> [DEBUG] Loaded AlwaysValidRiskController from:", __file__)

@dataclass
class AlwaysValidConfig:
    enabled: bool = True
    alpha_base: float = 0.05

class AlwaysValidRiskController:
    def __init__(self, config: Optional[AlwaysValidConfig] = None, **kwargs: Any):
        self.config = config or AlwaysValidConfig()
        if "alpha_base" in kwargs:
            try:
                self.config.alpha_base = float(kwargs["alpha_base"])
            except Exception:
                pass
        self.init_kwargs: Dict[str, Any] = dict(kwargs)
        print(f">>> [INIT] AlwaysValidRiskController(alpha_base={self.config.alpha_base}) initialized")

    def step(self, request: Any = None, **kwargs: Any) -> Dict[str, Any]:
        return {
            "allowed": True,
            "reason": "always-valid",
            "alpha_base": self.config.alpha_base,
            "extra": kwargs,
            "has_request": request is not None,
        }

__all__ = ["AlwaysValidConfig", "AlwaysValidRiskController"]