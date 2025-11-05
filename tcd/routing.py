# FILE: tcd/routing.py
from dataclasses import dataclass
from typing import List

@dataclass
class Route:
    temperature: float
    top_p: float
    decoder: str
    tags: List[str]

class StrategyRouter:
    def decide(self, decision_fail: bool, score: float, base_temp: float, base_top_p: float) -> Route:
        if decision_fail:
            t = max(0.1, float(base_temp) * 0.7)
            p = max(0.1, float(base_top_p) * 0.85)
            return Route(t, p, "degraded", ["degrade"])
        return Route(float(base_temp), float(base_top_p), "default", [])