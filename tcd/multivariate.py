# FILE: tcd/multivariate.py
from dataclasses import dataclass

@dataclass
class MultiVarConfig:
    enabled: bool = False
    window: int = 10

class MultiVarDetector:
    def __init__(self, config: MultiVarConfig = None):
        self.config = config or MultiVarConfig()

    def detect(self, data):
        return {"verdict": False, "score": 0.0}