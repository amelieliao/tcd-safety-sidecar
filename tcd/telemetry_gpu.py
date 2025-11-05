# FILE: tcd/telemetry_gpu.py
import random

class GpuSampler:
    def __init__(self):
        self.enabled = True

    def sample(self):
        # return a dummy GPU utilization metric
        return {
            "gpu_util": round(random.uniform(0, 1), 3),
            "memory_used": round(random.uniform(0, 1), 3),
            "temperature": 55.0
        }