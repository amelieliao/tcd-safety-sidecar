# FILE: tcd/telemetry_gpu.py
class GpuSampler:
    def __init__(self, index: int = 0):
        self.index = index

    def sample(self):
        return {"gpu_util": 0.0, "gpu_temp_c": 0.0}
