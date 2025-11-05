# FILE: tcd/kv.py
import hashlib
from typing import Iterable

class RollingHasher:
    def __init__(self, alg: str = "blake3", ctx: str = ""):
        self._h = hashlib.sha256()
        if ctx:
            self._h.update(ctx.encode())

    def update_ints(self, xs: Iterable[int]):
        for v in xs or []:
            self._h.update(int(v).to_bytes(8, "little", signed=False))

    def hex(self) -> str:
        return self._h.hexdigest()