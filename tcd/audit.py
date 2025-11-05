# FILE: tcd/audit.py
from __future__ import annotations
import json, os, time, threading
from hashlib import blake2s
from typing import Any, Dict, Optional, TextIO

class AuditLedger:
    def __init__(self, path: str = "./audit/audit.log", rotate_mb: int = 50):
        self.path = path
        self.rotate_bytes = int(rotate_mb * 1024 * 1024)
        self._lock = threading.RLock()
        self._fh: Optional[TextIO] = None
        self._prev = "0" * 64
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._open()

    def _open(self) -> None:
        exists = os.path.exists(self.path)
        self._fh = open(self.path, "a+", buffering=1, encoding="utf-8")
        if exists:
            try:
                self._fh.seek(0, os.SEEK_END)
                if self._fh.tell() > 0:
                    # recover last prev from tail
                    with open(self.path, "rb") as rf:
                        rf.seek(-min(8192, os.path.getsize(self.path)), os.SEEK_END)
                        tail = rf.read().splitlines()
                        for line in reversed(tail):
                            try:
                                obj = json.loads(line.decode("utf-8"))
                                self._prev = obj.get("head", self._prev)
                                break
                            except Exception:
                                continue
            except Exception:
                pass

    @staticmethod
    def _h(s: str) -> str:
        return blake2s(s.encode("utf-8"), digest_size=32).hexdigest()

    def head(self) -> str:
        return self._prev

    def append(self, record: Dict[str, Any]) -> str:
        with self._lock:
            rec = {
                "ts": time.time(),
                "prev": self._prev,
                "payload": record,
            }
            body = json.dumps(rec, separators=(",", ":"), ensure_ascii=False)
            h = self._h(body)
            out = {"head": h, "body": body}
            self._fh.write(json.dumps(out, separators=(",", ":"), ensure_ascii=False) + "\n")
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._prev = h
            if self._fh.tell() >= self.rotate_bytes:
                self._rotate()
            return h

    def _rotate(self) -> None:
        self._fh.close()
        ts = int(time.time())
        os.rename(self.path, f"{self.path}.{ts}")
        self._open()