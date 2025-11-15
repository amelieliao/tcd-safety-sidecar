# tcd/crypto.py
# Temporary crypto shim for Render deployment

import hashlib

class Blake3Hash:
    @staticmethod
    def digest(data: bytes) -> str:
        # use blake2b as a stand-in for blake3
        return hashlib.blake2b(data).hexdigest()
