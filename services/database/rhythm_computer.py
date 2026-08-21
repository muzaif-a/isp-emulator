"""Watermark rhythm computer — precomputes SHA-512 bitstream from secret_key.

Stateless: no session tracking, no timestamps, no packet counts.
All session state is owned by the _API_SCRIPT inside database_manager.py.

Usage
-----
    rhythm = WatermarkBitstream("my-secret", short_delay_ms=20, long_delay_ms=50)
    delay_s, bit = rhythm.get_delay(index)   # cycles mod 512
"""

import hashlib
from typing import List, Tuple

BITS_PER_DIGEST = 512


class WatermarkBitstream:
    """Precomputes the 512-bit SHA-512 keystream from secret_key.

    Instantiate once per DB server at startup. Call get_delay(index) to
    retrieve the delay and bit for each chunk — index advances per chunk
    sent and cycles back through the same 512 bits when exhausted.
    """

    def __init__(
        self,
        secret_key: str = "",
        short_delay_ms: float = 20.0,
        long_delay_ms: float = 50.0,
    ) -> None:
        self.short_delay_s: float = short_delay_ms / 1000.0
        self.long_delay_s: float  = long_delay_ms  / 1000.0
        self._bits: List[int] = self._derive_bits(secret_key)

    # ── public API ───────────────────────────────────────────────────────────

    def get_delay(self, index: int) -> Tuple[float, int]:
        """Return (delay_seconds, bit) for the given chunk index.

        Cycles mod BITS_PER_DIGEST (512) so transfers of any size are covered
        without re-hashing.
        """
        bit = self._bits[index % BITS_PER_DIGEST]
        return (self.short_delay_s if bit == 0 else self.long_delay_s), bit

    @property
    def bits(self) -> List[int]:
        """Full 512-bit precomputed sequence (read-only)."""
        return self._bits

    # ── internals ────────────────────────────────────────────────────────────

    @staticmethod
    def _derive_bits(secret_key: str) -> List[int]:
        digest = hashlib.sha512((secret_key or "").encode("utf-8")).digest()
        return [
            (byte >> shift) & 1
            for byte in digest
            for shift in range(7, -1, -1)   # MSB first
        ]


# Backwards-compatible alias
TimingProtocol = WatermarkBitstream
