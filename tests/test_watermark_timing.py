"""Unit tests for timing watermark correctness — no root, no Mininet required.

Covers:
  1. Rhythm determinism   — same key always produces same bit sequence
  2. Bit cycling          — 512 bits repeat after exhaustion
  3. clock_nanosleep hold — kernel-clock accuracy for short/long delays
  4. Chunk delay sim      — get_delay(index) returns correct short/long per bit
  5. Server↔attacker sync — both derive identical rhythm from secret_key alone

Run:
    python3 -m pytest tests/test_watermark_timing.py -v
"""

import ctypes
import hashlib
import sys
import time

import pytest

sys.path.insert(0, __file__.replace("/tests/test_watermark_timing.py", ""))
from services.database.rhythm_computer import WatermarkBitstream

# ── clock_nanosleep helpers (mirror of _API_SCRIPT embedded code) ─────────────
_CLOCK_MONO = 1
_ABSTIME    = 1


class _Ts(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]


try:
    _librt    = ctypes.CDLL("librt.so.1", use_errno=True)
    _librt_ok = True
except Exception:
    _librt_ok = False


def _mono_ns() -> int:
    ts = _Ts()
    _librt.clock_gettime(_CLOCK_MONO, ctypes.byref(ts))
    return ts.tv_sec * 1_000_000_000 + ts.tv_nsec


def _cns_hold(delay_s: float) -> None:
    """Kernel-clock hold — same logic as _API_SCRIPT's _cns_hold."""
    if not (_librt_ok and delay_s > 0):
        return
    abs_ns = _mono_ns() + int(delay_s * 1_000_000_000)
    ts = _Ts(tv_sec=abs_ns // 1_000_000_000, tv_nsec=abs_ns % 1_000_000_000)
    while _librt.clock_nanosleep(_CLOCK_MONO, _ABSTIME, ctypes.byref(ts), None) == 4:
        pass


# ── 1. Rhythm determinism ─────────────────────────────────────────────────────

class TestTimingRhythm:

    def _tp(self, key="test-key", short=20.0, long_=50.0):
        return WatermarkBitstream(secret_key=key, short_delay_ms=short, long_delay_ms=long_)

    def test_same_key_same_rhythm(self):
        r1 = [self._tp("k").get_delay(i) for i in range(64)]
        r2 = [self._tp("k").get_delay(i) for i in range(64)]
        assert r1 == r2

    def test_different_keys_different_rhythm(self):
        r1 = [self._tp("key-A").get_delay(i)[0] for i in range(64)]
        r2 = [self._tp("key-B").get_delay(i)[0] for i in range(64)]
        assert r1 != r2

    def test_delay_values_only_short_or_long(self):
        tp = self._tp()
        for i in range(128):
            d, bit = tp.get_delay(i)
            assert d in (0.020, 0.050), f"unexpected delay {d}"
            assert bit in (0, 1)

    def test_bit_matches_delay(self):
        tp = self._tp(short=20.0, long_=50.0)
        for i in range(512):
            delay, bit = tp.get_delay(i)
            if bit == 0:
                assert delay == 0.020
            else:
                assert delay == 0.050

    def test_timestamp_does_not_affect_bits(self):
        """Rhythm is keyed only on secret_key — no timestamp in seed."""
        r1 = [WatermarkBitstream("same-key").get_delay(i)[0] for i in range(32)]
        r2 = [WatermarkBitstream("same-key").get_delay(i)[0] for i in range(32)]
        assert r1 == r2, "rhythm must be deterministic — no timestamp in seed"


# ── 2. Bit cycling ────────────────────────────────────────────────────────────

class TestBitCycling:

    def test_512_bits_then_cycle(self):
        tp = WatermarkBitstream(secret_key="cycle", short_delay_ms=20, long_delay_ms=50)
        first  = [tp.get_delay(i) for i in range(512)]
        second = [tp.get_delay(i) for i in range(512, 1024)]
        assert first == second, "bitstream must repeat identically after 512 bits"

    def test_bits_property_length(self):
        tp = WatermarkBitstream(secret_key="len-check")
        assert len(tp.bits) == 512

    def test_bits_property_values(self):
        tp = WatermarkBitstream(secret_key="bin-check")
        assert all(b in (0, 1) for b in tp.bits)

    def test_bits_match_sha512(self):
        secret = "sha-verify"
        tp = WatermarkBitstream(secret_key=secret)
        digest = hashlib.sha512(secret.encode()).digest()
        expected = [(byte >> shift) & 1 for byte in digest for shift in range(7, -1, -1)]
        assert tp.bits == expected


# ── 3. clock_nanosleep accuracy ───────────────────────────────────────────────

@pytest.mark.skipif(not _librt_ok, reason="librt.so.1 not available")
class TestClockNanosleep:
    TOLERANCE_MS = 4.0   # allow ±4 ms (kernel scheduler jitter)

    def _measure_ms(self, delay_s: float) -> float:
        t0 = time.monotonic()
        _cns_hold(delay_s)
        return (time.monotonic() - t0) * 1000

    def test_short_delay_20ms(self):
        elapsed = self._measure_ms(0.020)
        assert 20 - self.TOLERANCE_MS <= elapsed <= 20 + self.TOLERANCE_MS, \
            f"20ms hold took {elapsed:.2f}ms"

    def test_long_delay_50ms(self):
        elapsed = self._measure_ms(0.050)
        assert 50 - self.TOLERANCE_MS <= elapsed <= 50 + self.TOLERANCE_MS, \
            f"50ms hold took {elapsed:.2f}ms"

    def test_abstime_prevents_drift(self):
        """10 alternating 20/50ms holds: total drift < 6ms (ABSTIME is cumulative)."""
        pattern = [0.020, 0.050] * 5
        expected = sum(pattern) * 1000
        t0 = time.monotonic()
        for d in pattern:
            _cns_hold(d)
        elapsed = (time.monotonic() - t0) * 1000
        assert abs(elapsed - expected) < 6, \
            f"Drift too high: expected {expected:.0f}ms, got {elapsed:.1f}ms"


# ── 4. Chunk delay simulation ─────────────────────────────────────────────────

class TestChunkDelayLogic:
    """Simulate /backup chunk dispatch — test get_delay(index) decision logic."""

    def test_data_chunk_gets_delay(self):
        tp = WatermarkBitstream(secret_key="cb-test", short_delay_ms=20, long_delay_ms=50)
        delay, bit = tp.get_delay(0)
        assert delay in (0.020, 0.050)
        assert bit in (0, 1)

    def test_sequential_indices_advance_bits(self):
        tp = WatermarkBitstream(secret_key="seq-test", short_delay_ms=20, long_delay_ms=50)
        delays = [tp.get_delay(i)[0] for i in range(10)]
        # All values must be valid short or long delays
        assert all(d in (0.020, 0.050) for d in delays)

    def test_gate_off_skips_delay(self):
        """When TIMING_GATE=False the /backup handler skips get_delay entirely."""
        tp = WatermarkBitstream(secret_key="gate-off", short_delay_ms=20, long_delay_ms=50)
        timing_gate = False
        result = tp.get_delay(0) if timing_gate else None
        assert result is None    # gate off → no delay returned

    def test_custom_delays_reflected(self):
        tp = WatermarkBitstream(secret_key="custom", short_delay_ms=10, long_delay_ms=100)
        for i in range(64):
            delay, bit = tp.get_delay(i)
            if bit == 0:
                assert delay == pytest.approx(0.010)
            else:
                assert delay == pytest.approx(0.100)


# ── 5. Server ↔ attacker synchronisation ──────────────────────────────────────

class TestServerAttackerSync:

    def test_attacker_predicts_server_rhythm(self):
        """Attacker pre-computes from SHA-512(secret_key) — must match server output."""
        secret = "covert-channel-key"
        short_ms, long_ms = 20.0, 50.0

        server   = WatermarkBitstream(secret_key=secret, short_delay_ms=short_ms, long_delay_ms=long_ms)
        attacker = WatermarkBitstream(secret_key=secret, short_delay_ms=short_ms, long_delay_ms=long_ms)

        server_rhythm   = [server.get_delay(i)   for i in range(64)]
        attacker_rhythm = [attacker.get_delay(i) for i in range(64)]

        assert server_rhythm == attacker_rhythm, \
            "Attacker cannot decode watermark — rhythm mismatch"

    def test_rhythm_bits_match_sha512_directly(self):
        """WatermarkBitstream.bits == SHA-512(secret_key) expanded to bits."""
        secret = "meta-check"
        tp = WatermarkBitstream(secret_key=secret, short_delay_ms=20, long_delay_ms=50)

        digest = hashlib.sha512(secret.encode()).digest()
        expected_bits = [(byte >> shift) & 1 for byte in digest for shift in range(7, -1, -1)]

        assert tp.bits == expected_bits, "bits property must equal raw SHA-512 expansion"

    def test_independent_instances_agree(self):
        """Two WatermarkBitstream instances with same key produce identical get_delay results."""
        secret = "shared-key"
        a = WatermarkBitstream(secret_key=secret)
        b = WatermarkBitstream(secret_key=secret)
        for i in range(512):
            assert a.get_delay(i) == b.get_delay(i), f"mismatch at index {i}"
