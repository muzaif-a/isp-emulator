"""Unit tests for timing watermark correctness — no root, no Mininet required.

Covers:
  1. Rhythm determinism   — same key always produces same bit sequence
  2. Bit cycling          — 512 bits repeat after exhaustion
  3. clock_nanosleep hold — kernel-clock accuracy for short/long delays
  4. Chunk delay sim — data chunks get delay + record; control segments pass free
  5. Server↔attacker sync — both derive identical rhythm from secret_key alone

Run:
    python3 -m pytest tests/test_watermark_timing.py -v
"""

import ctypes
import sys
import time

import pytest

sys.path.insert(0, __file__.replace("/tests/test_watermark_timing.py", ""))
from services.database.timing_protocol import TimingProtocol

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
        tp = TimingProtocol(enabled=True, secret_key=key,
                            short_delay_ms=short, long_delay_ms=long_)
        tp.new_session(1.0, src="10.0.0.2", dest="10.0.0.3:9090")
        return tp

    def test_same_key_same_rhythm(self):
        tp1, tp2 = self._tp("k"), self._tp("k")
        r1 = [tp1.next_delay_seconds() for _ in range(64)]
        r2 = [tp2.next_delay_seconds() for _ in range(64)]
        assert r1 == r2

    def test_different_keys_different_rhythm(self):
        tp1, tp2 = self._tp("key-A"), self._tp("key-B")
        r1 = [tp1.next_delay_seconds() for _ in range(64)]
        r2 = [tp2.next_delay_seconds() for _ in range(64)]
        assert r1 != r2

    def test_delay_values_only_short_or_long(self):
        tp = self._tp()
        for _ in range(128):
            d = tp.next_delay_seconds()
            assert d in (0.020, 0.050), f"unexpected delay {d}"

    def test_disabled_returns_zero(self):
        tp = TimingProtocol(enabled=False, secret_key="x")
        assert tp.next_delay_seconds() == 0.0

    def test_timestamp_does_not_affect_bits(self):
        """t0 no longer part of seed — different timestamps → same rhythm."""
        tp1 = TimingProtocol(enabled=True, secret_key="same-key",
                             short_delay_ms=20, long_delay_ms=50)
        tp2 = TimingProtocol(enabled=True, secret_key="same-key",
                             short_delay_ms=20, long_delay_ms=50)
        tp1.new_session(1000.0)
        tp2.new_session(9999.9)   # completely different t0
        r1 = [tp1.next_delay_seconds() for _ in range(32)]
        r2 = [tp2.next_delay_seconds() for _ in range(32)]
        assert r1 == r2, "t0 should not influence the keyed bitstream"


# ── 2. Bit cycling ────────────────────────────────────────────────────────────

class TestBitCycling:

    def test_512_bits_then_cycle(self):
        tp = TimingProtocol(enabled=True, secret_key="cycle",
                            short_delay_ms=20, long_delay_ms=50)
        tp.new_session(1.0)
        first  = [tp.next_delay_seconds() for _ in range(512)]
        second = [tp.next_delay_seconds() for _ in range(512)]
        assert first == second, "bitstream must repeat identically after 512 bits"

    def test_rhythm_length_matches_packets_consumed(self):
        tp = TimingProtocol(enabled=True, secret_key="len-check",
                            short_delay_ms=20, long_delay_ms=50)
        tp.new_session(1.0)
        for _ in range(17):
            tp.next_delay_seconds()
            tp.record_data_packet()
        md = tp.metadata()
        assert len(md.rhythm) == 17
        assert md.total_data_packets == 17


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
    """Simulate /backup chunk dispatch without HTTP — test delay decision logic."""

    def _simulated_on_pkt(self, tp, has_payload: bool, timing_gate: bool = True):
        """Returns (delay_applied, packet_accepted)."""
        if has_payload and timing_gate:
            delay = tp.next_delay_seconds()
            tp.record_data_packet()
            return delay, True
        return None, True   # SYN/ACK/control → pass through immediately

    def test_data_segments_get_delay(self):
        tp = TimingProtocol(enabled=True, secret_key="cb-test",
                            short_delay_ms=20, long_delay_ms=50)
        tp.new_session(1.0)
        delay, accepted = self._simulated_on_pkt(tp, has_payload=True)
        assert delay in (0.020, 0.050)
        assert accepted is True

    def test_ack_segments_pass_free(self):
        tp = TimingProtocol(enabled=True, secret_key="ack-test",
                            short_delay_ms=20, long_delay_ms=50)
        tp.new_session(1.0)
        delay, accepted = self._simulated_on_pkt(tp, has_payload=False)
        assert delay is None   # no delay consumed
        assert accepted is True

    def test_only_data_packets_counted(self):
        tp = TimingProtocol(enabled=True, secret_key="count-test",
                            short_delay_ms=20, long_delay_ms=50)
        tp.new_session(1.0)
        # 3 data, 4 control
        for has_payload in [True, False, True, False, False, True, False]:
            self._simulated_on_pkt(tp, has_payload=has_payload)
        md = tp.metadata()
        assert md.total_data_packets == 3
        assert len(md.rhythm) == 3

    def test_gate_off_skips_delay(self):
        tp = TimingProtocol(enabled=True, secret_key="gate-off",
                            short_delay_ms=20, long_delay_ms=50)
        tp.new_session(1.0)
        delay, accepted = self._simulated_on_pkt(tp, has_payload=True, timing_gate=False)
        assert delay is None    # TIMING_GATE=False → no delay, no bit consumed
        assert accepted is True


# ── 5. Server ↔ attacker synchronisation ──────────────────────────────────────

class TestServerAttackerSync:

    def test_attacker_predicts_server_rhythm(self):
        """Attacker pre-computes from SHA-512(secret_key) — must match server's output."""
        secret = "covert-channel-key"
        short_ms, long_ms = 20.0, 50.0

        # Server side — driven by TOS sniffer triggering new_session
        server = TimingProtocol(enabled=True, secret_key=secret,
                                short_delay_ms=short_ms, long_delay_ms=long_ms)
        server.new_session(timestamp=1724000000.0, src="10.0.0.2", dest="10.0.0.3:9090")

        # Attacker side — pre-computes offline; different timestamp (doesn't matter)
        attacker = TimingProtocol(enabled=True, secret_key=secret,
                                  short_delay_ms=short_ms, long_delay_ms=long_ms)
        attacker.new_session(timestamp=0.0)

        server_rhythm   = [server.next_delay_seconds()   for _ in range(64)]
        attacker_rhythm = [attacker.next_delay_seconds() for _ in range(64)]

        assert server_rhythm == attacker_rhythm, \
            "Attacker cannot decode watermark — rhythm mismatch"

    def test_session_metadata_complete(self):
        tp = TimingProtocol(enabled=True, secret_key="meta-check",
                            short_delay_ms=20, long_delay_ms=50)
        tp.new_session(1234567890.0, src="192.168.1.10", dest="192.168.2.5:9090")
        for _ in range(8):
            tp.next_delay_seconds()
            tp.record_data_packet()
        tp.record_end()
        md = tp.metadata()
        assert md.enabled is True
        assert md.secret_key == "meta-check"
        assert md.start_timestamp == 1234567890.0
        assert md.end_timestamp is not None
        assert md.total_data_packets == 8
        assert len(md.rhythm) == 8
        assert md.src == "192.168.1.10"
        assert md.dest == "192.168.2.5:9090"
        assert md.short_delay_ms == 20.0
        assert md.long_delay_ms == 50.0

    def test_session_accumulation(self):
        """Multiple injector cycles → multiple session records."""
        tp = TimingProtocol(enabled=True, secret_key="multi-session",
                            short_delay_ms=20, long_delay_ms=50)
        # Cycle 1
        tp.new_session(1.0, src="10.0.0.2")
        for _ in range(4):
            tp.next_delay_seconds(); tp.record_data_packet()
        tp.finalize_session()
        # Cycle 2
        tp.new_session(2.0, src="10.0.0.2")
        for _ in range(7):
            tp.next_delay_seconds(); tp.record_data_packet()
        tp.finalize_session()

        sessions = tp.sessions()
        assert len(sessions) == 2
        assert sessions[0].total_data_packets == 4
        assert sessions[1].total_data_packets == 7
        assert len(sessions[0].rhythm) == 4
        assert len(sessions[1].rhythm) == 7
        # Each session resets to bit 0 of the 512-bit pool — both start identical.
        # rhythm stores raw bits (0/1); next_delay_seconds() converts to ms.
        # Derive expected raw bits from SHA-512(secret_key) directly.
        import hashlib
        digest = hashlib.sha512("multi-session".encode()).digest()
        raw_bits = []
        for byte in digest:
            for shift in range(7, -1, -1):
                raw_bits.append((byte >> shift) & 1)
        assert sessions[0].rhythm == raw_bits[:4], \
            "Session 1 rhythm must be first 4 raw bits of SHA-512 bitstream"
        assert sessions[1].rhythm == raw_bits[:7], \
            "Session 2 rhythm must be first 7 raw bits — resets to bit 0 each session"
