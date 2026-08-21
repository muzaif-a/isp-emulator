"""Application-layer watermark — delays between HTTP /backup chunk writes.

rhythm_computer.WatermarkBitstream computes the 512-bit rhythm.
database_manager instantiates it and passes it here as `rhythm`.
AppWatermark owns arm/disarm/rotation; database_manager just calls the interface.

Usage:
    from rhythm_computer import WatermarkBitstream
    rhythm = WatermarkBitstream(secret_key, short_delay_ms=20, long_delay_ms=50)

    wm = AppWatermark(rhythm)
    wm.arm("10.0.0.2", start_ts=time.time())   # TOS sniffer on SYN
    delay, bit = wm.next_chunk_delay()          # /backup handler per chunk
    wm.disarm()                                 # TOS sniffer on FIN
"""

import ctypes
import threading
import time

# ── kernel-clock hold ─────────────────────────────────────────────────────────
_CLOCK_MONO = 1
_ABSTIME    = 1


class _Ts(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]


try:
    _librt    = ctypes.CDLL("librt.so.1", use_errno=True)
    _librt_ok = True
except Exception:
    _librt_ok = False


def _mono_ns():
    ts = _Ts()
    _librt.clock_gettime(_CLOCK_MONO, ctypes.byref(ts))
    return ts.tv_sec * 1_000_000_000 + ts.tv_nsec


def cns_hold(delay_s: float) -> None:
    """clock_nanosleep absolute-time hold — ±50–200µs accuracy."""
    if not (_librt_ok and delay_s > 0):
        time.sleep(max(0, delay_s))
        return
    abs_ns = _mono_ns() + int(delay_s * 1_000_000_000)
    ts = _Ts(tv_sec=abs_ns // 1_000_000_000, tv_nsec=abs_ns % 1_000_000_000)
    while _librt.clock_nanosleep(_CLOCK_MONO, _ABSTIME, ctypes.byref(ts), None) == 4:
        pass


# ── AppWatermark ──────────────────────────────────────────────────────────────

class AppWatermark:
    """Application-layer watermark engine.

    Receives a WatermarkBitstream from database_manager.
    Calls rhythm.get_delay(index) for each chunk — rotation (mod 512) is inside
    WatermarkBitstream; this class only owns the session lifecycle.

    Session lifecycle:
        arm()               ← TOS sniffer sees attacker SYN
        next_chunk_delay()  ← /backup handler calls per chunk
        session_snapshot()  ← read before disarm for schema.json
        disarm()            ← TOS sniffer sees FIN/RST
        reset()             ← between experiments
    """

    MODE = "app-layer"

    def __init__(self, rhythm):
        """rhythm: WatermarkBitstream (or any object with .get_delay(idx) and .bits)."""
        self._rhythm = rhythm
        self._lock   = threading.Lock()
        self._event  = threading.Event()

        self.attacker_ip = None
        self.start_ts    = None
        self.bits_used   = 0
        self.chunks_sent = 0

    # ── public control ───────────────────────────────────────────────────────

    def arm(self, attacker_ip=None, start_ts=None) -> None:
        """Arm a new session. Call on TOS SYN detection."""
        with self._lock:
            self.attacker_ip = attacker_ip
            self.start_ts    = start_ts or time.time()
            self.bits_used   = 0
            self.chunks_sent = 0
        self._event.set()

    def disarm(self) -> None:
        self._event.clear()

    def reset(self) -> None:
        """Clear all state between experiments."""
        with self._lock:
            self.attacker_ip = None
            self.start_ts    = None
            self.bits_used   = 0
            self.chunks_sent = 0
        self._event.clear()

    def is_armed(self) -> bool:
        return self._event.is_set()

    def wait_armed(self, timeout: float = 0.5) -> bool:
        return self._event.wait(timeout=timeout)

    # ── per-chunk injection ──────────────────────────────────────────────────

    def next_chunk_delay(self) -> tuple:
        """Advance bit index, apply delay, return (delay_s, bit).

        Call AFTER wfile.write() + flush() — delay-after-write so
        IPD_i = delay_i = f(bit_i). Delay-before-write causes off-by-one.
        """
        with self._lock:
            idx              = self.bits_used
            self.bits_used  += 1
            self.chunks_sent += 1
        delay, bit = self._rhythm.get_delay(idx)   # rhythm owns mod-512 rotation
        cns_hold(delay)
        return delay, bit

    # ── session data ─────────────────────────────────────────────────────────

    def session_snapshot(self) -> dict:
        """Return current session state as a dict (for schema.json)."""
        with self._lock:
            return {
                "attacker_ip":              self.attacker_ip,
                "start_timestamp":          self.start_ts,
                "exfiltrated_data_packets": self.chunks_sent,
                "rhythm": [self._rhythm.bits[i % 512] for i in range(self.bits_used)],
            }
