"""Network-layer watermark — NFQUEUE intercepts outgoing TCP segments.

rhythm_computer.WatermarkBitstream computes the 512-bit rhythm.
database_manager instantiates it and passes it here as `rhythm`.
NetWatermark owns arm/disarm/NFQUEUE lifecycle; database_manager just calls the interface.

Requires: python3-netfilterqueue, nftables, root privileges.

Usage:
    from rhythm_computer import WatermarkBitstream
    rhythm = WatermarkBitstream(secret_key, short_delay_ms=20, long_delay_ms=50)

    wm = NetWatermark(port=8080, rhythm=rhythm)
    if wm.setup():                 # installs nft rule, starts NFQUEUE thread
        wm.arm("10.0.0.2")        # TOS sniffer on SYN
        wm.disarm()               # TOS sniffer on FIN
        wm.teardown()             # DB shutdown

    NetWatermark.is_available()   # check without running setup
"""

import ctypes
import subprocess
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


def _cns_hold(delay_s: float) -> None:
    """clock_nanosleep absolute-time hold — ±50–200µs accuracy."""
    if not (_librt_ok and delay_s > 0):
        time.sleep(max(0, delay_s))
        return
    abs_ns = _mono_ns() + int(delay_s * 1_000_000_000)
    ts = _Ts(tv_sec=abs_ns // 1_000_000_000, tv_nsec=abs_ns % 1_000_000_000)
    while _librt.clock_nanosleep(_CLOCK_MONO, _ABSTIME, ctypes.byref(ts), None) == 4:
        pass


# ── NetWatermark ──────────────────────────────────────────────────────────────

class NetWatermark:
    """Network-layer watermark engine using NFQUEUE.

    Receives a WatermarkBitstream from database_manager.
    NFQUEUE callback calls rhythm.get_delay(index) per outgoing data segment —
    rotation (mod 512) is inside WatermarkBitstream; this class only owns
    session lifecycle and NFQUEUE/nftables management.

    Session lifecycle:
        setup()              called at DB start — nft rule + NFQUEUE thread
        arm(attacker_ip)     TOS sniffer sees SYN
        [callback auto-delays data segments while armed]
        session_snapshot()   read before disarm for schema.json
        disarm()             TOS sniffer sees FIN/RST
        teardown()           DB shutdown — remove nft rule
        reset()              between experiments
    """

    MODE = "network-layer"

    def __init__(self, port: int, rhythm):
        """rhythm: WatermarkBitstream (or any object with .get_delay(idx) and .bits)."""
        self._port      = port
        self._rhythm    = rhythm
        self._lock      = threading.Lock()
        self._event     = threading.Event()
        self._nfq       = None
        self._active    = False
        self._nfq_num   = port % 100
        self._nft_table = f"wm_{port}"

        self.attacker_ip = None
        self.start_ts    = None
        self.bits_used   = 0
        self.chunks_sent = 0

    # ── availability ─────────────────────────────────────────────────────────

    @staticmethod
    def is_available() -> bool:
        try:
            import netfilterqueue  # noqa: F401
            subprocess.check_call(["nft", "--version"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

    # ── lifecycle ────────────────────────────────────────────────────────────

    def setup(self) -> bool:
        """Install nftables rule + bind NFQUEUE thread. Returns False on failure."""
        try:
            from netfilterqueue import NetfilterQueue
            for cmd in [
                ["nft", "add", "table", "ip", self._nft_table],
                ["nft", "add", "chain", "ip", self._nft_table, "out",
                 "{", "type", "filter", "hook", "output", "priority", "0", ";",
                 "policy", "accept", ";", "}"],
                ["nft", "add", "rule", "ip", self._nft_table, "out",
                 "ip", "protocol", "tcp", "tcp", "sport", str(self._port),
                 "queue", "num", str(self._nfq_num)],
            ]:
                subprocess.check_call(cmd, stderr=subprocess.DEVNULL)

            self._nfq = NetfilterQueue()
            self._nfq.bind(self._nfq_num, self._callback)
            threading.Thread(target=self._nfq.run, daemon=True,
                             name=f"nfq-{self._port}").start()
            self._active = True
            return True
        except Exception:
            self._active = False
            return False

    def teardown(self) -> None:
        """Remove nftables rule and unbind NFQUEUE."""
        if self._nfq:
            try:
                self._nfq.unbind()
            except Exception:
                pass
            self._nfq = None
        subprocess.call(["nft", "delete", "table", "ip", self._nft_table],
                        stderr=subprocess.DEVNULL)
        self._active = False

    def is_active(self) -> bool:
        return self._active

    # ── public control ───────────────────────────────────────────────────────

    def arm(self, attacker_ip=None, start_ts=None) -> None:
        with self._lock:
            self.attacker_ip = attacker_ip
            self.start_ts    = start_ts or time.time()
            self.bits_used   = 0
            self.chunks_sent = 0
        self._event.set()

    def disarm(self) -> None:
        self._event.clear()

    def reset(self) -> None:
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

    # ── session data ─────────────────────────────────────────────────────────

    def session_snapshot(self) -> dict:
        with self._lock:
            return {
                "attacker_ip":              self.attacker_ip,
                "start_timestamp":          self.start_ts,
                "exfiltrated_data_packets": self.chunks_sent,
                "rhythm": [self._rhythm.bits[i % 512] for i in range(self.bits_used)],
            }

    # ── NFQUEUE callback ─────────────────────────────────────────────────────

    def _callback(self, nfpkt) -> None:
        """Intercept outgoing TCP segment: delay data segments, pass control free.

        rhythm.get_delay(idx) owns the mod-512 rotation and returns (delay_s, bit).
        """
        delay = 0.0
        try:
            from scapy.layers.inet import IP as _IP, TCP as _TCP
            p = _IP(nfpkt.get_payload())
            if p.haslayer(_TCP):
                tcp = p[_TCP]
                payload_len = len(bytes(tcp.payload))
                if (payload_len > 0
                        and self._event.is_set()
                        and p.dst == self.attacker_ip):
                    with self._lock:
                        idx              = self.bits_used
                        self.bits_used  += 1
                        self.chunks_sent += 1
                    delay, _bit = self._rhythm.get_delay(idx)
        except Exception:
            pass   # never drop packet on error
        _cns_hold(delay)
        nfpkt.accept()
