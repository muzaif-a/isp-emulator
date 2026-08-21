"""Timing protocol helpers for database response-delay metadata.

Lightweight, pure-Python — usable in unit tests, flow_watermark.py, and the
embedded _API_SCRIPT.  Tracks per-injector-cycle sessions: one session = one
TOS-marked TCP connection from attacker → one row of rhythm + metadata.

Session lifecycle
-----------------
new_session(timestamp, src, dest)
    Arms a fresh session (archives any in-progress one first).
    Called by TOS sniffer on each distinct attacker connection.

next_delay_seconds()
    Pops one bit from the SHA-512 keyed bitstream.
    Returns short_delay_s (bit=0) or long_delay_s (bit=1).
    Bitstream cycles when 512 bits exhausted.

record_data_packet()
    Increments exfiltrated-packet counter for the active session.

record_end()
    Stamps end_timestamp on the active session.

finalize_session()
    Archives active session into _sessions, resets to idle.
    Called by HTTP handler after each response is fully sent.

sessions()
    Returns list of all archived TimingProtocolMetadata (finalized sessions).

metadata()
    Returns TimingProtocolMetadata for the current active session only
    (backwards-compatible single-session view for tests and flow_watermark).
"""

import hashlib
import threading
from dataclasses import dataclass
from typing import List, Optional

BITS_PER_DIGEST = 512


@dataclass
class TimingProtocolMetadata:
    enabled: bool
    secret_key: Optional[str]
    start_timestamp: Optional[float]
    end_timestamp: Optional[float]
    total_data_packets: Optional[int]
    rhythm: Optional[List[int]]
    src: Optional[str]
    dest: Optional[str]
    short_delay_ms: Optional[float] = None
    long_delay_ms: Optional[float] = None


class TimingProtocol:
    """Keyed bitstream generator with per-injector-cycle session accumulation."""

    def __init__(
        self,
        enabled: bool = False,
        secret_key: Optional[str] = None,
        short_delay_ms: float = 20.0,
        long_delay_ms: float = 50.0,
    ) -> None:
        self._lock = threading.Lock()
        self.secret_key = secret_key
        self.short_delay_s = short_delay_ms / 1000.0
        self.long_delay_s = long_delay_ms / 1000.0

        self._fixed_bits: List[int] = self._derive_bits(secret_key)
        self._sessions: List[TimingProtocolMetadata] = []

        # Per-session mutable state — reset between sessions.
        self.enabled: bool = bool(enabled)
        self.start_timestamp: Optional[float] = None
        self.end_timestamp: Optional[float] = None
        self.src: Optional[str] = None
        self.dest: Optional[str] = None
        self._bits_pool: List[int] = list(self._fixed_bits)
        self._rhythm: List[int] = []
        self._total_data_packets: int = 0

    # ── session lifecycle ────────────────────────────────────────────────────

    def new_session(
        self,
        timestamp: float,
        src: Optional[str] = None,
        dest: Optional[str] = None,
    ) -> None:
        """Start a new injector cycle.

        Archives any active session first, then resets state and arms a new one.
        """
        with self._lock:
            if self.enabled and (self._total_data_packets or self._rhythm):
                self._sessions.append(self._snapshot_locked())
            self._reset_locked()
            self.enabled = True
            self.start_timestamp = timestamp
            self.src = src
            self.dest = dest

    def finalize_session(self) -> None:
        """Archive active session and return to idle.

        Called by HTTP handler after each response is fully sent, so the next
        non-TOS request does not inherit the previous session's armed state.
        """
        with self._lock:
            if self.enabled:
                self._sessions.append(self._snapshot_locked())
            self._reset_locked()

    def reset(self) -> None:
        """Full reset — clears all accumulated sessions. Between experiments."""
        with self._lock:
            self._sessions.clear()
            self._reset_locked()

    # ── per-packet recording ─────────────────────────────────────────────────

    def observe_first_request(
        self,
        now: float,
        src: Optional[str] = None,
        dest: Optional[str] = None,
    ) -> None:
        """Backwards-compatible: set t0/src/dest if not already set."""
        with self._lock:
            if self.start_timestamp is None:
                self.start_timestamp = now
            if src and not self.src:
                self.src = src
            if dest and not self.dest:
                self.dest = dest

    def record_data_packet(self) -> None:
        if self.enabled:
            with self._lock:
                self._total_data_packets += 1

    def record_end(self) -> None:
        """Stamp end_timestamp on the active session."""
        if self.enabled:
            with self._lock:
                import time
                self.end_timestamp = time.time()

    def next_delay_seconds(self) -> float:
        if not self.enabled:
            return 0.0
        with self._lock:
            if not self._bits_pool:
                self._bits_pool = list(self._fixed_bits)   # cycle same 512 bits
            bit = self._bits_pool.pop(0)
            self._rhythm.append(bit)
        return self.short_delay_s if bit == 0 else self.long_delay_s

    # ── metadata accessors ───────────────────────────────────────────────────

    def metadata(self) -> TimingProtocolMetadata:
        """Current active session metadata (single-session view)."""
        with self._lock:
            return self._snapshot_locked()

    def sessions(self) -> List[TimingProtocolMetadata]:
        """All finalized sessions (one per injector cycle)."""
        with self._lock:
            return list(self._sessions)

    def all_sessions(self) -> List[TimingProtocolMetadata]:
        """Finalized sessions + current active session (if any)."""
        with self._lock:
            result = list(self._sessions)
            if self.enabled:
                result.append(self._snapshot_locked())
            return result

    # ── internals ────────────────────────────────────────────────────────────

    @staticmethod
    def _derive_bits(secret_key: Optional[str]) -> List[int]:
        digest = hashlib.sha512((secret_key or "").encode("utf-8")).digest()
        bits: List[int] = []
        for byte in digest:
            for shift in range(7, -1, -1):
                bits.append((byte >> shift) & 1)
        return bits

    def _reset_locked(self) -> None:
        """Reset per-session state. Caller must hold self._lock."""
        self.enabled = False
        self.start_timestamp = None
        self.end_timestamp = None
        self.src = None
        self.dest = None
        self._bits_pool = list(self._fixed_bits)
        self._rhythm = []
        self._total_data_packets = 0

    def _snapshot_locked(self) -> TimingProtocolMetadata:
        """Snapshot current session as TimingProtocolMetadata. Caller holds lock."""
        if not self.enabled:
            return TimingProtocolMetadata(
                enabled=False,
                secret_key=None,
                start_timestamp=None,
                end_timestamp=None,
                total_data_packets=None,
                rhythm=None,
                src=self.src,
                dest=self.dest,
            )
        return TimingProtocolMetadata(
            enabled=True,
            secret_key=self.secret_key,
            start_timestamp=self.start_timestamp,
            end_timestamp=self.end_timestamp,
            total_data_packets=self._total_data_packets,
            rhythm=list(self._rhythm),
            src=self.src,
            dest=self.dest,
            short_delay_ms=self.short_delay_s * 1000,
            long_delay_ms=self.long_delay_s * 1000,
        )
