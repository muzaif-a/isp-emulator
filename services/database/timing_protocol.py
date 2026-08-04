"""Timing protocol helpers for database response-delay metadata.

This module is intentionally lightweight and pure-Python so it can be reused
in both unit tests and runtime script generation.
"""

import hashlib
from dataclasses import dataclass
from typing import List, Optional

BITS_PER_DIGEST = 512


@dataclass
class TimingProtocolMetadata:
	enabled: bool
	secret_key: Optional[str]
	start_timestamp: Optional[float]
	end_timestamp: Optional[float]
	nonces_used: Optional[List[int]]
	total_data_packets: Optional[int]
	rhythm: Optional[List[int]]
	src: Optional[str]
	dest: Optional[str]
	short_delay_ms: Optional[float] = None
	long_delay_ms: Optional[float] = None


class TimingProtocol:
	"""Generate deterministic timing bits and runtime metadata."""

	def __init__(
		self,
		enabled: bool = False,
		secret_key: Optional[str] = None,
		short_delay_ms: float = 20.0,
		long_delay_ms: float = 50.0,
	) -> None:
		self.enabled = bool(enabled)
		self.secret_key = secret_key
		self.short_delay_s = short_delay_ms / 1000.0
		self.long_delay_s = long_delay_ms / 1000.0
		self.start_timestamp: Optional[float] = None
		self.end_timestamp: Optional[float] = None
		self.src: Optional[str] = None
		self.dest: Optional[str] = None

		self._current_nonce = 1
		self._bits_pool: List[int] = []
		self._rhythm: List[int] = []
		self._nonces_used: List[int] = []
		self._total_data_packets = 0

	def observe_first_request(
		self,
		now: float,
		src: Optional[str] = None,
		dest: Optional[str] = None,
	) -> None:
		if self.start_timestamp is None:
			self.start_timestamp = now
		if src and not self.src:
			self.src = src
		if dest and not self.dest:
			self.dest = dest

	def record_data_packet(self) -> None:
		if self.enabled:
			self._total_data_packets += 1

	def next_delay_seconds(self) -> float:
		if not self.enabled:
			return 0.0

		if not self._bits_pool:
<<<<<<< HEAD
			# digest = hashlib.sha512(f"{self.secret_key}:{self._current_nonce}".encode("utf-8")).digest()
=======
>>>>>>> 0c1e099 (static routing and ip issue solved)
			digest = hashlib.sha512(f"{self.secret_key}:{self.start_timestamp}:{self._current_nonce}".encode("utf-8")).digest()
			bits: List[int] = []
			for byte in digest:
				for shift in range(7, -1, -1):
					bits.append((byte >> shift) & 1)
			self._bits_pool = bits
			self._nonces_used.append(self._current_nonce)
			self._current_nonce += 1

		bit = self._bits_pool.pop(0)
		self._rhythm.append(bit)
		return self.short_delay_s if bit == 0 else self.long_delay_s

	def metadata(self) -> TimingProtocolMetadata:
		if not self.enabled:
			return TimingProtocolMetadata(
				enabled=False,
				secret_key=None,
				start_timestamp=None,
			end_timestamp=None,
				nonces_used=None,
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
			nonces_used=list(self._nonces_used),
			total_data_packets=self._total_data_packets,
			rhythm=list(self._rhythm),
			src=self.src,
			dest=self.dest,
			short_delay_ms=self.short_delay_s * 1000,
			long_delay_ms=self.long_delay_s * 1000,
		)