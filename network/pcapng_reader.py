"""Minimal PCAPNG reader.

Parses Interface Description Blocks (IDB) to extract if_name and
Enhanced Packet Blocks (EPB) to expose interface_id per packet.
This gives the Feature Selection Engine the metadata needed to populate
DEVICE and INTERFACE columns without hardcoding or inference.

Designed to work without PcapNgWriter/PcapNgReader — uses raw struct parsing
against the PCAPNG spec (RFC draft).

Usage:
    from pcapng_reader import PcapNgFile
    with PcapNgFile("session.pcapng") as f:
        for pkt in f:
            print(pkt.interface_name, pkt.data)
"""

import struct
from decimal import Decimal
from typing import Iterator, List, Optional

# Block type constants
_SHB = 0x0A0D0D0A
_IDB = 0x00000001
_EPB = 0x00000006
_SPB = 0x00000003  # Simple Packet Block (interface_id = 0 implied)
_OPB = 0x00000002  # Obsolete Packet Block (interface_id = 0 implied)

# IDB option codes
_OPT_IF_NAME   = 2
_OPT_IF_TSRESOL = 9


class PcapNgPacket:
    """A single packet from a PCAPNG capture."""

    __slots__ = ("data", "interface_id", "interface_name", "timestamp_us", "tsresol", "linktype")

    def __init__(
        self,
        data: bytes,
        interface_id: int,
        interface_name: str,
        timestamp_us: int,
        linktype: int,
        tsresol: int = 1_000_000,
    ) -> None:
        self.data = data
        self.interface_id = interface_id
        self.interface_name = interface_name
        self.timestamp_us = timestamp_us  # raw EPB timestamp value (units = 1/tsresol s)
        self.tsresol = tsresol
        self.linktype = linktype

    @property
    def device(self) -> str:
        """Derive device name from Mininet interface naming convention.

        Mininet names interfaces as <node>-<ethN>, e.g. r1-eth0.
        The device is everything before the first '-'.
        Returns 'Unknown' if interface_name is 'Unknown' or unparseable.
        """
        if self.interface_name in ("", "Unknown"):
            return "Unknown"
        return self.interface_name.split("-")[0]

    @property
    def timestamp_s(self) -> float:
        return self.timestamp_us / self.tsresol

    @property
    def timestamp_decimal(self) -> Decimal:
        """Full-precision timestamp as Decimal seconds since epoch."""
        return Decimal(self.timestamp_us) / Decimal(self.tsresol)


def _parse_idb_options(opts: bytes, endian: str):
    """Scan IDB option bytes; return (if_name, tsresol).

    if_name: option code 2. Default 'Unknown'.
    tsresol: option code 9, per PCAPNG spec. Default 1_000_000 (microseconds).
    """
    name = "Unknown"
    tsresol_byte: Optional[int] = None
    i = 0
    while i + 4 <= len(opts):
        code, length = struct.unpack_from(endian + "HH", opts, i)
        i += 4
        if code == 0:  # end of options
            break
        value = opts[i : i + length]
        pad = (4 - length % 4) % 4
        i += length + pad
        if code == _OPT_IF_NAME:
            name = value.decode("utf-8", errors="replace").rstrip("\x00")
        elif code == _OPT_IF_TSRESOL and length >= 1:
            tsresol_byte = value[0]

    if tsresol_byte is None:
        tsresol = 1_000_000           # PCAPNG default: microseconds (10^-6)
    elif tsresol_byte & 0x80:
        tsresol = 2 ** (tsresol_byte & 0x7F)
    else:
        tsresol = 10 ** tsresol_byte

    return name, tsresol


class PcapNgFile:
    """Iterate packets from a PCAPNG file, exposing per-packet interface metadata."""

    def __init__(self, filename: str) -> None:
        self._filename = filename
        self._fh = None
        self._endian = "<"
        self._interfaces: List[dict] = []  # [{name, linktype, tsresol}, ...]

    def __enter__(self) -> "PcapNgFile":
        self._fh = open(self._filename, "rb")
        self._parse_shb()
        return self

    def __exit__(self, *_) -> None:
        if self._fh:
            self._fh.close()

    def __iter__(self) -> Iterator[PcapNgPacket]:
        return self._iter_packets()

    # ---------------------------------------------------------------- internals

    def _read(self, n: int) -> bytes:
        data = self._fh.read(n)
        if len(data) < n:
            raise EOFError("Unexpected end of PCAPNG file")
        return data

    def _parse_shb(self) -> None:
        """Read and validate the Section Header Block."""
        raw_type = self._fh.read(4)
        if len(raw_type) < 4:
            raise ValueError("File too short to be PCAPNG")
        (block_type,) = struct.unpack("<I", raw_type)
        if block_type != _SHB:
            raise ValueError(f"Not a PCAPNG file (expected SHB {_SHB:#010x}, got {block_type:#010x})")

        (block_len,) = struct.unpack("<I", self._read(4))
        (bom,) = struct.unpack("<I", self._read(4))

        if bom == 0x1A2B3C4D:
            self._endian = "<"
        elif bom == 0x4D3C2B1A:
            self._endian = ">"
        else:
            raise ValueError(f"Unknown byte-order magic: {bom:#010x}")

        # Skip remaining SHB body and trailing block length
        remaining = block_len - 16  # already consumed: type(4)+len(4)+bom(4) = 12, then trailing(4)
        self._fh.read(remaining)  # major, minor, section_len, options
        self._fh.read(4)  # trailing block length

    def _next_block(self) -> Optional[tuple]:
        """Read next block. Returns (block_type, body) or None at EOF."""
        header = self._fh.read(8)
        if len(header) < 8:
            return None
        block_type, block_len = struct.unpack(self._endian + "II", header)
        if block_len < 12:
            return None
        body = self._fh.read(block_len - 12)
        self._fh.read(4)  # trailing block length
        return block_type, body

    def _parse_idb(self, body: bytes) -> None:
        """Parse an Interface Description Block and append to interfaces list."""
        if len(body) < 8:
            self._interfaces.append({"name": "Unknown", "linktype": 1, "tsresol": 1_000_000})
            return
        link_type, _reserved, _snap_len = struct.unpack_from(self._endian + "HHI", body)
        iface_name, tsresol = _parse_idb_options(body[8:], self._endian)
        self._interfaces.append({
            "name": iface_name,
            "linktype": link_type,
            "tsresol": tsresol,
        })

    def _parse_epb(self, body: bytes) -> Optional[PcapNgPacket]:
        """Parse an Enhanced Packet Block."""
        if len(body) < 20:
            return None
        iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack_from(
            self._endian + "IIIII", body
        )
        pkt_data = body[20 : 20 + cap_len]
        ts_us = (ts_high << 32) | ts_low

        if iface_id < len(self._interfaces):
            iface = self._interfaces[iface_id]
            iface_name = iface["name"]
            linktype = iface["linktype"]
            tsresol = iface["tsresol"]
        else:
            iface_name = "Unknown"
            linktype = 1
            tsresol = 1_000_000

        return PcapNgPacket(
            data=pkt_data,
            interface_id=iface_id,
            interface_name=iface_name,
            timestamp_us=ts_us,
            linktype=linktype,
            tsresol=tsresol,
        )

    def _iter_packets(self) -> Iterator[PcapNgPacket]:
        while True:
            try:
                result = self._next_block()
            except EOFError:
                return
            if result is None:
                return
            block_type, body = result

            if block_type == _IDB:
                self._parse_idb(body)

            elif block_type == _EPB:
                pkt = self._parse_epb(body)
                if pkt is not None:
                    yield pkt

            elif block_type == _SPB:
                # Simple Packet Block — interface_id implicitly 0
                if len(body) >= 4:
                    (orig_len,) = struct.unpack_from(self._endian + "I", body)
                    pkt_data = body[4:]
                    iface = self._interfaces[0] if self._interfaces else {"name": "Unknown", "linktype": 1}
                    yield PcapNgPacket(
                        data=pkt_data,
                        interface_id=0,
                        interface_name=iface["name"],
                        timestamp_us=0,
                        linktype=iface["linktype"],
                    )

            elif block_type == _SHB:
                # New section — reset interface list
                self._interfaces = []

            # All other block types: skip
