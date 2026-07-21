"""Feature Selection API — Scapy-based feature extraction functions.

Each function receives a Scapy packet and returns exactly one value (string).

Scapy is the capture backend and is already available everywhere the
framework runs — no additional dependencies are introduced here.

Users can create additional feature modules alongside this one and reference
them in the YAML feature_selection section without modifying any framework code.

YAML format:
    COLUMN_NAME: featureselectionapi.py:get_function_name
"""

import datetime
from decimal import Decimal

from scapy.all import IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, Ether, ARP, DNS

# TCP flag bit values in wire order
_TCP_FLAG_BITS = [
    (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
    (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"),
]


def get_device(packet) -> str:
    """Device name — read from PCAPNG IDB if_name metadata injected by Feature Selection Engine."""
    return getattr(packet, "_device", "Unknown") or "Unknown"


def get_interface(packet) -> str:
    """Interface name — read from PCAPNG IDB if_name metadata injected by Feature Selection Engine."""
    return getattr(packet, "_interface", "Unknown") or "Unknown"


def get_frame_number(packet) -> str:
    return str(getattr(packet, "_frame_number", ""))


def get_timestamp(packet) -> str:
    """Return timestamp in Wireshark format: YYYY-MM-DD HH:MM:SS.NNNNNNNNN."""
    try:
        t = packet.time
        if not isinstance(t, Decimal):
            t = Decimal(str(t))
        secs = int(t)
        nanos = int((t - secs) * 1_000_000_000)
        dt = datetime.datetime.utcfromtimestamp(secs)
        return dt.strftime("%Y-%m-%d %H:%M:%S") + f".{nanos:09d}"
    except Exception:
        return ""


def get_source(packet) -> str:
    if IP in packet:
        return packet[IP].src
    if IPv6 in packet:
        return packet[IPv6].src
    if ARP in packet:
        return packet[ARP].psrc
    if Ether in packet:
        return packet[Ether].src
    return ""


def get_destination(packet) -> str:
    if IP in packet:
        return packet[IP].dst
    if IPv6 in packet:
        return packet[IPv6].dst
    if ARP in packet:
        return packet[ARP].pdst
    if Ether in packet:
        return packet[Ether].dst
    return ""


def get_protocol(packet) -> str:
    # Most specific layer wins
    if DNS in packet:
        return "DNS"
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if ICMP in packet:
        return "ICMP"
    if ICMPv6EchoRequest in packet:
        return "ICMPv6"
    if ARP in packet:
        return "ARP"
    if IPv6 in packet:
        return "IPv6"
    if IP in packet:
        return "IP"
    if Ether in packet:
        return "Ethernet"
    return packet.__class__.__name__


def get_length(packet) -> str:
    try:
        return str(len(packet))
    except Exception:
        return ""


def get_source_port(packet) -> str:
    if TCP in packet:
        return str(packet[TCP].sport)
    if UDP in packet:
        return str(packet[UDP].sport)
    return ""


def get_destination_port(packet) -> str:
    if TCP in packet:
        return str(packet[TCP].dport)
    if UDP in packet:
        return str(packet[UDP].dport)
    return ""


def get_info(packet) -> str:
    """Build a Wireshark-style Info string for common protocols."""
    try:
        if TCP in packet:
            tcp = packet[TCP]
            flags = [name for bit, name in _TCP_FLAG_BITS if int(tcp.flags) & bit]
            flag_str = ", ".join(flags)
            payload_len = len(bytes(tcp.payload)) if tcp.payload else 0
            info = f"{tcp.sport} → {tcp.dport} [{flag_str}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window} Len={payload_len}"
            for opt_name, opt_val in (tcp.options or []):
                if opt_name == "MSS":
                    info += f" MSS={opt_val}"
                elif opt_name == "SAckOK":
                    info += " SACK_PERM=1"
                elif opt_name == "Timestamp":
                    info += f" TSval={opt_val[0]} TSecr={opt_val[1]}"
                elif opt_name == "WScale":
                    info += f" WS={2 ** opt_val}"
            return info

        if UDP in packet:
            udp = packet[UDP]
            return f"{udp.sport} → {udp.dport} Len={udp.len}"

        if ICMP in packet:
            icmp = packet[ICMP]
            type_names = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable", 11: "Time Exceeded"}
            type_str = type_names.get(icmp.type, f"Type={icmp.type}")
            return f"ICMP {type_str} id={getattr(icmp, 'id', '')} seq={getattr(icmp, 'seq', '')}"

        if ARP in packet:
            arp = packet[ARP]
            if arp.op == 1:
                return f"Who has {arp.pdst}? Tell {arp.psrc}"
            if arp.op == 2:
                return f"{arp.psrc} is at {arp.hwsrc}"

        return packet.summary()
    except Exception:
        try:
            return packet.summary()
        except Exception:
            return ""
