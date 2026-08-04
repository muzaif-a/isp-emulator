"""Feature API — reusable feature provider functions for the capture framework.

Each function receives a Scapy packet and returns exactly one value (string).

Users can create additional feature modules and reference them in the YAML
Features section without modifying any framework code.
"""

import os

from scapy.all import IP, IPv6, TCP, UDP, ICMP, Ether, ARP

ATTACK_TOS = int(os.environ.get("ATTACK_TOS", "0x10"), 0)


def get_device(packet) -> str:
    """Return the capture device name. Not available from merged PCAP."""
    return getattr(packet, "_device", "")


def get_interface(packet) -> str:
    """Return the capture interface name. Not available from merged PCAP."""
    return getattr(packet, "_interface", "")


def get_frame_number(packet) -> str:
    return str(getattr(packet, "_frame_number", ""))


def get_timestamp(packet) -> str:
    try:
        return str(float(packet.time))
    except Exception:
        return ""


def get_source(packet) -> str:
    if IP in packet:
        return packet[IP].src
    if IPv6 in packet:
        return packet[IPv6].src
    if Ether in packet:
        return packet[Ether].src
    return ""


def get_destination(packet) -> str:
    if IP in packet:
        return packet[IP].dst
    if IPv6 in packet:
        return packet[IPv6].dst
    if Ether in packet:
        return packet[Ether].dst
    return ""


def get_protocol(packet) -> str:
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if ICMP in packet:
        return "ICMP"
    if ARP in packet:
        return "ARP"
    if IP in packet:
        return "IP"
    if IPv6 in packet:
        return "IPv6"
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
    try:
        return packet.summary()
    except Exception:
        return ""


def get_tos(packet) -> str:
    """Return IP TOS field as integer string. TOS=16 (0x10) = attack traffic."""
    if IP in packet:
        return str(packet[IP].tos)
    return ""


def get_is_attack(packet) -> str:
    """Return '1' if TOS=0x10 (attack marker), '0' otherwise."""
    if IP in packet:
        return "1" if packet[IP].tos == ATTACK_TOS else "0"
    return "0"


def get_ttl(packet) -> str:
    if IP in packet:
        return str(packet[IP].ttl)
    return ""
