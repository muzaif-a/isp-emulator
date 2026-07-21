"""Logging and diagnostic utilities for ISP Network emulator."""

import logging
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from config_loader import TopologyConfig
    from ip_allocator import AllocationResult

# ANSI colour codes
_RESET = "\033[0m"
_BOLD = "\033[1m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_RED = "\033[31m"
_MAGENTA = "\033[35m"


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configure root logger with coloured console output."""
    numeric = getattr(logging, level.upper(), logging.INFO)
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(numeric)
    return root


def _section(title: str) -> None:
    bar = "=" * 60
    print(f"\n{_BOLD}{_CYAN}{bar}{_RESET}")
    print(f"{_BOLD}{_CYAN}  {title}{_RESET}")
    print(f"{_BOLD}{_CYAN}{bar}{_RESET}")


def print_topology(config: "TopologyConfig") -> None:
    """Pretty-print loaded topology."""
    _section("TOPOLOGY CONFIGURATION")
    print(f"\n{'Node':<12} {'Type':<10}")
    print("-" * 22)
    for node in config.nodes:
        colour = _GREEN if node.type == "router" else (_YELLOW if node.type == "host" else _CYAN)
        print(f"  {colour}{node.name:<10}{_RESET} {node.type}")

    print(f"\n{'Links':}")
    for link in config.links:
        print(f"  {link[0]} <---> {link[1]}")

    print(f"\nLAN gateways : {', '.join(config.lan_gateways)}")
    print(f"VPN gateways : {', '.join(config.vpn_gateways)}")
    for vp in config.vpn_peers:
        print(f"VPN peers    : {vp.gateway} --> {', '.join(vp.clients)}")


def print_allocation(allocation: "AllocationResult") -> None:
    """Pretty-print IP allocation result."""
    _section("IP ALLOCATION")

    print(f"\n{'Node':<10} {'Interface':<16} {'IP/Prefix':<20}")
    print("-" * 48)
    for node_name in sorted(allocation.node_interfaces):
        for iface, (ip, prefix) in sorted(allocation.node_interfaces[node_name].items()):
            print(f"  {_GREEN}{node_name:<8}{_RESET}  {iface:<14}  {ip}/{prefix}")

    print(f"\n{'Node':<10} {'Default Gateway'}")
    print("-" * 30)
    for node, gw in sorted(allocation.default_gateways.items()):
        print(f"  {_YELLOW}{node:<8}{_RESET}  {gw}")

    if allocation.vpn_node_ips:
        print(f"\n{'Node':<10} {'VPN IP'}")
        print("-" * 22)
        for node, vpn_ip in sorted(allocation.vpn_node_ips.items()):
            print(f"  {_MAGENTA}{node:<8}{_RESET}  {vpn_ip}")


def print_iface_aliases(allocation: "AllocationResult") -> None:
    """Show the node-name → alias mapping for nodes that needed shortening."""
    aliased = [
        (name, alias)
        for name, alias in sorted(allocation.node_aliases.items())
        if name != alias
    ]
    if not aliased:
        return
    _section("INTERFACE NAME ALIASES (long node names → short Linux interface prefix)")
    print(f"\n  {'Node name':<28} {'Alias':<10} {'Generated interfaces'}")
    print("  " + "-" * 70)
    for node_name, alias in aliased:
        ifaces = sorted(allocation.node_interfaces.get(node_name, {}).keys())
        ifaces_str = ", ".join(ifaces) if ifaces else "(no IP interfaces)"
        print(f"  {_YELLOW}{node_name:<26}{_RESET}  {_CYAN}{alias:<8}{_RESET}  {ifaces_str}")
    print()


def print_routing_table(node_name: str, table_output: str) -> None:
    """Print routing table for a node."""
    _section(f"ROUTING TABLE — {node_name}")
    for line in table_output.strip().splitlines():
        print(f"  {line}")


def print_test_result(name: str, passed: bool, detail: str = "") -> None:
    """Print a single test result line."""
    status = f"{_GREEN}PASS{_RESET}" if passed else f"{_RED}FAIL{_RESET}"
    suffix = f"  {detail}" if detail else ""
    print(f"  [{status}] {name}{suffix}")


def print_summary(passed: int, total: int) -> None:
    """Print final test summary."""
    _section("TEST SUMMARY")
    colour = _GREEN if passed == total else _RED
    print(f"\n  {colour}{passed}/{total} tests passed{_RESET}\n")
