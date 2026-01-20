"""Utility helpers for parsing and matching."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from typing import Iterable, Optional

from .models import AddressObject, AddressType, Protocol, ServiceEntry, ServiceObject


PORT_PATTERN = re.compile(r"^(?P<proto>tcp|udp)_(?P<start>\d+)(?:-(?P<end>\d+))?$")


@dataclass(frozen=True)
class PortSpec:
    """Represents a label + port/protocol entry from the ports file."""

    label: str
    protocol: Protocol
    port: int


class ParseError(ValueError):
    """Raised when parsing input data fails."""


def parse_ipv4_network(value: str) -> IPv4Network:
    """Parse IPv4 CIDR, raising ParseError on failure."""
    try:
        network = ip_network(value, strict=False)
    except ValueError as exc:
        raise ParseError(f"Invalid IPv4 CIDR: {value}") from exc
    if network.version != 4:
        raise ParseError(f"Only IPv4 is supported: {value}")
    return network


def parse_ipv4_address(value: str) -> IPv4Address:
    """Parse IPv4 address, raising ParseError on failure."""
    try:
        address = ip_address(value)
    except ValueError as exc:
        raise ParseError(f"Invalid IPv4 address: {value}") from exc
    if address.version != 4:
        raise ParseError(f"Only IPv4 is supported: {value}")
    return address


def parse_address_object(
    name: str,
    address_type: str,
    subnet: Optional[str] = None,
    start_ip: Optional[str] = None,
    end_ip: Optional[str] = None,
) -> AddressObject:
    """Build an AddressObject from string inputs."""
    normalized_type = address_type.lower()
    if normalized_type == AddressType.IPMASK.value:
        if not subnet:
            raise ParseError(f"Missing subnet for address object: {name}")
        return AddressObject(
            name=name,
            address_type=AddressType.IPMASK,
            subnet=parse_ipv4_network(subnet),
        )
    if normalized_type == "none":
        if not start_ip or not end_ip:
            raise ParseError(f"Missing subnet IP/mask for address object: {name}")
        # Some exports mark subnet records as "none" while providing IP + netmask fields.
        # Treat these as subnet definitions by building a network from the IP and netmask.
        subnet_ip = parse_ipv4_address(start_ip)
        subnet_mask = parse_ipv4_address(end_ip)
        try:
            subnet_network = ip_network(f"{subnet_ip}/{subnet_mask}", strict=False)
        except ValueError as exc:
            raise ParseError(
                f"Invalid subnet IP/mask for address object: {name} ({start_ip} {end_ip})"
            ) from exc
        if subnet_network.version != 4:
            raise ParseError(f"Only IPv4 is supported: {start_ip}/{end_ip}")
        return AddressObject(
            name=name,
            address_type=AddressType.IPMASK,
            subnet=subnet_network,
        )
    if normalized_type == AddressType.IPRANGE.value:
        if not start_ip or not end_ip:
            raise ParseError(f"Missing IP range for address object: {name}")
        return AddressObject(
            name=name,
            address_type=AddressType.IPRANGE,
            start_ip=parse_ipv4_address(start_ip),
            end_ip=parse_ipv4_address(end_ip),
        )
    if normalized_type == AddressType.FQDN.value:
        return AddressObject(name=name, address_type=AddressType.FQDN)
    raise ParseError(f"Unsupported address type: {address_type}")


def parse_service_entry(value: str) -> ServiceEntry:
    """Parse a service entry like tcp_80 or udp_1000-2000."""
    match = PORT_PATTERN.match(value.strip().lower())
    if not match:
        raise ParseError(f"Invalid service entry: {value}")
    proto = Protocol(match.group("proto"))
    start = int(match.group("start"))
    end = int(match.group("end") or start)
    if not (1 <= start <= 65535 and 1 <= end <= 65535):
        raise ParseError(f"Port out of range: {value}")
    if start > end:
        raise ParseError(f"Invalid port range: {value}")
    return ServiceEntry(protocol=proto, start_port=start, end_port=end)


def parse_ports_file(lines: Iterable[str]) -> list[PortSpec]:
    """Parse the ports input file into PortSpec entries."""
    specs: list[PortSpec] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        if "," not in line:
            raise ParseError(f"Invalid port line: {line}")
        label, value = [part.strip() for part in line.split(",", 1)]
        if "/" not in value:
            raise ParseError(f"Invalid port line: {line}")
        port_str, proto_str = [part.strip() for part in value.split("/", 1)]
        if not port_str.isdigit():
            raise ParseError(f"Invalid port: {port_str}")
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise ParseError(f"Port out of range: {port}")
        try:
            protocol = Protocol(proto_str.lower())
        except ValueError as exc:
            raise ParseError(f"Unsupported protocol: {proto_str}") from exc
        specs.append(PortSpec(label=label, protocol=protocol, port=port))
    return specs


def parse_json_array(value: str) -> list[str]:
    """Parse a JSON array string into a list of strings."""
    try:
        data = json.loads(value or "[]")
    except json.JSONDecodeError as exc:
        raise ParseError(f"Invalid JSON array: {value}") from exc
    if not isinstance(data, list):
        raise ParseError(f"Expected JSON array, got: {type(data).__name__}")
    return [str(item) for item in data]


def make_any_service(name: str = "ALL") -> ServiceObject:
    """Create a service that matches any protocol and port."""
    return ServiceObject(name=name, entries=(ServiceEntry(protocol=None, start_port=None, end_port=None),))
