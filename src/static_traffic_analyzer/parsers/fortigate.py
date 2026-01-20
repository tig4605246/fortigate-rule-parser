"""Parser for FortiGate CLI configuration files."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
import socket

from ..catalog import DEFAULT_SERVICES
from ..models import (
    AddressBook,
    AddressGroup,
    PolicyRule,
    ServiceBook,
    ServiceGroup,
    ServiceObject,
)
from ..utils import ParseError, make_any_service, parse_address_object, parse_service_entry


@dataclass
class FortiGateData:
    """Parsed FortiGate configuration payload."""

    address_book: AddressBook
    service_book: ServiceBook
    policies: list[PolicyRule]


def _split_fortigate_members(members: str | list[str]) -> tuple[str, ...]:
    """Split FortiGate member strings into a tuple of members."""
    all_members = []
    if isinstance(members, str):
        all_members.extend(members.split())
    elif isinstance(members, list):
        for member_str in members:
            all_members.extend(member_str.split())
    return tuple(member.strip('"') for member in all_members if member)


def parse_fortigate_config(lines: Iterable[str]) -> FortiGateData:
    """Parse a FortiGate CLI configuration file into internal models."""
    address_book = AddressBook()
    service_book = ServiceBook()
    policies: list[PolicyRule] = []

    current_section = None
    current_name = None
    current_fields: dict[str, list[str] | str] = {}

    def flush_address() -> None:
        nonlocal current_name, current_fields
        if not current_name:
            return
        address_type = str(current_fields.get("type", "ipmask"))
        subnet = current_fields.get("subnet")
        if isinstance(subnet, list):
            subnet_value = " ".join(subnet)
        else:
            subnet_value = subnet
        start_ip = current_fields.get("start-ip")
        end_ip = current_fields.get("end-ip")
        if isinstance(start_ip, list):
            start_ip = start_ip[0]
        if isinstance(end_ip, list):
            end_ip = end_ip[0]
        if subnet_value and address_type == "ipmask":
            parts = subnet_value.split()
            if len(parts) == 2:
                subnet_value = f"{parts[0]}/{parts[1]}"
        try:
            address_book.objects[current_name] = parse_address_object(
                name=current_name,
                address_type=address_type,
                subnet=subnet_value,
                start_ip=start_ip,
                end_ip=end_ip,
            )
        except ParseError:
            address_book.objects[current_name] = parse_address_object(
                name=current_name,
                address_type="fqdn",
            )
        current_name = None
        current_fields = {}

    def flush_addr_group() -> None:
        nonlocal current_name, current_fields
        if not current_name:
            return
        members = current_fields.get("member", [])
        cleaned = _split_fortigate_members(members)
        address_book.groups[current_name] = AddressGroup(name=current_name, members=cleaned)
        current_name = None
        current_fields = {}

    def flush_service() -> None:
        nonlocal current_name, current_fields
        if not current_name:
            return
        entries = []
        for key in ("tcp-portrange", "udp-portrange"):
            raw = current_fields.get(key)
            if not raw:
                continue
            if isinstance(raw, list):
                raw_values = raw
            else:
                raw_values = [raw]
            for value in raw_values:
                for part in str(value).split():
                    proto = "tcp" if key.startswith("tcp") else "udp"
                    entry_value = f"{proto}_{part}"
                    try:
                        entries.append(parse_service_entry(entry_value))
                    except ParseError:
                        continue
        if not entries:
            service_book.services[current_name] = make_any_service(current_name)
        else:
            service_book.services[current_name] = ServiceObject(name=current_name, entries=tuple(entries))
        current_name = None
        current_fields = {}

    def flush_service_group() -> None:
        nonlocal current_name, current_fields
        if not current_name:
            return
        members = current_fields.get("member", [])
        cleaned = _split_fortigate_members(members)
        service_book.groups[current_name] = ServiceGroup(name=current_name, members=cleaned)

        for member in cleaned:
            if member in service_book.services or member in service_book.groups:
                continue

            if member.lower().startswith("tcp_") or member.lower().startswith("udp_"):
                try:
                    service_book.services[member] = ServiceObject(
                        name=member, entries=(parse_service_entry(member),)
                    )
                except ParseError:
                    pass  # May not be a valid entry, or defined later
            else:
                try:
                    service_book.services[member] = ServiceObject(
                        name=member, entries=(socket.getservbyname(member),)
                    )
                except (OSError, TypeError):
                    pass  # Might be a custom service defined later.

        current_name = None
        current_fields = {}

    def flush_policy() -> None:
        nonlocal current_name, current_fields
        if not current_name:
            return
        policy_id = current_name
        name = str(current_fields.get("name", "no-name")).strip('"')
        srcaddr = current_fields.get("srcaddr", [])
        dstaddr = current_fields.get("dstaddr", [])
        service = current_fields.get("service", [])
        action = str(current_fields.get("action", "deny"))
        schedule = current_fields.get("schedule")
        status = str(current_fields.get("status", "enable"))

        cleaned_services = _split_fortigate_members(service)
        for member in cleaned_services:
            if member in service_book.services or member in service_book.groups:
                continue

            if member.lower().startswith("tcp_") or member.lower().startswith("udp_"):
                try:
                    service_book.services[member] = ServiceObject(
                        name=member, entries=(parse_service_entry(member),)
                    )
                except ParseError:
                    pass
            else:
                try:
                    service_book.services[member] = ServiceObject(
                        name=member, entries=(socket.getservbyname(member),)
                    )
                except (OSError, TypeError):
                    pass

        policies.append(
            PolicyRule(
                policy_id=policy_id,
                name=name,
                priority=int(policy_id) if policy_id.isdigit() else len(policies) + 1,
                source=_split_fortigate_members(srcaddr),
                destination=_split_fortigate_members(dstaddr),
                services=cleaned_services,
                action=action,
                enabled=status.lower() == "enable",
                schedule=schedule.strip('"') if isinstance(schedule, str) else None,
            )
        )
        current_name = None
        current_fields = {}

    section_flush = {
        "config firewall address": flush_address,
        "config firewall addrgrp": flush_addr_group,
        "config firewall service custom": flush_service,
        "config firewall service group": flush_service_group,
        "config firewall policy": flush_policy,
    }

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("config "):
            if current_section in section_flush:
                section_flush[current_section]()
            current_section = line
            continue
        if line == "end":
            if current_section in section_flush:
                section_flush[current_section]()
            current_section = None
            continue
        if line.startswith("edit "):
            if current_section in section_flush:
                section_flush[current_section]()
            current_name = line.split(" ", 1)[1].strip().strip('"')
            current_fields = {}
            continue
        if line == "next":
            if current_section in section_flush:
                section_flush[current_section]()
            continue
        if line.startswith("set "):
            parts = line.split(" ", 2)
            if len(parts) < 3:
                continue
            key = parts[1]
            value = parts[2].strip()
            if key in current_fields:
                existing = current_fields[key]
                if isinstance(existing, list):
                    existing.append(value)
                else:
                    current_fields[key] = [existing, value]
            else:
                current_fields[key] = value
            continue
        if line.startswith("unset "):
            key = line.split(" ", 1)[1].strip()
            current_fields.pop(key, None)

    if current_section in section_flush:
        section_flush[current_section]()

    if "all" not in address_book.objects:
        address_book.objects["all"] = parse_address_object("all", "ipmask", subnet="0.0.0.0/0")
    for name, service in DEFAULT_SERVICES.items():
        service_book.services.setdefault(name, service)
    if "ALL" not in service_book.services:
        service_book.services["ALL"] = make_any_service("ALL")

    policies.sort(key=lambda rule: rule.priority)

    return FortiGateData(address_book=address_book, service_book=service_book, policies=policies)
