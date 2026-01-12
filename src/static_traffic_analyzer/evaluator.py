"""Policy evaluation logic for the static traffic analyzer."""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import Iterable, Optional

from .models import (
    AddressBook,
    AddressObject,
    AddressType,
    Decision,
    MatchDetail,
    MatchOutcome,
    PolicyRule,
    Protocol,
    ServiceBook,
    ServiceEntry,
    ServiceObject,
)


@dataclass(frozen=True)
class MatchMode:
    """Matching behavior for address containment."""

    mode: str
    max_hosts: int


def _evaluate_address_objects(
    objects: Iterable[AddressObject],
    network: IPv4Network,
    mode: MatchMode,
) -> MatchOutcome:
    """Evaluate address objects against a target network."""
    has_unknown = False
    for obj in objects:
        if obj.address_type == AddressType.FQDN:
            has_unknown = True
            continue
        if mode.mode == "sample-ip":
            if obj.contains_ip(network.network_address):
                return MatchOutcome.MATCH
        elif mode.mode == "expand":
            if network.num_addresses <= mode.max_hosts:
                all_match = True
                for ip in network.hosts() if network.num_addresses > 2 else [network.network_address]:
                    if not obj.contains_ip(ip):
                        all_match = False
                        break
                if all_match:
                    return MatchOutcome.MATCH
            else:
                if obj.contains_network(network):
                    return MatchOutcome.MATCH
        else:
            if obj.contains_network(network):
                return MatchOutcome.MATCH
    if has_unknown:
        return MatchOutcome.UNKNOWN
    return MatchOutcome.NO_MATCH


def _evaluate_address_group(
    address_book: AddressBook,
    names: Iterable[str],
    network: IPv4Network,
    mode: MatchMode,
) -> MatchOutcome:
    """Evaluate address group references against a target network."""
    aggregated_objects: list[AddressObject] = []
    has_unknown = False
    print("_evaluate_address_group")
    for name in names:
        objects = list(address_book.resolve_group_members(name))
        print(objects)
        if not objects:
            has_unknown = True
        aggregated_objects.extend(objects)
    if not aggregated_objects and has_unknown:
        return MatchOutcome.UNKNOWN
    result = _evaluate_address_objects(aggregated_objects, network, mode)
    if result == MatchOutcome.NO_MATCH and has_unknown:
        return MatchOutcome.UNKNOWN
    return result


def _evaluate_services(
    services: Iterable[ServiceObject],
    protocol: Protocol,
    port: int,
) -> MatchOutcome:
    """Evaluate services against a protocol/port."""
    has_unknown = False
    for service in services:
        if not service.entries:
            has_unknown = True
            continue
        for entry in service.entries:
            if entry.matches(protocol, port):
                return MatchOutcome.MATCH
    if has_unknown:
        return MatchOutcome.UNKNOWN
    return MatchOutcome.NO_MATCH


def _evaluate_service_group(
    service_book: ServiceBook,
    names: Iterable[str],
    protocol: Protocol,
    port: int,
) -> MatchOutcome:
    """Evaluate service group references against a protocol/port."""
    aggregated_services: list[ServiceObject] = []
    has_unknown = False
    for name in names:
        services = list(service_book.resolve_group_members(name))
        if not services:
            has_unknown = True
        aggregated_services.extend(services)
    if not aggregated_services and has_unknown:
        return MatchOutcome.UNKNOWN
    result = _evaluate_services(aggregated_services, protocol, port)
    if result == MatchOutcome.NO_MATCH and has_unknown:
        return MatchOutcome.UNKNOWN
    return result


def _schedule_active(schedule: Optional[str]) -> bool:
    """Return True if the schedule should be treated as active."""
    if schedule is None:
        return True
    return schedule.lower() == "always"


def evaluate_policy(
    policies: Iterable[PolicyRule],
    address_book: AddressBook,
    service_book: ServiceBook,
    src_network: IPv4Network,
    dst_network: IPv4Network,
    protocol: Protocol,
    port: int,
    match_mode: MatchMode,
    ignore_schedule: bool,
) -> MatchDetail:
    """Evaluate policies and return the first definitive decision."""
    print(service_book)
    for policy in policies:
        print(policy.name, policy.schedule, policy.enabled, src_network,policy.source, dst_network,policy.destination)
        if not policy.enabled:
            print("policy continue")
            continue
        if not _schedule_active(policy.schedule):
            print("schedule continue")
            continue
        src_result = _evaluate_address_group(address_book, policy.source, src_network, match_mode)
        print(src_result)
        if src_result == MatchOutcome.NO_MATCH:
            continue
        dst_result = _evaluate_address_group(address_book, policy.destination, dst_network, match_mode)
        print(dst_result)
        if dst_result == MatchOutcome.NO_MATCH:
            continue
        service_result = _evaluate_service_group(service_book, policy.services, protocol, port)
        print(service_result)
        if service_result == MatchOutcome.NO_MATCH:
            continue

        if MatchOutcome.UNKNOWN in (src_result, dst_result, service_result):
            return MatchDetail(
                decision=Decision.UNKNOWN,
                matched_policy_id=policy.policy_id,
                matched_policy_name=policy.name,
                matched_policy_action=policy.action,
                reason="UNKNOWN_MATCH_CONDITION",
            )

        decision = Decision.ALLOW if policy.action.lower() == "accept" else Decision.DENY
        if decision == Decision.ALLOW:
            return MatchDetail(
                decision=decision,
                matched_policy_id=policy.policy_id,
                matched_policy_name=policy.name,
                matched_policy_action=policy.action,
                reason="MATCH_POLICY_ACCEPT",
            )
        elif decision == Decision.DENY:
            return MatchDetail(
                decision=decision,
                matched_policy_id=policy.policy_id,
                matched_policy_name=policy.name,
                matched_policy_action=policy.action,
                reason="MATCH_POLICY_DENY",
            )

    return MatchDetail(
        decision=Decision.DENY,
        matched_policy_id=None,
        matched_policy_name=None,
        matched_policy_action=None,
        reason="IMPLICIT_DENY",
    )


def normalize_service_entries(entries: Iterable[ServiceEntry]) -> tuple[ServiceEntry, ...]:
    """Return a normalized tuple of service entries."""
    normalized: list[ServiceEntry] = []
    for entry in entries:
        normalized.append(entry)
    return tuple(normalized)
