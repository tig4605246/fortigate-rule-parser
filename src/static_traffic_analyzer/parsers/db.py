"""Parser for MariaDB firewall tables."""
from __future__ import annotations

from dataclasses import dataclass
import socket
import logging
from typing import Any

from ..catalog import DEFAULT_SERVICES
from ..models import (
    AddressBook,
    AddressGroup,
    PolicyRule,
    Protocol,
    ServiceBook,
    ServiceEntry,
    ServiceGroup,
    ServiceObject,
)
from ..utils import ParseError, make_any_service, parse_address_object, parse_json_array, parse_service_entry


@dataclass
class DatabaseData:
    """Parsed database data container."""

    address_book: AddressBook
    service_book: ServiceBook
    policies: list[PolicyRule]


def _require_connector() -> Any:
    """Import the MariaDB connector, raising a clear error if missing."""
    try:
        import mysql.connector  # type: ignore
    except ModuleNotFoundError as exc:
        raise ParseError(
            "mysql-connector-python is required for MariaDB support. "
            "Install with: pip install 'static-traffic-analyzer[db]'"
        ) from exc
    return mysql.connector


def parse_database(
    user: str, password: str, host: str, database: str, fab_name: str | None = None
) -> DatabaseData:
    """Load MariaDB firewall tables into internal models."""
    logger = logging.getLogger(__name__)
    connector = _require_connector()
    connection = connector.connect(
        user=user,
        password=password,
        host=host,
        database=database,
    )
    cursor = connection.cursor(dictionary=True)

    address_book = AddressBook()
    service_book = ServiceBook()
    policies: list[PolicyRule] = []

    def register_service_name(service_name: str) -> None:
        """Register a service name into the service book if it is missing.

        This handles service references that only appear in policies by:
        - Parsing explicit tcp_/udp_ service strings into concrete entries.
        - Falling back to well-known ports for named services (e.g., "http").
        - Respecting existing service definitions or groups to avoid overwrites.
        """
        normalized = str(service_name).strip()
        if not normalized:
            return
        if normalized in service_book.services or normalized in service_book.groups:
            return
        if normalized.upper() == "ALL":
            service_book.services.setdefault("ALL", make_any_service("ALL"))
            return
        if normalized.lower().startswith(("tcp_", "udp_")):
            try:
                entry = parse_service_entry(normalized)
            except ParseError:
                return
            service_book.services[normalized] = ServiceObject(
                name=normalized,
                entries=(entry,),
            )
            return
        try:
            port = socket.getservbyname(normalized.lower())
        except (OSError, TypeError):
            return
        service_book.services[normalized] = ServiceObject(
            name=normalized,
            entries=(
                ServiceEntry(protocol=Protocol.TCP, start_port=port, end_port=port),
                ServiceEntry(protocol=Protocol.UDP, start_port=port, end_port=port),
            ),
        )

    params = (fab_name,) if fab_name else None
    where_clause = " WHERE fab_name = %s" if fab_name else ""

    cursor.execute(
        "SELECT object_name, address_type, subnet, start_ip, end_ip FROM cfg_address"
        + where_clause,
        params,
    )
    for row in cursor:
        name = str(row["object_name"])
        if str(row["object_name"]).lower() == "all":
            continue
        try:
            address_book.objects[name] = parse_address_object(
                name=name,
                address_type=str(row["address_type"]),
                subnet=row.get("subnet"),
                start_ip=row.get("start_ip"),
                end_ip=row.get("end_ip"),
            )
        except ParseError as exc:
            logger.warning(
                "Address parse error for %s (type=%s): %s",
                name,
                row.get("address_type"),
                exc,
            )
            address_book.objects[name] = parse_address_object(
                name=name, address_type="fqdn"
            )

    cursor.execute(
        "SELECT group_name, members FROM cfg_address_group" + where_clause, params
    )
    for row in cursor:
        members = tuple(parse_json_array(row.get("members", "[]")))
        address_book.groups[str(row["group_name"])] = AddressGroup(
            name=str(row["group_name"]), members=members
        )

    cursor.execute(
        "SELECT group_name, members FROM cfg_service_group" + where_clause, params
    )
    for row in cursor:
        members = tuple(parse_json_array(row.get("members", "[]")))
        service_book.groups[str(row["group_name"])] = ServiceGroup(
            name=str(row["group_name"]), members=members
        )

    cursor.execute(
        "SELECT priority, policy_id, src_objects, dst_objects, service_objects, action, is_enabled, log_traffic, comments "
        "FROM cfg_policy" + where_clause,
        params,
    )
    for row in cursor:
        src_objects = parse_json_array(row.get("src_objects", "[]"))
        dst_objects = parse_json_array(row.get("dst_objects", "[]"))
        service_object = row.get("service_objects")
        if isinstance(service_object, str) and service_object.strip().startswith("["):
            services = parse_json_array(service_object)
        elif service_object is None:
            services = []
        else:
            services = [str(service_object)]
        for service_name in services:
            register_service_name(service_name)
        policies.append(
            PolicyRule(
                policy_id=str(row["policy_id"]),
                name=str(row["policy_id"]),
                priority=int(row["priority"]),
                source=tuple(src_objects),
                destination=tuple(dst_objects),
                services=tuple(services),
                action=str(row.get("action", "deny")),
                enabled=bool(row.get("is_enabled", 0)),
                schedule="always",
                comment=str(row.get("comments")) if row.get("comments") else None,
            )
        )

    for name, service in DEFAULT_SERVICES.items():
        service_book.services.setdefault(name, service)
    if "ALL" not in service_book.services:
        service_book.services["ALL"] = make_any_service("ALL")
    if "all" not in address_book.objects:
        address_book.objects["all"] = parse_address_object("all", "ipmask", subnet="0.0.0.0/0")


    for group in list(service_book.groups.values()):
        for member in group.members:
            register_service_name(member)


    policies.sort(key=lambda rule: rule.priority)

    cursor.close()
    connection.close()

    return DatabaseData(address_book=address_book, service_book=service_book, policies=policies)
