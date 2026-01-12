"""Parser for MariaDB firewall tables."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..catalog import DEFAULT_SERVICES
from ..models import AddressBook, AddressGroup, PolicyRule, ServiceBook, ServiceGroup, ServiceObject
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


def parse_database(user: str, password: str, host: str, database: str) -> DatabaseData:
    """Load MariaDB firewall tables into internal models."""
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

    cursor.execute("SELECT object_name, address_type, subnet, start_ip, end_ip FROM cfg_address")
    for row in cursor.fetchall():
        name = str(row["object_name"])
        try:
            address_book.objects[name] = parse_address_object(
                name=name,
                address_type=str(row["address_type"]),
                subnet=row.get("subnet"),
                start_ip=row.get("start_ip"),
                end_ip=row.get("end_ip"),
            )
        except ParseError:
            address_book.objects[name] = parse_address_object(name=name, address_type="fqdn")

    cursor.execute("SELECT group_name, members FROM cfg_address_group")
    for row in cursor.fetchall():
        members = tuple(parse_json_array(row.get("members", "[]")))
        address_book.groups[str(row["group_name"])] = AddressGroup(name=str(row["group_name"]), members=members)

    cursor.execute("SELECT group_name, members FROM cfg_service_group")
    for row in cursor.fetchall():
        members = tuple(parse_json_array(row.get("members", "[]")))
        service_book.groups[str(row["group_name"])] = ServiceGroup(name=str(row["group_name"]), members=members)

    cursor.execute(
        "SELECT priority, src_objects, dst_objects, service_object, action, is_enabled, log_traffic, comments "
        "FROM cfg_policy"
    )
    for row in cursor.fetchall():
        src_objects = parse_json_array(row.get("src_objects", "[]"))
        dst_objects = parse_json_array(row.get("dst_objects", "[]"))
        service_object = row.get("service_object")
        if isinstance(service_object, str) and service_object.strip().startswith("["):
            services = parse_json_array(service_object)
        elif service_object is None:
            services = []
        else:
            services = [str(service_object)]
        policies.append(
            PolicyRule(
                policy_id=str(row["priority"]),
                name=str(row["priority"]),
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

    for group in list(service_book.groups.values()):
        for member in group.members:
            if member in service_book.services:
                continue
            if member.lower().startswith("tcp_") or member.lower().startswith("udp_"):
                try:
                    service_book.services[member] = ServiceObject(name=member, entries=(parse_service_entry(member),))
                except ParseError:
                    continue

    policies.sort(key=lambda rule: rule.priority)

    cursor.close()
    connection.close()

    return DatabaseData(address_book=address_book, service_book=service_book, policies=policies)
