"""Default service catalog for common well-known services."""
from __future__ import annotations

import csv
from importlib import resources

from .models import Protocol, ServiceEntry, ServiceObject


def _fallback_services() -> dict[str, ServiceObject]:
    """Provide a minimal fallback set when the well-known port sheet is unavailable."""
    return {
        "DNS": ServiceObject("DNS", (ServiceEntry(protocol=Protocol.UDP, start_port=53, end_port=53),)),
        "HTTP": ServiceObject("HTTP", (ServiceEntry(protocol=Protocol.TCP, start_port=80, end_port=80),)),
        "HTTPS": ServiceObject("HTTPS", (ServiceEntry(protocol=Protocol.TCP, start_port=443, end_port=443),)),
        "SSH": ServiceObject("SSH", (ServiceEntry(protocol=Protocol.TCP, start_port=22, end_port=22),)),
        "SMTP": ServiceObject("SMTP", (ServiceEntry(protocol=Protocol.TCP, start_port=25, end_port=25),)),
    }


def _normalize_service_name(name: str) -> str:
    """Normalize service names to keep catalog keys stable and readable."""
    return name.strip().upper()


def _load_well_known_services() -> dict[str, ServiceObject]:
    """Load all well-known services from the bundled CSV sheet."""
    entries_by_name: dict[str, set[ServiceEntry]] = {}
    try:
        data_path = resources.files(__package__) / "data" / "well_known_ports.csv"
        with data_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                try:
                    port = int(row["Port"])
                except (KeyError, TypeError, ValueError):
                    continue
                for column, protocol in (
                    ("Service Name (TCP)", Protocol.TCP),
                    ("Service Name (UDP)", Protocol.UDP),
                ):
                    raw_name = row.get(column, "").strip()
                    if not raw_name or raw_name.upper() == "N/A":
                        continue
                    name = _normalize_service_name(raw_name)
                    entries = entries_by_name.setdefault(name, set())
                    entries.add(ServiceEntry(protocol=protocol, start_port=port, end_port=port))
    except (FileNotFoundError, OSError, csv.Error):
        return _fallback_services()

    services: dict[str, ServiceObject] = {}
    for name in sorted(entries_by_name):
        sorted_entries = tuple(
            sorted(
                entries_by_name[name],
                key=lambda entry: (entry.protocol.value if entry.protocol else "", entry.start_port or 0),
            )
        )
        services[name] = ServiceObject(name, sorted_entries)
    return services


DEFAULT_SERVICES: dict[str, ServiceObject] = _load_well_known_services()
