"""Default service catalog for common well-known services."""
from __future__ import annotations
import os

from .models import Protocol, ServiceEntry, ServiceObject


DEFAULT_SERVICES: dict[str, ServiceObject] = {
    "DNS": ServiceObject("DNS", (ServiceEntry(protocol=Protocol.UDP, start_port=53, end_port=53),)),
    "HTTP": ServiceObject("HTTP", (ServiceEntry(protocol=Protocol.TCP, start_port=80, end_port=80),)),
    "HTTPS": ServiceObject("HTTPS", (ServiceEntry(protocol=Protocol.TCP, start_port=443, end_port=443),)),
    "SSH": ServiceObject("SSH", (ServiceEntry(protocol=Protocol.TCP, start_port=22, end_port=22),)),
    "SMTP": ServiceObject("SMTP", (ServiceEntry(protocol=Protocol.TCP, start_port=25, end_port=25),)),
}


def _parse_services_from_file(file_path: str) -> None:
    """
    Parses a standard 'services' file and appends found services to DEFAULT_SERVICES.
    """
    if not os.path.exists(file_path):
        return

    # Temporary map to aggregate entries: ServiceName -> list[ServiceEntry]
    services_map: dict[str, list[ServiceEntry]] = {}

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Strip whitespace
            line = line.strip()
            
            # Skip empty lines and full-line comments
            if not line or line.startswith('#'):
                continue
            
            # Remove inline comments and split by whitespace
            # Format: service-name  port/protocol  [aliases...] [# comment]
            clean_line = line.split('#', 1)[0].strip()
            if not clean_line:
                continue

            parts = clean_line.split()
            
            # We need at least 'service-name' and 'port/protocol'
            if len(parts) < 2:
                continue

            service_name = parts[0]
            port_def = parts[1]

            # Validate port definition format
            if '/' not in port_def:
                continue

            try:
                port_str, proto_str = port_def.split('/', 1)
                port = int(port_str)
            except ValueError:
                continue

            # Map protocol string to Enum
            protocol = None
            if proto_str.lower() == 'tcp':
                protocol = Protocol.TCP
            elif proto_str.lower() == 'udp':
                protocol = Protocol.UDP
            
            # Skip unknown protocols (e.g. ddp, sctp)
            if protocol is None:
                continue

            # Create the entry
            entry = ServiceEntry(protocol=protocol, start_port=port, end_port=port)
            
            # Normalize key to uppercase to match existing style
            key = service_name.upper()

            if key not in services_map:
                services_map[key] = []
            
            # Avoid duplicates if the file lists the same port/proto multiple times for aliases
            # (Note: ServiceEntry equality check is assumed, otherwise duplicates might occur)
            if entry not in services_map[key]:
                services_map[key].append(entry)

    # Append to DEFAULT_SERVICES
    for name, entries in services_map.items():
        # Only add if not already defined (preserve the hardcoded defaults)
        if name.upper() not in DEFAULT_SERVICES:
            DEFAULT_SERVICES[name.upper()] = ServiceObject(name.upper(), tuple(entries))


# Execute parsing assuming 'services' file is in the same directory
_parse_services_from_file('/etc/services')