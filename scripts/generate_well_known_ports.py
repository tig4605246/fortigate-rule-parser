"""Generate a CSV sheet of well-known ports and service names.

The output is used by the default service catalog so that all ports in the
well-known range (1-1023) are available to the analyzer.
"""
from __future__ import annotations

import csv
import socket
from pathlib import Path

WELL_KNOWN_PORTS_RANGE = range(1, 65535)


def get_service_name(port: int, protocol: str = "tcp") -> str | None:
    """Return the service name for a port/protocol, if available."""
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return None


def build_rows() -> list[dict[str, str]]:
    """Build CSV rows for well-known ports with TCP/UDP service names."""
    rows: list[dict[str, str]] = []
    for port in WELL_KNOWN_PORTS_RANGE:
        print("port"+str(port))
        tcp_service = get_service_name(port, "tcp")
        udp_service = get_service_name(port, "udp")
        if not tcp_service and not udp_service:
            continue
        rows.append(
            {
                "Port": str(port),
                "Service Name (TCP)": tcp_service or "N/A",
                "Service Name (UDP)": udp_service or "N/A",
            }
        )
    return rows


def write_csv(output_path: Path, rows: list[dict[str, str]]) -> None:
    """Write the well-known ports sheet to the supplied output path."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["Port", "Service Name (TCP)", "Service Name (UDP)"])
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    """Generate the CSV in the package data directory."""
    repo_root = Path(__file__).resolve().parents[1]
    output_path = repo_root / "src" / "static_traffic_analyzer" / "data" / "well_known_ports.csv"
    rows = build_rows()
    if not rows:
        print("No well-known services were found on this system.")
        return 1
    try:
        write_csv(output_path, rows)
    except OSError as exc:
        print(f"Failed to write CSV to {output_path}: {exc}")
        return 1
    print(f"Wrote {len(rows)} rows to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
