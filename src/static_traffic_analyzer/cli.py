"""Command-line interface for the static traffic analyzer."""
from __future__ import annotations

import argparse
import csv
import logging
import os
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from ipaddress import IPv4Network
from multiprocessing import Queue
from pathlib import Path
from typing import Iterable, Iterator

from .evaluator import MatchMode, evaluate_policy
from .models import AddressBook, Decision, PolicyRule, ServiceBook
from .parsers.db import parse_database
from .parsers.excel import parse_excel
from .parsers.fortigate import parse_fortigate_config
from .logging_utils import configure_logging, configure_worker_logging, stop_listener
from .utils import ParseError, PortSpec, expand_ipv4_network, parse_ipv4_network, parse_ports_file


@dataclass(frozen=True)
class SimulationContext:
    """Immutable container for data shared with worker processes."""

    policies: tuple[PolicyRule, ...]
    address_book: AddressBook
    service_book: ServiceBook
    match_mode: MatchMode
    ignore_schedule: bool
    log_queue: Queue | None
    log_level: str


_WORKER_CONTEXT: SimulationContext | None = None


@dataclass(frozen=True)
class SimulationTask:
    """Represents a single simulation unit of work."""

    src_record: dict[str, str]
    dst_record: dict[str, str]
    dst_network: IPv4Network
    port_spec: PortSpec


def _init_worker(context: SimulationContext) -> None:
    """Initialize worker process state for multiprocessing."""
    global _WORKER_CONTEXT
    configure_worker_logging(context.log_queue, context.log_level)
    _WORKER_CONTEXT = context


def _simulate_task(task: SimulationTask) -> tuple[dict[str, str | int | None], dict[str, str | int | None] | None]:
    """Run the policy simulation for a single task using shared worker context."""
    if _WORKER_CONTEXT is None:
        raise RuntimeError("Worker context was not initialized")
    return _simulate_task_with_context(_WORKER_CONTEXT, task)


def _simulate_task_with_context(
    context: SimulationContext,
    task: SimulationTask,
) -> tuple[dict[str, str | int | None], dict[str, str | int | None] | None]:
    """Run the policy simulation for a single task with explicit context."""
    logger = logging.getLogger(__name__)
    src_network = parse_ipv4_network(task.src_record["Network Segment"])
    logger.debug(
        "Evaluating policy for src=%s dst=%s proto=%s port=%s label=%s",
        src_network,
        task.dst_network,
        task.port_spec.protocol.value,
        task.port_spec.port,
        task.port_spec.label,
    )
    match = evaluate_policy(
        policies=context.policies,
        address_book=context.address_book,
        service_book=context.service_book,
        src_network=src_network,
        dst_network=task.dst_network,
        protocol=task.port_spec.protocol,
        port=task.port_spec.port,
        match_mode=context.match_mode,
        ignore_schedule=context.ignore_schedule,
    )
    output_row = {
        "src_network_segment": str(src_network),
        "dst_network_segment": str(task.dst_network),
        "dst_gn": task.dst_record.get("GN") or "",
        "dst_site": task.dst_record.get("Site") or "",
        "dst_location": task.dst_record.get("Location") or "",
        "service_label": task.port_spec.label,
        "protocol": task.port_spec.protocol.value,
        "port": task.port_spec.port,
        "decision": match.decision.value,
        "matched_policy_id": match.matched_policy_id or "",
        "matched_policy_action": match.matched_policy_action or "",
        "reason": match.reason,
    }
    routable_row: dict[str, str | int | None] | None = None
    if context.match_mode.mode == "fuzzy" and match.reason == "MATCH_POLICY_ACCEPT":
        destination = ", ".join(match.matched_policy_destination or ())
        routable_row = {
            **output_row,
            "dst_network_segment": destination,
        }
    return output_row, routable_row


def _resolve_worker_count(requested: int, record_count: int) -> int:
    """Determine the number of worker processes to use."""
    if record_count < 1:
        return 1
    if requested < 0:
        raise ParseError("--workers must be zero or a positive integer")
    if requested == 0:
        return min(os.cpu_count() or 1, record_count)
    return min(requested, record_count)


def _load_csv_networks(path: Path, header_name: str) -> list[dict[str, str]]:
    """Load CSV records with at least the given header."""
    records: list[dict[str, str]] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if header_name not in reader.fieldnames:
            raise ParseError(f"CSV file missing required header: {header_name}")
        for row in reader:
            records.append({key: (value or "").strip() for key, value in row.items()})
    return records


def _select_rule_source(config: str | None, excel: str | None, db_selected: bool):
    """Ensure exactly one rules source is selected."""
    provided = [value for value in (config, excel, "db" if db_selected else None) if value]
    if len(provided) != 1:
        raise ParseError("Specify exactly one of --config, --excel, or MariaDB args")


def _iter_ports(ports_path: Path):
    """Yield port specs from the ports file."""
    with ports_path.open(encoding="utf-8") as handle:
        for spec in parse_ports_file(handle.readlines()):
            yield spec


def _iter_dst_networks(
    dst_records: Iterable[dict[str, str]],
    match_mode: MatchMode,
) -> Iterable[tuple[dict[str, str], IPv4Network]]:
    """Yield destination networks, expanding CIDRs when match_mode requests it."""
    for dst_record in dst_records:
        dst_network = parse_ipv4_network(dst_record["Network Segment"])
        if match_mode.mode == "expand":
            for expanded_network in expand_ipv4_network(dst_network, match_mode.max_hosts):
                yield dst_record, expanded_network
        else:
            yield dst_record, dst_network


def _iter_simulation_tasks(
    src_records: Iterable[dict[str, str]],
    dst_networks: Iterable[tuple[dict[str, str], IPv4Network]],
    ports: Iterable[PortSpec],
) -> Iterator[SimulationTask]:
    """Yield single-unit tasks for every src/dst/port combination."""
    for src_record in src_records:
        for dst_record, dst_network in dst_networks:
            for port_spec in ports:
                yield SimulationTask(
                    src_record=src_record,
                    dst_record=dst_record,
                    dst_network=dst_network,
                    port_spec=port_spec,
                )


def _write_output(
    output_path: Path,
    rows: Iterable[dict[str, str | int | None]],
) -> None:
    """Write output rows to CSV file."""
    fieldnames = [
        "src_network_segment",
        "dst_network_segment",
        "dst_gn",
        "dst_site",
        "dst_location",
        "service_label",
        "protocol",
        "port",
        "decision",
        "matched_policy_id",
        "matched_policy_action",
        "reason",
    ]
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description="Static Traffic Analyzer")
    parser.add_argument("--config", help="FortiGate CLI config file")
    parser.add_argument("--excel", help="Excel rules workbook")
    parser.add_argument("--db-user", help="MariaDB user")
    parser.add_argument("--db-password", help="MariaDB password")
    parser.add_argument("--db-host", help="MariaDB host")
    parser.add_argument("--db-name", help="MariaDB database")
    parser.add_argument("--fab-name", help="Fabrication plant name to filter rules")
    parser.add_argument("--src-csv", required=True, help="Source CIDR list CSV")
    parser.add_argument("--dst-csv", required=True, help="Destination CIDR list CSV")
    parser.add_argument("--ports", required=True, help="Ports list file")
    parser.add_argument("--out", required=True, help="Output CSV path")
    parser.add_argument("--ignore-schedule", action="store_true", help="Ignore policy schedules")
    parser.add_argument(
        "--match-mode",
        choices=["segment", "sample-ip", "expand", "fuzzy"],
        default="segment",
        help="Address match mode",
    )
    parser.add_argument("--max-hosts", type=int, default=256, help="Max hosts for expand mode")
    parser.add_argument(
        "--workers",
        type=int,
        default=0,
        help="Worker process count (0=auto, 1=disable multiprocessing)",
    )
    parser.add_argument("--filter-policy-id", help="Only output results matching this Policy ID")
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["debug", "info", "warning", "error", "fatal"],
        help="Logging verbosity (debug, info, warning, error, fatal)",
    )
    parser.add_argument(
        "--log-file",
        help="Optional log file path (defaults to console output)",
    )

    args = parser.parse_args()

    logger_context = configure_logging(args.log_level, args.log_file, use_queue=True)
    logger = logging.getLogger(__name__)
    try:
        logger.info("Starting static traffic analysis")
        db_selected = any((args.db_user, args.db_password, args.db_host, args.db_name))
        _select_rule_source(args.config, args.excel, db_selected)

        if args.config:
            with Path(args.config).open(encoding="utf-8") as handle:
                data = parse_fortigate_config(handle.readlines())
        elif args.excel:
            data = parse_excel(args.excel)
        else:
            missing = [
                name
                for name, value in (
                    ("--db-user", args.db_user),
                    ("--db-password", args.db_password),
                    ("--db-host", args.db_host),
                    ("--db-name", args.db_name),
                )
                if not value
            ]
            if missing:
                raise ParseError(f"Missing required MariaDB args: {', '.join(missing)}")
            data = parse_database(
                user=args.db_user,
                password=args.db_password,
                host=args.db_host,
                database=args.db_name,
                fab_name=args.fab_name,
            )

        src_records = _load_csv_networks(Path(args.src_csv), "Network Segment")
        dst_records = _load_csv_networks(Path(args.dst_csv), "Network Segment")
        ports = list(_iter_ports(Path(args.ports)))
        logger.info(
            "Loaded %s source records, %s destination records, %s ports",
            len(src_records),
            len(dst_records),
            len(ports),
        )

        if args.max_hosts < 1:
            raise ParseError("--max-hosts must be a positive integer")
        match_mode = MatchMode(mode=args.match_mode, max_hosts=args.max_hosts)

        # Eagerly resolve all group memberships to optimize the simulation hot path.
        data.address_book.flatten_all_groups()
        data.service_book.flatten_all_groups()
        logger.debug("Flattened address and service groups")

        # Build a shared context to avoid re-serializing large datasets for every task.
        context = SimulationContext(
            policies=tuple(data.policies),
            address_book=data.address_book,
            service_book=data.service_book,
            match_mode=match_mode,
            ignore_schedule=args.ignore_schedule,
            log_queue=logger_context.queue,
            log_level=args.log_level,
        )
        # Choose a worker count that respects both the CLI input and dataset size.
        worker_count = _resolve_worker_count(args.workers, len(src_records))
        logger.info("Using %s worker processes", worker_count)

        dst_networks = tuple(_iter_dst_networks(dst_records, match_mode))
        ports_tuple = tuple(ports)
        total_tasks = len(src_records) * len(dst_networks) * len(ports_tuple)
        output_rows: list[dict[str, str | int | None]] = []
        routable_rows: list[dict[str, str | int | None]] = []
        if worker_count <= 1:
            # Single-process execution avoids multiprocessing overhead for small inputs.
            for task in _iter_simulation_tasks(src_records, dst_networks, ports_tuple):
                row, routable_row = _simulate_task_with_context(context, task)
                if args.filter_policy_id and str(row["matched_policy_id"]) != args.filter_policy_id:
                    continue
                output_rows.append(row)
                if routable_row is not None:
                    routable_rows.append(routable_row)
        else:
            # Multiprocessing uses chunked maps to reduce inter-process coordination overhead.
            chunksize = max(1, total_tasks // (worker_count * 4)) if total_tasks else 1
            with ProcessPoolExecutor(
                max_workers=worker_count,
                initializer=_init_worker,
                initargs=(context,),
            ) as executor:
                tasks = _iter_simulation_tasks(src_records, dst_networks, ports_tuple)
                for row, routable_row in executor.map(_simulate_task, tasks, chunksize=chunksize):
                    # Rows are appended only in the parent process, avoiding shared-state races.
                    if args.filter_policy_id and str(row["matched_policy_id"]) != args.filter_policy_id:
                        continue
                    output_rows.append(row)
                    if routable_row is not None:
                        routable_rows.append(routable_row)

        _write_output(Path(args.out), output_rows)
        logger.info("Wrote %s rows to %s", len(output_rows), args.out)
        if match_mode.mode == "fuzzy":
            routable_path = Path(args.out).with_name("routable.csv")
            _write_output(routable_path, routable_rows)
            logger.info("Wrote %s rows to %s", len(routable_rows), routable_path)
    except ParseError as exc:
        logger.warning("Parsing failed: %s", exc)
        raise SystemExit(str(exc)) from exc
    except Exception:
        logger.fatal("Fatal error during processing", exc_info=True)
        raise
    finally:
        stop_listener(logger_context)


if __name__ == "__main__":
    main()
