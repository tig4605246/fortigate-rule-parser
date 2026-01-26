#!/usr/bin/env python3
"""Go-based test runner for static-traffic-analyzer.

This variant runs the compiled Go binary.
It discovers and runs test cases from the 'samples' directory, compares output
with expected results, and provides a detailed analysis of differences.
"""

import csv
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Define the root of the project so paths remain stable regardless of CWD.
PROJECT_ROOT = Path(__file__).parent
SAMPLES_DIR = PROJECT_ROOT / "samples"
OUT_FILE = PROJECT_ROOT / "out.csv"
GO_BINARY = PROJECT_ROOT / "static-traffic-analyzer-go"

# The primary key for a flow in the CSV output, used for matching rows.
CSV_KEY = (
    "src_ip",
    "src_network_segment",
    "dst_ip",
    "dst_network_segment",
    "protocol",
    "port",
    "service_label",
)


def find_test_cases() -> List[Path]:
    """Finds all test case directories in the samples folder."""
    return sorted([d for d in SAMPLES_DIR.glob("case*") if d.is_dir()])


def run_command(args: List[str]) -> None:
    """Runs a command and raises an exception if it fails.

    The function captures stdout/stderr to make failures easier to diagnose
    in CI or local runs, and surfaces a detailed exception on non-zero exit.
    """
    process = subprocess.run(args, capture_output=True, text=True, check=False)
    if process.returncode != 0:
        print(f"Error running command: {' '.join(args)}", file=sys.stderr)
        print(f"stdout:\n{process.stdout}", file=sys.stderr)
        print(f"stderr:\n{process.stderr}", file=sys.stderr)
        raise subprocess.CalledProcessError(
            process.returncode,
            args,
            output=process.stdout,
            stderr=process.stderr,
        )


def parse_csv(file_path: Path) -> Dict[Tuple[str, ...], Dict[str, str]]:
    """Parses a result CSV into a dictionary keyed by the flow's identity."""
    data: Dict[Tuple[str, ...], Dict[str, str]] = {}
    with file_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = tuple(row[k] for k in CSV_KEY)
            data[key] = row
    return data


def analyze_differences(expected_path: Path, result_path: Path) -> bool:
    """Compares expected and result CSVs and prints an analysis of differences.

    Returns True if differences are found, otherwise False.
    """
    try:
        expected_data = parse_csv(expected_path)
        result_data = parse_csv(result_path)
    except FileNotFoundError as e:
        print(f"  ❌ Error: Could not open file {e.filename}", file=sys.stderr)
        return True

    is_different = False

    # Check for missing or extra rows.
    expected_keys = set(expected_data.keys())
    result_keys = set(result_data.keys())

    if expected_keys != result_keys:
        is_different = True
        missing_rows = expected_keys - result_keys
        extra_rows = result_keys - expected_keys
        if missing_rows:
            print("  ❌ Missing rows in result:")
            for row_key in sorted(missing_rows):
                print(f"    - {dict(zip(CSV_KEY, row_key))}")
        if extra_rows:
            print("  ❌ Extra rows in result:")
            for row_key in sorted(extra_rows):
                print(f"    - {dict(zip(CSV_KEY, row_key))}")

    # Check for differences in common rows.
    for key, expected_row in expected_data.items():
        if key not in result_data:
            continue

        result_row = result_data[key]
        if result_row != expected_row:
            if not is_different:
                # Print header only on first difference to reduce noise.
                print(f"  - Differences found for flow: {dict(zip(CSV_KEY, key))}")
            is_different = True

            for field, expected_value in expected_row.items():
                result_value = result_row.get(field, "")
                if result_value != expected_value:
                    print(f"    - Field '{field}':")
                    print(f"      - Expected: '{expected_value}'")
                    print(f"      - Got:      '{result_value}'")
                    # Add potential reasons for specific fields.
                    if field == "decision":
                        print(
                            "      - Potential Reason: Policy logic might be incorrect. "
                            "Check the matched policy's action or if a different policy "
                            "should have matched."
                        )
                    elif field == "matched_policy_id":
                        print(
                            "      - Potential Reason: A different policy was matched. "
                            "Check policy order, source/destination objects, and service "
                            "definitions for the intended policy."
                        )

    return is_different


def is_db_running() -> bool:
    """Checks if the MariaDB docker container is up and running."""
    print("--- Checking for MariaDB container ---")
    try:
        result = subprocess.run(
            ["docker","compose", "ps"],
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8",
        )
    except FileNotFoundError:
        print("  -> docker","compose not found. Is Docker installed and on PATH?")
        return False
    except subprocess.CalledProcessError as exc:
        print("  -> docker","compose failed. Is Docker running?")
        print(f"  -> Error output: {exc.stderr}")
        return False

    if "mariadb" in result.stdout and "Up" in result.stdout:
        print("  -> MariaDB container is running.")
        return True

    print("  -> MariaDB container is not running.")
    return False


def build_golang_cli_command() -> List[str]:
    """Builds the base command to run the analyzer via the Go binary."""
    if not GO_BINARY.exists():
        raise FileNotFoundError(
            f"Go binary not found at {GO_BINARY}. "
            "Please build it first with 'go build -o static-traffic-analyzer-go cmd/analyzer/main.go'"
        )
    return [str(GO_BINARY)]


def run_case(case_path: Path, db_is_running: bool) -> bool:
    """Runs all tests for a single case directory. Returns True if any test fails."""
    case_name = case_path.name
    print(f"--- Running test case: {case_name} ---")

    had_failure = False

    inputs_dir = case_path / "inputs"
    rules_dir = case_path / "rules"
    expected_dir = case_path / "expected"

    if not inputs_dir.is_dir():
        print("  - Skipping (no 'inputs' directory)")
        return False

    common_args = [
        "--src",
        str(inputs_dir / "src.csv"),
        "--dst",
        str(inputs_dir / "dst.csv"),
        "--ports",
        str(inputs_dir / "ports.txt"),
        "--out",
        str(OUT_FILE),
        "--mode",
        "sample",
    ]

    # Test with fortigate.conf.
    fortigate_conf = rules_dir / "fortigate.conf"
    if fortigate_conf.is_file():
        if OUT_FILE.exists(): OUT_FILE.unlink()
        print("  -> Running with fortigate.conf")
        try:
            run_command(
                build_golang_cli_command()
                + ["--provider", "fortigate", "--rules", str(fortigate_conf)]
                + common_args
            )
            expected_csv = expected_dir / "expected.csv"
            if expected_csv.is_file():
                if analyze_differences(expected_csv, OUT_FILE):
                    had_failure = True
                    print("  ❌ FortiGate test FAILED")
                else:
                    print("  ✅ FortiGate test PASSED")
            else:
                print("  ✅ FortiGate test PASSED (no expected.csv to compare)")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"  ❌ FortiGate test FAILED with exception: {e}", file=sys.stderr)
            had_failure = True
    
    # Test with mariadb.sql.
    mariadb_sql = rules_dir / "mariadb.sql"
    if mariadb_sql.is_file():
        if db_is_running:
            if OUT_FILE.exists(): OUT_FILE.unlink()
            print("  -> Running with mariadb.sql")
            try:
                # Seed the database.
                with mariadb_sql.open("rb") as f:
                    subprocess.run(
                        [
                            "docker","compose",
                            "exec",
                            "-T",
                            "mariadb",
                            "mysql",
                            "-uroot",
                            "-pstatic",
                            "firewall_mgmt",
                        ],
                        stdin=f,
                        check=True,
                    )

                # DSN for the Go application
                db_dsn = "root:static@tcp(127.0.0.1:3306)/firewall_mgmt"
                
                db_args = [
                    "--provider",
                    "mariadb",
                    "--db",
                    db_dsn
                ]
                run_command(build_golang_cli_command() + db_args + common_args)
                expected_csv = expected_dir / "expected.csv"
                if expected_csv.is_file():
                    if analyze_differences(expected_csv, OUT_FILE):
                        had_failure = True
                        print("  ❌ MariaDB test FAILED")
                    else:
                        print("  ✅ MariaDB test PASSED")
                else:
                    print("  ✅ MariaDB test PASSED (no expected.csv to compare)")
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                print(f"  ❌ MariaDB test FAILED with exception: {e}", file=sys.stderr)
                had_failure = True
        else:
            print("  -> Skipping DB test (MariaDB container not running)")

    return had_failure


def main() -> None:
    """Main entry point for the test runner."""
    print("Starting static-traffic-analyzer test run (Go binary)...")

    total_failures = 0
    test_cases = find_test_cases()

    if not test_cases:
        print("No test cases found in 'samples' directory.", file=sys.stderr)
        sys.exit(1)
    
    # Ensure the Go binary exists before running tests
    try:
        build_golang_cli_command()
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        sys.exit(1)


    db_running = is_db_running()

    for case in test_cases:
        if run_case(case, db_running):
            total_failures += 1

    if OUT_FILE.exists():
        OUT_FILE.unlink()

    if total_failures > 0:
        print(f"\nCompleted with {total_failures} failing test sets.")
        sys.exit(1)

    print("\nAll tests passed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
