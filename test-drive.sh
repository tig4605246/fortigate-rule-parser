#! /bin/bash

# set -euo pipefail

# Make a temporary file for output
out_file=$(mktemp)
# Make sure to clean it up
trap 'rm -f "$out_file"' SIGINT

for case_path in samples/case*; do
  if [ ! -d "$case_path/inputs" ]; then
    echo "--- Skipping $case_path (no inputs directory) ---"
    continue
  fi

  case=$(basename "$case_path")
  echo "--- Running test case: $case ---"

  # Common arguments
  common_args=(
    --src-csv "$case_path/inputs/src.csv"
    --dst-csv "$case_path/inputs/dst.csv"
    --ports "$case_path/inputs/ports.txt"
    --out "$out_file"
  )

  # FortiGate config test
  # if [ -f "$case_path/rules/fortigate.conf" ]; then
  #   echo "  -> Running with fortigate.conf"
  #   uv run static-traffic-analyzer --config "$case_path/rules/fortigate.conf" "${common_args[@]}"
  #   diff "$out_file" "$case_path/expected/expected.csv"
  # fi
  # # Excel test
  # if [ -f "$case_path/rules/rules.xlsx" ]; then
  #   echo "  -> Running with rules.xlsx"
  #   uv run static-traffic-analyzer --excel "$case_path/rules/rules.xlsx" "${common_args[@]}"
  #   diff "$out_file" "$case_path/expected/expected.csv"
  # fi

done

# MariaDB example (requires docker compose.yaml to be running)
# Check if docker is running and the mariadb container is up
if docker compose ps | grep -q 'mariadb.*Up'; then
    echo "### Running MariaDB-based test (using case02_addrgrp_basic) ###"
    echo "--- NOTE: Assumes 'docker compose up' has been run and the DB is seeded ---"
    
    # I'll use case02_addrgrp_basic for the DB test, as it's more likely to have addrgrp data.
    case_path="samples/case02_addrgrp_basic"
    common_args=(
      --src-csv "$case_path/inputs/src.csv"
      --dst-csv "$case_path/inputs/dst.csv"
      --ports "$case_path/inputs/ports.txt"
      --out "$out_file"
    )

    # Before running the test, we need to load the data from the .sql file.
    # if [ -f "$case_path/rules/mariadb.sql" ]; then
    #     echo "  -> Seeding DB with $case_path/rules/mariadb.sql"
    #     docker compose exec -T mariadb mysql -uroot -pstatic firewall_mgmt < "$case_path/rules/mariadb.sql"
    # fi
    
# uv run static-traffic-analyzer \
#       --db-user root \
#       --db-password static \
#       --db-host 127.0.0.1 \
#       --db-name firewall_mgmt \
#       --fab-name FAB \
    echo  "${common_args[@]}"

    diff "$out_file" "$case_path/expected/expected.csv"
else
    echo "### Skipping MariaDB-based test ###"
    echo "--- NOTE: 'docker compose up' does not appear to be running, or the mariadb container is not healthy. ---"
fi

uv run static-traffic-analyzer \
      --db-user root \
      --db-password static \
      --db-host 127.0.0.1 \
      --db-name firewall_mgmt \
      --fab-name FAB \
      --src-csv samples/case01_address_only_implicit_deny/inputs/src.csv --dst-csv samples/case01_address_only_implicit_deny/inputs/dst.csv --ports samples/case01_address_only_implicit_deny/inputs/ports.txt --out out.csv