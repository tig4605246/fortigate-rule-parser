#! /bin/bash

set -euo pipefail

for case in case_basic case_addrgrp case_servicegrp case_policy case_addrgrp_servicegrp; do
  PYTHONPATH=src python3 -m static_traffic_analyzer.cli --config samples/$case/rules/fortigate.conf \
    --src-csv samples/$case/inputs/src.csv \
    --dst-csv samples/$case/inputs/dst.csv \
    --ports samples/$case/inputs/ports.txt \
    --out out.csv

  diff -u out.csv samples/$case/expected/expected.csv
done

# MariaDB example (requires docker-compose.yaml to be running)
PYTHONPATH=src python3 -m static_traffic_analyzer.cli \
  --db-user root \
  --db-password static \
  --db-host 127.0.0.1 \
  --db-name firewall_mgmt \
  --src-csv samples/case_basic/inputs/src.csv \
  --dst-csv samples/case_basic/inputs/dst.csv \
  --ports samples/case_basic/inputs/ports.txt \
  --out out.csv
