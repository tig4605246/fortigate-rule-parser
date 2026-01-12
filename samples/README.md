# static-traffic-analyzer — Test Fixtures (with `config firewall addrgrp`)

Generated: 20260112-112225

This bundle provides **inputs**, **FortiGate rules**, and **expected outputs** for golden tests.
Focus areas: **address**, **addrgrp**, **policy**, **service group**.

## Layout
- `00_schema/mariadb_schema.sql` : MariaDB DDL (exact column types)
- `case*/`
  - `inputs/` : `src.csv`, `dst.csv`, `ports.txt`
  - `rules/`  : `fortigate.conf`, `mariadb.sql`
  - `expected/` : `expected.csv`

## Cases
1. `case01_address_only_implicit_deny`
2. `case02_addrgrp_basic`
3. `case03_policy_order_first_match_wins`
4. `case04_service_group_custom_range`
5. `case05_integrated_all_features`

## Example check
```bash
static-traffic-analyzer \
  --config case02_addrgrp_basic/rules/fortigate.conf \
  --src-csv case02_addrgrp_basic/inputs/src.csv \
  --dst-csv case02_addrgrp_basic/inputs/dst.csv \
  --ports case02_addrgrp_basic/inputs/ports.txt \
  --out out.csv

diff -u out.csv case02_addrgrp_basic/expected/expected.csv
```
