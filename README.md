# static-traffic-analyzer

## Purpose

The tool is made to parse firewall rules from a designated source and map src/dst ip port pair to see if the route will be allowed to pass or not. Finally output the result to a csv file.

The implementation of the tool can be divided into 3 parts
1. parse rules from either FortiGate configuration, Excel or MariaDB tables
  - `fortigate-rule-parser-conf`
  - `fortigate-rule-parser-excel`
  - `fortigate-rule-parser-mariadb`
2. Verify each src ip, dst ip and port pair is allow to access or not
3. output result as a csv or JSON for port scanner

## Overview

A FrotiGate configuration written in Golang.

## Reference

- [Well Known Ports](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
- On Linux system, we use /etc/services to resolve well known ports.

## CLI usage

Parse rules from MariaDB using explicit connection args:

```sh
PYTHONPATH=src python3 -m static_traffic_analyzer.cli \
  --db-user root \
  --db-password static \
  --db-host 127.0.0.1 \
  --db-name firewall_mgmt \
  --src-csv samples/case_basic/inputs/src.csv \
  --dst-csv samples/case_basic/inputs/dst.csv \
  --ports samples/case_basic/inputs/ports.txt \
  --out out.csv
```

If you want a local MariaDB with sample rules, use `docker-compose.yaml` and start it with:

```sh
docker compose up -d
```

## Tutorial: run with Python directly

This walkthrough shows how to execute the CLI straight from the repository using a Python command,
without relying on an installed console script.

### 1) Create and activate a virtual environment

```sh
python3 -m venv .venv
source .venv/bin/activate
```

### 2) Install dependencies

Install the base dependencies (required for the CLI and Excel parsing):

```sh
pip install -e .
```

If you plan to parse rules from MariaDB, also install the database extras:

```sh
pip install -e ".[db]"
```

### 3) Run the CLI with `python -m`

From the repository root, execute the module directly and point to any of the sample inputs:

```sh
PYTHONPATH=src python3 -m static_traffic_analyzer.cli \
  --config samples/case02_addrgrp_basic/rules/fortigate.conf \
  --src-csv samples/case02_addrgrp_basic/inputs/src.csv \
  --dst-csv samples/case02_addrgrp_basic/inputs/dst.csv \
  --ports samples/case02_addrgrp_basic/inputs/ports.txt \
  --out out.csv
```

The resulting CSV will be written to `out.csv` in the current directory.
