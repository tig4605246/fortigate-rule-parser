# static-traffic-analyzer — Samples & Golden Testcases

This bundle contains **ready-to-run fixture inputs** and **golden outputs** to validate that
`static-traffic-analyzer` produces deterministic results across **three rule sources**:

- FortiGate CLI config (FortiOS 6.0 style)
- Excel workbook (4 sheets)
- MariaDB (firewall_mgmt schema; members stored as JSON array strings)

Policy evaluation assumptions (used by all golden cases):
- Policies are evaluated **top → down**, **first match wins**. If nothing matches: **implicit deny**.  (Fortinet community) 
- Custom services can contain multiple TCP/UDP port ranges; addresses can be ipmask/iprange/fqdn. (Fortinet docs)

References:
- How policy order works on FortiGate (top-down, first match): https://community.fortinet.com/t5/FortiGate/Technical-Tip-How-policy-order-works-on-FortiGate/ta-p/207381
- Implicit deny concept: https://community.fortinet.com/t5/Support-Forum/Implicit-Deny-in-FortiGate/m-p/283649
- FortiOS 6.0 CLI Reference PDF: https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/c287b6bf-a995-11e9-81a4-00505692583a/FortiOS-6.0-CLI_Reference.pdf
- firewall service custom (tcp-portrange/udp-portrange): https://docs.fortinet.com/document/fortigate/6.2.6/cli-reference/244620/firewall-service-custom
- firewall address (ipmask/iprange/fqdn): https://docs.fortinet.com/document/fortigate/6.2.7/cli-reference/234620/config-firewall-address

## Directory layout

Each case contains:

- `inputs/`
  - `src.csv`
  - `dst.csv`
  - `ports.txt`
- `rules/`
  - `fortigate.conf`
  - `rules.xlsx`
  - `mariadb.sql`
- `expected/`
  - Golden CSV output(s)

## Cases

### case01_basic
Covers:
- address group expansion (SRC_NETS)
- service group expansion (SG_DB_CUSTOM → tcp_8001-8004)
- explicit deny that must be overridden by a higher allow (order matters)
- implicit deny for unmatched traffic

Golden output: `expected/expected.csv`

### case02_schedule
Same as case01, but the HTTP allow rule uses a **non-always schedule** (`office-hours`).
Default behavior (no `--ignore-schedule`):
- flows that would match that rule become `UNKNOWN` with reason `SCHEDULE_NOT_EVALUATED`

Golden outputs:
- `expected/expected_default.csv`
- `expected/expected_ignore_schedule.csv`

Note: The Excel/MariaDB fixtures in this case are copied from case01 because your Excel/DB schema does not carry schedule.
Schedule handling is validated via the FortiGate config fixture.

### case03_fqdn
Demonstrates FQDN address object:
- A rule would otherwise match, but the destination is an FQDN object, so decision becomes `UNKNOWN` with reason `FQDN_NOT_RESOLVED` by default.

Golden output: `expected/expected.csv`

## Quick run (example)
```bash
static-traffic-analyzer   --config case01_basic/rules/fortigate.conf   --src-csv case01_basic/inputs/src.csv   --dst-csv case01_basic/inputs/dst.csv   --ports case01_basic/inputs/ports.txt   --out out.csv
diff -u out.csv case01_basic/expected/expected.csv
```

## MariaDB fixture usage (example)
```bash
mysql -h <host> -u <user> -p < case01_basic/rules/mariadb.sql
```
Then run the analyzer with your DSN option (e.g. `--db-conn`).
