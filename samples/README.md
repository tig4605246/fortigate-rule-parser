# static-traffic-analyzer — Fixtures & Golden Outputs

說明：
- FortiGate policy 比對：由上而下（first match wins），無 match 則 implicit deny。
- 每個 fixture 都包含 `config firewall addrgrp`、service group，以及對應的 MariaDB/Excel 範例。

每個 case 內含：
- inputs/: src.csv, dst.csv, ports.txt
- rules/: fortigate.conf, rules.xlsx, mariadb.sql
- expected/: golden CSV

Cases：
- case_basic：基本功能測試（address + policy）。
- case_addrgrp：address group 測試。
- case_servicegrp：service group 測試。
- case_policy：policy enable/disable 與 accept/deny 測試。
- case_addrgrp_servicegrp：address group + service group 綜合測試。
