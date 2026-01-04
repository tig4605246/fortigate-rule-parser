# static-traffic-analyzer — Fixtures & Golden Outputs (NO `config firewall addrgrp`)

產生時間：20260104-122504

說明：
- FortiGate policy 比對：由上而下（first match wins），無 match 則 implicit deny。
- 本套件的 FortiGate config fixture **不使用** `config firewall addrgrp`；若需多來源，使用多條 policy 表達。

每個 case 內含：
- inputs/: src.csv, dst.csv, ports.txt
- rules/: fortigate.conf, rules.xlsx, mariadb.sql
- expected/: golden CSV

Cases：
- case01_basic_no_addrgrp
- case02_schedule_no_addrgrp
- case03_fqdn_no_addrgrp
