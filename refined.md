下面是根據你的 **Clarification Answers** 更新後的 **精準可執行的開發者規格**。我已整合 Excel 服務群組格式、MariaDB members 資料結構、MariaDB 規則優先順序，以及明確限定 IPv4/CIDR 支援。
內容完整、可直交付給開發者實作。

---

## 靜態流量分析器 — *Static Traffic Analyzer* 開發規格（最終版）

---

## 1) Overview

`static-traffic-analyzer` 是一個 CLI 工具，用於靜態分析防火牆規則是否允許指定來源到目的的流量通過。
工具輸入包括三種規則來源（FortiGate Config / Excel / MariaDB），以及來源網段列表、目的網段列表及埠/協定列表。工具輸出一份結果 CSV，對每個 `(src × dst × port)` 組合顯示允許狀態。

核心策略執行模型：

> **Rules are evaluated top–down (first match wins).**
> 若沒有任何規則匹配，則為 **DENY (implicit deny)**。

> 註：本工具目前僅支援 **IPv4 / IPv4-CIDR**。

---

## 2) Inputs

---

### 2.1 防火牆規則來源（Firewall Rules Inputs）

---

#### 2.1.1 FortiGate CLI Config File

格式為 FortiOS **6.0.9** CLI 標準配置：

* address / addrgrp
* service custom / service group
* firewall policy

**要點**

* address object:

  * `set subnet <CIDR>`
  * `set type {ipmask | iprange | fqdn}`
* service object:

  * `tcp-portrange`, `udp-portrange`
* policy:

  * `srcaddr`, `dstaddr`, `service`, `action`, `schedule`, `status`

---

#### 2.1.2 Excel File

Excel 必須包含以下 **四個 Worksheets**：

---

##### Sheet: `Address Object`

| Column               | Description                                         |
| -------------------- | --------------------------------------------------- |
| Object Name          | 唯一名稱                                                |
| Type                 | `ipmask` / `iprange` / `fqdn`                       |
| Subnet/Start-IP      | 若 Type=`ipmask` 則為 CIDR；若 Type=`iprange` 則為起始 IP    |
| Mask/End-IP          | 若 Type=`ipmask` 則為 Netmask；若 Type=`iprange` 則為結束 IP |
| Associated Interface | 介面名稱（可忽略在靜態分析中）                                     |
| Description          | 註解                                                  |

---

##### Sheet: `Address Group`

| Column     | Description              |
| ---------- | ------------------------ |
| Group Name | 群組名稱                     |
| Member     | 群組成員列表，每行一個 address name |

---

##### Sheet: `Service Group`

| Column     | Description                 |
| ---------- | --------------------------- |
| Group Name | 群組名稱                        |
| Member     | 每行一個 port name 或 port range |

**Excel 的 Service Group 格式範例**

```
DNS
SMTP
tcp_30000-31000
```

其中 `Member` 欄位是以 **換行符（new line）分隔** 的清單。
工具必須解析每一行：有效值可以是預定義 port 名稱、單埠或範圍。

---

##### Sheet: `Rule`

| Column      | Description                |
| ----------- | -------------------------- |
| Seq         | 規則順序（整數；越小優先越高）            |
| Enable      | `true` / `false`           |
| Src Int     | 來源介面（可忽略）                  |
| Dst Int     | 目的介面（可忽略）                  |
| Source      | Address / Address Group 名稱 |
| Destination | Address / Address Group 名稱 |
| Service     | Service 或 Service Group 名稱 |
| Action      | `accept` / `deny`          |
| Logging     | 是否 Logging（可忽略）            |
| ID          | 唯一識別碼                      |
| Comments    | 註解                         |

---

#### 2.1.3 MariaDB Tables

使用資料庫 `firewall_mgmt` 的 4 張 Table：

---

##### Table: `cfg_address`

| Column       | Meaning                       |
| ------------ | ----------------------------- |
| object_name  | 名稱                            |
| address_type | `subnet` / `iprange` / `fqdn` |
| subnet       | 若 address_type=`subnet`       |
| start_ip     | 若 address_type=`iprange`      |
| end_ip       | 若 address_type=`iprange`      |

---

##### Table: `cfg_address_group`

| Column               | Meaning       |
| -------------------- | ------------- |
| group_name           | 群組名稱          |
| members              | JSON Array 字串 |
| 例: `["A", "B", "C"]` |               |

members 內容類型固定為 **JSON Array**（longtext）且值為 address 名稱。

---

##### Table: `cfg_service_group`

| Column     | Meaning       |
| ---------- | ------------- |
| group_name | 群組名稱          |
| members    | JSON Array 字串 |

members 內容類型固定為 **JSON Array**，且可包含：

* 預定義服務名稱
* 自訂服務名稱
* 埠範圍（格式例如 `"tcp_8001-8004"` 或 `"udp_2049"`）

---

##### Table: `cfg_policy`

| Column         | Meaning                    |
| -------------- | -------------------------- |
| priority       | 數字，排序值（由小到大決定 Top–Down 評估） |
| src_objects    | JSON Array 字串              |
| dst_objects    | JSON Array 字串              |
| service_objects | JSON Array 或單一 service 名稱  |
| action         | `accept` / `deny`          |
| is_enabled     | 0 / 1                      |
| log_traffic    | boolean                    |
| comments       | 描述文字                       |

> **規則匹配順序依照 `priority` 欄由小到大排序。**

---

### 2.2 Source IP List — `--src-csv`

* Header 欄： `Network Segment`
* 欄位內容必須為 IPv4 CIDR
* 允許有其他非必要欄位，但必須忽略

---

### 2.3 Destination IP List — `--dst-csv`

* Header 欄： `Network Segment`
* Optional：`GN`, `Site`, `Location`
* 其他欄位忽略

---

### 2.4 Port List — `--ports`

* 每行格式必須為：

  ```
  <label>,<port>/<proto>
  ```
* `proto` 必須是 `tcp` 或 `udp`
* `port` 介於 `1–65535`
* 範例：

  ```
  ssh,22/tcp
  http,80/tcp
  ```

---

## 3) Output CSV

---

### 3.1 每行必要輸出欄位

| Column                  | Type   | Meaning                          |
| ----------------------- | ------ | -------------------------------- |
| `src_network_segment`   | string | 來源 CIDR                          |
| `dst_network_segment`   | string | 目的 CIDR                          |
| `dst_gn`                | string | 若提供                              |
| `dst_site`              | string | 若提供                              |
| `dst_location`          | string | 若提供                              |
| `service_label`         | string | Port Label                       |
| `protocol`              | string | `tcp` / `udp`                    |
| `port`                  | int    | 埠號                               |
| `decision`              | enum   | `ALLOW` / `DENY` / `UNKNOWN`     |
| `matched_policy_id`     | string | 若 match                          |
| `matched_policy_name`   | string | 來源 Config、Excel ID 或 MariaDB key |
| `matched_policy_action` | string | `accept` / `deny`                |
| `reason`                | string | 機器可讀原因碼                          |

---

## 4) Policy Matching Semantics

---

### 4.1 Match Order

1. enabled = true
2. schedule active = yes
3. source address contains CIDR
4. dest address contains CIDR
5. service matches protocol/port

**第一條符合的規則即為最終結果。**

若無任何符合 → `decision=DENY`（Implicit deny）。

---

## 5) Object Parsing & Resolution

---

### 5.1 Address

* IPv4/CIDR: 支援 `ipmask`
* IPRange: 需支援
* FQDN: 預設視為 `UNKNOWN`（因為無法靜態 resolve）

---

### 5.2 Service Groups

Excel 及 MariaDB 的 group members 可包含：

* service 名稱（例如 `DNS`）
* port 直寫（例如 `udp_53`）
* 埠範圍（例如 `tcp_30000-31000`）

**解析規則**

```
proto_port_pattern  := <proto>_<start>-<end>
single_port_pattern := <proto>_<port>
```

---

## 6) CLI Contract

---

### 6.1 CLI Usage

```bash
static-traffic-analyzer \
  [--config fortigate.conf] \
  [--excel rules.xlsx] \
  [--db-conn "<dsn>"] \
  --src-csv src.csv \
  --dst-csv dst.csv \
  --ports ports.txt \
  --out result.csv \
  [--ignore-schedule] \
  [--match-mode segment|sample-ip|expand] \
  [--max-hosts 256]
```

---

## 7) Unit Testing

必須涵蓋：

| Area                   | Coverage            |
| ---------------------- | ------------------- |
| Port parsing           | 正常 / error          |
| CIDR containment       | 多種 CIDR case        |
| Service / ServiceGroup | 個別與 group 解析        |
| AddressGroup           | 多層 group            |
| Policy order           | first-match         |
| implicit deny          | no match            |
| Excel 格式變異檢測           | member 空行 / invalid |

---

## 8) Acceptance Criteria

* CLI 產出穩定結果與標準格式
* 典型 rule fixture match 預期
* 未支援 construct → `UNKNOWN`（不 crash）
* 可解析 Excel / DB / FortiGate config
