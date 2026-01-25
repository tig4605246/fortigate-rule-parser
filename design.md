這是一份針對將現有 Python `static-traffic-analyzer` 專案重寫為 Go 語言的技術設計文件。

---

# Static Traffic Analyzer (Go Rewrite) - 技術設計文件

## 1. 程式目的 (Program Purpose)

本程式為一個高效能的靜態防火牆規則分析工具。其主要功能為讀取防火牆設定（規則來源），並針對指定的大量「來源 IP」、「目的 IP」與「端口/服務」組合進行模擬路由測試，判斷每一筆流量是被 **允許 (ALLOW)** 還是 **拒絕 (DENY)**，並產生詳細的分析報告。

**核心目標：**

* **正確性**：精確模擬 FortiGate 防火牆的 "First Match Wins"（由上而下優先權）邏輯與 "Implicit Deny"（預設拒絕）機制。
* **效能**：利用 Go 的高並發特性，大幅縮短海量流量組合（例如百萬級別的 Src/Dst/Port 組合）的分析時間。
* **可擴展性**：模組化設計，易於支援新的規則來源格式。

---

## 2. 系統架構 (System Architecture)

程式將採用 **Producer-Consumer** 模型與 **Pipeline** 架構來實現高並發處理。

### 2.1 資料流 (Data Flow)

1. **Rule Loader**: 啟動時一次性載入防火牆規則（Policy, Address Object, Service Object）至記憶體，建立快速查詢索引。
2. **Task Producer**: 讀取 Source CSV, Destination CSV, Ports File，生成所有需驗證的 `(Src, Dst, Port)` 三元組任務 (Tasks)。
3. **Worker Pool**: 多個 Goroutines 並行從 Task Queue 領取任務，執行規則比對 (Policy Evaluation)。
4. **Result Collector**: 接收 Worker 的比對結果，透過 Channel 傳送給 Writer。
5. **Async Writer**: 獨立的 Goroutine 負責將結果即時寫入 CSV 檔案，避免 I/O 阻塞計算流程。

---

## 3. 模組設計 (Module Design)

### 3.1 輸入資料支援 (Input Data Support)

程式需實作 `RuleProvider` 介面，支援以下三種輸入來源：

1. **FortiGate Config (`.conf`)**
* 解析 `config firewall address`, `addrgrp`, `service custom`, `service group`, `policy` 區塊。
* 支援 `set type ipmask`, `iprange`, `fqdn`。
* 支援 `tcp-portrange`, `udp-portrange`。

Example FortiGate Config:

```conf
config firewall address
    edit "SRC_NET_10"
        set type ipmask
        set subnet 192.168.10.0 255.255.255.0
    next
    edit "SRC_HOST_20_10"
        set type ipmask
        set subnet 192.168.20.10 255.255.255.255
    next
    edit "DST_WEB_NET"
        set type ipmask
        set subnet 10.0.0.0 255.255.255.0
    next
    edit "DST_DB_HOST"
        set type ipmask
        set subnet 10.0.1.5 255.255.255.255
    next
end

config firewall addrgrp
    edit "SRC_ALL"
        set member "SRC_NET_10" "SRC_HOST_20_10"
    next
    edit "DST_SENSITIVE"
        set member "DST_DB_HOST"
    next
end

config firewall service custom
    edit "tcp_8001-8004"
        set tcp-portrange 8001-8004
    next
end

config firewall service group
    edit "SG_DB_CUSTOM"
        set member "tcp_8001-8004" "DNS"
    next
end

config firewall policy
    edit 50
        set name "allow-db-custom-range-host"
        set status enable
        set schedule "always"
        set srcaddr "SRC_HOST_20_10"
        set dstaddr "DST_DB_HOST"
        set service "SG_DB_CUSTOM"
        set action accept
    next
    edit 51
        set name "deny-all-to-sensitive"
        set status enable
        set schedule "always"
        set srcaddr "SRC_ALL"
        set dstaddr "DST_SENSITIVE"
        set service "ALL"
        set action deny
    next
    edit 52
        set name "allow-web-http-from-src-all"
        set status enable
        set schedule "always"
        set srcaddr "SRC_ALL"
        set dstaddr "DST_WEB_NET"
        set service "HTTP"
        set action accept
    next
end

```

2. **MariaDB Database**
* 連接資料庫讀取 `cfg_address`, `cfg_address_group`, `cfg_service_group`, `cfg_policy` 表格。
* 解析 `members` 欄位中的 JSON 陣列字串。
* 依據 `priority` 欄位排序規則。

Example MariaDB Schema:

```SQL
-- MariaDB schema (as provided)
CREATE DATABASE IF NOT EXISTS firewall_mgmt;
USE firewall_mgmt;

DROP TABLE IF EXISTS cfg_policy;
DROP TABLE IF EXISTS cfg_address;
DROP TABLE IF EXISTS cfg_address_group;
DROP TABLE IF EXISTS cfg_service_group;

CREATE TABLE cfg_address (
  id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  fab_name VARCHAR(16) NULL,
  firewall_id VARCHAR(64) NULL,
  object_name VARCHAR(64) NOT NULL,
  address_type VARCHAR(16) NOT NULL,
  subnet VARCHAR(64) NULL,
  start_ip VARCHAR(64) NULL,
  end_ip VARCHAR(64) NULL,
  created_at TIMESTAMP NULL,
  updated_at TIMESTAMP NULL
);

CREATE TABLE cfg_address_group (
  id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  fab_name VARCHAR(16) NULL,
  firewall_id VARCHAR(64) NULL,
  group_name VARCHAR(64) NOT NULL,
  members LONGTEXT NOT NULL,
  created_at TIMESTAMP NULL,
  updated_at TIMESTAMP NULL
);

CREATE TABLE cfg_service_group (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  fab_name VARCHAR(16) NULL,
  firewall_id VARCHAR(64) NULL,
  group_name VARCHAR(64) NOT NULL,
  members LONGTEXT NOT NULL,
  created_at TIMESTAMP NULL,
  updated_at TIMESTAMP NULL
);

CREATE TABLE cfg_policy (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  fab_name VARCHAR(16) NULL,
  firewall_id VARCHAR(64) NULL,
  priority INT(10) UNSIGNED NOT NULL,
  policy_id INT(10) UNSIGNED NOT NULL,
  src_objects LONGTEXT NOT NULL,
  dst_objects LONGTEXT NOT NULL,
  service_objects LONGTEXT NOT NULL,
  action VARCHAR(16) NOT NULL,
  is_enabled VARCHAR(16) NOT NULL,
  log_traffic VARCHAR(16) NULL,
  comments VARCHAR(1024) NULL,
  created_at TIMESTAMP NULL,
  updated_at TIMESTAMP NULL
);
INSERT INTO cfg_address (fab_name, firewall_id, object_name, address_type, subnet, start_ip, end_ip) VALUES
  ('FAB', 'FW1', 'SRC_NET_10', 'iprange', NULL, '192.168.10.0', '192.168.10.255'),
  ('FAB', 'FW1', 'SRC_NET_1', 'ipmask', '1.1.1.1/24', NULL, NULL),
  ('FAB', 'FW1', 'DST_SERVER', 'ipmask', '5.5.5.5/24', NULL, NULL),
  ('FAB', 'FW1', 'DST_WEB_NET', 'ipmask', '10.0.0.0/24', NULL, NULL);

INSERT INTO cfg_policy (fab_name, firewall_id, priority, policy_id, src_objects, dst_objects, service_objects, action, is_enabled, log_traffic, comments)
VALUES
  ('FAB', 'FW1', 10, 10, '["SRC_NET_1","SRC_NET_10"]', '["DST_SERVER","DST_WEB_NET"]', '["HTTP"]', 'accept', 'enable', 'all', 'allow http from src_net_10 to web');

```


1. **Excel / CSV Rule Files**
* (選擇性支援或透過 CSV 中介) 讀取規則清單。根據 Python 程式碼，Excel 解析包含 Address Object, Address Group, Service Group, Rule 等分頁。



**流量輸入 (Traffic Inputs):**

* **Source IP List**: CSV 格式，需解析 CIDR 欄位 (e.g., `Network Segment`)。
* **Destination IP List**: CSV 格式，需解析 CIDR 及相關 metadata (Site, GN, Location)。
* **Ports List**: 純文字或 CSV，包含 `Service Label`, `Port`, `Protocol` (e.g., `ssh,22/tcp`)。

### 3.2 核心資料結構 (Core Data Structures)

使用強型別 Structs 儲存規則與物件，並優化查詢效率（例如將 Group 預先展開為 IP 列表）。

```go
type Protocol string // "tcp", "udp"

type AddressObject struct {
    Name        string
    Type        string // "ipmask", "iprange", "fqdn"
    IPNet       *net.IPNet
    StartIP     net.IP
    EndIP       net.IP
    FQDN        string
}

type ServiceObject struct {
    Name      string
    Protocol  Protocol
    StartPort int
    EndPort   int
}

type Policy struct {
    ID          string
    Priority    int
    SrcAddrs    []*AddressObject // 預先解析 Group
    DstAddrs    []*AddressObject
    Services    []*ServiceObject
    Action      string // "accept", "deny"
    Enabled     bool
    Schedule    string
}

```

### 3.3 Well Known Ports 查詢表

* **實作方式**: 內嵌 (Embed) `well_known_ports.csv` 到 Go執行檔中。
* **用途**: 當規則中引用如 "HTTP", "SSH" 等標準服務名稱但未定義在 `service custom` 時，由此表查找對應端口 (e.g., HTTP -> 80/tcp)。
* **初始化**: 程式啟動時載入至 `map[string][]ServiceEntry` 全域變數中。

```go
//go:embed data/well_known_ports.csv
var wellKnownPortsData string

type ServiceRegistry struct {
    tcpMap map[int]string
    udpMap map[int]string
}

```

---

## 4. 並發與效能設計 (Concurrency & Performance)

### 4.1 多執行緒處理 (Multi-threading / Concurrency)

這是 Go 版本最大的優勢所在。

* **Worker Pool Pattern**:
* 主程式根據 CPU 核心數 (或 CLI 參數 `--workers`) 啟動 N 個 Worker Goroutines。
* 使用 `chan Task` 作為任務佇列。
* 使用 `sync.WaitGroup` 等待所有任務完成。
* Task Channel: 定義一個 chan SimulationTask，緩衝區大小可設為 Worker 數量的倍數。
* Worker: 根據 CPU 核心數 (或是 --workers 參數) 啟動 $N$ 個 Goroutine。
* Context Sharing: 所有 Worker 共享唯讀的 PolicyEngine (包含 AddressBook, ServiceBook, PolicyList)。由於是唯讀，無需 Mutex 鎖，效能極高。
* 流程：
  * Main Goroutine 產生 Src * Dst * Port 的組合，發送至 Task Channel。
  * Worker 從 Channel 領取任務，呼叫 EvaluatePolicy()。
  * Worker 將結果發送至 Result Channel。


* **Task 定義**:
```go
type Task struct {
    SrcIP   net.IP
    DstIP   net.IP // 或 net.IPNet
    DstMeta map[string]string // 用於輸出
    Port    int
    Proto   Protocol
}

```



### 4.2 非同步輸出 (Asynchronous Output)

* **架構**:
* 建立一個 `chan Result` (Buffered Channel)。
* 啟動 **單一** Writer Goroutine 監聽此 Channel。
* Worker 完成計算後，將 `Result` 丟入 Channel 即繼續處理下個任務，不等待 I/O。
* Writer Goroutine 負責將 `Result` 序列化為 CSV 行並寫入檔案 (使用 `encoding/csv` 並配合 `Flush`)。
* Graceful Shutdown: 當 Result Channel 關閉且緩衝區寫入完畢後，才關閉檔案並通知主程式結束。

```go
// SimulationResult 模擬結果
type SimulationResult struct {
    Src       string
    Dst       string
    Port      uint16
    Decision  string // "ALLOW", "DENY"
    PolicyID  string
    Reason    string
}
```


### 4.3 支援輸出資料 (Output Data)

輸出為 CSV 格式，包含以下欄位 (參考 Python `cli.py` 與 `expected.csv`):

* `src_network_segment`
* `dst_network_segment`
* `dst_gn`, `dst_site`, `dst_location` (來自 Dst CSV metadata)
* `service_label`
* `protocol`, `port`
* `decision`: **ALLOW** / **DENY** / **UNKNOWN**
* `matched_policy_id`: 命中的規則 ID
* `matched_policy_action`: 命中的規則動作 (accept/deny)
* `reason`: 例如 `MATCH_POLICY_ACCEPT`, `IMPLICIT_DENY`, `FQDN_NOT_RESOLVED`

輸出有兩份檔案:
* All Result CSV (--out)
  * 內容： 包含所有模擬的結果（無論 Allow 或 Deny）。
* Accept Traffic CSV (routable.csv)
  * 觸發條件： 當模式設定為 fuzzy 或使用者要求輸出可路由清單時。
  * 內容： 僅包含 Decision 為 ALLOW 的紀錄。

---

## 5. 日誌系統 (Logging Strategy)

### 5.1 Tiered Log Level

使用 Go 1.21+ 內建的 `log/slog` 套件實現結構化分級日誌。

* **Levels**:
* **DEBUG**: 顯示詳細的比對過程 (e.g., "SrcIP 1.2.3.4 match Policy 10 SrcObject 'LAN'").
* **INFO**: 顯示進度摘要 (e.g., "Loaded 500 policies", "Processed 1000/50000 tasks").
* **WARN**: 解析錯誤或無效的規則參照 (e.g., "Policy 5 refers to unknown address object 'OBSOLETE'").
* **ERROR**: 致命錯誤 (e.g., "Cannot open input file").

* **Informative Logs**:
* 日誌需包含 Context 資訊 (e.g., Worker ID, Policy ID)。
* 支援輸出到 Stderr 或 Log File。

* 實作：
  * 支援 --log-level 參數動態調整 Handler 的 Level。
  * 支援 --log-file 輸出至檔案，或預設輸出至 Stderr。
  * 在 Worker 中記錄 Log 時，需確保 Logger 是 Thread-safe 的 (slog 預設即是)。

---

## 6. 實作步驟建議 (Implementation Steps)

1. **Phase 1: 基礎建設**
* 定義 `Policy`, `Address`, `Service` 等 Structs。
* 實作 `CIDR` 包含判斷與 `IP` 比對邏輯 (使用 `net` 標準庫)。
* 嵌入 `well_known_ports.csv` 並實作查找器。


2. **Phase 2: 解析器 (Parsers)**
* 實作 FortiGate Config 解析器 (Text scanning)。
* 實作 MariaDB 解析器 (使用 `database/sql` + `go-sql-driver/mysql`)。
* 實作 CSV/Excel 讀取器。


3. **Phase 3: 核心引擎 (Core Engine)**
* 實作 `Evaluator` 邏輯：遍歷規則列表 -> 比對 Src/Dst/Svc -> 返回結果。
* 處理 Implicit Deny。


4. **Phase 4: 並發與 CLI**
* 實作 Worker Pool 與 Channel 串接。
* 實作 Async CSV Writer。
* 整合 `cobra` 或 `flag` 處理 CLI 參數。


5. **Phase 5: 測試與優化**
* 使用 Python 版的 `samples` 作為 Golden Test Cases 進行驗收測試。
* 進行 Benchmark，優化記憶體配置 (減少 GC 壓力)。

---

## 7. 目錄結構

static-traffic-analyzer-go/
├── cmd/
│   └── analyzer/
│       └── main.go        # CLI 入口 (使用 cobra 或 flag)
├── internal/
│   ├── parser/            # 解析器 (FortiGate, CSV, DB)
│   ├── model/             # 資料結構定義
│   ├── engine/            # 核心匹配邏輯 (Evaluator)
│   ├── worker/            # Concurrency 管理
│   └── logger/            # Log 設定
├── pkg/
│   └── wellknown/         # Embedded ports data
├── go.mod
└── go.sum

---

## 8. 關鍵優化點 (Go vs Python)

* **預先展開 (Flattening)**: 在 Python 版中，Address Group 和 Service Group 的成員解析可能在執行期進行。在 Go 版本中，建議在載入階段就將所有 Group 展開為扁平的 `[]*Object` Slice，這樣在 `Evaluate` 迴圈中無需重複查找 Map，可達到 O(1) 存取。
* **IP 比對**: Python 的 `ipaddress` 庫功能強大但稍慢。Go 的 `net.IPNet.Contains()` 非常高效，可直接使用位元運算加速 CIDR 比對。
* **無鎖設計**: 由於規則載入後只讀不寫 (Read-only)，Worker 之間無需 Mutex 鎖即可安全讀取全域規則表。