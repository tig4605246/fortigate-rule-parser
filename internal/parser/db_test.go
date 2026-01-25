package parser

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	"static-traffic-analyzer/internal/model"
)

var testDB *sql.DB
var dsn = "root:static@tcp(127.0.0.1:3306)/firewall_mgmt"

func TestMain(m *testing.M) {
	var err error
	testDB, err = sql.Open("mysql", dsn)
	if err != nil {
		fmt.Printf("failed to connect to MariaDB: %v\n", err)
		os.Exit(0) // Skip tests if DB is not available
	}

	if err := testDB.Ping(); err != nil {
		fmt.Printf("MariaDB not reachable: %v\n", err)
		os.Exit(0) // Skip tests if DB is not reachable
	}

	setupSchema()
	code := m.Run()
	os.Exit(code)
}

func setupSchema() {
	testDB.Exec("DROP TABLE IF EXISTS cfg_policy")
	testDB.Exec("DROP TABLE IF EXISTS cfg_address")
	testDB.Exec("DROP TABLE IF EXISTS cfg_address_group")
	testDB.Exec("DROP TABLE IF EXISTS cfg_service_group")

	testDB.Exec(`CREATE TABLE cfg_address (
		id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
		object_name VARCHAR(64) NOT NULL,
		address_type VARCHAR(16) NOT NULL,
		subnet VARCHAR(64) NULL,
		start_ip VARCHAR(64) NULL,
		end_ip VARCHAR(64) NULL
	)`)

	testDB.Exec(`CREATE TABLE cfg_address_group (
		id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
		group_name VARCHAR(64) NOT NULL,
		members LONGTEXT NOT NULL
	)`)

	testDB.Exec(`CREATE TABLE cfg_service_group (
		id BIGINT PRIMARY KEY AUTO_INCREMENT,
		group_name VARCHAR(64) NOT NULL,
		members LONGTEXT NOT NULL
	)`)

	testDB.Exec(`CREATE TABLE cfg_policy (
		id BIGINT PRIMARY KEY AUTO_INCREMENT,
		priority INT(10) UNSIGNED NOT NULL,
		policy_id INT(10) UNSIGNED NOT NULL,
		src_objects LONGTEXT NOT NULL,
		dst_objects LONGTEXT NOT NULL,
		service_objects LONGTEXT NOT NULL,
		action VARCHAR(16) NOT NULL,
		is_enabled VARCHAR(16) NOT NULL
	)`)
}

func TestMariaDBParser(t *testing.T) {
	// Clean tables
	testDB.Exec("DELETE FROM cfg_address")
	testDB.Exec("DELETE FROM cfg_address_group")
	testDB.Exec("DELETE FROM cfg_service_group")
	testDB.Exec("DELETE FROM cfg_policy")

	// Insert data
	testDB.Exec("INSERT INTO cfg_address (object_name, address_type, subnet) VALUES (?, ?, ?)", "addr1", "ipmask", "10.0.0.0/24")
	testDB.Exec("INSERT INTO cfg_address (object_name, address_type, start_ip, end_ip) VALUES (?, ?, ?, ?)", "addr2", "iprange", "192.168.1.1", "192.168.1.10")
	testDB.Exec("INSERT INTO cfg_address_group (group_name, members) VALUES (?, ?)", "grp1", `["addr1", "addr2"]`)
	testDB.Exec("INSERT INTO cfg_service_group (group_name, members) VALUES (?, ?)", "svcgrp1", `["DNS"]`)
	testDB.Exec("INSERT INTO cfg_policy (priority, policy_id, src_objects, dst_objects, service_objects, action, is_enabled) VALUES (?, ?, ?, ?, ?, ?, ?)", 
		10, 101, `["grp1"]`, `["all"]`, `["svcgrp1"]`, "accept", "enable")

	p, err := NewMariaDBParser(dsn)
	if err != nil {
		t.Fatalf("failed to create parser: %v", err)
	}
	defer p.Close()

	if err := p.Parse(); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if len(p.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(p.Policies))
	}

	policy := p.Policies[0]
	if len(policy.SrcAddrs) != 2 {
		t.Errorf("expected 2 flattened src addrs, got %d", len(policy.SrcAddrs))
	}
	if len(policy.Services) < 1 {
		t.Errorf("expected at least 1 flattened service, got %d", len(policy.Services))
	}
}

func TestMariaDBParserFlattenGroups(t *testing.T) {
    p := &MariaDBParser{
        Policies: []model.Policy{
            {ID: "1", RawSrcAddrNames: []string{"A"}},
        },
        AddrGrps: map[string][]string{
            "A": {"B"},
            "B": {"A"},
        },
    }
    err := p.flattenGroups()
    if err == nil || !strings.Contains(err.Error(), "circular dependency") {
        t.Errorf("expected circular dependency error, got %v", err)
    }

    p2 := &MariaDBParser{
        Policies: []model.Policy{
            {ID: "2", RawDstAddrNames: []string{"A"}},
        },
        AddrGrps: map[string][]string{
            "A": {"B"},
            "B": {"A"},
        },
    }
    err = p2.flattenGroups()
    if err == nil || !strings.Contains(err.Error(), "circular dependency") {
        t.Errorf("expected circular dependency error, got %v", err)
    }

    p3 := &MariaDBParser{
        Policies: []model.Policy{
            {ID: "3", RawSvcNames: []string{"A"}},
        },
        SvcGrps: map[string][]string{
            "A": {"B"},
            "B": {"A"},
        },
    }
    err = p3.flattenGroups()
    if err == nil || !strings.Contains(err.Error(), "circular dependency") {
        t.Errorf("expected circular dependency error, got %v", err)
    }
}

func TestMariaDBParserSvcFlattening(t *testing.T) {
    p := &MariaDBParser{
        ServiceObjects: make(map[string]*model.ServiceObject),
        SvcGrps: make(map[string][]string),
    }
    
    // Test ad-hoc service
    svcs, err := p.flattenSvcGroup("tcp_8001-8004", make(map[string]bool))
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if len(svcs) != 1 || svcs[0].StartPort != 8001 || svcs[0].EndPort != 8004 {
        t.Errorf("failed to flatten ad-hoc service: %#v", svcs)
    }

    // Test unknown service
    svcs, err = p.flattenSvcGroup("unknown_svc", make(map[string]bool))
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if len(svcs) != 0 {
        t.Errorf("expected 0 svcs for unknown, got %d", len(svcs))
    }
}

func TestNewMariaDBParserErrors(t *testing.T) {
    _, err := NewMariaDBParser("invalid-dsn")
    if err == nil {
        t.Errorf("expected error for invalid DSN")
    }
}
