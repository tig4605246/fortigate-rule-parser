package main

import (
	"net"
	"os"
	"path/filepath"
	"static-traffic-analyzer/internal/parser"
	"testing"
)

func TestNewRootCmd(t *testing.T) {
	cmd := newRootCmd()
	if cmd == nil {
		t.Fatal("newRootCmd returned nil")
	}
	if cmd.Use != "static-traffic-analyzer" {
		t.Errorf("Expected use 'static-traffic-analyzer', got '%s'", cmd.Use)
	}
}

func TestEstimateTotalTasks(t *testing.T) {
	traffic := (*parser.InputTraffic)(nil)
	if estimateTotalTasks(traffic, "sample", 10) != 0 {
		t.Error("Expected 0 for nil traffic")
	}

	_, ipnet, _ := net.ParseCIDR("10.0.0.0/24")
	traffic = &parser.InputTraffic{
		SrcIPs: []*net.IPNet{ipnet},
		DstIPs: []parser.Destination{
			{IPNet: ipnet},
		},
		Ports: []parser.PortInfo{
			{Protocol: "tcp", Port: 80},
		},
	}

	// Sample mode
	count := estimateTotalTasks(traffic, "sample", 65536)
	if count != 1 {
		t.Errorf("Expected 1 task in sample mode, got %d", count)
	}

	// Expand mode
	count = estimateTotalTasks(traffic, "expand", 65536)
	if count != 256*256 {
		t.Errorf("Expected %d tasks in expand mode, got %d", 256*256, count)
	}

	// Max hosts restriction
	count = estimateTotalTasks(traffic, "expand", 10)
	if count != 1 {
		t.Errorf("Expected 1 task when max-hosts is exceeded, got %d", count)
	}
}

func TestSetupLogger(t *testing.T) {
	levels := []string{"DEBUG", "INFO", "WARN", "ERROR", "UNKNOWN"}
	for _, lvl := range levels {
		l := setupLogger(lvl, "")
		if l == nil {
			t.Errorf("setupLogger returned nil for level %s", lvl)
		}
	}

	tmpDir, _ := os.MkdirTemp("", "log-test")
	defer os.RemoveAll(tmpDir)
	logFile := filepath.Join(tmpDir, "test.log")
	l1 := setupLogger("INFO", logFile)
	if l1 == nil {
		t.Error("setupLogger with file returned nil")
	}
	
	// Test invalid log file path
	l2 := setupLogger("INFO", "/nonexistent/path/to/log.log")
	if l2 == nil {
		t.Error("setupLogger should return a logger even if file fails")
	}
}

func TestLoadPolicies(t *testing.T) {
	// Test unknown provider
	_, err := loadPolicies("unknown", "", "", "")
	if err == nil {
		t.Error("Expected error for unknown provider")
	}

	// Test fortigate with missing file
	_, err = loadPolicies("fortigate", "", "", "")
	if err == nil {
		t.Error("Expected error for missing fortigate rules path")
	}
	
	_, err = loadPolicies("fortigate", "/nonexistent/rules", "", "")
	if err == nil {
		t.Error("Expected error for nonexistent fortigate rules file")
	}

	// Test mariadb with missing DSN
	_, err = loadPolicies("mariadb", "", "", "")
	if err == nil {
		t.Error("Expected error for missing mariadb DSN")
	}

	// Test mariadb with invalid DSN (should fail on connection/parsing)
	_, err = loadPolicies("mariadb", "", "invalid-dsn", "")
	if err == nil {
		t.Error("Expected error for invalid mariadb DSN")
	}
}

func TestRun(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "analyzer-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	srcFile := filepath.Join(tmpDir, "src.csv")
	dstFile := filepath.Join(tmpDir, "dst.csv")
	portsFile := filepath.Join(tmpDir, "ports.txt")
	rulesFile := filepath.Join(tmpDir, "fortigate.conf")
	outFile := filepath.Join(tmpDir, "out.csv")
	routableFile := filepath.Join(tmpDir, "routable.csv")

	os.WriteFile(srcFile, []byte("Network Segment\n10.0.0.0/24"), 0644)
	os.WriteFile(dstFile, []byte("Network Segment,GN,Site,Location\n10.1.0.0/24,GN1,Site1,Loc1"), 0644)
	os.WriteFile(portsFile, []byte("HTTP,80/tcp"), 0644)
	os.WriteFile(rulesFile, []byte("config firewall policy\n    edit 1\n        set srcaddr \"all\"\n        set dstaddr \"all\"\n        set service \"HTTP\"\n        set action accept\n    next\nend"), 0644)

	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"--src", srcFile,
		"--dst", dstFile,
		"--ports", portsFile,
		"--rules", rulesFile,
		"--out", outFile,
		"--routable", routableFile,
		"--mode", "sample",
		"--log-level", "DEBUG",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Check if output files exist
	if _, err := os.Stat(outFile); os.IsNotExist(err) {
		t.Error("Output file was not created")
	}
	if _, err := os.Stat(routableFile); os.IsNotExist(err) {
		t.Error("Routable file was not created")
	}

	// Test Expand mode in run
	cmdExpand := newRootCmd()
	cmdExpand.SetArgs([]string{
		"--src", srcFile,
		"--dst", dstFile,
		"--ports", portsFile,
		"--rules", rulesFile,
		"--out", filepath.Join(tmpDir, "out_expand.csv"),
		"--routable", filepath.Join(tmpDir, "routable_expand.csv"),
		"--mode", "expand",
		"--max-hosts", "256",
	})
	if err := cmdExpand.Execute(); err != nil {
		t.Fatalf("Expand mode Execute failed: %v", err)
	}
}

func TestRunErrors(t *testing.T) {
    // Missing input files or other errors that should cause run to return error
    tmpDir, _ := os.MkdirTemp("", "run-errors")
    defer os.RemoveAll(tmpDir)

    cmd := newRootCmd()
    cmd.SetArgs([]string{"--src", filepath.Join(tmpDir, "nonexistent"), "--dst", "nonexistent", "--ports", "nonexistent"})
    if err := cmd.Execute(); err == nil {
        t.Error("Expected error for nonexistent input files")
    }

    // Invalid provider
    srcFile := filepath.Join(tmpDir, "src.csv")
    dstFile := filepath.Join(tmpDir, "dst.csv")
    portsFile := filepath.Join(tmpDir, "ports.txt")
    os.WriteFile(srcFile, []byte("Network Segment\n10.0.0.0/24"), 0644)
    os.WriteFile(dstFile, []byte("Network Segment\n10.1.0.0/24"), 0644)
    os.WriteFile(portsFile, []byte("80/tcp"), 0644)

    cmd = newRootCmd()
    cmd.SetArgs([]string{"--src", srcFile, "--dst", dstFile, "--ports", portsFile, "--provider", "invalid"})
    if err := cmd.Execute(); err == nil {
        t.Error("Expected error for invalid provider")
    }
}

func TestExpandCIDR(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("192.168.1.0/30")
	ips := expandCIDR(cidr)
	if len(ips) != 4 {
		t.Errorf("Expected 4 IPs, got %d", len(ips))
	}
}
